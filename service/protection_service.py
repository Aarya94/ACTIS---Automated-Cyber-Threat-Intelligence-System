"""
ACTIS Windows Protection Service
Provides the resident protection layer foundation, coordinating service lifecycle,
state transitions, worker pools, event intake queue, and dispatch to the Analysis Orchestrator.

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. Pure infrastructure & orchestration: Contains NO detection logic, ML scoring, or PE inspection.
2. Events are received via SecurityEvent boundary and dispatched to AnalysisOrchestrator.
3. Thread-safe lifecycle transitions and bounded worker execution.
"""

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from service.lifecycle import ServiceState, IServiceLifecycle, ServiceLifecycleError
from service.config import ServiceConfig, get_default_service_config
from service.state import ServiceStateManager
from service.workers import WorkerManager
from service.events import SecurityEvent, SecurityEventQueue, SecurityEventType
from service.dispatcher import EventDispatcher, IAnalysisOrchestrationBoundary, AnalysisOrchestrationStub
from service.health import ServiceHealth
from scanners.file_watcher import FilesystemEventSource, FilesystemEvent
from service.file_normalizer import FilesystemEventNormalizer, NormalizedFileEvent
from service.file_filter import FileEventFilter, FileFilterPolicy
from service.debouncer import FileEventDebouncer
from config.config import get_logger

logger = get_logger("ProtectionService")


class ProtectionService(IServiceLifecycle):
    """
    Resident Protection Service foundation for ACTIS.
    Manages background workers, event queues, and dispatch handoffs.
    """

    def __init__(
        self,
        config: Optional[ServiceConfig] = None,
        orchestrator: Optional[IAnalysisOrchestrationBoundary] = None,
        worker_task_override: Optional[Callable[[], bool]] = None,
    ):
        self.config = config or get_default_service_config()
        self.state_manager = ServiceStateManager(initial_state=ServiceState.STOPPED)
        self.dispatcher = EventDispatcher()
        self._worker_task_override = worker_task_override

        # Connect analysis orchestrator handoff boundary
        self.orchestrator = orchestrator or AnalysisOrchestrationStub()
        self.dispatcher.connect_orchestrator(self.orchestrator)

        # Event intake queue
        self.event_queue = SecurityEventQueue(maxsize=self.config.queue_max_size)

        # Worker manager
        self.worker_manager = WorkerManager(
            worker_count=self.config.worker_count,
            worker_name_prefix=f"{self.config.service_name}-Worker",
            on_worker_error=self._on_worker_error,
        )

        # Filesystem event monitoring components
        self.monitored_paths: List[str] = list(getattr(self.config, "monitored_paths", []))
        self.file_event_source: Optional[FilesystemEventSource] = None
        self.file_normalizer = FilesystemEventNormalizer()
        self.file_filter = FileEventFilter(
            policy=FileFilterPolicy(
                filter_temporary_files=getattr(self.config, "filter_temporary_files", True),
                monitored_roots=self.monitored_paths,
            )
        )
        self.file_debouncer: Optional[FileEventDebouncer] = None

        self._lock = threading.Lock()
        self._start_time: Optional[float] = None
        self._start_iso: Optional[str] = None
        self._restart_count = 0

    def _worker_task(self) -> bool:
        """
        Single work cycle executed by managed workers.
        Consumes from the bounded event queue and dispatches across the analysis boundary.
        Returns True if an item was processed, False otherwise.
        """
        if self._worker_task_override is not None:
            return self._worker_task_override()

        event = self.event_queue.get(block=True, timeout=0.1)
        if event is None:
            return False

        try:
            self.dispatcher.dispatch(event)
            return True
        finally:
            self.event_queue.task_done()

    def _on_worker_error(self, worker_id: str, error: Exception) -> None:
        """Callback invoked when a managed worker thread encounters an error."""
        err_msg = f"Worker '{worker_id}' failed: {str(error)}"
        logger.error(err_msg)
        self.state_manager.record_error(err_msg)

        with self._lock:
            # If service is stopping or stopped, ignore
            if self.state_manager.current_state in (ServiceState.STOPPING, ServiceState.STOPPED):
                return

            # Check bounded recovery policy
            if (
                self.config.auto_restart_workers
                and self._restart_count < self.config.max_restart_attempts
            ):
                self._restart_count += 1
                logger.warning(
                    f"Initiating bounded worker recovery attempt {self._restart_count}/"
                    f"{self.config.max_restart_attempts} for worker '{worker_id}'..."
                )
                if self.config.restart_cooldown_seconds > 0:
                    time.sleep(self.config.restart_cooldown_seconds)

                restarted = self.worker_manager.restart_failed_workers(work_fn=self._worker_task)
                if restarted > 0 and self.worker_manager.all_alive():
                    logger.info(f"Worker recovery successful: {restarted} worker(s) restored.")
                    if self.state_manager.current_state != ServiceState.RUNNING:
                        try:
                            self.state_manager.transition_to(
                                ServiceState.RUNNING,
                                reason=f"Recovered via restart attempt {self._restart_count}"
                            )
                        except ServiceLifecycleError:
                            pass
                    return

            # If recovery not enabled or attempts exhausted
            alive_count = self.worker_manager.active_count()
            current_state = self.state_manager.current_state

            if alive_count == 0:
                logger.critical(
                    f"All workers terminated unexpectedly (recovery attempts: "
                    f"{self._restart_count}/{self.config.max_restart_attempts}). Transitioning to FAILED."
                )
                try:
                    self.state_manager.transition_to(
                        ServiceState.FAILED,
                        reason=f"All workers terminated. Last error: {err_msg}"
                    )
                except ServiceLifecycleError:
                    pass
            elif current_state == ServiceState.RUNNING:
                logger.warning(
                    f"Worker failure detected ({alive_count}/{self.worker_manager.total_count()} active). "
                    f"Transitioning to DEGRADED."
                )
                try:
                    self.state_manager.transition_to(
                        ServiceState.DEGRADED,
                        reason=f"Degraded worker pool ({alive_count} active). Last error: {err_msg}"
                    )
                except ServiceLifecycleError:
                    pass

    # --- IServiceLifecycle Implementation ---

    def start(self) -> bool:
        """
        Starts the protection service and background worker threads.
        Thread-safe and idempotent.
        """
        with self._lock:
            current = self.state_manager.current_state
            if current == ServiceState.RUNNING:
                logger.info("start() called but service is already RUNNING. No action needed.")
                return True
            if current == ServiceState.STARTING:
                logger.warning("start() called while service is already STARTING.")
                return True

            logger.info(f"Starting ACTIS Protection Service '{self.config.service_name}'...")
            try:
                self.state_manager.transition_to(
                    ServiceState.STARTING,
                    reason="Startup requested"
                )
            except ServiceLifecycleError as ex:
                logger.error(f"Failed to initiate startup: {ex}")
                return False

            try:
                # Start background workers
                started = self.worker_manager.start_workers(work_fn=self._worker_task)
                if not started:
                    raise RuntimeError("WorkerManager failed to launch worker threads.")

                self._start_time = time.time()
                self._start_iso = datetime.now(timezone.utc).isoformat()

                # Transition to RUNNING
                self.state_manager.transition_to(
                    ServiceState.RUNNING,
                    reason="Workers successfully initialized and started"
                )
                logger.info(f"ACTIS Protection Service '{self.config.service_name}' is now RUNNING.")

                # Start filesystem monitoring if enabled and paths configured
                if getattr(self.config, "enable_file_monitoring", False) and self.monitored_paths:
                    self.start_filesystem_monitoring()

                return True

            except Exception as start_err:
                err_msg = f"Startup failed: {str(start_err)}"
                logger.critical(err_msg, exc_info=True)
                self.state_manager.record_error(err_msg)
                try:
                    self.state_manager.transition_to(
                        ServiceState.FAILED,
                        reason=err_msg
                    )
                except ServiceLifecycleError:
                    pass
                # Ensure any partially started workers are stopped
                self.worker_manager.stop_workers(timeout_per_worker=1.0)
                return False

    def stop(self, timeout: Optional[float] = None) -> bool:
        """
        Gracefully stops the protection service and terminates workers.
        Thread-safe and idempotent.
        """
        with self._lock:
            current = self.state_manager.current_state
            if current == ServiceState.STOPPED:
                logger.info("stop() called but service is already STOPPED. No action needed.")
                return True

            logger.info(f"Stopping ACTIS Protection Service '{self.config.service_name}'...")
            shutdown_timeout = timeout or self.config.shutdown_timeout_seconds

            try:
                self.state_manager.transition_to(
                    ServiceState.STOPPING,
                    reason="Shutdown requested"
                )
            except ServiceLifecycleError:
                # If already FAILED or in another state, proceed with resource cleanup
                pass

            # Gracefully stop filesystem monitoring first
            self.stop_filesystem_monitoring()

            # Gracefully stop workers
            workers_clean = self.worker_manager.stop_workers(timeout_per_worker=shutdown_timeout)
            if not workers_clean:
                logger.warning("One or more workers did not terminate within timeout during stop().")

            self.worker_manager.clear()
            self._start_time = None

            try:
                self.state_manager.transition_to(
                    ServiceState.STOPPED,
                    reason="Workers stopped and resources released"
                )
            except ServiceLifecycleError as ex:
                logger.error(f"Error transitioning to STOPPED: {ex}")

            logger.info(f"ACTIS Protection Service '{self.config.service_name}' has STOPPED.")
            return True

    def pause(self) -> bool:
        """Pauses worker intake without terminating threads."""
        with self._lock:
            current = self.state_manager.current_state
            if current != ServiceState.RUNNING:
                logger.warning(f"Cannot pause service in state '{current.value}'. Must be RUNNING.")
                return False

            try:
                self.state_manager.transition_to(
                    ServiceState.PAUSED,
                    reason="Pause requested"
                )
                self.worker_manager.pause_workers()
                logger.info("Service PAUSED.")
                return True
            except ServiceLifecycleError as ex:
                logger.error(f"Pause transition rejected: {ex}")
                return False

    def resume(self) -> bool:
        """Resumes event processing after being paused."""
        with self._lock:
            current = self.state_manager.current_state
            if current != ServiceState.PAUSED:
                logger.warning(f"Cannot resume service in state '{current.value}'. Must be PAUSED.")
                return False

            try:
                self.state_manager.transition_to(
                    ServiceState.RUNNING,
                    reason="Resume requested"
                )
                self.worker_manager.resume_workers()
                logger.info("Service RESUMED to RUNNING.")
                return True
            except ServiceLifecycleError as ex:
                logger.error(f"Resume transition rejected: {ex}")
                return False

    def get_state(self) -> ServiceState:
        """Returns the current deterministic lifecycle state."""
        return self.state_manager.current_state

    def is_running(self) -> bool:
        """Returns True if the service is actively in RUNNING or PAUSED state."""
        return self.state_manager.current_state in (ServiceState.RUNNING, ServiceState.PAUSED)

    # --- Filesystem Monitoring Integration ---

    def _on_debounced_file_event(self, event: NormalizedFileEvent) -> None:
        """Callback invoked by FileEventDebouncer when a file event has settled."""
        try:
            sec_event = SecurityEvent(
                event_type=event.event_type,
                source="filesystem_watcher",
                target=event.path,
                metadata={
                    "source_type": "filesystem",
                    "raw_path": event.raw_path,
                    "previous_path": event.previous_path,
                    "is_directory": event.is_directory,
                    "coalesced_count": event.coalesced_count,
                    "file_size": event.file_size,
                    "debounced": True,
                }
            )
            success = self.submit_event(sec_event)
            if not success:
                logger.warning(
                    f"Failed to submit debounced file event {sec_event.event_id} for "
                    f"'{event.path}' (queue full or service not running)."
                )
        except Exception as ex:
            logger.error(f"Error handling debounced file event: {ex}", exc_info=True)

    def _on_raw_file_event(self, fs_event: FilesystemEvent) -> None:
        """Pipeline entry point for raw OS filesystem events from FilesystemEventSource."""
        try:
            normalized = self.file_normalizer.normalize(fs_event)
            is_allowed, reason = self.file_filter.filter_event(normalized)
            if not is_allowed:
                return

            if self.file_debouncer is not None:
                self.file_debouncer.submit(normalized)
        except Exception as ex:
            logger.error(f"Error filtering/normalizing raw filesystem event: {ex}", exc_info=True)

    def start_filesystem_monitoring(self, paths: Optional[List[str]] = None) -> bool:
        """
        Starts filesystem event monitoring on specified or configured paths.
        Validates target directories, initializes normalizer, filter, debouncer,
        and safely feeds settled events into the service queue.
        """
        target_paths = list(paths) if paths is not None else list(self.monitored_paths)
        if not target_paths:
            logger.info("No paths configured for filesystem monitoring.")
            return False

        valid_paths: List[str] = []
        for p in target_paths:
            try:
                p_obj = Path(p)
                if p_obj.exists() and p_obj.is_dir():
                    valid_paths.append(str(p_obj.resolve()))
                else:
                    logger.warning(f"Configured monitoring path does not exist or is not a directory: '{p}'")
            except Exception as ex:
                logger.warning(f"Invalid path '{p}': {ex}")

        if not valid_paths:
            logger.warning("No valid directories available to monitor.")
            return False

        self.monitored_paths = valid_paths

        # Safely shut down any active watcher or debouncer before reconfiguring
        self.stop_filesystem_monitoring()

        # Start debouncer
        self.file_debouncer = FileEventDebouncer(
            debounce_seconds=getattr(self.config, "debounce_delay_seconds", 1.0),
            on_stable_event=self._on_debounced_file_event,
        )
        self.file_debouncer.start()

        # Start filesystem event source
        self.file_event_source = FilesystemEventSource(
            paths=valid_paths,
            on_event=self._on_raw_file_event,
            recursive=True,
        )
        started = self.file_event_source.start()
        if started:
            logger.info(f"Filesystem monitoring started on {len(valid_paths)} path(s): {valid_paths}")
            return True
        else:
            logger.error("Failed to start FilesystemEventSource.")
            return False

    def stop_filesystem_monitoring(self) -> None:
        """Safely stops filesystem watcher and flushes debouncer."""
        if self.file_event_source is not None:
            try:
                self.file_event_source.stop()
            except Exception as ex:
                logger.error(f"Error stopping FilesystemEventSource: {ex}")
            finally:
                self.file_event_source = None

        if self.file_debouncer is not None:
            try:
                self.file_debouncer.stop()
            except Exception as ex:
                logger.error(f"Error stopping FileEventDebouncer: {ex}")
            finally:
                self.file_debouncer = None

    # --- Event Intake Boundary ---

    def submit_event(self, event: SecurityEvent) -> bool:
        """
        Accepts a SecurityEvent and queues it for dispatch to analysis.
        Rejects events if the service is not running or if queue is full.
        """
        if not self.is_running():
            logger.warning(
                f"Cannot submit event: service is in '{self.get_state().value}' state, not running."
            )
            return False

        return self.event_queue.put(event)

    # --- Health & Diagnostics ---

    def get_health(self) -> ServiceHealth:
        """Gathers and returns operational health telemetry."""
        with self._lock:
            current_state = self.state_manager.current_state
            now = time.time()
            uptime = (now - self._start_time) if (self._start_time and self.is_running()) else 0.0

            queue_stats = self.event_queue.get_stats()
            dispatch_stats = self.dispatcher.get_stats()
            worker_statuses = self.worker_manager.get_statuses()

            alive_count = sum(1 for w in worker_statuses if w.is_alive)
            total_count = len(worker_statuses)
            is_healthy = (current_state == ServiceState.RUNNING and alive_count == total_count)

            fs_info = {
                "active": self.file_event_source is not None and self.file_event_source.is_running,
                "monitored_paths": list(self.monitored_paths),
                "debouncer_stats": self.file_debouncer.get_stats() if self.file_debouncer else None,
                "filter_stats": self.file_filter.get_stats() if self.file_filter else None,
                "normalizer_stats": self.file_normalizer.get_stats() if self.file_normalizer else None,
            }

            return ServiceHealth(
                state=current_state.value,
                is_running=self.is_running(),
                is_healthy=is_healthy,
                uptime_seconds=round(uptime, 2),
                start_time=self._start_iso,
                workers_total=total_count,
                workers_alive=alive_count,
                queue_size=queue_stats["current_size"],
                events_enqueued=queue_stats["enqueued_count"],
                events_dequeued=queue_stats["dequeued_count"],
                events_dropped=queue_stats["dropped_count"],
                events_dispatched=dispatch_stats["dispatched_events"],
                last_error=self.state_manager.last_error,
                last_transition_time=self.state_manager.last_transition_time,
                restart_count=self._restart_count,
                worker_details=[w.to_dict() for w in worker_statuses],
                filesystem_monitoring=fs_info,
            )
