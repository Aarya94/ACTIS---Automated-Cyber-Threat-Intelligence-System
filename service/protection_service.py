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
from typing import Any, Dict, Optional

from service.lifecycle import ServiceState, IServiceLifecycle, ServiceLifecycleError
from service.config import ServiceConfig, get_default_service_config
from service.state import ServiceStateManager
from service.workers import WorkerManager
from service.events import SecurityEvent, SecurityEventQueue, SecurityEventType
from service.dispatcher import EventDispatcher, IAnalysisOrchestrationBoundary, AnalysisOrchestrationStub
from service.health import ServiceHealth
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
    ):
        self.config = config or get_default_service_config()
        self.state_manager = ServiceStateManager(initial_state=ServiceState.STOPPED)
        self.dispatcher = EventDispatcher()

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
            )
