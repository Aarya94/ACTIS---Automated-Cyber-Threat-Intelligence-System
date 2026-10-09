"""
ACTIS Protection Service Worker Lifecycle Management
Provides safe, thread-safe background worker execution with deterministic
startup, graceful shutdown, pause/resume, and failure reporting.
"""

import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Callable, Dict, List, Optional

from config.config import get_logger

logger = get_logger("ServiceWorkers")


class WorkerState(str, Enum):
    """Deterministic states for individual service workers."""
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    FAILED = "FAILED"


@dataclass
class WorkerStatus:
    """Snapshot of an individual service worker's operational status."""
    worker_id: str
    name: str
    state: WorkerState
    is_alive: bool
    items_processed: int
    errors_count: int
    last_error: Optional[str]
    start_time: Optional[str]

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


class ServiceWorker(threading.Thread):
    """
    Controlled background worker thread for the ACTIS Protection Service.
    Monitors cancellation events, reports failures, and respects pause requests.
    """

    def __init__(
        self,
        worker_id: str,
        name: Optional[str] = None,
        work_fn: Optional[Callable[[], bool]] = None,
        on_error: Optional[Callable[[str, Exception], None]] = None,
        idle_sleep: float = 0.05,
    ):
        worker_name = name or f"ACTIS-Worker-{worker_id}"
        super().__init__(name=worker_name, daemon=True)
        self.worker_id = worker_id
        self._work_fn = work_fn
        self._on_error = on_error
        self._idle_sleep = max(0.01, idle_sleep)

        self._shutdown_event = threading.Event()
        self._pause_event = threading.Event()
        self._lock = threading.Lock()

        self._state = WorkerState.STOPPED
        self._items_processed = 0
        self._errors_count = 0
        self._last_error: Optional[str] = None
        self._start_time: Optional[str] = None

    @property
    def state(self) -> WorkerState:
        with self._lock:
            return self._state

    def run(self) -> None:
        """Main worker execution loop."""
        with self._lock:
            self._state = WorkerState.RUNNING
            self._start_time = datetime.now(timezone.utc).isoformat()
        logger.info(f"Worker '{self.name}' started [ID: {self.worker_id}]")

        try:
            while not self._shutdown_event.is_set():
                if self._pause_event.is_set():
                    with self._lock:
                        self._state = WorkerState.PAUSED
                    time.sleep(self._idle_sleep)
                    continue
                else:
                    with self._lock:
                        if self._state == WorkerState.PAUSED:
                            self._state = WorkerState.RUNNING

                # Execute work cycle if configured, else remain safely idle
                if self._work_fn is not None:
                    try:
                        processed = self._work_fn()
                        if processed:
                            with self._lock:
                                self._items_processed += 1
                        else:
                            # No work item available; sleep briefly to prevent busy-spinning
                            time.sleep(self._idle_sleep)
                    except Exception as ex:
                        err_msg = f"Worker '{self.name}' encountered task error: {str(ex)}"
                        logger.error(err_msg, exc_info=True)
                        with self._lock:
                            self._errors_count += 1
                            self._last_error = str(ex)
                            self._state = WorkerState.FAILED

                        if self._on_error:
                            try:
                                self._on_error(self.worker_id, ex)
                            except Exception as cb_err:
                                logger.error(f"Worker error callback failed: {str(cb_err)}")
                        # Stop execution loop on uncaught worker task failure
                        break
                else:
                    time.sleep(self._idle_sleep)

        except Exception as unhandled:
            err_msg = f"Worker '{self.name}' suffered fatal unhandled exception: {str(unhandled)}"
            logger.critical(err_msg, exc_info=True)
            with self._lock:
                self._errors_count += 1
                self._last_error = str(unhandled)
                self._state = WorkerState.FAILED
            if self._on_error:
                try:
                    self._on_error(self.worker_id, unhandled)
                except Exception:
                    pass
        finally:
            with self._lock:
                if self._state != WorkerState.FAILED:
                    self._state = WorkerState.STOPPED
            logger.info(f"Worker '{self.name}' finished with state: {self.state.value}")

    def stop(self, timeout: Optional[float] = 2.0) -> bool:
        """Signals worker termination and waits up to timeout seconds."""
        logger.debug(f"Requesting stop for worker '{self.name}'")
        with self._lock:
            if self._state not in (WorkerState.STOPPED, WorkerState.FAILED):
                self._state = WorkerState.STOPPING
        self._shutdown_event.set()
        # Ensure pause does not block shutdown
        self._pause_event.clear()

        if self.is_alive():
            self.join(timeout=timeout)

        is_stopped = not self.is_alive()
        with self._lock:
            if is_stopped and self._state != WorkerState.FAILED:
                self._state = WorkerState.STOPPED
        return is_stopped

    def pause(self) -> None:
        """Requests the worker to temporarily pause processing."""
        self._pause_event.set()

    def resume(self) -> None:
        """Resumes processing from paused state."""
        self._pause_event.clear()

    def get_status(self) -> WorkerStatus:
        """Returns a snapshot of worker operational status."""
        with self._lock:
            return WorkerStatus(
                worker_id=self.worker_id,
                name=self.name,
                state=self._state,
                is_alive=self.is_alive(),
                items_processed=self._items_processed,
                errors_count=self._errors_count,
                last_error=self._last_error,
                start_time=self._start_time,
            )


class WorkerManager:
    """
    Manages the lifecycle of a pool of ServiceWorkers.
    Prevents duplicate worker creation, coordinates synchronized shutdown,
    and reports pool health status.
    """

    def __init__(
        self,
        worker_count: int = 1,
        worker_name_prefix: str = "ACTIS-Worker",
        on_worker_error: Optional[Callable[[str, Exception], None]] = None,
    ):
        self.worker_count = max(1, worker_count)
        self.worker_name_prefix = worker_name_prefix
        self.on_worker_error = on_worker_error

        self._lock = threading.Lock()
        self._workers: List[ServiceWorker] = []

    def start_workers(
        self,
        work_fn: Optional[Callable[[], bool]] = None,
    ) -> bool:
        """
        Starts the configured worker threads.
        Idempotent: prevents duplicate creation if workers are already active.
        """
        with self._lock:
            alive_workers = [w for w in self._workers if w.is_alive()]
            if alive_workers:
                logger.warning(
                    f"start_workers called while {len(alive_workers)} workers are already active. "
                    f"Refusing to duplicate workers."
                )
                return False

            self._workers.clear()
            for idx in range(self.worker_count):
                worker_id = f"worker-{idx + 1}"
                name = f"{self.worker_name_prefix}-{idx + 1}"
                worker = ServiceWorker(
                    worker_id=worker_id,
                    name=name,
                    work_fn=work_fn,
                    on_error=self.on_worker_error,
                )
                self._workers.append(worker)

            for worker in self._workers:
                worker.start()

            logger.info(f"Successfully launched {len(self._workers)} service workers.")
            return True

    def stop_workers(self, timeout_per_worker: float = 2.0) -> bool:
        """
        Gracefully signals and waits for all active workers to terminate.
        """
        with self._lock:
            if not self._workers:
                return True

            logger.info(f"Stopping {len(self._workers)} service workers (timeout: {timeout_per_worker}s each)...")
            all_clean = True
            for worker in self._workers:
                clean = worker.stop(timeout=timeout_per_worker)
                if not clean:
                    all_clean = False
                    logger.warning(f"Worker '{worker.name}' did not stop within allocated timeout.")

            return all_clean

    def pause_workers(self) -> None:
        """Pauses all managed workers."""
        with self._lock:
            for worker in self._workers:
                worker.pause()
            logger.info(f"Paused {len(self._workers)} service workers.")

    def resume_workers(self) -> None:
        """Resumes all managed workers."""
        with self._lock:
            for worker in self._workers:
                worker.resume()
            logger.info(f"Resumed {len(self._workers)} service workers.")

    def get_statuses(self) -> List[WorkerStatus]:
        """Returns statuses for all managed workers."""
        with self._lock:
            return [w.get_status() for w in self._workers]

    def active_count(self) -> int:
        """Returns the number of currently running worker threads."""
        with self._lock:
            return sum(1 for w in self._workers if w.is_alive())

    def total_count(self) -> int:
        """Returns total configured workers in the pool."""
        with self._lock:
            return len(self._workers)

    def all_alive(self) -> bool:
        """Returns True if all configured workers are actively running."""
        with self._lock:
            if not self._workers:
                return False
            return all(w.is_alive() for w in self._workers)

    def is_any_failed(self) -> bool:
        """Returns True if any managed worker has entered FAILED state."""
        with self._lock:
            return any(w.state == WorkerState.FAILED for w in self._workers)

    def clear(self) -> None:
        """Clears worker references after shutdown."""
        with self._lock:
            self._workers.clear()
