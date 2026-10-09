"""
ACTIS Real-Time Filesystem Event Source
Provides safe, watchdog-based filesystem event monitoring for ACTIS.
Observes filesystem creation, modification, move/rename, and deletion events
and dispatches normalized events into the ACTIS Protection Service.

CRITICAL ARCHITECTURAL POLICY:
The Filesystem Event Source ONLY observes and reports filesystem changes.
It does NOT execute files, analyze malware, delete files, quarantine files,
or modify files directly. All analysis is orchestrated downstream.
"""

import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileDeletedEvent,
    DirCreatedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    DirDeletedEvent,
)

from config.config import WATCHDOG_DEBOUNCE_SECONDS, get_logger

logger = get_logger("FileWatcher")


def wait_until_file_stable(
    file_path: Path,
    timeout: float = 4.0,
    check_interval: float = 0.2,
) -> bool:
    """
    Waits until a newly created or written file stops changing size and can be opened.
    Ensures writing processes have released the file lock before analysis begins.
    Returns True if file is stable and readable, False on timeout or error.
    """
    deadline = time.time() + timeout
    last_size = -1

    while time.time() < deadline:
        try:
            if not file_path.exists():
                return False

            curr_size = file_path.stat().st_size
            # If size is positive and hasn't changed across interval, verify readability
            if curr_size == last_size and curr_size > 0:
                with open(file_path, "rb") as f:
                    f.read(min(1024, curr_size))
                return True
            last_size = curr_size
        except (PermissionError, OSError):
            pass

        time.sleep(check_interval)

    # Final check if file exists and has size > 0
    try:
        if file_path.exists() and file_path.stat().st_size > 0:
            with open(file_path, "rb") as f:
                f.read(min(1024, file_path.stat().st_size))
            return True
    except (PermissionError, OSError):
        pass

    return False


@dataclass
class FilesystemEvent:
    """
    Raw filesystem event captured by the watchdog filesystem observer.
    """
    event_type: str  # "created", "modified", "moved", "deleted"
    src_path: str
    dest_path: Optional[str] = None
    is_directory: bool = False
    timestamp: float = field(default_factory=time.time)


class WatchdogBridgeHandler(FileSystemEventHandler):
    """
    Watchdog event listener that forwards raw filesystem events to a callback.
    Does NOT spawn unbounded worker threads; events are forwarded directly
    to the service debouncer and bounded queue.
    """

    def __init__(self, on_event: Callable[[FilesystemEvent], None]):
        super().__init__()
        self._on_event = on_event

    def on_created(self, event):
        fs_event = FilesystemEvent(
            event_type="created",
            src_path=event.src_path,
            is_directory=event.is_directory,
        )
        self._on_event(fs_event)

    def on_modified(self, event):
        fs_event = FilesystemEvent(
            event_type="modified",
            src_path=event.src_path,
            is_directory=event.is_directory,
        )
        self._on_event(fs_event)

    def on_moved(self, event):
        dest = getattr(event, "dest_path", None)
        fs_event = FilesystemEvent(
            event_type="moved",
            src_path=event.src_path,
            dest_path=dest,
            is_directory=event.is_directory,
        )
        self._on_event(fs_event)

    def on_deleted(self, event):
        fs_event = FilesystemEvent(
            event_type="deleted",
            src_path=event.src_path,
            is_directory=event.is_directory,
        )
        self._on_event(fs_event)


class FilesystemEventSource:
    """
    Manages background watchdog Observer instances for user-configured directories.
    Provides thread-safe start, stop, and status querying.
    """

    def __init__(
        self,
        paths: Optional[List[str]] = None,
        on_event: Optional[Callable[[FilesystemEvent], None]] = None,
        recursive: bool = False,
    ):
        self._observer: Optional[Observer] = None
        self._monitored_paths: List[Path] = []
        if paths:
            self._monitored_paths = [Path(p).resolve() for p in paths if Path(p).exists()]
        self._init_paths = list(paths) if paths else []
        self._init_on_event = on_event
        self._init_recursive = recursive
        self._is_running = False
        self._lock = threading.Lock()
        self._on_event_callback: Optional[Callable[[FilesystemEvent], None]] = on_event

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    @property
    def monitored_paths(self) -> List[Path]:
        with self._lock:
            return list(self._monitored_paths)

    @property
    def paths(self) -> List[str]:
        """Returns string representations of configured monitored paths."""
        with self._lock:
            return [str(p) for p in self._monitored_paths]

    def start(
        self,
        directories: Optional[List[Any]] = None,
        recursive: Optional[bool] = None,
        on_event: Optional[Callable[[FilesystemEvent], None]] = None,
    ) -> bool:
        """
        Starts filesystem monitoring on the specified directories.
        Thread-safe and idempotent.
        """
        with self._lock:
            if self._is_running:
                logger.info("FilesystemEventSource is already running.")
                return True

            target_dirs = directories if directories is not None else self._init_paths
            is_recursive = recursive if recursive is not None else self._init_recursive
            event_callback = on_event or self._init_on_event or (lambda ev: None)

            valid_paths = [Path(p).resolve() for p in target_dirs if Path(p).exists()]
            if not valid_paths:
                logger.warning("FilesystemEventSource: No valid existing directories provided to monitor.")
                return False

            self._monitored_paths = valid_paths
            self._on_event_callback = event_callback

            try:
                self._observer = Observer()
                handler = WatchdogBridgeHandler(on_event=self._on_event_callback)

                for path_obj in self._monitored_paths:
                    self._observer.schedule(handler, str(path_obj), recursive=is_recursive)
                    logger.info(f"FilesystemEventSource: Scheduled monitoring on {path_obj} (recursive={is_recursive})")

                self._observer.start()
                self._is_running = True
                logger.info(f"FilesystemEventSource started successfully on {len(self._monitored_paths)} path(s).")
                return True
            except Exception as ex:
                logger.error(f"Failed to start FilesystemEventSource observer: {ex}", exc_info=True)
                if self._observer:
                    try:
                        self._observer.stop()
                    except Exception:
                        pass
                self._observer = None
                self._is_running = False
                return False

    def stop(self, timeout: float = 3.0) -> bool:
        """
        Gracefully terminates the watchdog observer and joins threads.
        Thread-safe and idempotent.
        """
        with self._lock:
            if not self._is_running or not self._observer:
                return True

            logger.info("Stopping FilesystemEventSource observer...")
            try:
                self._observer.stop()
                self._observer.join(timeout=timeout)
            except Exception as ex:
                logger.error(f"Error while stopping FilesystemEventSource observer: {ex}")
            finally:
                self._observer = None
                self._is_running = False
                logger.info("FilesystemEventSource stopped.")

            return True

    def get_status(self) -> Dict[str, Any]:
        """Returns snapshot telemetry of the event source."""
        with self._lock:
            return {
                "is_running": self._is_running,
                "monitored_paths": [str(p) for p in self._monitored_paths],
            }


class DirectoryWatcherService(FilesystemEventSource):
    """Backwards-compatible alias for DirectoryWatcherService."""
    pass


# Global singleton instance for legacy imports
file_watcher_service = DirectoryWatcherService()
