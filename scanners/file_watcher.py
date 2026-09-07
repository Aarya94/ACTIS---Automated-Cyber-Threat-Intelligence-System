"""
ACTIS Real-Time File Watcher Module
Monitors user-selected directories for newly created/downloaded files using watchdog.
Includes write-stability debounce, safe static analysis, and alert notification.
"""

import time
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

from scanners.file_scanner import scan_file
from notifications.notifier import notifier
from config.config import WATCHDOG_DEBOUNCE_SECONDS, get_logger

logger = get_logger("FileWatcher")


def wait_until_file_stable(file_path: Path, timeout: float = 6.0, check_interval: float = 0.5) -> bool:
    """
    Waits until a newly created or downloaded file stops changing size and can be opened.
    Returns True if file is stable and readable, False on timeout or error.
    """
    deadline = time.time() + timeout
    last_size = -1

    while time.time() < deadline:
        try:
            if not file_path.exists():
                return False

            curr_size = file_path.stat().st_size
            # If size has not changed since last check and can be opened for reading
            if curr_size == last_size and curr_size > 0:
                with open(file_path, "rb") as f:
                    f.read(min(1024, curr_size))
                return True
            last_size = curr_size
        except (PermissionError, OSError):
            pass

        time.sleep(check_interval)

    return False


class ThreatFileEventHandler(FileSystemEventHandler):
    """Handles file system creation and modification events for ACTIS."""

    def __init__(self, callback=None):
        super().__init__()
        self.callback = callback
        self._recently_scanned: Set[str] = set()
        self._lock = threading.Lock()

    def _process_file(self, file_path_str: str):
        path = Path(file_path_str)
        if not path.is_file():
            return

        with self._lock:
            if str(path) in self._recently_scanned:
                return
            self._recently_scanned.add(str(path))
            if len(self._recently_scanned) > 500:
                self._recently_scanned.clear()

        # Wait for file to complete writing
        if not wait_until_file_stable(path, timeout=WATCHDOG_DEBOUNCE_SECONDS + 3.0):
            logger.debug(f"File did not stabilize in time: {path.name}")
            return

        logger.info(f"[Watcher] New file detected: {path.name}. Performing static analysis...")
        try:
            result = scan_file(path)
            if result.get("is_threat", False):
                logger.warning(f"[Watcher] Threat detected in new file: {path.name} ({result['risk_level']})")
                notifier.notify_threat(
                    target=str(path),
                    target_type="file",
                    risk_level=result["risk_level"],
                    score=result["score"],
                    reasons=result["reasons"],
                    recommended_action=result["recommended_action"]
                )

            if self.callback:
                self.callback(result)
        except Exception as e:
            logger.error(f"[Watcher] Error scanning {path.name}: {e}")

    def on_created(self, event):
        if not event.is_directory:
            # Run in separate worker thread so file events aren't blocked
            threading.Thread(target=self._process_file, args=(event.src_path,), daemon=True).start()

    def on_modified(self, event):
        if not event.is_directory:
            threading.Thread(target=self._process_file, args=(event.src_path,), daemon=True).start()


class DirectoryWatcherService:
    """Manages background watchdog observers on selected directories."""

    def __init__(self):
        self.observer: Optional[Observer] = None
        self.monitored_paths: List[Path] = []
        self.is_running = False
        self._lock = threading.Lock()

    def start(self, directories: List[Path], on_event_callback=None) -> bool:
        """Starts monitoring the specified directories."""
        with self._lock:
            if self.is_running:
                return True

            self.monitored_paths = [Path(p) for p in directories if Path(p).exists()]
            if not self.monitored_paths:
                logger.warning("No valid directories provided for file watcher.")
                return False

            self.observer = Observer()
            handler = ThreatFileEventHandler(callback=on_event_callback)

            for p in self.monitored_paths:
                try:
                    self.observer.schedule(handler, str(p), recursive=False)
                    logger.info(f"[Watcher] Monitoring active on: {p}")
                except Exception as e:
                    logger.error(f"[Watcher] Failed to monitor {p}: {e}")

            try:
                self.observer.start()
                self.is_running = True
                logger.info("File watcher service started successfully.")
                return True
            except Exception as e:
                logger.error(f"Failed to start observer: {e}")
                self.observer = None
                return False

    def stop(self):
        """Stops the file watcher observer."""
        with self._lock:
            if not self.is_running or not self.observer:
                return
            try:
                self.observer.stop()
                self.observer.join(timeout=3.0)
            except Exception as e:
                logger.error(f"Error stopping file watcher: {e}")
            finally:
                self.observer = None
                self.is_running = False
                logger.info("File watcher service stopped.")

    def get_status(self) -> Dict[str, Any]:
        """Returns current operational status and monitored directories."""
        return {
            "is_running": self.is_running,
            "monitored_paths": [str(p) for p in self.monitored_paths]
        }


file_watcher_service = DirectoryWatcherService()
