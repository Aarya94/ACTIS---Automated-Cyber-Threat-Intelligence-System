"""
ACTIS File Protection Pipeline & Incremental State Integration
Connects debounced filesystem events to the incremental scan state
manager and determines whether static file analysis is required.

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. Reuses Day 8 IncrementalStateManager; does NOT duplicate state logic.
2. Identifies unchanged files and suppresses redundant deep analysis.
3. Classifies new/changed files for downstream analysis handoff.
4. Purely read-only; never modifies, deletes, or executes target files.
"""

import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from service.events import SecurityEvent, SecurityEventType
from service.dispatcher import IAnalysisOrchestrationBoundary
from scanners.incremental_state import (
    IncrementalStateManager,
    FileScanState,
    FileChangeType,
    FileScanStatus,
)
from config.config import get_logger

logger = get_logger("FileProtectionPipeline")


class EventProcessingStatus(str, Enum):
    """Execution status resulting from processing a filesystem security event."""
    ANALYZED = "ANALYZED"
    UNCHANGED = "UNCHANGED"
    SKIPPED_OVERSIZED = "SKIPPED_OVERSIZED"
    SKIPPED_UNSUPPORTED = "SKIPPED_UNSUPPORTED"
    DISAPPEARED = "DISAPPEARED"
    INACCESSIBLE = "INACCESSIBLE"
    CHANGED_DURING_ANALYSIS = "CHANGED_DURING_ANALYSIS"
    DELETED = "DELETED"
    ERROR = "ERROR"


@dataclass
class EventProcessingResult:
    """Structured receipt representing the evaluation outcome of an event."""
    event_id: str
    target_path: str
    status: EventProcessingStatus
    change_type: Optional[FileChangeType] = None
    is_threat: bool = False
    risk_score: float = 0.0
    risk_level: str = "LOW"
    detection_reasons: List[str] = field(default_factory=list)
    sha256: str = ""
    processed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error_message: Optional[str] = None
    analysis_details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes processing result to dictionary."""
        d = asdict(self)
        d["status"] = self.status.value
        d["change_type"] = self.change_type.value if self.change_type else None
        return d


class FileProtectionPipeline(IAnalysisOrchestrationBoundary):
    """
    Connects filesystem security events from ProtectionService to incremental scan state.
    Suppresses redundant analysis for unchanged files and prepares changed/new files
    for analysis dispatch.
    """

    def __init__(
        self,
        state_manager: Optional[IncrementalStateManager] = None,
        max_file_size_bytes: int = 100 * 1024 * 1024,
        analysis_fn: Optional[Callable[[Path], Dict[str, Any]]] = None,
    ):
        self.state_manager = state_manager or IncrementalStateManager(auto_load=True)
        self.max_file_size_bytes = max_file_size_bytes
        self.analysis_fn = analysis_fn

        self._lock = threading.Lock()
        self._events_processed = 0
        self._unchanged_count = 0
        self._new_or_changed_count = 0
        self._disappeared_count = 0
        self._inaccessible_count = 0
        self._deleted_count = 0
        self._oversized_count = 0
        self._analyzed_count = 0
        self._error_count = 0
        self._last_results: List[EventProcessingResult] = []

    def process_file_event(self, event: SecurityEvent) -> EventProcessingResult:
        """
        Evaluates a file security event against incremental state.
        Determines if analysis is needed or if previous state can be reused.
        """
        event.validate()
        raw_target = event.target or ""
        path_obj = Path(raw_target)

        with self._lock:
            self._events_processed += 1

        # 1. Handle file deletions
        if event.event_type == SecurityEventType.FILE_DELETED:
            try:
                canonical = str(path_obj.resolve()) if path_obj.exists() else str(path_obj)
            except (OSError, RuntimeError):
                canonical = str(path_obj)

            removed = self.state_manager.remove_state(canonical)
            with self._lock:
                self._deleted_count += 1

            logger.info(f"File deleted event for '{canonical}' (pruned from state: {removed}).")
            result = EventProcessingResult(
                event_id=event.event_id,
                target_path=canonical,
                status=EventProcessingStatus.DELETED,
                change_type=FileChangeType.REMOVED_FILE,
            )
            self._record_result(result)
            return result

        # 2. Check if file disappeared prior to intake processing
        if not path_obj.exists():
            with self._lock:
                self._disappeared_count += 1
            logger.info(f"File '{raw_target}' disappeared prior to intake processing.")
            result = EventProcessingResult(
                event_id=event.event_id,
                target_path=str(path_obj),
                status=EventProcessingStatus.DISAPPEARED,
                change_type=FileChangeType.UNAVAILABLE_FILE,
                error_message="File disappeared before processing could begin.",
            )
            self._record_result(result)
            return result

        # 3. Query incremental state for change classification
        try:
            canonical_path = str(path_obj.resolve())
        except (OSError, RuntimeError):
            canonical_path = str(path_obj)

        change_type, prev_state, meta = self.state_manager.check_file_status(
            path_obj,
            max_size_bytes=self.max_file_size_bytes,
        )

        # 4. Handle inaccessible files
        if change_type == FileChangeType.UNAVAILABLE_FILE:
            with self._lock:
                self._inaccessible_count += 1
            logger.warning(f"File '{canonical_path}' is inaccessible (permission/lock error).")
            result = EventProcessingResult(
                event_id=event.event_id,
                target_path=canonical_path,
                status=EventProcessingStatus.INACCESSIBLE,
                change_type=change_type,
                error_message="File is inaccessible or unreadable.",
            )
            self._record_result(result)
            return result

        # 5. Handle oversized files
        if meta and getattr(meta, "is_oversized", False):
            with self._lock:
                self._oversized_count += 1
            logger.info(f"File '{canonical_path}' skipped: exceeds max size ({self.max_file_size_bytes} bytes).")
            result = EventProcessingResult(
                event_id=event.event_id,
                target_path=canonical_path,
                status=EventProcessingStatus.SKIPPED_OVERSIZED,
                change_type=change_type,
                error_message=f"File exceeds maximum allowed size ({self.max_file_size_bytes} bytes).",
            )
            self._record_result(result)
            return result

        # 6. Unchanged files: reuse existing verdict, skip deep analysis
        if change_type == FileChangeType.UNCHANGED_FILE and prev_state is not None:
            now_iso = datetime.now(timezone.utc).isoformat()
            self.state_manager.mark_unchanged(prev_state, now_iso)
            with self._lock:
                self._unchanged_count += 1
            logger.info(
                f"File '{canonical_path}' UNCHANGED relative to scan state. "
                f"Reusing previous verdict (risk: {prev_state.risk_level}, score: {prev_state.risk_score})."
            )
            result = EventProcessingResult(
                event_id=event.event_id,
                target_path=canonical_path,
                status=EventProcessingStatus.UNCHANGED,
                change_type=change_type,
                is_threat=prev_state.is_threat,
                risk_score=prev_state.risk_score,
                risk_level=prev_state.risk_level,
                detection_reasons=list(prev_state.detection_reasons),
                sha256=prev_state.sha256,
            )
            self._record_result(result)
            return result

        # 7. Changed or new file: requires analysis handoff
        with self._lock:
            self._new_or_changed_count += 1

        logger.info(f"File '{canonical_path}' classified as {change_type.value}. Proceeding to analysis.")
        return self._execute_analysis_handoff(
            event=event,
            path_obj=path_obj,
            canonical_path=canonical_path,
            change_type=change_type,
            meta=meta,
        )

    def _execute_analysis_handoff(
        self,
        event: SecurityEvent,
        path_obj: Path,
        canonical_path: str,
        change_type: FileChangeType,
        meta: Any,
    ) -> EventProcessingResult:
        """
        Placeholder / extension hook for analysis dispatch.
        Overridden or wired in Commit 8 to invoke the central ACTIS analysis pipeline.
        """
        if self.analysis_fn is not None:
            try:
                analysis = self.analysis_fn(path_obj)
                with self._lock:
                    self._analyzed_count += 1

                is_threat = bool(analysis.get("is_threat", False))
                risk_score = float(analysis.get("score", 0.0))
                risk_level = str(analysis.get("risk_level", "LOW"))
                reasons = list(analysis.get("reasons", []))
                sha256_hash = str(analysis.get("sha256", ""))

                # Update incremental scan state
                now_iso = datetime.now(timezone.utc).isoformat()
                file_size = getattr(meta, "file_size", 0) if meta else 0
                mtime = getattr(meta, "mtime", 0.0) if meta else 0.0

                new_state = FileScanState(
                    canonical_path=canonical_path,
                    file_size=file_size,
                    mtime=mtime,
                    sha256=sha256_hash,
                    last_scanned_at=now_iso,
                    scan_status=FileScanStatus.SUSPICIOUS.value if is_threat else FileScanStatus.CLEAN.value,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    detection_reasons=reasons,
                )
                self.state_manager.record_state(new_state)

                res = EventProcessingResult(
                    event_id=event.event_id,
                    target_path=canonical_path,
                    status=EventProcessingStatus.ANALYZED,
                    change_type=change_type,
                    is_threat=is_threat,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    detection_reasons=reasons,
                    sha256=sha256_hash,
                    analysis_details=analysis,
                )
                self._record_result(res)
                return res

            except Exception as ex:
                with self._lock:
                    self._error_count += 1
                logger.error(f"Analysis failed for '{canonical_path}': {ex}", exc_info=True)
                err_res = EventProcessingResult(
                    event_id=event.event_id,
                    target_path=canonical_path,
                    status=EventProcessingStatus.ERROR,
                    change_type=change_type,
                    error_message=str(ex),
                )
                self._record_result(err_res)
                return err_res

        # If no analysis_fn registered yet (foundation stage), return ready status
        res = EventProcessingResult(
            event_id=event.event_id,
            target_path=canonical_path,
            status=EventProcessingStatus.ANALYZED,
            change_type=change_type,
        )
        self._record_result(res)
        return res

    def _record_result(self, result: EventProcessingResult) -> None:
        with self._lock:
            self._last_results.append(result)
            if len(self._last_results) > 200:
                self._last_results.pop(0)

    # --- IAnalysisOrchestrationBoundary Interface ---

    def handle_security_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """
        Boundary method invoked by ProtectionService dispatcher.
        Routes file-related events through incremental state evaluation.
        """
        file_event_types = {
            SecurityEventType.FILE_CREATED,
            SecurityEventType.FILE_MODIFIED,
            SecurityEventType.FILE_RENAMED,
            SecurityEventType.FILE_DELETED,
        }
        if event.event_type in file_event_types:
            result = self.process_file_event(event)
            return {
                "status": "PROCESSED",
                "orchestrator": "FileProtectionPipeline",
                "event_id": event.event_id,
                "result": result.to_dict(),
            }

        # Non-file events (e.g. URL, MESSAGE, MANUAL_SCAN)
        logger.info(f"FileProtectionPipeline: Accepted non-file event '{event.event_id}' ({event.event_type.value})")
        return {
            "status": "ACCEPTED",
            "orchestrator": "FileProtectionPipeline",
            "event_id": event.event_id,
            "event_type": event.event_type.value,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Returns snapshot telemetry of file event pipeline operations."""
        with self._lock:
            return {
                "events_processed": self._events_processed,
                "unchanged_count": self._unchanged_count,
                "new_or_changed_count": self._new_or_changed_count,
                "disappeared_count": self._disappeared_count,
                "inaccessible_count": self._inaccessible_count,
                "deleted_count": self._deleted_count,
                "oversized_count": self._oversized_count,
                "analyzed_count": self._analyzed_count,
                "error_count": self._error_count,
                "cached_states_count": self.state_manager.get_cached_count(),
            }
