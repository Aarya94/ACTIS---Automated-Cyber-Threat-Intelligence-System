"""
ACTIS Filesystem Event Normalization
Standardizes raw filesystem stimuli, path casings, directory separators,
and event types into canonical NormalizedFileEvent and SecurityEvent representations.
"""

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from service.events import SecurityEvent, SecurityEventType
from scanners.file_watcher import FilesystemEvent
from config.config import get_logger

logger = get_logger("FileNormalizer")


def normalize_filesystem_path(path_input: Union[str, Path]) -> str:
    """
    Normalizes a filesystem path:
    - Resolves symbolic links and relative references.
    - Standardizes directory separators.
    - Preserves canonical casing on Windows via resolve().
    Raises ValueError on empty or invalid paths.
    """
    if not path_input:
        raise ValueError("Cannot normalize an empty path.")

    raw_str = str(path_input).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError(f"Path contains invalid characters: '{raw_str}'")

    path_obj = Path(raw_str)
    try:
        resolved = path_obj.resolve()
        # On Windows, normcase can be used for case-folding comparisons if needed,
        # but resolve() provides the canonical disk path representation.
        return str(resolved)
    except (OSError, RuntimeError) as ex:
        # Fallback to normalized absolute path if file does not exist or access denied
        return str(path_obj.absolute())


@dataclass
class NormalizedFileEvent:
    """
    Normalized intermediate filesystem event representation.
    Ensures consistent paths and canonical SecurityEventType mappings.
    """
    event_type: SecurityEventType
    path: str
    previous_path: Optional[str] = None
    is_directory: bool = False
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_security_event(self, source: str = "filesystem_watcher") -> SecurityEvent:
        """
        Converts the normalized filesystem event into a canonical SecurityEvent.
        """
        meta = dict(self.metadata)
        meta["is_directory"] = self.is_directory
        if self.previous_path:
            meta["previous_path"] = self.previous_path
        meta["event_epoch"] = self.timestamp

        dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
        iso_ts = dt.isoformat()

        event = SecurityEvent(
            event_type=self.event_type,
            source=source,
            target=self.path,
            timestamp=iso_ts,
            metadata=meta,
        )
        event.validate()
        return event


class FilesystemEventNormalizer:
    """
    Translates raw FilesystemEvent objects from watchdog into NormalizedFileEvent instances.
    """

    def __init__(self):
        self._normalized_count = 0

    def get_stats(self) -> Dict[str, Any]:
        """Returns telemetry on normalization activity."""
        return {"normalized_count": self._normalized_count}

    def normalize(self, raw_event: FilesystemEvent) -> Optional[NormalizedFileEvent]:
        """
        Normalizes a raw FilesystemEvent.
        Returns NormalizedFileEvent or None if event cannot be safely normalized.
        """
        if not raw_event.src_path:
            logger.warning("Dropped raw event with empty src_path.")
            return None

        # Map string raw event types to canonical SecurityEventType
        raw_type = raw_event.event_type.lower()
        if raw_type == "created":
            canonical_type = SecurityEventType.FILE_CREATED
            normalized_path = normalize_filesystem_path(raw_event.src_path)
            previous_path = None
        elif raw_type == "modified":
            canonical_type = SecurityEventType.FILE_MODIFIED
            normalized_path = normalize_filesystem_path(raw_event.src_path)
            previous_path = None
        elif raw_type == "moved":
            canonical_type = SecurityEventType.FILE_RENAMED
            # For moved/renamed files, dest_path is the new target, src_path is previous
            if raw_event.dest_path:
                normalized_path = normalize_filesystem_path(raw_event.dest_path)
                previous_path = normalize_filesystem_path(raw_event.src_path)
            else:
                normalized_path = normalize_filesystem_path(raw_event.src_path)
                previous_path = None
        elif raw_type == "deleted":
            canonical_type = SecurityEventType.FILE_DELETED
            normalized_path = normalize_filesystem_path(raw_event.src_path)
            previous_path = None
        else:
            logger.debug(f"Ignored unknown raw filesystem event type: '{raw_event.event_type}'")
            return None

        self._normalized_count += 1
        return NormalizedFileEvent(
            event_type=canonical_type,
            path=normalized_path,
            previous_path=previous_path,
            is_directory=raw_event.is_directory,
            timestamp=raw_event.timestamp,
        )
