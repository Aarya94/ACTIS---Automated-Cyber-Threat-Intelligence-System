"""
ACTIS Filesystem Event Filtering
Provides policy-driven filtering of irrelevant, temporary, lock, and directory events
before expensive debounce and static analysis pipelines are engaged.

CRITICAL SAFETY & SCOPE:
Filtering is conservative: only known-ephemeral/temporary patterns or directories
are filtered out. Genuine executable or target files are never silently dropped.
"""

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from service.file_normalizer import NormalizedFileEvent
from config.config import get_logger

logger = get_logger("FileFilter")


class FilterReason(str, Enum):
    """Reason for event acceptance or rejection by FileEventFilter."""
    ACCEPTED = "ACCEPTED"
    IGNORED_DIRECTORY = "IGNORED_DIRECTORY"
    TEMPORARY_FILE = "TEMPORARY_FILE"
    EXCLUDED_DIRECTORY_PATTERN = "EXCLUDED_DIRECTORY_PATTERN"
    OUTSIDE_MONITORED_ROOT = "OUTSIDE_MONITORED_ROOT"
    INVALID_PATH = "INVALID_PATH"


DEFAULT_TEMPORARY_PATTERNS: Set[str] = {
    "*.tmp",
    "*.temp",
    "*.crdownload",
    "*.part",
    "~$*",        # Microsoft Office temp lock files
    "*.swp",      # Vim swap files
    "*.lock",
    "*~",
}

DEFAULT_EXCLUDED_SEGMENTS: Set[str] = {
    ".git",
    ".svn",
    ".hg",
    ".venv",
    "venv",
    "__pycache__",
    ".idea",
    ".vscode",
    "node_modules",
}


@dataclass
class FileFilterPolicy:
    """
    Configuration parameters governing filesystem event filtering.
    """
    ignore_directories: bool = True
    filter_temporary_files: bool = True
    temporary_patterns: Set[str] = field(default_factory=lambda: set(DEFAULT_TEMPORARY_PATTERNS))
    excluded_segments: Set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDED_SEGMENTS))
    monitored_roots: List[str] = field(default_factory=list)

    def is_temporary(self, file_name: str) -> bool:
        """Checks if a filename matches any configured temporary/ephemeral pattern."""
        if not self.filter_temporary_files:
            return False
        lower_name = file_name.lower()
        return any(fnmatch.fnmatch(lower_name, pat.lower()) for pat in self.temporary_patterns)


class FileEventFilter:
    """
    Evaluates NormalizedFileEvent objects against configured safety and relevance policies.
    """

    def __init__(self, policy: Optional[FileFilterPolicy] = None):
        self.policy = policy or FileFilterPolicy()
        self._inspected_count = 0
        self._accepted_count = 0
        self._filtered_count = 0
        self._filter_reasons_count: Dict[str, int] = {r.value: 0 for r in FilterReason}

    def should_process(self, event: NormalizedFileEvent) -> Tuple[bool, FilterReason]:
        """
        Determines whether a normalized filesystem event should proceed to debouncing and analysis.
        Returns (True, FilterReason.ACCEPTED) if allowed, or (False, reason) if filtered.
        """
        self._inspected_count += 1
        path_obj = Path(event.path)

        # 1. Ignore directory events when configured
        if event.is_directory and self.policy.ignore_directories:
            return self._record_rejection(FilterReason.IGNORED_DIRECTORY, event.path)

        # 2. Check excluded directory segments (e.g. .git, venv)
        parts = {p.lower() for p in path_obj.parts}
        for excluded in self.policy.excluded_segments:
            if excluded.lower() in parts:
                return self._record_rejection(FilterReason.EXCLUDED_DIRECTORY_PATTERN, event.path)

        # 3. Check temporary and lock file patterns
        if self.policy.is_temporary(path_obj.name):
            return self._record_rejection(FilterReason.TEMPORARY_FILE, event.path)

        # 4. Check monitored root boundary if configured
        if self.policy.monitored_roots:
            resolved_event_path = str(path_obj.resolve())
            within_root = False
            for root_str in self.policy.monitored_roots:
                resolved_root = str(Path(root_str).resolve())
                if resolved_event_path == resolved_root or resolved_event_path.startswith(resolved_root + "\\") or resolved_event_path.startswith(resolved_root + "/"):
                    within_root = True
                    break
            if not within_root:
                return self._record_rejection(FilterReason.OUTSIDE_MONITORED_ROOT, event.path)

        # Accepted
        self._accepted_count += 1
        self._filter_reasons_count[FilterReason.ACCEPTED.value] += 1
        return True, FilterReason.ACCEPTED

    def _record_rejection(self, reason: FilterReason, path: str) -> Tuple[bool, FilterReason]:
        self._filtered_count += 1
        self._filter_reasons_count[reason.value] += 1
        logger.debug(f"FileEventFilter: Filtered '{path}' (Reason: {reason.value})")
        return False, reason

    def get_stats(self) -> Dict[str, Any]:
        """Returns filter operational statistics."""
        return {
            "inspected_count": self._inspected_count,
            "accepted_count": self._accepted_count,
            "filtered_count": self._filtered_count,
            "reasons": dict(self._filter_reasons_count),
        }

    def reset_stats(self) -> None:
        """Resets filter metrics counters."""
        self._inspected_count = 0
        self._accepted_count = 0
        self._filtered_count = 0
        self._filter_reasons_count = {r.value: 0 for r in FilterReason}
