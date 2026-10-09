"""
ACTIS Incremental Scan State Contract & State Models
Defines typed representations for file scan states, change detection classifications,
model versioning tags, and incremental scan lifecycle records.
"""

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional


class FileChangeType(str, Enum):
    """Categorical classification of a file relative to previous scan state."""
    NEW_FILE = "NEW_FILE"
    CHANGED_FILE = "CHANGED_FILE"
    UNCHANGED_FILE = "UNCHANGED_FILE"
    REMOVED_FILE = "REMOVED_FILE"
    UNAVAILABLE_FILE = "UNAVAILABLE_FILE"


class FileScanStatus(str, Enum):
    """Normalized scan outcome status for an inspected file."""
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    SKIPPED_OVERSIZED = "SKIPPED_OVERSIZED"
    SKIPPED_UNSUPPORTED = "SKIPPED_UNSUPPORTED"
    INACCESSIBLE = "INACCESSIBLE"
    ERROR = "ERROR"


# Current analyzer and model version tags for cache invalidation
CURRENT_ANALYZER_VERSION = "1.0.0"
CURRENT_MODEL_VERSION = "rf_malware_pe_v1"
CURRENT_RULE_VERSION = "pe_heuristics_v1"


@dataclass
class FileScanState:
    """
    Immutable representation of an evaluated file's scan state.
    Preserves cryptographic identity, filesystem timestamps, and previous verdicts.
    """
    canonical_path: str
    file_size: int
    mtime: float
    sha256: str
    last_scanned_at: str
    scan_status: str = FileScanStatus.CLEAN.value
    risk_score: float = 0.0
    risk_level: str = "LOW"
    analyzer_version: str = CURRENT_ANALYZER_VERSION
    model_version: str = CURRENT_MODEL_VERSION
    rule_version: str = CURRENT_RULE_VERSION
    detection_reasons: List[str] = field(default_factory=list)

    @property
    def is_threat(self) -> bool:
        """Determines if the recorded state represents an active threat."""
        return (
            self.scan_status in (FileScanStatus.SUSPICIOUS.value, FileScanStatus.MALICIOUS.value)
            or self.risk_level in ("HIGH", "CRITICAL")
            or self.risk_score >= 60.0
        )

    def is_version_compatible(
        self,
        target_analyzer_version: str = CURRENT_ANALYZER_VERSION,
        target_model_version: str = CURRENT_MODEL_VERSION,
        target_rule_version: str = CURRENT_RULE_VERSION
    ) -> bool:
        """Verifies whether this cached state matches current analytical versions."""
        return (
            self.analyzer_version == target_analyzer_version
            and self.model_version == target_model_version
            and self.rule_version == target_rule_version
        )

    def to_dict(self) -> Dict[str, Any]:
        """Converts the state into a JSON-serializable dictionary."""
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileScanState":
        """Reconstructs a FileScanState from a stored dictionary or database row."""
        reasons = data.get("detection_reasons", [])
        if isinstance(reasons, str):
            try:
                reasons = json.loads(reasons)
            except Exception:
                reasons = [reasons] if reasons else []

        return cls(
            canonical_path=str(data["canonical_path"]),
            file_size=int(data.get("file_size", 0)),
            mtime=float(data.get("mtime", 0.0)),
            sha256=str(data.get("sha256", "")),
            last_scanned_at=str(data.get("last_scanned_at", "")),
            scan_status=str(data.get("scan_status", FileScanStatus.CLEAN.value)),
            risk_score=float(data.get("risk_score", 0.0)),
            risk_level=str(data.get("risk_level", "LOW")),
            analyzer_version=str(data.get("analyzer_version", CURRENT_ANALYZER_VERSION)),
            model_version=str(data.get("model_version", CURRENT_MODEL_VERSION)),
            rule_version=str(data.get("rule_version", CURRENT_RULE_VERSION)),
            detection_reasons=reasons
        )
