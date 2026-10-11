"""
ACTIS Non-PE File Analysis Contracts
Defines typed contracts for safe static inspection of non-PE files (archives, scripts, generic).
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple


class NonPEFileType(str, Enum):
    """Categorical format of a non-PE file."""
    ARCHIVE_ZIP = "ARCHIVE_ZIP"
    ARCHIVE_TAR = "ARCHIVE_TAR"
    ARCHIVE_GZIP = "ARCHIVE_GZIP"
    ARCHIVE_7Z = "ARCHIVE_7Z"
    SCRIPT_POWERSHELL = "SCRIPT_POWERSHELL"
    SCRIPT_BATCH = "SCRIPT_BATCH"
    SCRIPT_VBSCRIPT = "SCRIPT_VBSCRIPT"
    SCRIPT_PYTHON = "SCRIPT_PYTHON"
    GENERIC_BINARY = "GENERIC_BINARY"
    GENERIC_TEXT = "GENERIC_TEXT"
    UNKNOWN = "UNKNOWN"


class NonPEAnalysisMethod(str, Enum):
    """Method utilized to evaluate the non-PE file."""
    ARCHIVE_METADATA_INSPECTION = "ARCHIVE_METADATA_INSPECTION"
    SCRIPT_STATIC_HEURISTICS = "SCRIPT_STATIC_HEURISTICS"
    GENERIC_METADATA_ONLY = "GENERIC_METADATA_ONLY"
    FORMAT_UNSUPPORTED = "FORMAT_UNSUPPORTED"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"


class NonPEAnalysisStatus(str, Enum):
    """Execution status of the non-PE analysis routine."""
    ANALYZED = "ANALYZED"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    PARSING_FAILED = "PARSING_FAILED"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True)
class ArchiveMetadata:
    """Safe metadata extracted from non-PE archive containers without extracting contents to disk."""
    entry_count: int = 0
    total_uncompressed_size: int = 0
    compression_ratio: float = 0.0
    has_nested_archives: bool = False
    has_executable_entries: bool = False
    has_encrypted_entries: bool = False
    executable_entries: Tuple[str, ...] = field(default_factory=tuple)
    nested_archives: Tuple[str, ...] = field(default_factory=tuple)
    has_double_extension: bool = False
    double_extension_entries: Tuple[str, ...] = field(default_factory=tuple)
    is_suspicious_bomb: bool = False
    warnings: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScriptMetadata:
    """Safe static heuristics extracted from scripts without code execution."""
    script_type: str = ""
    line_count: int = 0
    matched_indicators: Tuple[str, ...] = field(default_factory=tuple)
    suspicious_patterns: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    has_download_cradle: bool = False
    has_encoded_payload: bool = False
    has_dynamic_eval: bool = False
    has_execution_bypass: bool = False
    has_shadow_copy_tampering: bool = False
    warnings: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NonPEAnalysisResult:
    """Consolidated structured analysis result for non-PE files."""
    file_path: str
    file_name: str
    extension: str
    file_size: int
    sha256: str
    md5: str
    sha1: str
    entropy: float
    detected_format: NonPEFileType
    analysis_method: NonPEAnalysisMethod
    analysis_status: NonPEAnalysisStatus
    is_supported: bool = True
    archive_metadata: Optional[ArchiveMetadata] = None
    script_metadata: Optional[ScriptMetadata] = None
    extracted_indicators: Tuple[str, ...] = field(default_factory=tuple)
    warnings: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["detected_format"] = self.detected_format.value
        res["analysis_method"] = self.analysis_method.value
        res["analysis_status"] = self.analysis_status.value
        return res
