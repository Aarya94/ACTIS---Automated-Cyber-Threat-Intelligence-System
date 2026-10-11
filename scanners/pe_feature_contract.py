"""
ACTIS Windows PE Structured Feature Contract
Automated Cyber Threat Intelligence System — Week 1 Day 5

Defines formal, immutable, typed contracts for static PE analysis.
Cleanly isolates threat-intelligence identifiers (path, filename, hashes)
from numeric/behavioral features (PE metadata, sections, imports, entropy)
to strictly prevent model data leakage.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from detection_engine.malware_dataset_schema import MALWARE_FEATURE_COLUMNS


@dataclass(frozen=True)
class PEIdentifiers:
    """Threat intelligence identifiers. Must NEVER be used as ML training features."""
    path: str
    filename: str
    sha256: str
    md5: str = ""
    sha1: str = ""


@dataclass(frozen=True)
class FileMetadata:
    """Filesystem and binary-level metadata."""
    file_size: int
    extension: str
    entropy: float
    is_pe: bool
    is_valid: bool = True


@dataclass(frozen=True)
class PEMetadata:
    """Core PE header and optional header structural properties."""
    architecture: str
    machine: int
    entry_point: int
    image_base: int
    subsystem: int
    subsystem_name: str
    number_of_sections: int
    major_linker_version: int = 0
    minor_linker_version: int = 0
    major_operating_system_version: int = 0
    major_image_version: int = 0
    dll_characteristics: int = 0
    size_of_stack_reserve: int = 0
    time_date_stamp: int = 0


@dataclass(frozen=True)
class PESectionFeature:
    """Per-section structural and entropy metrics."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    entropy: float
    is_executable: bool = False
    is_readable: bool = False
    is_writable: bool = False
    is_write_and_execute: bool = False
    is_high_entropy: bool = False


@dataclass(frozen=True)
class PEImportFeature:
    """Import table and threat API heuristics."""
    imported_dll_count: int
    imported_function_count: int
    imported_dlls: Tuple[str, ...] = field(default_factory=tuple)
    imported_functions: Tuple[str, ...] = field(default_factory=tuple)
    suspicious_apis_found: Tuple[str, ...] = field(default_factory=tuple)
    suspicious_api_count: int = 0
    imphash: str = ""
    api_categories_found: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes import features to dictionary."""
        return asdict(self)



@dataclass
class PEStaticFeatures:
    """
    Consolidated structured feature representation for safe Windows PE static analysis.
    
    Provides clean separation between identifiers and features,
    while maintaining full backward compatibility with dictionary consumers.
    """
    identifiers: PEIdentifiers
    file_metadata: FileMetadata
    pe_metadata: Optional[PEMetadata] = None
    sections: List[PESectionFeature] = field(default_factory=list)
    imports: Optional[PEImportFeature] = None
    pe_features_15: Dict[str, int] = field(default_factory=dict)
    is_signed: bool = False
    warnings: List[str] = field(default_factory=list)

    def to_ml_feature_vector(self) -> List[int]:
        """
        Extracts the exact ordered 15 numeric PE features matching
        MALWARE_FEATURE_COLUMNS and malware_dataset.csv.
        """
        return [self.pe_features_15.get(col, 0) for col in MALWARE_FEATURE_COLUMNS]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the structured features into a nested dictionary."""
        return {
            "identifiers": asdict(self.identifiers),
            "file_metadata": asdict(self.file_metadata),
            "pe_metadata": asdict(self.pe_metadata) if self.pe_metadata else None,
            "sections": [asdict(s) for s in self.sections],
            "imports": asdict(self.imports) if self.imports else None,
            "pe_features_15": dict(self.pe_features_15),
            "ml_feature_vector": self.to_ml_feature_vector(),
            "is_signed": self.is_signed,
            "warnings": list(self.warnings),
        }
