"""
ACTIS Project Paths Configuration
Automated Cyber Threat Intelligence System — Week 1 Day 2

Centralizes filesystem paths and directory layout for the ACTIS project.
All paths are resolved relative to ACTIS_ROOT or user profile dynamically,
avoiding hardcoded user-specific or system-specific absolute paths.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List


# Base directories resolved relative to this module
CONFIG_DIR = Path(__file__).resolve().parent
ACTIS_ROOT = CONFIG_DIR.parent
DATA_DIR = ACTIS_ROOT / "data"
MODELS_DIR = ACTIS_ROOT / "models"
LOGS_DIR = ACTIS_ROOT / "logs"
REPORTS_DIR = ACTIS_ROOT / "reports"
BACKEND_DIR = ACTIS_ROOT / "backend"
SCANNERS_DIR = ACTIS_ROOT / "scanners"
DETECTION_DIR = ACTIS_ROOT / "detection_engine"
TESTS_DIR = ACTIS_ROOT / "tests"

# SQLite databases
DATABASE_PATH = DATA_DIR / "threat_intelligence.db"
CENTRAL_BACKEND_DB = BACKEND_DIR / "central_threat_intel.db"
TEST_DATABASE_PATH = DATA_DIR / "test_threat_intelligence.db"
TEST_CENTRAL_BACKEND_DB = BACKEND_DIR / "test_central_threat_intel.db"
TEST_LOGS_DIR = LOGS_DIR / "test"

# Model artifacts and contracts
PHISHING_MODEL_PATH = MODELS_DIR / "phishing_model.pkl"
PHISHING_METADATA_PATH = MODELS_DIR / "phishing_model_metadata.json"
MALWARE_MODEL_PATH = MODELS_DIR / "malware_model.pkl"
MALWARE_METADATA_PATH = MODELS_DIR / "malware_model_metadata.json"

# Quick scan default target directories (Windows-oriented)
USER_HOME = Path.home()
DEFAULT_QUICK_SCAN_PATHS: List[Path] = [
    USER_HOME / "Downloads",
    USER_HOME / "Desktop",
    USER_HOME / "AppData" / "Local" / "Temp",
    USER_HOME / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
]


@dataclass
class PathConfig:
    """Encapsulates all standard filesystem paths for ACTIS."""
    root_dir: Path = ACTIS_ROOT
    config_dir: Path = CONFIG_DIR
    data_dir: Path = DATA_DIR
    models_dir: Path = MODELS_DIR
    logs_dir: Path = LOGS_DIR
    reports_dir: Path = REPORTS_DIR
    backend_dir: Path = BACKEND_DIR
    database_path: Path = DATABASE_PATH
    central_backend_db: Path = CENTRAL_BACKEND_DB
    test_database_path: Path = TEST_DATABASE_PATH
    test_central_backend_db: Path = TEST_CENTRAL_BACKEND_DB
    test_logs_dir: Path = TEST_LOGS_DIR
    phishing_model_path: Path = PHISHING_MODEL_PATH
    phishing_metadata_path: Path = PHISHING_METADATA_PATH
    malware_model_path: Path = MALWARE_MODEL_PATH
    malware_metadata_path: Path = MALWARE_METADATA_PATH
    quick_scan_paths: List[Path] = field(default_factory=lambda: list(DEFAULT_QUICK_SCAN_PATHS))

    def ensure_directories(self) -> None:
        """Ensures that crucial runtime directories exist on disk."""
        for p in [self.data_dir, self.models_dir, self.logs_dir, self.reports_dir]:
            p.mkdir(parents=True, exist_ok=True)


def ensure_runtime_directories() -> None:
    """Convenience helper ensuring standard runtime directories exist."""
    PathConfig().ensure_directories()
