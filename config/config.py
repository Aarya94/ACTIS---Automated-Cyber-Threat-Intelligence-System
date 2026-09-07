"""
ACTIS Configuration Module
Automated Cyber Threat Intelligence System
Provides centralized settings, environment variable management, paths, and logging.
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from dotenv import load_dotenv

# Base paths
CONFIG_DIR = Path(__file__).resolve().parent
ACTIS_ROOT = CONFIG_DIR.parent
DATA_DIR = ACTIS_ROOT / "data"
MODELS_DIR = ACTIS_ROOT / "models"
LOGS_DIR = ACTIS_ROOT / "logs"
REPORTS_DIR = ACTIS_ROOT / "reports"

# Load environment variables from .env if present
ENV_FILE = ACTIS_ROOT / ".env"
if ENV_FILE.exists():
    load_dotenv(dotenv_path=ENV_FILE)
else:
    load_dotenv()

# Database paths
DATABASE_PATH = DATA_DIR / "threat_intelligence.db"
CENTRAL_BACKEND_DB = ACTIS_ROOT / "backend" / "central_threat_intel.db"

# Model paths and metadata
PHISHING_MODEL_PATH = MODELS_DIR / "phishing_model.pkl"
PHISHING_METADATA_PATH = MODELS_DIR / "phishing_model_metadata.json"
MALWARE_MODEL_PATH = MODELS_DIR / "malware_model.pkl"
MALWARE_METADATA_PATH = MODELS_DIR / "malware_model_metadata.json"

# External Threat Intelligence Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "").strip()

# Central ACTIS Backend configuration
ACTIS_BACKEND_URL = os.getenv("ACTIS_BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
ACTIS_CLIENT_API_KEY = os.getenv("ACTIS_CLIENT_API_KEY", "actis-client-default-secret-token").strip()

# Risk Engine Thresholds (0 - 100 score)
RISK_CRITICAL_THRESHOLD = 80
RISK_HIGH_THRESHOLD = 60
RISK_MEDIUM_THRESHOLD = 35

# Evidence Weights (sum to 1.0)
WEIGHT_KNOWN_INTEL = 0.35
WEIGHT_ML_PROBABILITY = 0.30
WEIGHT_HEURISTIC_RULES = 0.20
WEIGHT_EXTERNAL_INTEL = 0.15

# Scanner settings
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB safe limit for in-depth static analysis
HASH_CHUNK_SIZE = 64 * 1024               # 64 KB chunk size for streaming hash
WATCHDOG_DEBOUNCE_SECONDS = 2.0           # Seconds to wait for file writing to complete before scan

# Quick scan default target directories (Windows-oriented)
USER_HOME = Path.home()
DEFAULT_QUICK_SCAN_PATHS = [
    USER_HOME / "Downloads",
    USER_HOME / "Desktop",
    USER_HOME / "AppData" / "Local" / "Temp",
    USER_HOME / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
]

# Ensure crucial directories exist
for p in [DATA_DIR, MODELS_DIR, LOGS_DIR]:
    p.mkdir(parents=True, exist_ok=True)


def get_logger(name: str = "ACTIS") -> logging.Logger:
    """Configures and returns a structured logger for ACTIS."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler
        log_file = LOGS_DIR / "actis.log"
        # Use a rotating file handler to avoid unbounded log growth
        fh = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
    return logger
