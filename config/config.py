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
from typing import Optional

# Subsystem components (Week 1 Day 2 foundation)
from config.paths import (
    ACTIS_ROOT,
    CONFIG_DIR,
    DATA_DIR,
    MODELS_DIR,
    LOGS_DIR,
    REPORTS_DIR,
    BACKEND_DIR,
    SCANNERS_DIR,
    DETECTION_DIR,
    TESTS_DIR,
    DATABASE_PATH,
    CENTRAL_BACKEND_DB,
    TEST_DATABASE_PATH,
    TEST_CENTRAL_BACKEND_DB,
    PHISHING_MODEL_PATH,
    PHISHING_METADATA_PATH,
    MALWARE_MODEL_PATH,
    MALWARE_METADATA_PATH,
    DEFAULT_QUICK_SCAN_PATHS,
    PathConfig,
    ensure_runtime_directories,
)
from config.settings import (
    AppConfig,
    DatabaseConfig,
    ModelConfig,
    ExternalApiConfig,
    RiskEngineConfig,
    ScannerConfig,
    ServerConfig,
)
from config.env_loader import (
    load_environment,
    get_str,
    get_int,
    get_float,
    get_bool,
    get_list,
    get_int_bounded,
    get_float_bounded,
    get_path,
)
from config.defaults import (
    APP_NAME,
    DEFAULT_ENVIRONMENT,
    VALID_ENVIRONMENTS,
    DEFAULT_LOG_LEVEL,
    DEFAULT_BACKEND_URL,
    DEFAULT_CLIENT_API_KEY,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_RISK_CRITICAL_THRESHOLD,
    DEFAULT_RISK_HIGH_THRESHOLD,
    DEFAULT_RISK_MEDIUM_THRESHOLD,
    DEFAULT_WEIGHT_KNOWN_INTEL,
    DEFAULT_WEIGHT_ML_PROBABILITY,
    DEFAULT_WEIGHT_HEURISTIC_RULES,
    DEFAULT_WEIGHT_EXTERNAL_INTEL,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_HASH_CHUNK_SIZE,
    DEFAULT_WATCHDOG_DEBOUNCE_SECONDS,
    DEFAULT_DB_TIMEOUT_SECONDS,
    DEFAULT_ENABLE_WAL,
    DEFAULT_API_TIMEOUT,
    create_default_config,
)
from config.validator import (
    ConfigurationError,
    validate_config,
)

# Ensure runtime directories exist
ensure_runtime_directories()


def load_app_config(
    env_file: Optional[Path] = None,
    environment: Optional[str] = None,
) -> AppConfig:
    """Builds and returns an AppConfig instance with environment variable overrides."""
    if env_file:
        load_environment(env_file)
    else:
        load_environment()

    active_env = environment or get_str("ACTIS_ENVIRONMENT", DEFAULT_ENVIRONMENT)
    active_log_level = get_str("ACTIS_LOG_LEVEL", "DEBUG" if active_env == "development" else "INFO")

    if active_env == "testing":
        default_db = TEST_DATABASE_PATH
        default_backend_db = TEST_CENTRAL_BACKEND_DB
    else:
        default_db = DATABASE_PATH
        default_backend_db = CENTRAL_BACKEND_DB

    db_config = DatabaseConfig(
        db_path=default_db,
        backend_db_path=default_backend_db,
        timeout_seconds=get_float("ACTIS_DB_TIMEOUT", DEFAULT_DB_TIMEOUT_SECONDS),
        enable_wal_mode=get_bool("ACTIS_DB_WAL", DEFAULT_ENABLE_WAL),
    )

    model_config = ModelConfig(
        phishing_model_path=PHISHING_MODEL_PATH,
        phishing_metadata_path=PHISHING_METADATA_PATH,
        malware_model_path=MALWARE_MODEL_PATH,
        malware_metadata_path=MALWARE_METADATA_PATH,
    )

    api_config = ExternalApiConfig(
        virustotal_api_key=get_str("VIRUSTOTAL_API_KEY", ""),
        abuseipdb_api_key=get_str("ABUSEIPDB_API_KEY", ""),
        urlhaus_api_key=get_str("URLHAUS_API_KEY", ""),
        openphish_api_key=get_str("OPENPHISH_API_KEY", ""),
        phishtank_api_key=get_str("PHISHTANK_API_KEY", ""),
        request_timeout=get_float("ACTIS_REQUEST_TIMEOUT", DEFAULT_API_TIMEOUT),
    )

    risk_config = RiskEngineConfig(
        threshold_critical=get_int("RISK_CRITICAL_THRESHOLD", DEFAULT_RISK_CRITICAL_THRESHOLD),
        threshold_high=get_int("RISK_HIGH_THRESHOLD", DEFAULT_RISK_HIGH_THRESHOLD),
        threshold_medium=get_int("RISK_MEDIUM_THRESHOLD", DEFAULT_RISK_MEDIUM_THRESHOLD),
        weight_known_intel=get_float("WEIGHT_KNOWN_INTEL", DEFAULT_WEIGHT_KNOWN_INTEL),
        weight_ml_probability=get_float("WEIGHT_ML_PROBABILITY", DEFAULT_WEIGHT_ML_PROBABILITY),
        weight_heuristic_rules=get_float("WEIGHT_HEURISTIC_RULES", DEFAULT_WEIGHT_HEURISTIC_RULES),
        weight_external_intel=get_float("WEIGHT_EXTERNAL_INTEL", DEFAULT_WEIGHT_EXTERNAL_INTEL),
    )

    max_file_size_mb = get_int("ACTIS_MAX_FILE_SIZE_MB", 100)
    scanner_config = ScannerConfig(
        max_file_size_bytes=max_file_size_mb * 1024 * 1024,
        hash_chunk_size=get_int("ACTIS_HASH_CHUNK_SIZE", DEFAULT_HASH_CHUNK_SIZE),
        watchdog_debounce_seconds=get_float("ACTIS_WATCHDOG_DEBOUNCE_SECONDS", DEFAULT_WATCHDOG_DEBOUNCE_SECONDS),
        quick_scan_paths=list(DEFAULT_QUICK_SCAN_PATHS),
    )

    server_config = ServerConfig(
        backend_url=get_str("ACTIS_BACKEND_URL", DEFAULT_BACKEND_URL).rstrip("/"),
        client_api_key=get_str("ACTIS_CLIENT_API_KEY", DEFAULT_CLIENT_API_KEY),
        host=get_str("ACTIS_SERVER_HOST", DEFAULT_HOST),
        port=get_int("ACTIS_SERVER_PORT", DEFAULT_PORT),
    )

    cfg = AppConfig(
        app_name=APP_NAME,
        environment=active_env,
        log_level=active_log_level,
        database=db_config,
        models=model_config,
        apis=api_config,
        risk=risk_config,
        scanner=scanner_config,
        server=server_config,
    )
    validate_config(cfg, strict=False)
    return cfg


# Active singleton instance
config: AppConfig = load_app_config()


def get_config(
    reload: bool = False,
    env_file: Optional[Path] = None,
    environment: Optional[str] = None,
) -> AppConfig:
    """Returns the central AppConfig singleton, optionally reloading from environment."""
    global config
    if reload or config is None:
        config = load_app_config(env_file=env_file, environment=environment)
    return config


# Backward-compatible global aliases
ENV_FILE = ACTIS_ROOT / ".env"
DATABASE_PATH = config.database.db_path
CENTRAL_BACKEND_DB = config.database.backend_db_path

PHISHING_MODEL_PATH = config.models.phishing_model_path
PHISHING_METADATA_PATH = config.models.phishing_metadata_path
MALWARE_MODEL_PATH = config.models.malware_model_path
MALWARE_METADATA_PATH = config.models.malware_metadata_path

VIRUSTOTAL_API_KEY = config.apis.virustotal_api_key
ABUSEIPDB_API_KEY = config.apis.abuseipdb_api_key
URLHAUS_API_KEY = config.apis.urlhaus_api_key

ACTIS_BACKEND_URL = config.server.backend_url
ACTIS_CLIENT_API_KEY = config.server.client_api_key

RISK_CRITICAL_THRESHOLD = config.risk.threshold_critical
RISK_HIGH_THRESHOLD = config.risk.threshold_high
RISK_MEDIUM_THRESHOLD = config.risk.threshold_medium

WEIGHT_KNOWN_INTEL = config.risk.weight_known_intel
WEIGHT_ML_PROBABILITY = config.risk.weight_ml_probability
WEIGHT_HEURISTIC_RULES = config.risk.weight_heuristic_rules
WEIGHT_EXTERNAL_INTEL = config.risk.weight_external_intel

MAX_FILE_SIZE_BYTES = config.scanner.max_file_size_bytes
HASH_CHUNK_SIZE = config.scanner.hash_chunk_size
WATCHDOG_DEBOUNCE_SECONDS = config.scanner.watchdog_debounce_seconds


def get_logger(name: str = "ACTIS") -> logging.Logger:
    """Configures and returns a structured logger for ACTIS."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        level_name = config.log_level.upper()
        level = getattr(logging, level_name, logging.INFO)
        logger.setLevel(level)
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
        fh = RotatingFileHandler(
            filename=str(log_file),
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger
