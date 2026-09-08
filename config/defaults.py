"""
ACTIS Runtime Configuration Defaults
Automated Cyber Threat Intelligence System — Week 1 Day 2

Provides centralized default constants and factory helpers to instantiate
baseline configuration models for development, testing, and production environments.
"""

from pathlib import Path
from typing import Optional

from config.paths import (
    ACTIS_ROOT,
    DATABASE_PATH,
    CENTRAL_BACKEND_DB,
    PHISHING_MODEL_PATH,
    PHISHING_METADATA_PATH,
    MALWARE_MODEL_PATH,
    MALWARE_METADATA_PATH,
    DEFAULT_QUICK_SCAN_PATHS,
    PathConfig,
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

# Application Baseline
APP_NAME = "ACTIS"
DEFAULT_ENVIRONMENT = "development"
DEFAULT_LOG_LEVEL = "INFO"

# Server & Backend Defaults
DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"
DEFAULT_CLIENT_API_KEY = "actis-client-default-secret-token"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# Risk Engine Thresholds (0 - 100 score)
DEFAULT_RISK_CRITICAL_THRESHOLD = 80
DEFAULT_RISK_HIGH_THRESHOLD = 60
DEFAULT_RISK_MEDIUM_THRESHOLD = 35

# Evidence Fusion Weights (must sum to 1.0)
DEFAULT_WEIGHT_KNOWN_INTEL = 0.35
DEFAULT_WEIGHT_ML_PROBABILITY = 0.30
DEFAULT_WEIGHT_HEURISTIC_RULES = 0.20
DEFAULT_WEIGHT_EXTERNAL_INTEL = 0.15

# Scanner Operational Settings
DEFAULT_MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB safe limit
DEFAULT_HASH_CHUNK_SIZE = 64 * 1024               # 64 KB chunk
DEFAULT_WATCHDOG_DEBOUNCE_SECONDS = 2.0           # 2.0s debounce

# Database Settings
DEFAULT_DB_TIMEOUT_SECONDS = 30.0
DEFAULT_ENABLE_WAL = True

# External Threat Intel API Defaults
DEFAULT_API_TIMEOUT = 10.0


def create_default_config(environment: str = DEFAULT_ENVIRONMENT) -> AppConfig:
    """Creates a fully configured AppConfig instance populated with standard defaults."""
    db_config = DatabaseConfig(
        db_path=DATABASE_PATH,
        backend_db_path=CENTRAL_BACKEND_DB,
        timeout_seconds=DEFAULT_DB_TIMEOUT_SECONDS,
        enable_wal_mode=DEFAULT_ENABLE_WAL,
    )

    model_config = ModelConfig(
        phishing_model_path=PHISHING_MODEL_PATH,
        phishing_metadata_path=PHISHING_METADATA_PATH,
        malware_model_path=MALWARE_MODEL_PATH,
        malware_metadata_path=MALWARE_METADATA_PATH,
    )

    api_config = ExternalApiConfig(
        virustotal_api_key="",
        abuseipdb_api_key="",
        urlhaus_api_key="",
        openphish_api_key="",
        phishtank_api_key="",
        request_timeout=DEFAULT_API_TIMEOUT,
    )

    risk_config = RiskEngineConfig(
        threshold_critical=DEFAULT_RISK_CRITICAL_THRESHOLD,
        threshold_high=DEFAULT_RISK_HIGH_THRESHOLD,
        threshold_medium=DEFAULT_RISK_MEDIUM_THRESHOLD,
        weight_known_intel=DEFAULT_WEIGHT_KNOWN_INTEL,
        weight_ml_probability=DEFAULT_WEIGHT_ML_PROBABILITY,
        weight_heuristic_rules=DEFAULT_WEIGHT_HEURISTIC_RULES,
        weight_external_intel=DEFAULT_WEIGHT_EXTERNAL_INTEL,
    )

    scanner_config = ScannerConfig(
        max_file_size_bytes=DEFAULT_MAX_FILE_SIZE_BYTES,
        hash_chunk_size=DEFAULT_HASH_CHUNK_SIZE,
        watchdog_debounce_seconds=DEFAULT_WATCHDOG_DEBOUNCE_SECONDS,
        quick_scan_paths=list(DEFAULT_QUICK_SCAN_PATHS),
    )

    server_config = ServerConfig(
        backend_url=DEFAULT_BACKEND_URL,
        client_api_key=DEFAULT_CLIENT_API_KEY,
        host=DEFAULT_HOST,
        port=DEFAULT_PORT,
    )

    log_level = "DEBUG" if environment == "development" else "INFO"
    if environment == "testing":
        log_level = "WARNING"

    return AppConfig(
        app_name=APP_NAME,
        environment=environment,
        log_level=log_level,
        database=db_config,
        models=model_config,
        apis=api_config,
        risk=risk_config,
        scanner=scanner_config,
        server=server_config,
    )
