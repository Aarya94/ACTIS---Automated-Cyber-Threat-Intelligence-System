"""
ACTIS Configuration Foundation: Core Settings Schema
Automated Cyber Threat Intelligence System — Week 1 Day 2

Defines structured, type-annotated dataclasses representing all configuration
domains across the ACTIS architecture.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


def _redact_secret(val: str) -> str:
    """Returns redacted string representation for sensitive credentials."""
    if not val:
        return "<not set>"
    if len(val) <= 4:
        return "****"
    return f"{val[:2]}****{val[-2:]}"


@dataclass
class DatabaseConfig:
    """Configuration for local SQLite and central backend databases."""
    db_path: Path
    backend_db_path: Path
    timeout_seconds: float = 30.0
    enable_wal_mode: bool = True


@dataclass
class ModelConfig:
    """Paths and specifications for machine learning model artifacts."""
    phishing_model_path: Path
    phishing_metadata_path: Path
    malware_model_path: Path
    malware_metadata_path: Path


@dataclass
class ExternalApiConfig:
    """Credentials and settings for external threat intelligence providers."""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    urlhaus_api_key: str = ""
    openphish_api_key: str = ""
    phishtank_api_key: str = ""
    request_timeout: float = 10.0

    def __repr__(self) -> str:
        return (
            f"ExternalApiConfig("
            f"virustotal_api_key={_redact_secret(self.virustotal_api_key)}, "
            f"abuseipdb_api_key={_redact_secret(self.abuseipdb_api_key)}, "
            f"urlhaus_api_key={_redact_secret(self.urlhaus_api_key)}, "
            f"openphish_api_key={_redact_secret(self.openphish_api_key)}, "
            f"phishtank_api_key={_redact_secret(self.phishtank_api_key)}, "
            f"request_timeout={self.request_timeout})"
        )


@dataclass
class RiskEngineConfig:
    """Thresholds and fusion weights for the multi-criteria risk engine."""
    threshold_critical: int = 80
    threshold_high: int = 60
    threshold_medium: int = 35
    weight_known_intel: float = 0.35
    weight_ml_probability: float = 0.30
    weight_heuristic_rules: float = 0.20
    weight_external_intel: float = 0.15


@dataclass
class ScannerConfig:
    """Limits and operational parameters for file and URL scanners."""
    max_file_size_bytes: int = 100 * 1024 * 1024  # 100 MB
    hash_chunk_size: int = 64 * 1024               # 64 KB
    watchdog_debounce_seconds: float = 2.0
    quick_scan_paths: List[Path] = field(default_factory=list)


@dataclass
class ServerConfig:
    """Network settings for central ACTIS sync backend and API client."""
    backend_url: str = "http://127.0.0.1:8000"
    client_api_key: str = "actis-client-default-secret-token"
    host: str = "127.0.0.1"
    port: int = 8000

    def __repr__(self) -> str:
        return (
            f"ServerConfig("
            f"backend_url='{self.backend_url}', "
            f"client_api_key={_redact_secret(self.client_api_key)}, "
            f"host='{self.host}', "
            f"port={self.port})"
        )


@dataclass
class AppConfig:
    """Unified application configuration root for ACTIS."""
    app_name: str = "ACTIS"
    environment: str = "development"
    log_level: str = "INFO"
    database: Optional[DatabaseConfig] = None
    models: Optional[ModelConfig] = None
    apis: Optional[ExternalApiConfig] = None
    risk: Optional[RiskEngineConfig] = None
    scanner: Optional[ScannerConfig] = None
    server: Optional[ServerConfig] = None
