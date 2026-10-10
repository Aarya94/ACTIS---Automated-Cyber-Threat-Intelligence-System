"""
ACTIS Configuration Foundation: Core Settings Schema
Automated Cyber Threat Intelligence System — Week 1 Day 2

Defines structured, type-annotated dataclasses representing all configuration
domains across the ACTIS architecture with safe dictionary serialization.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


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

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "db_path": str(self.db_path),
            "backend_db_path": str(self.backend_db_path),
            "timeout_seconds": self.timeout_seconds,
            "enable_wal_mode": self.enable_wal_mode,
        }


@dataclass
class ModelConfig:
    """Paths and specifications for machine learning model artifacts."""
    phishing_model_path: Path
    phishing_metadata_path: Path
    malware_model_path: Path
    malware_metadata_path: Path

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "phishing_model_path": str(self.phishing_model_path),
            "phishing_metadata_path": str(self.phishing_metadata_path),
            "malware_model_path": str(self.malware_model_path),
            "malware_metadata_path": str(self.malware_metadata_path),
        }


@dataclass
class ExternalApiConfig:
    """Credentials and settings for external threat intelligence providers."""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    urlhaus_api_key: str = ""
    openphish_api_key: str = ""
    phishtank_api_key: str = ""
    virustotal_enabled: bool = True
    urlhaus_enabled: bool = True
    abuseipdb_enabled: bool = True
    request_timeout: float = 5.0
    cache_ttl_seconds: int = 3600
    max_retries: int = 1
    rate_limit_vt_rpm: int = 4

    def __repr__(self) -> str:
        return (
            f"ExternalApiConfig("
            f"virustotal_api_key={_redact_secret(self.virustotal_api_key)}, "
            f"abuseipdb_api_key={_redact_secret(self.abuseipdb_api_key)}, "
            f"urlhaus_api_key={_redact_secret(self.urlhaus_api_key)}, "
            f"openphish_api_key={_redact_secret(self.openphish_api_key)}, "
            f"phishtank_api_key={_redact_secret(self.phishtank_api_key)}, "
            f"virustotal_enabled={self.virustotal_enabled}, "
            f"urlhaus_enabled={self.urlhaus_enabled}, "
            f"abuseipdb_enabled={self.abuseipdb_enabled}, "
            f"request_timeout={self.request_timeout}, "
            f"cache_ttl_seconds={self.cache_ttl_seconds}, "
            f"max_retries={self.max_retries})"
        )

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "virustotal_api_key": _redact_secret(self.virustotal_api_key) if mask_secrets else self.virustotal_api_key,
            "abuseipdb_api_key": _redact_secret(self.abuseipdb_api_key) if mask_secrets else self.abuseipdb_api_key,
            "urlhaus_api_key": _redact_secret(self.urlhaus_api_key) if mask_secrets else self.urlhaus_api_key,
            "openphish_api_key": _redact_secret(self.openphish_api_key) if mask_secrets else self.openphish_api_key,
            "phishtank_api_key": _redact_secret(self.phishtank_api_key) if mask_secrets else self.phishtank_api_key,
            "virustotal_enabled": self.virustotal_enabled,
            "urlhaus_enabled": self.urlhaus_enabled,
            "abuseipdb_enabled": self.abuseipdb_enabled,
            "request_timeout": self.request_timeout,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "max_retries": self.max_retries,
            "rate_limit_vt_rpm": self.rate_limit_vt_rpm,
        }


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

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "threshold_critical": self.threshold_critical,
            "threshold_high": self.threshold_high,
            "threshold_medium": self.threshold_medium,
            "weight_known_intel": self.weight_known_intel,
            "weight_ml_probability": self.weight_ml_probability,
            "weight_heuristic_rules": self.weight_heuristic_rules,
            "weight_external_intel": self.weight_external_intel,
        }


@dataclass
class ScannerConfig:
    """Limits and operational parameters for file and URL scanners."""
    max_file_size_bytes: int = 100 * 1024 * 1024  # 100 MB
    hash_chunk_size: int = 64 * 1024               # 64 KB
    watchdog_debounce_seconds: float = 2.0
    quick_scan_paths: List[Path] = field(default_factory=list)

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "max_file_size_bytes": self.max_file_size_bytes,
            "hash_chunk_size": self.hash_chunk_size,
            "watchdog_debounce_seconds": self.watchdog_debounce_seconds,
            "quick_scan_paths": [str(p) for p in self.quick_scan_paths],
        }


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

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "backend_url": self.backend_url,
            "client_api_key": _redact_secret(self.client_api_key) if mask_secrets else self.client_api_key,
            "host": self.host,
            "port": self.port,
        }


@dataclass
class ServiceConfig:
    """Settings for the resident Windows Protection Service foundation."""
    service_name: str = "ACTISProtectionService"
    display_name: str = "ACTIS Threat Protection Service"
    description: str = "Resident background protection service for the Automated Cyber Threat Intelligence System."
    worker_count: int = 1
    queue_max_size: int = 1000
    shutdown_timeout_seconds: float = 5.0
    health_check_interval_seconds: float = 10.0
    auto_restart_workers: bool = True
    max_restart_attempts: int = 3
    restart_cooldown_seconds: float = 1.0
    monitored_paths: List[str] = field(default_factory=list)
    debounce_delay_seconds: float = 1.0
    max_file_size_bytes: int = 100 * 1024 * 1024
    enable_file_monitoring: bool = False
    filter_temporary_files: bool = True

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "display_name": self.display_name,
            "description": self.description,
            "worker_count": self.worker_count,
            "queue_max_size": self.queue_max_size,
            "shutdown_timeout_seconds": self.shutdown_timeout_seconds,
            "health_check_interval_seconds": self.health_check_interval_seconds,
            "auto_restart_workers": self.auto_restart_workers,
            "max_restart_attempts": self.max_restart_attempts,
            "restart_cooldown_seconds": self.restart_cooldown_seconds,
            "monitored_paths": list(self.monitored_paths),
            "debounce_delay_seconds": self.debounce_delay_seconds,
            "max_file_size_bytes": self.max_file_size_bytes,
            "enable_file_monitoring": self.enable_file_monitoring,
            "filter_temporary_files": self.filter_temporary_files,
        }


@dataclass
class ThreatSyncConfig:
    """Settings for scheduled upstream threat intelligence synchronization."""
    enabled: bool = False
    interval_seconds: int = 21600  # 6 hours
    batch_size: int = 500
    max_records_per_sync: int = 1000
    sync_urlhaus: bool = True
    sync_abuseipdb: bool = False
    sync_virustotal: bool = False
    sync_central: bool = True
    request_timeout: float = 10.0
    max_retries: int = 2

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "interval_seconds": self.interval_seconds,
            "batch_size": self.batch_size,
            "max_records_per_sync": self.max_records_per_sync,
            "sync_urlhaus": self.sync_urlhaus,
            "sync_abuseipdb": self.sync_abuseipdb,
            "sync_virustotal": self.sync_virustotal,
            "sync_central": self.sync_central,
            "request_timeout": self.request_timeout,
            "max_retries": self.max_retries,
        }


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
    service: Optional[ServiceConfig] = None
    sync: Optional[ThreatSyncConfig] = None

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        """Serializes complete AppConfig into a dictionary, redacting sensitive secrets by default."""
        return {
            "app_name": self.app_name,
            "environment": self.environment,
            "log_level": self.log_level,
            "database": self.database.to_dict(mask_secrets) if self.database else None,
            "models": self.models.to_dict(mask_secrets) if self.models else None,
            "apis": self.apis.to_dict(mask_secrets) if self.apis else None,
            "risk": self.risk.to_dict(mask_secrets) if self.risk else None,
            "scanner": self.scanner.to_dict(mask_secrets) if self.scanner else None,
            "server": self.server.to_dict(mask_secrets) if self.server else None,
            "service": self.service.to_dict(mask_secrets) if self.service else None,
            "sync": self.sync.to_dict(mask_secrets) if self.sync else None,
        }


