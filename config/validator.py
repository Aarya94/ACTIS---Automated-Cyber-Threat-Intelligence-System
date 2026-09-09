"""
ACTIS Configuration Validator
Automated Cyber Threat Intelligence System — Week 1 Day 2

Provides rigorous validation rules for configuration settings, ensuring
that weights, thresholds, paths, URLs, and operational limits meet system constraints.
"""

import math
from typing import List, Optional
from urllib.parse import urlparse

from config.settings import AppConfig, DatabaseConfig, RiskEngineConfig, ScannerConfig, ServerConfig


class ConfigurationError(ValueError):
    """Raised when an ACTIS configuration parameter violates operational constraints."""
    pass


VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
VALID_ENVIRONMENTS = {"development", "testing", "staging", "production"}


def validate_weights(risk_config: RiskEngineConfig) -> List[str]:
    """Validates that risk engine evidence weights are non-negative and sum to 1.0."""
    errors = []
    weights = [
        ("weight_known_intel", risk_config.weight_known_intel),
        ("weight_ml_probability", risk_config.weight_ml_probability),
        ("weight_heuristic_rules", risk_config.weight_heuristic_rules),
        ("weight_external_intel", risk_config.weight_external_intel),
    ]

    for name, w in weights:
        if w < 0.0 or w > 1.0:
            errors.append(f"{name} must be between 0.0 and 1.0 (got {w})")

    total_weight = sum(w for _, w in weights)
    if not math.isclose(total_weight, 1.0, rel_tol=1e-3, abs_tol=1e-3):
        errors.append(f"Risk engine weights must sum to 1.0 (current sum: {total_weight:.4f})")

    return errors


def validate_risk_thresholds(risk_config: RiskEngineConfig) -> List[str]:
    """Validates risk threshold ranges: 0 <= medium < high < critical <= 100."""
    errors = []
    med = risk_config.threshold_medium
    hi = risk_config.threshold_high
    crit = risk_config.threshold_critical

    for name, val in [("threshold_medium", med), ("threshold_high", hi), ("threshold_critical", crit)]:
        if not (0 <= val <= 100):
            errors.append(f"{name} must be in range [0, 100] (got {val})")

    if med >= hi:
        errors.append(f"threshold_medium ({med}) must be strictly less than threshold_high ({hi})")
    if hi >= crit:
        errors.append(f"threshold_high ({hi}) must be strictly less than threshold_critical ({crit})")

    return errors


def validate_scanner_settings(scanner_config: ScannerConfig) -> List[str]:
    """Validates operational limits for file scanners and watchers."""
    errors = []
    if scanner_config.max_file_size_bytes <= 0:
        errors.append(f"max_file_size_bytes must be > 0 (got {scanner_config.max_file_size_bytes})")
    if scanner_config.hash_chunk_size <= 0:
        errors.append(f"hash_chunk_size must be > 0 (got {scanner_config.hash_chunk_size})")
    if scanner_config.watchdog_debounce_seconds < 0:
        errors.append(f"watchdog_debounce_seconds must be non-negative (got {scanner_config.watchdog_debounce_seconds})")
    return errors


def validate_server_settings(server_config: ServerConfig) -> List[str]:
    """Validates network addresses and ports for central backend synchronization."""
    errors = []
    if not (1 <= server_config.port <= 65535):
        errors.append(f"Server port must be in range 1-65535 (got {server_config.port})")

    parsed = urlparse(server_config.backend_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        errors.append(
            f"backend_url must be a valid HTTP/HTTPS URL (got '{server_config.backend_url}')"
        )
    return errors


def validate_log_level(log_level: str) -> List[str]:
    """Validates that log_level is a recognized standard Python logging level."""
    errors = []
    if log_level.upper() not in VALID_LOG_LEVELS:
        errors.append(f"log_level must be one of {sorted(VALID_LOG_LEVELS)} (got '{log_level}')")
    return errors



def validate_environment(environment: str) -> List[str]:
    """Validates that environment matches approved deployment profiles."""
    errors = []
    if environment.lower() not in VALID_ENVIRONMENTS:
        errors.append(
            f"environment must be one of {sorted(VALID_ENVIRONMENTS)} (got '{environment}')"
        )
    return errors


def validate_database_settings(db_config: DatabaseConfig) -> List[str]:
    """Validates operational database configuration constraints."""
    errors = []
    if db_config.timeout_seconds <= 0:
        errors.append(
            f"database timeout_seconds must be > 0 (got {db_config.timeout_seconds})"
        )
    if not db_config.db_path:
        errors.append("database db_path must not be empty")
    return errors


def validate_config(config: AppConfig, strict: bool = True) -> List[str]:
    """
    Validates complete ACTIS AppConfig. Returns list of error messages.
    If strict=True and any errors exist, raises ConfigurationError.
    """
    errors: List[str] = []

    errors.extend(validate_log_level(config.log_level))
    errors.extend(validate_environment(config.environment))

    if config.database:
        errors.extend(validate_database_settings(config.database))

    if config.risk:
        errors.extend(validate_weights(config.risk))
        errors.extend(validate_risk_thresholds(config.risk))

    if config.scanner:
        errors.extend(validate_scanner_settings(config.scanner))

    if config.server:
        errors.extend(validate_server_settings(config.server))

    if errors and strict:
        err_msg = "ACTIS Configuration Validation Failed:\n  - " + "\n  - ".join(errors)
        raise ConfigurationError(err_msg)

    return errors
