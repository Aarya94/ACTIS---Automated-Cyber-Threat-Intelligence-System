"""
Unit Tests for ACTIS Configuration Validation
Automated Cyber Threat Intelligence System — Week 1 Day 2

Verifies validation of risk weights, severity thresholds, scanner constraints,
network endpoints, and log levels.
"""

import pytest

from config.defaults import create_default_config
from config.settings import (
    DatabaseConfig,
    ExternalApiConfig,
    RiskEngineConfig,
    ScannerConfig,
    ServerConfig,
)
from config.validator import (
    ConfigurationError,
    validate_config,
    validate_weights,
    validate_risk_thresholds,
    validate_scanner_settings,
    validate_server_settings,
    validate_log_level,
    validate_environment,
    validate_database_settings,
    validate_app_name,
    validate_api_settings,
)


def test_valid_default_config_passes_validation():
    """Default configuration should satisfy all operational rules with zero errors."""
    cfg = create_default_config()
    errors = validate_config(cfg, strict=True)
    assert errors == []


def test_invalid_log_level():
    """Unrecognized log level strings should be rejected."""
    assert len(validate_log_level("TRACE")) > 0
    assert len(validate_log_level("VERBOSE")) > 0
    assert len(validate_log_level("INFO")) == 0
    assert len(validate_log_level("DEBUG")) == 0


def test_weight_validation_sum_and_bounds():
    """Weights that do not sum to 1.0 or are out of bounds should fail."""
    # Sum != 1.0
    bad_weights = RiskEngineConfig(
        weight_known_intel=0.5,
        weight_ml_probability=0.5,
        weight_heuristic_rules=0.2,
        weight_external_intel=0.1,
    )
    errors = validate_weights(bad_weights)
    assert any("must sum to 1.0" in e for e in errors)

    # Negative weight
    neg_weight = RiskEngineConfig(
        weight_known_intel=-0.1,
        weight_ml_probability=0.5,
        weight_heuristic_rules=0.3,
        weight_external_intel=0.3,
    )
    errors = validate_weights(neg_weight)
    assert any("must be between 0.0 and 1.0" in e for e in errors)


def test_risk_threshold_ordering():
    """Thresholds must follow: 0 <= medium < high < critical <= 100."""
    # Inverted medium and high
    bad_order = RiskEngineConfig(
        threshold_medium=70,
        threshold_high=60,
        threshold_critical=80,
    )
    errors = validate_risk_thresholds(bad_order)
    assert any("threshold_medium" in e and "strictly less" in e for e in errors)

    # Out of range threshold
    out_of_bounds = RiskEngineConfig(
        threshold_medium=30,
        threshold_high=60,
        threshold_critical=120,
    )
    errors = validate_risk_thresholds(out_of_bounds)
    assert any("must be in range [0, 100]" in e for e in errors)


def test_scanner_limits_validation():
    """Scanner limits must be strictly positive."""
    bad_scanner = ScannerConfig(
        max_file_size_bytes=0,
        hash_chunk_size=-1024,
        watchdog_debounce_seconds=-1.0,
    )
    errors = validate_scanner_settings(bad_scanner)
    assert len(errors) == 3


def test_server_network_validation():
    """Server port must be valid 1-65535 and backend_url must be HTTP(S)."""
    bad_server = ServerConfig(
        backend_url="ftp://invalid.endpoint",
        port=70000,
    )
    errors = validate_server_settings(bad_server)
    assert any("Server port must be in range" in e for e in errors)
    assert any("backend_url must be a valid HTTP/HTTPS" in e for e in errors)


def test_strict_mode_raises_configuration_error():
    """When strict=True, validate_config raises ConfigurationError on invalid settings."""
    cfg = create_default_config()
    cfg.log_level = "NOT_A_VALID_LEVEL"
    with pytest.raises(ConfigurationError) as exc_info:
        validate_config(cfg, strict=True)
    assert "ACTIS Configuration Validation Failed" in str(exc_info.value)

def test_invalid_environment_validation():
    """Environment must belong to approved deployment profiles."""
    assert len(validate_environment("invalid_env")) > 0
    assert len(validate_environment("custom_env")) > 0
    assert len(validate_environment("development")) == 0
    assert len(validate_environment("testing")) == 0
    assert len(validate_environment("production")) == 0
    assert len(validate_environment("staging")) == 0


def test_database_settings_validation(tmp_path):
    """Database timeout must be strictly positive and path non-empty."""
    bad_timeout = DatabaseConfig(
        db_path=tmp_path / "test.db",
        backend_db_path=tmp_path / "backend.db",
        timeout_seconds=-5.0,
    )
    errors = validate_database_settings(bad_timeout)
    assert any("timeout_seconds must be > 0" in e for e in errors)


def test_app_name_validation():
    """Application name must be a non-empty string."""
    assert len(validate_app_name("")) > 0
    assert len(validate_app_name("   ")) > 0
    assert len(validate_app_name("ACTIS")) == 0


def test_api_request_timeout_validation():
    """External threat intel API timeout must be within (0, 120] seconds."""
    bad_zero = ExternalApiConfig(request_timeout=0.0)
    assert any("must be > 0" in e for e in validate_api_settings(bad_zero))

    bad_large = ExternalApiConfig(request_timeout=300.0)
    assert any("cannot exceed 120s" in e for e in validate_api_settings(bad_large))

    valid_api = ExternalApiConfig(request_timeout=15.0)
    assert len(validate_api_settings(valid_api)) == 0

