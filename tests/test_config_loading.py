"""
Unit Tests for ACTIS Configuration Loading
Automated Cyber Threat Intelligence System — Week 1 Day 2

Verifies default configuration generation, typed environment variable loading,
path resolution, and secret credential redaction.
"""

import os
from pathlib import Path
import pytest

from config.paths import (
    ACTIS_ROOT,
    CONFIG_DIR,
    DATA_DIR,
    MODELS_DIR,
    LOGS_DIR,
    REPORTS_DIR,
    DATABASE_PATH,
    TEST_DATABASE_PATH,
    TEST_CENTRAL_BACKEND_DB,
    PathConfig,
)
from config.config import get_config
from config.settings import (
    AppConfig,
    DatabaseConfig,
    ModelConfig,
    ExternalApiConfig,
    RiskEngineConfig,
    ScannerConfig,
    ServerConfig,
)
from config.defaults import create_default_config
from config.env_loader import (
    get_str,
    get_int,
    get_float,
    get_bool,
    get_list,
    get_int_bounded,
    get_float_bounded,
    get_path,
    load_environment,
)


def test_default_config_instantiation():
    """Verifies that default config generates a complete, non-null AppConfig."""
    cfg = create_default_config()
    assert isinstance(cfg, AppConfig)
    assert cfg.app_name == "ACTIS"
    assert cfg.environment == "development"
    assert cfg.log_level == "DEBUG"

    # Verify nested domain objects
    assert isinstance(cfg.database, DatabaseConfig)
    assert isinstance(cfg.models, ModelConfig)
    assert isinstance(cfg.apis, ExternalApiConfig)
    assert isinstance(cfg.risk, RiskEngineConfig)
    assert isinstance(cfg.scanner, ScannerConfig)
    assert isinstance(cfg.server, ServerConfig)


def test_project_paths_resolution():
    """Verifies all standard directory paths resolve to ACTIS root."""
    path_cfg = PathConfig()
    assert path_cfg.root_dir.is_dir()
    assert path_cfg.config_dir == ACTIS_ROOT / "config"
    assert path_cfg.data_dir == ACTIS_ROOT / "data"
    assert path_cfg.models_dir == ACTIS_ROOT / "models"
    assert path_cfg.logs_dir == ACTIS_ROOT / "logs"
    assert path_cfg.reports_dir == ACTIS_ROOT / "reports"
    assert path_cfg.database_path == ACTIS_ROOT / "data" / "threat_intelligence.db"
    assert len(path_cfg.quick_scan_paths) >= 3


def test_typed_env_loader_helpers(monkeypatch):
    """Verifies typed environment parsing helpers with valid values and fallbacks."""
    monkeypatch.setenv("ACTIS_TEST_STR", "  hello_actis  ")
    monkeypatch.setenv("ACTIS_TEST_INT", "42")
    monkeypatch.setenv("ACTIS_TEST_BAD_INT", "not_a_number")
    monkeypatch.setenv("ACTIS_TEST_FLOAT", "3.1415")
    monkeypatch.setenv("ACTIS_TEST_BAD_FLOAT", "invalid_float")
    monkeypatch.setenv("ACTIS_TEST_BOOL_T", "true")
    monkeypatch.setenv("ACTIS_TEST_BOOL_F", "0")
    monkeypatch.setenv("ACTIS_TEST_LIST", "alpha, beta , gamma,delta")

    assert get_str("ACTIS_TEST_STR") == "hello_actis"
    assert get_str("ACTIS_NONEXISTENT", "default_str") == "default_str"

    assert get_int("ACTIS_TEST_INT") == 42
    assert get_int("ACTIS_TEST_BAD_INT", 99) == 99
    assert get_int("ACTIS_NONEXISTENT", 10) == 10

    assert get_float("ACTIS_TEST_FLOAT") == 3.1415
    assert get_float("ACTIS_TEST_BAD_FLOAT", 1.0) == 1.0

    assert get_bool("ACTIS_TEST_BOOL_T") is True
    assert get_bool("ACTIS_TEST_BOOL_F") is False
    assert get_bool("ACTIS_NONEXISTENT", True) is True

    assert get_list("ACTIS_TEST_LIST") == ["alpha", "beta", "gamma", "delta"]
    assert get_list("ACTIS_NONEXISTENT", ["def"]) == ["def"]


def test_secret_redaction_in_repr():
    """Verifies that sensitive keys are never leaked in string representations."""
    api_cfg = ExternalApiConfig(
        virustotal_api_key="vt_secret_key_123456789",
        abuseipdb_api_key="abuse_secret_abcdefgh",
    )
    repr_str = repr(api_cfg)
    assert "vt_secret_key_123456789" not in repr_str
    assert "abuse_secret_abcdefgh" not in repr_str
    assert "vt****89" in repr_str

    srv_cfg = ServerConfig(client_api_key="super_secret_client_token")
    srv_repr = repr(srv_cfg)
    assert "super_secret_client_token" not in srv_repr
    assert "su****en" in srv_repr

def test_testing_profile_uses_isolated_test_paths():
    """Verifies that the testing profile safely routes databases to isolated test files."""
    test_cfg = create_default_config(environment="testing")
    assert test_cfg.environment == "testing"
    assert test_cfg.log_level == "WARNING"
    assert test_cfg.database.db_path == TEST_DATABASE_PATH
    assert test_cfg.database.backend_db_path == TEST_CENTRAL_BACKEND_DB
    assert test_cfg.database.db_path != DATABASE_PATH


def test_production_profile_configuration():
    """Verifies that the production profile configures standard paths and INFO logging."""
    prod_cfg = create_default_config(environment="production")
    assert prod_cfg.environment == "production"
    assert prod_cfg.log_level == "INFO"
    assert prod_cfg.database.db_path == DATABASE_PATH


def test_dynamic_get_config_reload():
    """Verifies get_config singleton access and reload capability across environments."""
    base_cfg = get_config()
    assert base_cfg is not None

    # Reload with testing environment profile
    reloaded_cfg = get_config(reload=True, environment="testing")
    assert reloaded_cfg.environment == "testing"
    assert reloaded_cfg.database.db_path == TEST_DATABASE_PATH

    # Reset back to default development
    reset_cfg = get_config(reload=True, environment="development")
    assert reset_cfg.environment == "development"

def test_bounded_int_and_float_loader(monkeypatch):
    """Verifies bounded numeric environment loaders enforce min/max constraints."""
    monkeypatch.setenv("TEST_BOUND_INT_VALID", "50")
    monkeypatch.setenv("TEST_BOUND_INT_LOW", "5")
    monkeypatch.setenv("TEST_BOUND_INT_HIGH", "150")

    assert get_int_bounded("TEST_BOUND_INT_VALID", default=10, min_val=10, max_val=100) == 50
    assert get_int_bounded("TEST_BOUND_INT_LOW", default=20, min_val=10, max_val=100) == 20
    assert get_int_bounded("TEST_BOUND_INT_HIGH", default=20, min_val=10, max_val=100) == 20
    assert get_int_bounded("TEST_UNSET", default=30, min_val=10, max_val=100) == 30

    monkeypatch.setenv("TEST_BOUND_FLOAT_VALID", "12.5")
    monkeypatch.setenv("TEST_BOUND_FLOAT_LOW", "-1.0")
    monkeypatch.setenv("TEST_BOUND_FLOAT_HIGH", "99.9")

    assert get_float_bounded("TEST_BOUND_FLOAT_VALID", default=5.0, min_val=0.0, max_val=30.0) == 12.5
    assert get_float_bounded("TEST_BOUND_FLOAT_LOW", default=5.0, min_val=0.0, max_val=30.0) == 5.0
    assert get_float_bounded("TEST_BOUND_FLOAT_HIGH", default=5.0, min_val=0.0, max_val=30.0) == 5.0


def test_path_env_loader(monkeypatch, tmp_path):
    """Verifies get_path parses, resolves, and verifies optional path existence."""
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("actis", encoding="utf-8")

    monkeypatch.setenv("TEST_PATH_EXISTS", str(sample_file))
    monkeypatch.setenv("TEST_PATH_MISSING", str(tmp_path / "nonexistent.bin"))

    assert get_path("TEST_PATH_EXISTS", must_exist=True) == sample_file.resolve()
    assert get_path("TEST_PATH_MISSING", default=Path("/default"), must_exist=True) == Path("/default")
    assert get_path("TEST_PATH_MISSING", must_exist=False) == (tmp_path / "nonexistent.bin").resolve()
    assert get_path("TEST_PATH_UNSET", default=None) is None

