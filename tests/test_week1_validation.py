import json
from pathlib import Path
import pytest


ROOT = Path(__file__).resolve().parent.parent


def test_required_directories_present():
    # Use the tools validator to ensure scaffold
    from tools.validate_structure import validate

    assert validate(create_missing=False) is True


def test_config_and_logger_load():
    from config.config import get_logger, DATABASE_PATH

    logger = get_logger("ACTIS_TEST")
    assert logger is not None
    # Database path should point inside data/
    assert str(DATABASE_PATH).startswith(str(ROOT / "data"))


def test_requirements_and_readme_exist():
    assert (ROOT / "requirements.txt").exists()
    assert (ROOT / "README.md").exists()


def test_phishing_model_metadata_contract():
    meta_file = ROOT / "models" / "phishing_model_metadata.json"
    assert meta_file.exists()
    data = json.loads(meta_file.read_text(encoding="utf-8"))
    assert data.get("feature_count") == 19
    features = data.get("features")
    assert isinstance(features, list)
    assert len(features) == 19
