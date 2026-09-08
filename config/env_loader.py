"""
ACTIS Configuration Environment Loader
Automated Cyber Threat Intelligence System — Week 1 Day 2

Handles safe loading and typed parsing of environment variables from .env
and system environment with fallback defaults.
"""

import os
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv


def load_environment(env_file_path: Optional[Path] = None) -> bool:
    """
    Loads environment variables from the given .env path or searches standard locations.
    Returns True if an existing .env file was loaded, False otherwise.
    """
    if env_file_path and env_file_path.is_file():
        load_dotenv(dotenv_path=env_file_path, override=False)
        return True

    # Check parent project root
    project_root = Path(__file__).resolve().parent.parent
    root_env = project_root / ".env"
    if root_env.is_file():
        load_dotenv(dotenv_path=root_env, override=False)
        return True

    # Fallback to standard dotenv discovery
    return load_dotenv(override=False)


def get_str(key: str, default: str = "") -> str:
    """Retrieves a string environment variable with whitespace stripped."""
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip()


def get_int(key: str, default: int = 0) -> int:
    """Retrieves an integer environment variable with fallback on parse error."""
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val.strip())
    except (ValueError, TypeError):
        return default


def get_float(key: str, default: float = 0.0) -> float:
    """Retrieves a float environment variable with fallback on parse error."""
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return float(val.strip())
    except (ValueError, TypeError):
        return default


def get_bool(key: str, default: bool = False) -> bool:
    """Retrieves a boolean environment variable recognizing standard boolean strings."""
    val = os.getenv(key)
    if val is None:
        return default
    cleaned = val.strip().lower()
    if cleaned in ("true", "1", "yes", "t", "on", "enable", "enabled"):
        return True
    if cleaned in ("false", "0", "no", "f", "off", "disable", "disabled"):
        return False
    return default


def get_list(key: str, default: Optional[List[str]] = None, delimiter: str = ",") -> List[str]:
    """Retrieves a delimited list of trimmed string tokens."""
    if default is None:
        default = []
    val = os.getenv(key)
    if not val:
        return list(default)
    tokens = [t.strip() for t in val.split(delimiter) if t.strip()]
    return tokens if tokens else list(default)
