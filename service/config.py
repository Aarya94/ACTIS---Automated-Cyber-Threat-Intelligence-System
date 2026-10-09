"""
ACTIS Protection Service Configuration
Re-exports ServiceConfig and provides safe factory helpers using the central configuration system.
"""

from typing import Optional
from config.settings import ServiceConfig
from config.defaults import create_default_config


def get_default_service_config() -> ServiceConfig:
    """Returns a ServiceConfig instance populated from standard ACTIS defaults."""
    app_cfg = create_default_config()
    if app_cfg.service is not None:
        return app_cfg.service
    return ServiceConfig()
