import os
from functools import lru_cache

from .base import BaseConfig
from .dev import DevConfig
from .prod import ProdConfig
from .test import TestConfig


ENV_MAP = {
    "dev": DevConfig,
    "prod": ProdConfig,
    "test": TestConfig,
}


@lru_cache
def get_settings() -> BaseConfig:
    env = os.getenv("DLP_ENV", "dev").lower()
    config_cls = ENV_MAP.get(env, DevConfig)
    return config_cls()


settings = get_settings()

