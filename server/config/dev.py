from .base import BaseConfig


class DevConfig(BaseConfig):
    environment: str = "dev"
    debug: bool = True

