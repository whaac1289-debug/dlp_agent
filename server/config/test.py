from .base import BaseConfig


class TestConfig(BaseConfig):
    environment: str = "test"
    debug: bool = True

