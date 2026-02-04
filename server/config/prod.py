from .base import BaseConfig


class ProdConfig(BaseConfig):
    environment: str = "prod"
    debug: bool = False

