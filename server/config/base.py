from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DLP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "DLP Platform"
    api_v1_prefix: str = "/api/v1"
    environment: str = "dev"
    jwt_secret: str = Field(..., repr=False)
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = 60
    jwt_refresh_exp_minutes: int = 60 * 24 * 7
    database_url: str = Field(..., repr=False)
    redis_url: str = Field(..., repr=False)
    rate_limit_per_minute: int = 120
    request_time_skew_seconds: int = 300
    admin_email: str = Field(..., repr=False)
    admin_password: str = Field(..., repr=False)
    syslog_host: str = "localhost"
    syslog_port: int = 514
    license_key: str = Field(..., repr=False)
    siem_enabled: bool = True
    metrics_enabled: bool = True

