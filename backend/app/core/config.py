from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "DLP Platform"
    api_v1_prefix: str = "/api/v1"
    jwt_secret: str = "change_me"
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = 60
    jwt_refresh_exp_minutes: int = 60 * 24 * 7
    database_url: str = "postgresql+psycopg2://dlp:dlp@db:5432/dlp"
    redis_url: str = "redis://redis:6379/0"
    rate_limit_per_minute: int = 120
    request_time_skew_seconds: int = 300
    admin_email: str = "admin@dlp.local"
    admin_password: str = "change_me"
    syslog_host: str = "localhost"
    syslog_port: int = 514


settings = Settings()
