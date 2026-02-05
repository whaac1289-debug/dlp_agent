from pydantic import Field
from pydantic import field_validator, model_validator
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
    jwt_issuer: str = "dlp-platform"
    jwt_audience: str = "dlp-dashboard"
    jwt_agent_audience: str = "dlp-agent"
    jwt_access_token_type: str = "access"
    jwt_refresh_token_type: str = "refresh"
    jwt_agent_token_type: str = "agent"
    cookie_access_name: str = "dlp_access"
    cookie_refresh_name: str = "dlp_refresh"
    csrf_cookie_name: str = "dlp_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    cookie_secure: bool = True
    allowed_origins: list[str] = Field(default_factory=list)
    agent_protocol_versions: list[str] = Field(default_factory=lambda: ["1.0"])
    database_url: str = Field(..., repr=False)
    redis_url: str = Field(..., repr=False)
    rate_limit_per_minute: int = 120
    request_time_skew_seconds: int = 60
    admin_email: str = Field(..., repr=False)
    admin_password: str = Field(..., repr=False)
    syslog_host: str = "localhost"
    syslog_port: int = 514
    license_key: str = Field(..., repr=False)
    siem_enabled: bool = True
    metrics_enabled: bool = True
    enrollment_token_ttl_hours: int = 24
    enrollment_signing_secret: str = Field(..., repr=False)
    dev_signature_bypass: bool = False

    @field_validator("jwt_secret", "admin_password", "enrollment_signing_secret", mode="after")
    @classmethod
    def validate_secret_strength(cls, value: str) -> str:
        if len(value) < 24:
            raise ValueError("sensitive settings must be at least 24 characters")
        return value

    @field_validator("allowed_origins", mode="after")
    @classmethod
    def validate_allowed_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            if not origin.startswith(("https://", "http://localhost", "http://127.0.0.1")):
                raise ValueError(f"invalid origin '{origin}'")
        return origins

    @model_validator(mode="after")
    def validate_production_transport_security(self) -> "BaseConfig":
        if self.environment == "prod":
            insecure_http = [
                origin
                for origin in self.allowed_origins
                if origin.startswith("http://")
                and not origin.startswith(("http://localhost", "http://127.0.0.1"))
            ]
            if insecure_http:
                raise ValueError("prod environment requires https origins")
        return self
