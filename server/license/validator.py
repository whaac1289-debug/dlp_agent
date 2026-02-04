from dataclasses import dataclass

from server.config import settings


@dataclass(frozen=True)
class LicenseStatus:
    valid: bool
    reason: str


def validate_license() -> LicenseStatus:
    if not settings.license_key:
        return LicenseStatus(False, "missing license key")
    return LicenseStatus(True, "ok")
