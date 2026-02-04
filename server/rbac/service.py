from dataclasses import dataclass


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str


def allow_admin_only(role_name: str) -> AccessDecision:
    if role_name != "admin":
        return AccessDecision(False, "role not permitted")
    return AccessDecision(True, "ok")
