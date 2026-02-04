from pydantic import BaseModel


class PolicyRuleCreate(BaseModel):
    rule_type: str
    pattern: str | None = None
    keywords: list[str] | None = None
    hashes: list[str] | None = None
    file_extension: str | None = None
    min_size: int | None = None
    max_size: int | None = None
    usb_only: bool = False
    action: str
    severity: str = "medium"
    severity_score: int = 0
    tags: list[str] | None = None
    is_whitelist: bool = False
    priority: int = 100


class PolicyCreate(BaseModel):
    name: str
    description: str | None = None
    rules: list[PolicyRuleCreate] = []


class PolicyResponse(BaseModel):
    id: int
    name: str
    description: str | None
    version: int
    is_active: bool
