import pytest
from fastapi import HTTPException

from server.models.models import Role, User
from server.rbac.deps import require_roles


def test_rbac_rejects_viewer_for_admin_action():
    user = User(id=1, tenant_id=1, email="viewer@example.com", password_hash="x", role=Role(name="viewer"))
    guard = require_roles("admin")
    with pytest.raises(HTTPException):
        guard(user)
