from fastapi import Depends, HTTPException, status

from server.models import models
from server.security.deps import get_current_user


def require_roles(*roles: str):
    def _guard(user: models.User = Depends(get_current_user)) -> models.User:
        role_name = user.role.name if user.role else None
        if role_name not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return user

    return _guard
