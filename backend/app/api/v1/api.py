from fastapi import APIRouter

from app.api.v1.routes import agent, admin

api_router = APIRouter()
api_router.include_router(agent.router)
api_router.include_router(admin.router)
