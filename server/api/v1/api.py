from fastapi import APIRouter

from server.api.v1.routes import admin, agent, health

api_router = APIRouter()
api_router.include_router(agent.router)
api_router.include_router(admin.router)
api_router.include_router(health.router)
