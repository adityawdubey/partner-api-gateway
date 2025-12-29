"""
API Gateway - FastAPI Application
Main entry point
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import logging

from app.config import get_settings
from app.database import create_db_and_tables
from app.api.routes import health, auth, gateway
from app.api.routes.admin import partners, services, analytics

# Import models to ensure they're registered with SQLModel
from app.models.partner import Partner
from app.models.service import Service
from app.models.permission import PartnerServicePermission
from app.models.audit import RequestLog
from app.models.rate_limit import RateLimitEntry
from app.models.token import RefreshToken, RevokedToken

settings = get_settings()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan - startup and shutdown events"""
    # Startup
    await create_db_and_tables()
    logger.info(f"API Gateway started on {settings.host}:{settings.port}")
    yield
    
    # Shutdown
    logger.info("API Gateway shutting down")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="API Gateway for managing external partner access to internal services",
    lifespan=lifespan,
    swagger_ui_parameters={
        "persistAuthorization": True  # Keep authorization after page refresh
    }
)


# =============================================================================
# Middleware
# =============================================================================

# CORS Middleware - Configure allowed origins for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Prevent clickjacking attacks
    response.headers["X-Frame-Options"] = "DENY"
    
    # Enable browser XSS protection
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Control referrer information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Enforce HTTPS (uncomment in production with HTTPS)
    # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Content Security Policy (adjust as needed)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    # Permissions Policy
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response


# =============================================================================
# Routers
# =============================================================================

# Public routers
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(gateway.router)

# Admin sub-routers under /admin prefix
admin_router = APIRouter(prefix="/admin")
admin_router.include_router(partners.router)
admin_router.include_router(services.router)
admin_router.include_router(analytics.router)
app.include_router(admin_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True
    )
