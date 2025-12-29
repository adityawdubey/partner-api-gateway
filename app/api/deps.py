"""
API Dependencies - Authentication, Rate Limiting, etc.
"""
from typing import Annotated
from fastapi import Depends, HTTPException, Header, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel.ext.asyncio.session import AsyncSession
import jwt
from jwt.exceptions import PyJWTError

from app.database import get_session
from app.models.partner import Partner
from app.services.partner import PartnerService
from app.services.rate_limit import RateLimiterService
from app.services.token import TokenService
from app.config import get_settings

settings = get_settings()

# Security scheme for Bearer token authentication (enables Swagger UI Authorize button)
security = HTTPBearer()


def get_api_key(
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None
) -> str:
    """Extract API key from request headers"""
    # Check X-API-Key header first
    if x_api_key:
        return x_api_key
    
    # Check Authorization Bearer header
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "Unauthorized",
            "message": "API key is required. Provide via 'X-API-Key' header or 'Authorization: Bearer <key>'"
        }
    )


def get_token_from_header(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]
) -> str:
    """Extract JWT token from Authorization header using HTTPBearer"""
    return credentials.credentials


async def verify_jwt_token(
    token: str,
    session: AsyncSession
) -> Partner:
    """Verify JWT token and return partner"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "Unauthorized",
            "message": "Could not validate credentials"
        },
        headers={"WWW-Authenticate": "Bearer"}
    )
    
    try:
        # Decode JWT token
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        
        partner_id: int = payload.get("partner_id")
        jti: str = payload.get("jti")  # JWT ID for revocation check
        
        if partner_id is None or jti is None:
            raise credentials_exception
        
        # Check if token has been revoked
        token_service = TokenService(session)
        if await token_service.is_token_revoked(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "Unauthorized",
                    "message": "Token has been revoked"
                },
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Get partner from database
        partner_service = PartnerService(session)
        partner = await partner_service.get_partner_by_id(partner_id)
        
        if partner is None:
            raise credentials_exception
        
        if not partner.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "Unauthorized",
                    "message": "Partner account has been deactivated"
                }
            )
        
        # Populate allowed services from token (faster than DB lookup)
        partner.allowed_services = payload.get("allowed_services", [])
        
        return partner
        
    except PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": f"Invalid token: {str(e)}"
            },
            headers={"WWW-Authenticate": "Bearer"}
        ) from e


def get_service_from_path(path: str) -> str:
    """Extract service name from request path"""
    # Remove leading slash and get first segment
    parts = path.strip("/").split("/")
    if parts and parts[0] in settings.available_services:
        return parts[0]
    return ""


class AuthenticatedPartner:
    """
    Dependency that handles JWT authentication, authorization, and rate limiting
    """
    
    def __init__(self, check_service_access: bool = True):
        self.check_service_access = check_service_access
    
    async def __call__(
        self,
        request: Request,
        token: Annotated[str, Depends(get_token_from_header)],
        session: Annotated[AsyncSession, Depends(get_session)]
    ) -> Partner:
        # Verify JWT and get partner
        partner = await verify_jwt_token(token, session)
        
        # Check service access
        if self.check_service_access:
            service = get_service_from_path(request.url.path)
            if service and not partner.can_access_service(service):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "Forbidden",
                        "message": f"Your API key does not have access to the '{service}' service",
                        "allowed_services": partner.allowed_services
                    }
                )
        
        # Check rate limit
        rate_limiter = RateLimiterService(session)
        allowed, rate_info = await rate_limiter.check_rate_limit(partner.id, partner.rate_limit)
        
        # Store rate info in request state for headers
        request.state.rate_info = rate_info
        request.state.partner = partner
        
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Limit: {rate_info['limit']} requests per {rate_info['window_seconds']} seconds",
                    "retry_after": rate_info["reset_at"] - int(__import__('time').time())
                },
                headers={
                    "X-RateLimit-Limit": str(rate_info["limit"]),
                    "X-RateLimit-Remaining": str(rate_info["remaining"]),
                    "X-RateLimit-Reset": str(rate_info["reset_at"]),
                    "Retry-After": str(rate_info["reset_at"] - int(__import__('time').time()))
                }
            )
        
        return partner


# Pre-configured dependency instances
get_authenticated_partner = AuthenticatedPartner(check_service_access=True)
get_authenticated_partner_no_service_check = AuthenticatedPartner(check_service_access=False)
