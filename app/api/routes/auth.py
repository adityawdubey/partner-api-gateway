"""
Auth Routes - JWT token generation
"""
from datetime import datetime, timedelta
from typing import Annotated
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
import jwt
from pydantic import BaseModel

from app.database import get_session
from app.services.partner import PartnerService
from app.services.token import TokenService
from app.config import get_settings

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


# =============================================================================
# Schemas
# =============================================================================

class TokenRequest(BaseModel):
    """Request schema for token generation"""
    api_key: str


class TokenResponse(BaseModel):
    """Response schema for token generation"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    partner_id: int
    partner_name: str
    allowed_services: list[str]
    rate_limit: int


class RefreshTokenRequest(BaseModel):
    """Request schema for refreshing access token"""
    refresh_token: str


class RevokeTokenRequest(BaseModel):
    """Request schema for revoking tokens"""
    token: str  # Can be access token or refresh token
    token_type: str = "access"  # "access" or "refresh"


# =============================================================================
# JWT Utilities
# =============================================================================

def create_access_token(data: dict, jti: str, expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": jti,  # JWT ID for token revocation
        "type": "access"
    })
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    
    return encoded_jwt


# =============================================================================
# Routes
# =============================================================================

@router.post("/token", response_model=TokenResponse)
async def get_token(
    token_request: TokenRequest,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """
    Exchange API key for JWT access token and refresh token.
    
    The access token expires in 1 hour and should be used for all API requests.
    The refresh token expires in 30 days and can be used to get new access tokens.
    """
    # Validate API key and get partner
    partner_service = PartnerService(session)
    partner = await partner_service.get_partner_by_api_key(token_request.api_key)
    
    if not partner:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": "Invalid API key"
            }
        )
    
    if not partner.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": "API key has been deactivated"
            }
        )
    
    # Generate unique JWT ID
    jti = str(uuid.uuid4())
    
    # Create JWT token with partner metadata
    token_data = {
        "sub": str(partner.id),  # subject (partner ID)
        "partner_id": partner.id,
        "partner_name": partner.name,
        "allowed_services": partner.allowed_services,
        "rate_limit": partner.rate_limit,
        "is_active": partner.is_active
    }
    
    access_token = create_access_token(token_data, jti)
    
    # Create refresh token
    token_service = TokenService(session)
    refresh_token, _ = await token_service.create_refresh_token(partner.id, jti)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.jwt_access_token_expire_minutes * 60,
        partner_id=partner.id,
        partner_name=partner.name,
        allowed_services=partner.allowed_services,
        rate_limit=partner.rate_limit
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    refresh_request: RefreshTokenRequest,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """
    Refresh access token using a valid refresh token.
    
    Returns a new access token and optionally a new refresh token (token rotation).
    """
    token_service = TokenService(session)
    
    # Get refresh token from database
    refresh_token = await token_service.get_refresh_token_by_token(refresh_request.refresh_token)
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": "Invalid refresh token"
            }
        )
    
    # Validate refresh token
    if not refresh_token.is_valid():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": "Refresh token has expired or been revoked"
            }
        )
    
    # Get partner
    partner_service = PartnerService(session)
    partner = await partner_service.get_partner_by_id(refresh_token.partner_id)
    
    if not partner or not partner.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": "Partner account is not active"
            }
        )
    
    # Generate new JWT ID
    new_jti = str(uuid.uuid4())
    
    # Create new access token
    token_data = {
        "sub": str(partner.id),
        "partner_id": partner.id,
        "partner_name": partner.name,
        "allowed_services": partner.allowed_services,
        "rate_limit": partner.rate_limit,
        "is_active": partner.is_active
    }
    
    new_access_token = create_access_token(token_data, new_jti)
    
    # Token rotation: Revoke old refresh token and create new one
    await token_service.revoke_refresh_token(refresh_token)
    new_refresh_token, _ = await token_service.create_refresh_token(partner.id, new_jti)
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.jwt_access_token_expire_minutes * 60,
        partner_id=partner.id,
        partner_name=partner.name,
        allowed_services=partner.allowed_services,
        rate_limit=partner.rate_limit
    )


@router.post("/revoke")
async def revoke_token(
    revoke_request: RevokeTokenRequest,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """
    Revoke an access token or refresh token.
    
    Once revoked, the token can no longer be used for authentication.
    """
    token_service = TokenService(session)
    
    if revoke_request.token_type == "refresh":
        # Revoke refresh token
        refresh_token = await token_service.get_refresh_token_by_token(revoke_request.token)
        
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "Not Found",
                    "message": "Refresh token not found"
                }
            )
        
        await token_service.revoke_refresh_token(refresh_token)
        
        return {
            "message": "Refresh token revoked successfully",
            "revoked_at": datetime.utcnow().isoformat()
        }
    
    else:  # access token
        # Decode and revoke access token
        try:
            payload = jwt.decode(
                revoke_request.token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm]
            )
            
            jti = payload.get("jti")
            partner_id = payload.get("partner_id")
            exp = payload.get("exp")
            
            if not jti or not partner_id or not exp:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "Bad Request",
                        "message": "Invalid token format"
                    }
                )
            
            expires_at = datetime.fromtimestamp(exp)
            
            await token_service.revoke_access_token(
                jti=jti,
                partner_id=partner_id,
                expires_at=expires_at,
                reason="Manual revocation"
            )
            
            return {
                "message": "Access token revoked successfully",
                "revoked_at": datetime.utcnow().isoformat()
            }
            
        except jwt.PyJWTError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Bad Request",
                    "message": f"Invalid token: {str(e)}"
                }
            )
