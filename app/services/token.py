"""
Token Service - Business logic for token management
"""
from typing import Optional, Tuple
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
import uuid
import jwt

from app.models.token import RefreshToken, RevokedToken
from app.models.partner import Partner
from app.config import get_settings

settings = get_settings()


class TokenService:
    """Service for managing tokens"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create_refresh_token(
        self, 
        partner_id: int, 
        access_token_jti: str
    ) -> Tuple[str, RefreshToken]:
        """
        Create a new refresh token
        Returns: (token, refresh_token_record)
        """
        token = RefreshToken.generate_token()
        token_hash = RefreshToken.hash_token(token)
        
        refresh_token = RefreshToken(
            token_hash=token_hash,
            jti=access_token_jti,
            partner_id=partner_id,
            expires_at=datetime.utcnow() + timedelta(days=settings.jwt_refresh_token_expire_days)
        )
        
        self.session.add(refresh_token)
        await self.session.commit()
        await self.session.refresh(refresh_token)
        
        return token, refresh_token
    
    async def get_refresh_token_by_token(self, token: str) -> Optional[RefreshToken]:
        """Get refresh token by token value"""
        token_hash = RefreshToken.hash_token(token)
        statement = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()
    
    async def revoke_refresh_token(self, refresh_token: RefreshToken) -> None:
        """Revoke a refresh token"""
        refresh_token.revoked = True
        refresh_token.revoked_at = datetime.utcnow()
        self.session.add(refresh_token)
        await self.session.commit()
    
    async def revoke_access_token(
        self, 
        jti: str, 
        partner_id: int, 
        expires_at: datetime,
        reason: Optional[str] = None
    ) -> None:
        """Revoke an access token by adding it to blacklist"""
        # Check if already revoked
        statement = select(RevokedToken).where(RevokedToken.jti == jti)
        result = await self.session.execute(statement)
        existing = result.scalar_one_or_none()
        
        if existing:
            return  # Already revoked
        
        revoked_token = RevokedToken(
            jti=jti,
            partner_id=partner_id,
            expires_at=expires_at,
            reason=reason
        )
        
        self.session.add(revoked_token)
        await self.session.commit()
    
    async def is_token_revoked(self, jti: str) -> bool:
        """Check if an access token is revoked"""
        statement = select(RevokedToken).where(RevokedToken.jti == jti)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none() is not None
    
    async def cleanup_expired_tokens(self) -> None:
        """Remove expired refresh tokens and revoked access tokens (cleanup job)"""
        now = datetime.utcnow()
        
        # Delete expired refresh tokens
        statement = select(RefreshToken).where(RefreshToken.expires_at < now)
        result = await self.session.execute(statement)
        expired_refresh = result.scalars().all()
        for token in expired_refresh:
            await self.session.delete(token)
        
        # Delete expired revoked tokens (no need to keep them after original expiry)
        statement = select(RevokedToken).where(RevokedToken.expires_at < now)
        result = await self.session.execute(statement)
        expired_revoked = result.scalars().all()
        for token in expired_revoked:
            await self.session.delete(token)
        
        await self.session.commit()
    
    async def revoke_all_partner_tokens(self, partner_id: int) -> None:
        """Revoke all tokens for a partner (when deactivating account)"""
        # Revoke all refresh tokens
        statement = select(RefreshToken).where(
            RefreshToken.partner_id == partner_id,
            RefreshToken.revoked == False
        )
        result = await self.session.execute(statement)
        refresh_tokens = result.scalars().all()
        
        for token in refresh_tokens:
            token.revoked = True
            token.revoked_at = datetime.utcnow()
            self.session.add(token)
        
        await self.session.commit()
