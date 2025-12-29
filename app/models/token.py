"""
Token Models - Refresh tokens and revoked tokens
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, Column, DateTime
import secrets


class RefreshToken(SQLModel, table=True):
    """Refresh Token database model"""
    __tablename__ = "refresh_tokens"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True, unique=True)
    jti: str = Field(index=True, unique=True)  # JWT ID for access token
    partner_id: int = Field(foreign_key="partners.id", index=True)
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime(timezone=True)))
    revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    
    @staticmethod
    def generate_token() -> str:
        """Generate a secure refresh token"""
        return f"rt_{secrets.token_urlsafe(64)}"
    
    @staticmethod
    def hash_token(token: str) -> str:
        """Hash a refresh token for storage"""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()
    
    def is_valid(self) -> bool:
        """Check if refresh token is still valid"""
        if self.revoked:
            return False
        if datetime.utcnow() > self.expires_at:
            return False
        return True


class RevokedToken(SQLModel, table=True):
    """Revoked Access Token database model"""
    __tablename__ = "revoked_tokens"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    jti: str = Field(index=True, unique=True)  # JWT ID
    partner_id: int = Field(foreign_key="partners.id", index=True)
    revoked_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime(timezone=True)))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))  # Original token expiry
    reason: Optional[str] = Field(default=None)  # Why was it revoked
    
    @classmethod
    def is_revoked(cls, jti: str) -> bool:
        """Check if a token JTI is revoked (to be called with async)"""
        # This is a helper method, actual check is done in service layer
        return False
