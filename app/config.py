"""
Application Configuration
Uses pydantic-settings for environment variable management
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # API Gateway Settings
    app_name: str = "API Gateway"
    app_version: str = "1.0.0"

    # Server Settings
    host: str = "0.0.0.0"
    port: int = 5000

    # Database Settings
    database_url: str = "sqlite:///./api_gateway.db"

    # Backend Service URL
    backend_base_url: str = "https://jsonplaceholder.typicode.com"

    # JWT Settings
    jwt_secret_key: str = "your-secret-key-change-this-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60  # 1 hour
    jwt_refresh_token_expire_days: int = 30  # 30 days

    # Security Settings
    cors_origins: List[str] = ["*"]  # In production, specify exact origins
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]
    cors_allow_headers: List[str] = ["*"]

    # Rate Limiting Defaults
    default_rate_limit: int = 60  # requests per window
    rate_limit_window: int = 60  # seconds

    # Available Services
    available_services: List[str] = [
        "users", "posts", "comments", "todos", "albums", "photos"
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance"""
    return Settings()
