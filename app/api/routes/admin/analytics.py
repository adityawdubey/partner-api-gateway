"""
Analytics & Monitoring Routes
"""
from typing import Annotated, List, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlmodel.ext.asyncio.session import AsyncSession

from app.database import get_session
from app.services.audit import RequestLoggerService
from app.services.token import TokenService
from app.models.audit import RequestLogRead

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/summary")
async def get_analytics(
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(24, ge=1, le=720, description="Time range in hours")
) -> Dict[str, Any]:
    """Get API usage analytics for the past N hours"""
    logger_service = RequestLoggerService(session)
    return await logger_service.get_analytics(hours=hours)


@router.get("/logs", response_model=List[RequestLogRead])
async def get_logs(
    session: Annotated[AsyncSession, Depends(get_session)],
    partner_id: int | None = Query(None, description="Filter by partner ID"),
    limit: int = Query(100, ge=1, le=1000, description="Number of logs to return"),
    offset: int = Query(0, ge=0, description="Pagination offset")
):
    """Get recent request logs with optional filtering"""
    logger_service = RequestLoggerService(session)
    return await logger_service.get_logs(
        partner_id=partner_id,
        limit=limit,
        offset=offset
    )


@router.post("/tokens/cleanup")
async def cleanup_expired_tokens(
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Cleanup expired refresh tokens and revoked access tokens (maintenance task)"""
    token_service = TokenService(session)
    await token_service.cleanup_expired_tokens()
    
    return {
        "message": "Expired tokens cleaned up successfully"
    }
