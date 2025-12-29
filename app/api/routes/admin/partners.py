"""
Partner Management Routes
"""
from typing import Annotated, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.database import get_session
from app.models.partner import PartnerCreate, PartnerReadWithKey, PartnerUpdate, PartnerRead
from app.services.partner import PartnerService
from app.services.token import TokenService

router = APIRouter(prefix="/partners", tags=["Partners"])


@router.get("", response_model=List[dict])
async def list_partners(
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """List all registered partners with their allowed services"""
    partner_service = PartnerService(session)
    return await partner_service.get_all_partners()


@router.post("", response_model=PartnerReadWithKey, status_code=status.HTTP_201_CREATED)
async def create_partner(
    partner_data: PartnerCreate,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """
    Register a new partner with API key and permissions.
    Returns the API key - this is the only time it will be shown!
    """
    partner_service = PartnerService(session)
    partner, api_key = await partner_service.create_partner(partner_data)
    
    # Get allowed services
    allowed_services = await partner_service.get_partner_services(partner.id)
    
    return PartnerReadWithKey(
        id=partner.id,
        name=partner.name,
        allowed_services=allowed_services,
        rate_limit=partner.rate_limit,
        is_active=partner.is_active,
        created_at=partner.created_at,
        updated_at=partner.updated_at,
        api_key=api_key
    )


@router.get("/{partner_id}", response_model=PartnerRead)
async def get_partner(
    partner_id: int,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Get a specific partner by ID"""
    partner_service = PartnerService(session)
    partner = await partner_service.get_partner_by_id(partner_id)
    
    if not partner:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Partner with ID {partner_id} not found"}
        )
    
    allowed_services = await partner_service.get_partner_services(partner.id)
    
    return PartnerRead(
        id=partner.id,
        name=partner.name,
        allowed_services=allowed_services,
        rate_limit=partner.rate_limit,
        is_active=partner.is_active,
        created_at=partner.created_at,
        updated_at=partner.updated_at
    )


@router.patch("/{partner_id}", response_model=PartnerRead)
async def update_partner(
    partner_id: int,
    partner_data: PartnerUpdate,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Update a partner's details"""
    partner_service = PartnerService(session)
    partner = await partner_service.update_partner(partner_id, partner_data)
    
    allowed_services = await partner_service.get_partner_services(partner.id)
    
    return PartnerRead(
        id=partner.id,
        name=partner.name,
        allowed_services=allowed_services,
        rate_limit=partner.rate_limit,
        is_active=partner.is_active,
        created_at=partner.created_at,
        updated_at=partner.updated_at
    )


@router.post("/{partner_id}/deactivate")
async def deactivate_partner(
    partner_id: int,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Deactivate a partner and revoke all their tokens"""
    partner_service = PartnerService(session)
    token_service = TokenService(session)
    
    # Deactivate partner
    partner = await partner_service.deactivate_partner(partner_id)
    
    # Revoke all tokens
    await token_service.revoke_all_partner_tokens(partner_id)
    
    return {
        "message": "Partner deactivated and all tokens revoked",
        "partner_id": partner_id,
        "is_active": partner.is_active
    }


@router.post("/{partner_id}/regenerate-key")
async def regenerate_partner_api_key(
    partner_id: int,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Regenerate API key for a partner. Returns new key - shown only once!"""
    partner_service = PartnerService(session)
    token_service = TokenService(session)
    
    # Revoke all existing tokens
    await token_service.revoke_all_partner_tokens(partner_id)
    
    # Generate new API key
    new_api_key = await partner_service.regenerate_api_key(partner_id)
    
    return {
        "message": "API key regenerated successfully. All previous tokens have been revoked.",
        "partner_id": partner_id,
        "api_key": new_api_key,
        "warning": "Save this key now - it won't be shown again!"
    }


@router.post("/{partner_id}/services/{service_id}", status_code=status.HTTP_201_CREATED)
async def grant_service_access(
    partner_id: int,
    service_id: int,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Grant a partner access to a specific service"""
    partner_service = PartnerService(session)
    permission = await partner_service.grant_service_access(partner_id, service_id)
    
    return {
        "message": "Service access granted",
        "partner_id": partner_id,
        "service_id": service_id,
        "granted_at": permission.granted_at
    }


@router.delete("/{partner_id}/services/{service_id}")
async def revoke_service_access(
    partner_id: int,
    service_id: int,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Revoke a partner's access to a specific service"""
    partner_service = PartnerService(session)
    await partner_service.revoke_service_access(partner_id, service_id)
    
    return {
        "message": "Service access revoked",
        "partner_id": partner_id,
        "service_id": service_id
    }
