"""
Service Management Routes
"""
from typing import Annotated, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.database import get_session
from app.models.service import Service, ServiceCreate, ServiceUpdate
from app.services.service_management import ServiceManagementService

router = APIRouter(prefix="/services", tags=["Services"])


@router.get("", response_model=List[Service])
async def list_services(
    session: Annotated[AsyncSession, Depends(get_session)],
    active_only: bool = Query(False, description="Only return active services")
):
    """List all backend services"""
    service_mgmt = ServiceManagementService(session)
    
    if active_only:
        return await service_mgmt.get_active_services()
    
    return await service_mgmt.get_all_services()


@router.post("", response_model=Service, status_code=status.HTTP_201_CREATED)
async def create_service(
    service_data: ServiceCreate,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Create a new backend service"""
    service_mgmt = ServiceManagementService(session)
    return await service_mgmt.create_service(service_data)


@router.get("/{service_id}", response_model=Service)
async def get_service(
    service_id: int,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Get a specific service by ID"""
    service_mgmt = ServiceManagementService(session)
    service = await service_mgmt.get_service_by_id(service_id)
    
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Service with ID {service_id} not found"}
        )
    
    return service


@router.patch("/{service_id}", response_model=Service)
async def update_service(
    service_id: int,
    service_data: ServiceUpdate,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Update a service's details"""
    service_mgmt = ServiceManagementService(session)
    return await service_mgmt.update_service(service_id, service_data)


@router.post("/{service_id}/deactivate")
async def deactivate_service(
    service_id: int,
    session: Annotated[AsyncSession, Depends(get_session)]
):
    """Deactivate a service"""
    service_mgmt = ServiceManagementService(session)
    service = await service_mgmt.deactivate_service(service_id)
    
    return {
        "message": f"Service '{service.name}' deactivated successfully",
        "service_id": service.id,
        "name": service.name,
        "is_active": service.is_active
    }
