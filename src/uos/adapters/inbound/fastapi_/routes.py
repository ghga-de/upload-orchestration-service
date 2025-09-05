# Copyright 2021 - 2025 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
# for the German Human Genome-Phenome Archive (GHGA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""FastAPI endpoints for UOS interaction"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from ghga_service_commons.auth.context import AuthContext, AuthContextProtocol
from pydantic import BaseModel

from uos.constants import TRACER
from uos.core.models import (
    CreateUploadBoxRequest,
    CreateUploadBoxResponse,
    GrantAccessRequest,
    ResearchDataUploadBox,
    UpdateUploadBoxRequest,
    UploadBoxSummary,
)
from uos.core.orchestrator import UploadOrchestrator

router = APIRouter()


async def get_correlation_id() -> UUID:
    """Get correlation ID from request context."""
    # This would extract correlation ID from request headers
    from uuid import uuid4

    return uuid4()


def check_data_steward_role(auth_context: AuthContext) -> bool:
    """Check if the user has Data Steward role."""
    return "data_steward" in auth_context.roles


@router.get(
    "/health",
    summary="health",
    tags=["UploadOrchestrationService"],
    status_code=200,
)
@TRACER.start_as_current_span("routes.health")
async def health():
    """Used to test if this service is alive"""
    return {"status": "OK"}


@router.get(
    "/boxes",
    summary="List upload boxes",
    tags=["UploadOrchestrationService"],
    response_model=list[UploadBoxSummary],
)
@TRACER.start_as_current_span("routes.list_upload_boxes")
async def list_upload_boxes(
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    upload_service: UploadOrchestrator = Depends(get_upload_service),
    auth_context: AuthContext = Depends(require_auth_context),
):
    """List upload boxes accessible to the authenticated user."""
    user_id = auth_context.id
    is_data_steward = check_data_steward_role(auth_context)

    try:
        boxes = await upload_service.list_upload_boxes_for_user(
            user_id=user_id,
            is_data_steward=is_data_steward,
            offset=offset,
            limit=limit,
        )
        return boxes
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list upload boxes: {exc}",
        ) from exc


@router.get(
    "/boxes/{box_id}",
    summary="Get upload box details",
    tags=["UploadOrchestrationService"],
    response_model=ResearchDataUploadBox,
)
@TRACER.start_as_current_span("routes.get_upload_box")
async def get_upload_box(
    box_id: UUID,
    upload_service: UploadOrchestrator = Depends(get_upload_service),
    auth_context: AuthContextProtocol = Depends(require_auth_context),
):
    """Get details of a specific upload box."""
    try:
        upload_box = await upload_service.get_upload_box(box_id)

        # Check access permissions
        user_id = auth_context.id
        is_data_steward = check_data_steward_role(auth_context)

        if not is_data_steward:
            # Check if user has access to this specific box
            accessible_boxes = (
                await upload_service._claims_client.get_accessible_upload_boxes(user_id)
            )
            if box_id not in accessible_boxes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this upload box",
                )

        return upload_box
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get upload box: {exc}",
        ) from exc


@router.post(
    "/boxes",
    summary="Create upload box",
    tags=["UploadOrchestrationService"],
    response_model=CreateUploadBoxResponse,
    status_code=status.HTTP_201_CREATED,
)
@TRACER.start_as_current_span("routes.create_upload_box")
async def create_upload_box(
    request: CreateUploadBoxRequest,
    upload_service: UploadOrchestrator = Depends(get_upload_service),
    auth_context: AuthContextProtocol = Depends(require_auth_context),
    correlation_id: UUID = Depends(get_correlation_id),
):
    """Create a new upload box. Requires Data Steward role."""
    # Check if user has Data Steward role
    if not check_data_steward_role(auth_context):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Data Steward role required to create upload boxes",
        )

    try:
        box_id = await upload_service.create_upload_box(
            request=request,
            user_id=auth_context.id,
        )
        return CreateUploadBoxResponse(box_id=box_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create upload box: {exc}",
        ) from exc


@router.patch(
    "/boxes/{box_id}",
    summary="Update upload box",
    tags=["UploadOrchestrationService"],
    response_model=ResearchDataUploadBox,
)
@TRACER.start_as_current_span("routes.update_upload_box")
async def update_upload_box(
    box_id: UUID,
    request: UpdateUploadBoxRequest,
    upload_service: UploadOrchestrator = Depends(get_upload_service),
    auth_context: AuthContextProtocol = Depends(require_auth_context),
    correlation_id: UUID = Depends(get_correlation_id),
):
    """Update an upload box."""
    user_id = auth_context.id
    is_data_steward = check_data_steward_role(auth_context)

    # Check permissions based on the type of update
    if request.state is not None:
        # State changes have specific permission rules
        try:
            current_box = await upload_service.get_upload_box(box_id)

            # Users can only do OPEN -> LOCKED transition
            # Data Stewards can do any transition
            if not is_data_steward:
                if not (
                    current_box.state.value == "open"
                    and request.state.value == "locked"
                ):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Only Data Stewards can perform this state transition",
                    )

                # Check if user has access to this box
                accessible_boxes = (
                    await upload_service._claims_client.get_accessible_upload_boxes(
                        user_id
                    )
                )
                if box_id not in accessible_boxes:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this upload box",
                    )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to check permissions: {exc}",
            ) from exc
    elif not is_data_steward:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Data Steward role required to update upload box details",
        )

    try:
        updated_box = await upload_service.update_upload_box(
            box_id=box_id,
            request=request,
            user_id=user_id,
        )
        return updated_box
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update upload box: {exc}",
        ) from exc


@router.post(
    "/access-grant",
    summary="Grant upload access",
    tags=["UploadOrchestrationService"],
    status_code=status.HTTP_201_CREATED,
)
@TRACER.start_as_current_span("routes.grant_upload_access")
async def grant_upload_access(
    request: GrantAccessRequest,
    upload_service: UploadOrchestrator = Depends(get_upload_service),
    auth_context: AuthContextProtocol = Depends(require_auth_context),
    correlation_id: UUID = Depends(get_correlation_id),
):
    """Grant upload access to a user. Requires Data Steward role."""
    # Check if user has Data Steward role
    if not check_data_steward_role(auth_context):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Data Steward role required to grant upload access",
        )

    try:
        await upload_service.grant_upload_access(
            request=request,
            granting_user_id=auth_context.id,
        )
        return {"message": "Upload access granted successfully"}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to grant upload access: {exc}",
        ) from exc


@router.get(
    "/boxes/{box_id}/uploads",
    summary="List files in upload box",
    tags=["UploadOrchestrationService"],
    response_model=list[str],
)
@TRACER.start_as_current_span("routes.list_upload_box_files")
async def list_upload_box_files(
    box_id: UUID,
    upload_service: UploadOrchestrator = Depends(get_upload_service),
    auth_context: AuthContextProtocol = Depends(require_auth_context),
):
    """List file IDs in an upload box."""
    user_id = auth_context.id
    is_data_steward = check_data_steward_role(auth_context)

    try:
        file_ids = await upload_service.get_upload_box_files(
            box_id=box_id,
            user_id=user_id,
            is_data_steward=is_data_steward,
        )
        return file_ids
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list upload box files: {exc}",
        ) from exc
