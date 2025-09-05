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

import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import UUID4

from uos.adapters.inbound.fastapi_.auth import UserAuthContext
from uos.adapters.inbound.fastapi_.dummies import UploadOrchestratorDummy
from uos.constants import TRACER
from uos.core.models import (
    CreateUploadBoxRequest,
    GrantAccessRequest,
    ResearchDataUploadBox,
    UpdateUploadBoxRequest,
)

log = logging.getLogger(__name__)

router = APIRouter()


def check_data_steward_role(auth_context: UserAuthContext) -> bool:
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
    "/boxes/{box_id}",
    summary="Get upload box details",
    tags=["UploadOrchestrationService"],
    response_model=ResearchDataUploadBox,
)
@TRACER.start_as_current_span("routes.get_research_data_upload_box")
async def get_research_data_upload_box(
    box_id: UUID,
    upload_service: UploadOrchestratorDummy,
    auth_context: UserAuthContext,
):
    """Get details of a specific upload box."""
    try:
        upload_box = await upload_service.get_research_data_upload_box(box_id=box_id)

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
    response_model=UUID4,
    status_code=status.HTTP_201_CREATED,
)
@TRACER.start_as_current_span("routes.create_research_data_upload_box")
async def create_research_data_upload_box(
    request: CreateUploadBoxRequest,
    upload_service: UploadOrchestratorDummy,
    auth_context: UserAuthContext,
) -> UUID4:
    """Create a new upload box. Requires Data Steward role."""
    # Check if user has Data Steward role
    if not check_data_steward_role(auth_context):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Data Steward role required to create upload boxes",
        )

    try:
        box_id = await upload_service.create_research_data_upload_box(
            request=request,
            user_id=UUID(auth_context.id),
        )
        return box_id
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create upload box: {exc}",
        ) from exc


@router.patch(
    "/boxes/{box_id}",
    summary="Update upload box",
    tags=["UploadOrchestrationService"],
    response_model=None,
    status_code=status.HTTP_204_NO_CONTENT,
)
@TRACER.start_as_current_span("routes.update_research_data_upload_box")
async def update_research_data_upload_box(
    box_id: UUID,
    request: UpdateUploadBoxRequest,
    upload_service: UploadOrchestratorDummy,
    auth_context: UserAuthContext,
) -> None:
    """Update a ResearchDataUploadBox."""
    try:
        await upload_service.update_research_data_upload_box(
            box_id=box_id, request=request, auth_context=auth_context
        )
    except upload_service.BoxAccessError as err:
        raise NotImplementedError()  # TODO: 403
    except upload_service.BoxNotFoundError as err:
        raise NotImplementedError()  # TODO: 404
    except Exception as err:
        log.error(err, exc_info=True)
        raise NotImplementedError()  # TODO: 500 + log


@router.post(
    "/access-grant",
    summary="Grant upload access",
    tags=["UploadOrchestrationService"],
    status_code=status.HTTP_201_CREATED,
)
@TRACER.start_as_current_span("routes.grant_upload_access")
async def grant_upload_access(
    request: GrantAccessRequest,
    upload_service: UploadOrchestratorDummy,
    auth_context: UserAuthContext,
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
            granting_user_id=UUID(auth_context.id),
        )
        return {"message": "Upload access granted successfully"}
    except Exception as exc:
        log.error(exc, exc_info=True)
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
    upload_service: UploadOrchestratorDummy,
    auth_context: UserAuthContext,
):
    """List file IDs in an upload box."""
    try:
        file_ids = await upload_service.get_upload_box_files(
            box_id=box_id,
            auth_context=auth_context,
        )
        return file_ids
    except upload_service.BoxAccessError as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN) from err
    except upload_service.BoxNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from err
    except Exception as err:
        log.error(err, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR) from err
