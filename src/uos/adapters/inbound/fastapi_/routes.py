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
from enum import Enum
from uuid import UUID

from fastapi import APIRouter, status
from pydantic import UUID4

from uos.adapters.inbound.fastapi_.auth import UserAuthContext
from uos.adapters.inbound.fastapi_.dummies import UploadOrchestratorDummy
from uos.adapters.inbound.fastapi_.http_exceptions import (
    HttpBoxNotFoundError,
    HttpInternalError,
    HttpNotAuthorizedError,
)
from uos.constants import TRACER
from uos.core.models import (
    CreateUploadBoxRequest,
    GrantAccessRequest,
    ResearchDataUploadBox,
    UpdateUploadBoxRequest,
)

log = logging.getLogger(__name__)

router = APIRouter()

TAGS: list[str | Enum] = ["UploadOrchestrationService"]
# TODO: fill in possible response codes (but don't define all the text like in UCS)


def check_data_steward_role(auth_context: UserAuthContext) -> bool:
    """Check if the user has Data Steward role."""
    return "data_steward" in auth_context.roles


@router.get(
    "/health",
    summary="health",
    tags=TAGS,
    status_code=200,
)
@TRACER.start_as_current_span("routes.health")
async def health():
    """Used to test if this service is alive"""
    return {"status": "OK"}


@router.get(
    "/boxes/{box_id}",
    summary="Get upload box details",
    description="Returns the details of an existing research data upload box.",
    tags=TAGS,
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
        user_id = UUID(auth_context.id)
        await upload_service.get_research_data_upload_box(
            box_id=box_id, user_id=user_id
        )
    except upload_service.BoxAccessError as err:
        raise HttpNotAuthorizedError() from err
    except upload_service.BoxNotFoundError as err:
        raise HttpBoxNotFoundError(box_id=box_id) from err
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to get upload box") from err


@router.post(
    "/boxes",
    summary="Create upload box",
    description="Create a new research data upload box to label and track related file"
    + " uploads for a given user.",
    tags=TAGS,
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
        raise HttpNotAuthorizedError()

    try:
        box_id = await upload_service.create_research_data_upload_box(
            title=request.title,
            description=request.description,
            storage_alias=request.storage_alias,
            user_id=UUID(auth_context.id),
        )
        return box_id
    except Exception as exc:
        raise HttpInternalError(message="Failed to create upload box") from exc


@router.patch(
    "/boxes/{box_id}",
    summary="Update upload box",
    description="Update modifiable details for a research data upload box, including"
    + " the description, title, and state. When modifying the state, users are only"
    + " allowed to move the state from OPEN to LOCKED, and all other changes are"
    + " restricted to Data Stewards.",
    tags=TAGS,
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
        raise HttpNotAuthorizedError() from err
    except upload_service.BoxNotFoundError as err:
        raise HttpBoxNotFoundError(box_id=box_id) from err
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to update upload box") from err


@router.post(
    "/access-grant",
    summary="Grant upload access",
    description="Grant upload access to a user for a single research data upload box."
    + " Users cannot upload any files until they have been granted access to a box.",
    tags=TAGS,
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
        raise HttpNotAuthorizedError()

    try:
        await upload_service.grant_upload_access(
            request=request,
            granting_user_id=UUID(auth_context.id),
        )
        return {"message": "Upload access granted successfully"}
    except Exception as exc:
        log.error(exc, exc_info=True)
        raise HttpInternalError(message="Failed to grant upload access") from exc


@router.get(
    "/boxes/{box_id}/uploads",
    summary="List files in upload box",
    description="List the file IDs of all files uploaded for a research data upload box.",
    tags=TAGS,
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
        raise HttpNotAuthorizedError() from err
    except upload_service.BoxNotFoundError as err:
        raise HttpBoxNotFoundError(box_id=box_id) from err
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to list upload box files") from err
