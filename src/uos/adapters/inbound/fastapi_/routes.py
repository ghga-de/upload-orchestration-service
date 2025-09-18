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
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, status
from pydantic import UUID4, NonNegativeInt

from uos.adapters.inbound.fastapi_.auth import StewardAuthContext, UserAuthContext
from uos.adapters.inbound.fastapi_.dummies import UploadOrchestratorDummy
from uos.adapters.inbound.fastapi_.http_exceptions import (
    HttpBoxNotFoundError,
    HttpGrantNotFoundError,
    HttpInternalError,
    HttpNotAuthorizedError,
    HttpPaginationError,
)
from uos.constants import TRACER
from uos.core.models import (
    BoxRetrievalResults,
    CreateUploadBoxRequest,
    GrantAccessRequest,
    GrantWithBoxInfo,
    ResearchDataUploadBox,
    UpdateUploadBoxRequest,
)
from uos.ports.inbound.orchestrator import UploadOrchestratorPort

log = logging.getLogger(__name__)

router = APIRouter()

TAGS: list[str | Enum] = ["UploadOrchestrationService"]
# TODO: fill in possible response codes


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
    "/boxes",
    summary="List upload boxes",
    description="Returns a list of research data upload boxes. Results are sorted alphabetically by title.",
    tags=TAGS,
    response_model=BoxRetrievalResults,
)
@TRACER.start_as_current_span("routes.get_research_data_upload_boxes")
async def get_research_data_upload_boxes(
    upload_service: UploadOrchestratorDummy,
    auth_context: UserAuthContext,
    skip: Annotated[
        NonNegativeInt | None,
        Query(
            description="Number of research data upload boxes to skip for pagination",
        ),
    ] = None,
    limit: Annotated[
        NonNegativeInt | None,
        Query(
            description="Maximum number of research data upload boxes to return",
        ),
    ] = None,
) -> BoxRetrievalResults:
    """Get list of all research data upload boxes with pagination support."""
    if skip and limit and (skip >= limit):
        raise HttpPaginationError(
            message="Skip must be less than limit",
            skip=skip,
            limit=limit,
        )

    try:
        results = await upload_service.get_research_data_upload_boxes(
            auth_context=auth_context,
            skip=skip,
            limit=limit,
        )
        return results
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to get upload boxes") from err


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
    """Get details of a specific upload box. If the user doesn't have access to an
    existing box, this endpoint will return a 404.
    """
    try:
        user_id = UUID(auth_context.id)
        box = await upload_service.get_research_data_upload_box(
            box_id=box_id, user_id=user_id
        )
        return box
    except UploadOrchestratorPort.BoxAccessError as err:
        raise HttpBoxNotFoundError(box_id=box_id) from err
    except UploadOrchestratorPort.BoxNotFoundError as err:
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
    auth_context: StewardAuthContext,
) -> UUID4:
    """Create a new upload box. Requires Data Steward role."""
    try:
        box_id = await upload_service.create_research_data_upload_box(
            title=request.title,
            description=request.description,
            storage_alias=request.storage_alias,
            user_id=UUID(auth_context.id),
        )
        return box_id
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to create upload box") from err


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
    except UploadOrchestratorPort.BoxAccessError as err:
        raise HttpNotAuthorizedError() from err
    except UploadOrchestratorPort.BoxNotFoundError as err:
        raise HttpBoxNotFoundError(box_id=box_id) from err
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to update upload box") from err


@router.post(
    "/access-grants",
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
    auth_context: StewardAuthContext,
):
    """Grant upload access to a user. Requires Data Steward role."""
    try:
        await upload_service.grant_upload_access(
            user_id=request.user_id,
            iva_id=request.iva_id,
            box_id=request.box_id,
            validity=request.validity,
            granting_user_id=UUID(auth_context.id),
        )
        return {"message": "Upload access granted successfully"}
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to grant upload access") from err


@router.delete(
    "/access-grants/{grant_id}",
    summary="Revoke an upload access grant",
    description="Revokes an existing upload access grant.",
    responses={
        204: {
            "description": "Upload access grant has been revoked.",
        },
        404: {"description": "The upload access grant was not found."},
    },
    status_code=204,
)
@TRACER.start_as_current_span("routes.revoke_upload_access_grant")
async def revoke_upload_access_grant(
    grant_id: UUID4,
    upload_service: UploadOrchestratorDummy,
    auth_context: StewardAuthContext,
) -> None:
    """Revoke an upload access grant."""
    try:
        await upload_service.revoke_upload_access_grant(grant_id)
    except UploadOrchestratorPort.GrantNotFoundError as err:
        raise HttpGrantNotFoundError(grant_id=grant_id) from err
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to revoke access grant") from err


@router.get(
    "/access-grants",
    tags=TAGS,
    summary="Get upload access grants",
    description="Endpoint to get the list of all upload access grants. Can be filtered by user ID, IVA ID, and box ID.",
    responses={
        200: {
            "model": list[GrantWithBoxInfo],
            "description": "Upload access grants have been fetched.",
        },
    },
    status_code=200,
)
@TRACER.start_as_current_span("routes.get_upload_access_grants")
async def get_upload_access_grants(  # noqa: PLR0913
    upload_service: UploadOrchestratorDummy,
    auth_context: StewardAuthContext,
    user_id: Annotated[
        UUID4 | None,
        Query(
            ...,
            alias="user_id",
            description="The internal ID of the user",
        ),
    ] = None,
    iva_id: Annotated[
        UUID4 | None,
        Query(
            ...,
            alias="iva_id",
            description="The ID of the IVA",
        ),
    ] = None,
    box_id: Annotated[
        UUID4 | None,
        Query(
            ...,
            alias="box_id",
            description="The ID of the upload box",
        ),
    ] = None,
    valid: Annotated[
        bool | None,
        Query(
            ...,
            alias="valid",
            description="Whether the grant is currently valid",
        ),
    ] = None,
) -> list[GrantWithBoxInfo]:
    """Get upload access grants.

    You can filter the grants by user ID, IVA ID, and box ID
    and by whether the grant is currently valid or not.
    """
    try:
        return await upload_service.get_upload_access_grants(
            user_id=user_id, iva_id=iva_id, box_id=box_id, valid=valid
        )
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to get upload access grants") from err


@router.get(
    "/boxes/{box_id}/uploads",
    summary="List files in upload box",
    description="List the file IDs of all files uploaded for a research data upload box.",
    tags=TAGS,
    response_model=list[UUID4],
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
    except UploadOrchestratorPort.BoxAccessError as err:
        raise HttpNotAuthorizedError() from err
    except UploadOrchestratorPort.BoxNotFoundError as err:
        raise HttpBoxNotFoundError(box_id=box_id) from err
    except Exception as err:
        log.error(err, exc_info=True)
        raise HttpInternalError(message="Failed to list upload box files") from err
