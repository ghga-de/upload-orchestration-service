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

"""Business logic service for the Upload Orchestration Service."""

import logging
from collections.abc import Sequence
from uuid import UUID

from ghga_service_commons.auth.ghga import AuthContext
from hexkit.protocols.dao import NoHitsFoundError, ResourceNotFoundError
from hexkit.utils import now_utc_ms_prec
from pydantic import UUID4

from uos.core.models import (
    CreateUploadBoxRequest,
    FileUploadBox,
    GrantAccessRequest,
    ResearchDataUploadBox,
    ResearchDataUploadBoxState,
    UpdateUploadBoxRequest,
)
from uos.ports.inbound.orchestrator import UploadOrchestratorPort
from uos.ports.outbound.audit import AuditRepositoryPort
from uos.ports.outbound.dao import BoxDao
from uos.ports.outbound.http import AccessClientPort, UCSClientPort

log = logging.getLogger(__name__)

__all__ = ["UploadOrchestrator"]


class UploadOrchestrator(UploadOrchestratorPort):
    """A class for orchestrating upload operations."""

    def __init__(
        self,
        *,
        box_dao: BoxDao,
        audit_repository: AuditRepositoryPort,
        ucs_client: UCSClientPort,
        claims_client: AccessClientPort,
    ):
        self._box_dao = box_dao
        self._audit_repository = audit_repository
        self._ucs_client = ucs_client
        self._access_client = claims_client

    async def create_research_data_upload_box(
        self,
        request: CreateUploadBoxRequest,
        user_id: UUID4,
    ) -> UUID4:
        """Create a new research data upload box.

        This operation:
        1. Creates a FileUploadBox in the UCS
        2. Creates a ResearchDataUploadBox locally
        3. Emits events and audit records

        Returns:
            The UUID of the newly created upload box

        Raises:
            UCSCallError: if there's a problem creating a corresponding box in the UCS.
        """
        # Create FileUploadBox in UCS
        file_upload_box_id = await self._ucs_client.create_file_upload_box(
            storage_alias=request.storage_alias
        )

        # Create ResearchDataUploadBox
        box = ResearchDataUploadBox(
            state=ResearchDataUploadBoxState.OPEN,
            title=request.title,
            description=request.description,
            last_changed=now_utc_ms_prec(),
            changed_by=user_id,
            file_upload_box_id=file_upload_box_id,
            storage_alias=request.storage_alias,
        )

        # Store in repository & create audit record
        await self._box_dao.insert(box)
        await self._audit_repository.log_box_created(box=box, user_id=user_id)
        return box.id

    async def update_research_data_upload_box(
        self,
        box_id: UUID4,
        request: UpdateUploadBoxRequest,
        auth_context: AuthContext,
    ) -> None:
        """Update a research data upload box.

        Raises:
            BoxNotFoundError: If the box doesn't exist.
            UCSCallError: if there's a problem updating the corresponding box in the UCS.
        """
        # Get existing box if user has access to it
        user_id = UUID(auth_context.id)
        box = await self.get_research_data_upload_box(box_id=box_id, user_id=user_id)
        updated_box = box.model_copy(update=request.model_dump())
        changed_fields = {
            k: v for k, v in request.model_dump().items() if getattr(box, k) != v
        }

        # If not a data steward, the only acceptable update is to move from OPEN to LOCKED
        is_data_steward = "data_steward" in auth_context.roles
        if not is_data_steward and not (
            changed_fields == {"state": "locked"}
            and box.state == ResearchDataUploadBoxState.OPEN
        ):
            raise self.BoxAccessError("Unauthorized")

        # If locking or unlocking, communicate with UCS (errors handled in ucs_client)
        if (
            updated_box.state != box.state
            and box.state == ResearchDataUploadBoxState.OPEN
        ):
            await self._ucs_client.lock_file_upload_box(box_id=box.file_upload_box_id)
            updated_box.locked = True
        elif (
            updated_box.state == ResearchDataUploadBoxState.OPEN
            and updated_box.state != box.state
        ):
            await self._ucs_client.unlock_file_upload_box(box_id=box.file_upload_box_id)
            updated_box.locked = False

        # Update the research data upload box in the DB
        updated_box.last_changed = now_utc_ms_prec()
        updated_box.changed_by = user_id
        await self._box_dao.update(updated_box)

        # Create audit record
        await self._audit_repository.log_box_updated(box=updated_box, user_id=user_id)

    async def grant_upload_access(
        self,
        request: GrantAccessRequest,
        granting_user_id: UUID4,
    ) -> None:
        """Grant upload access to a user for a specific upload box.

        Raises:
            BoxNotFoundError: If the box doesn't exist.
        """
        # Verify the upload box exists
        await self._box_dao.get_by_id(request.box_id)

        # Grant access via Claims Repository Service (errors handled by access client)
        await self._access_client.grant_upload_access(
            user_id=request.user_id,
            iva_id=request.iva_id,
            box_id=request.box_id,
        )
        # TODO: Create audit record?

    async def get_upload_box_files(
        self,
        box_id: UUID4,
        auth_context: AuthContext,
    ) -> Sequence[UUID4]:
        """Get list of file IDs for an upload box.

        Returns:
            Sequence of file IDs in the upload box

        Raises:
            BoxNotFoundError: If the box doesn't exist.
            BoxAccessError: If the user doesn't have access to the box.
            UCSCallError: if there's a problem querying the UCS.
        """
        # Verify access
        upload_box = await self._box_dao.get_by_id(box_id)

        is_data_steward = "data_steward" in auth_context.roles
        user_id = UUID(auth_context.id)

        if not is_data_steward:
            # Check if user has access to this box
            accessible_boxes = await self._access_client.get_accessible_upload_boxes(
                user_id
            )
            if box_id not in accessible_boxes:
                raise self.BoxAccessError(
                    f"User {user_id} does not have access to upload box {box_id}"
                )

        # Get file list from UCS
        file_ids = await self._ucs_client.get_file_upload_list(
            box_id=upload_box.file_upload_box_id,
        )
        return file_ids

    async def upsert_file_upload_box(self, file_upload_box: FileUploadBox) -> None:
        """Handle FileUploadBox update events from UCS.

        Updates the corresponding ResearchDataUploadBox with latest file count and size.
        """
        try:
            research_data_upload_box = await self._box_dao.find_one(
                mapping={"file_upload_box_id": file_upload_box.id}
            )
            # Get the fields that matter (ID and storage alias don't change)
            new = {
                "locked": file_upload_box.locked,
                "file_count": file_upload_box.file_count,
                "size": file_upload_box.size,
            }
            updated_model = research_data_upload_box.model_copy(update=new)

            # Conditionally update data
            if updated_model.model_dump() != research_data_upload_box.model_dump():
                await self._box_dao.update(research_data_upload_box)
        except NoHitsFoundError:
            # This might happen during initial creation - ignore
            log.info(
                "Did not find a matching ResearchDataUploadBox for inbound"
                + " FileUploadBox with ID %s. Was it just created?",
                file_upload_box.id,
            )

    async def get_research_data_upload_box(
        self, *, box_id: UUID4, user_id: UUID4
    ) -> ResearchDataUploadBox:
        """Retrieve a Research Data Upload Box by ID

        Raises:
            BoxAccessError: If the user doesn't have access to the box
            BoxNotFoundError: If the box doesn't exist
        """
        # Check that the user has access to this box (if nonexistent, show unauthorized)
        has_access = await self._access_client.check_box_access(
            box_id=box_id, user_id=user_id
        )

        if not has_access:
            log.error(
                "User ID %s does not have access to ResearchDataUploadBox with"
                + " ID %s OR it does not exist.",
                user_id,
                box_id,
            )
            raise self.BoxAccessError("Unauthorized")

        # Return the box if it exists
        try:
            return await self._box_dao.get_by_id(box_id)
        except ResourceNotFoundError as err:
            raise self.BoxNotFoundError(box_id=box_id) from err
