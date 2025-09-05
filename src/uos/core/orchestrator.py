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

from ghga_service_commons.utils.crypt import encrypt
from hexkit.protocols.dao import NoHitsFoundError
from hexkit.utils import now_utc_ms_prec
from jwcrypto import jwk
from pydantic import UUID4, Field, SecretStr
from pydantic_settings import BaseSettings

from uos.core.models import (
    ChangeFileBoxWorkOrder,
    CreateFileBoxWorkOrder,
    CreateUploadBoxRequest,
    FileUploadBox,
    GrantAccessRequest,
    ResearchDataUploadBox,
    ResearchDataUploadBoxState,
    UpdateUploadBoxRequest,
    ViewFileBoxWorkOrder,
)
from uos.core.tokens import sign_work_order_token
from uos.ports.inbound.orchestrator import UploadOrchestratorPort
from uos.ports.outbound.audit import AuditRepositoryPort
from uos.ports.outbound.dao import BoxDao
from uos.ports.outbound.http import ClaimsClientPort, UCSClientPort

log = logging.getLogger(__name__)

__all__ = ["UploadOrchestrator"]


class UploadOrchestratorConfig(BaseSettings):
    """Config parameters needed for the UploadOrchestrator."""

    work_order_signing_key: SecretStr = Field(
        ...,
        description="The private key for signing work order tokens",
        examples=['{"crv": "P-256", "kty": "EC", "x": "...", "y": "..."}'],
    )
    ucs_public_key: str = Field(
        ...,
        description="The public key used to encrypt work order tokens sent to the UCS",
        examples=[],  # TODO: fill in this and check the type-hint
    )


class UploadOrchestrator(UploadOrchestratorPort):
    """A class for orchestrating upload operations."""

    def __init__(
        self,
        *,
        config: UploadOrchestratorConfig,
        box_dao: BoxDao,
        audit_repository: AuditRepositoryPort,
        ucs_client: UCSClientPort,
        claims_client: ClaimsClientPort,
    ):
        self._signing_key = jwk.JWK.from_json(
            config.work_order_signing_key.get_secret_value()
        )
        if not self._signing_key.has_private:
            key_error = KeyError("No private work order signing key found.")
            log.error(key_error)
            raise key_error
        self._ucs_public_key = config.ucs_public_key
        self._box_dao = box_dao
        self._audit_repository = audit_repository
        self._ucs_client = ucs_client
        self._claims_client = claims_client

    async def create_upload_box(
        self,
        request: CreateUploadBoxRequest,
        user_id: UUID4,
    ) -> UUID4:
        """Create a new research data upload box.

        This operation:
        1. Creates a FileUploadBox in the UCS
        2. Creates a ResearchDataUploadBox locally
        3. Emits events and audit records
        """
        # Create FileUploadBox in UCS
        signed_wot = sign_work_order_token(CreateFileBoxWorkOrder(), self._signing_key)
        encrypted_wot = encrypt(signed_wot, self._ucs_public_key)
        file_upload_box_id = await self._ucs_client.create_file_upload_box(
            storage_alias=request.storage_alias,
            work_order=encrypted_wot,
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

    async def update_upload_box(
        self,
        box_id: UUID4,
        request: UpdateUploadBoxRequest,
        user_id: UUID4,
    ) -> ResearchDataUploadBox:
        """Update a research data upload box."""
        # Get existing box
        box = await self._box_dao.get_by_id(box_id)

        # Track changes for audit
        changes = []

        # Update fields if provided
        if request.title is not None:
            old_title = box.title
            box.title = request.title
            changes.append(f"title: '{old_title}' -> '{request.title}'")

        if request.description is not None:
            box.description = request.description
            changes.append("description updated")

        if request.state is not None:
            old_state = box.state
            box.state = request.state
            changes.append(f"state: {old_state} -> {request.state}")

            # If locking or unlocking, communicate with UCS
            if (
                request.state
                in [
                    ResearchDataUploadBoxState.LOCKED,
                    ResearchDataUploadBoxState.CLOSED,
                ]
                and old_state == ResearchDataUploadBoxState.OPEN
            ):
                wot = ChangeFileBoxWorkOrder(
                    work_type="lock",
                    box_id=box.file_upload_box_id,
                )
                signed_wot = sign_work_order_token(wot, self._signing_key)
                encrypted_wot = encrypt(signed_wot, self._ucs_public_key)
                await self._ucs_client.lock_file_upload_box(
                    box_id=box.file_upload_box_id,
                    work_order=encrypted_wot,
                )
                box.locked = True
            elif request.state == ResearchDataUploadBoxState.OPEN and old_state in [
                ResearchDataUploadBoxState.LOCKED,
                ResearchDataUploadBoxState.CLOSED,
            ]:
                # TODO: maybe put this and lock code into private methods to shorten this method
                wot = ChangeFileBoxWorkOrder(
                    work_type="unlock",
                    box_id=box.file_upload_box_id,
                )
                signed_wot = sign_work_order_token(wot, self._signing_key)
                encrypted_wot = encrypt(signed_wot, self._ucs_public_key)
                await self._ucs_client.unlock_file_upload_box(
                    box_id=box.file_upload_box_id,
                    work_order=encrypted_wot,
                )
                box.locked = False

        # Update metadata
        box.last_changed = now_utc_ms_prec()
        box.changed_by = user_id
        await self._box_dao.update(box)

        # Create audit record
        await self._audit_repository.log_box_updated(box=box, user_id=user_id)
        return box

    async def grant_upload_access(
        self,
        request: GrantAccessRequest,
        granting_user_id: str,
    ) -> None:
        """Grant upload access to a user for a specific upload box."""
        # Verify the upload box exists
        await self._box_dao.get_by_id(request.box_id)

        # Grant access via Claims Repository Service
        await self._claims_client.grant_upload_access(
            user_id=request.user_id,
            iva_id=request.iva_id,
            box_id=request.box_id,
        )
        # TODO: Create audit record?

    async def get_upload_box_files(
        self,
        box_id: UUID,
        user_id: str,
        is_data_steward: bool,
    ) -> Sequence[str]:
        """Get list of file IDs for an upload box."""
        # Verify access
        upload_box = await self._box_dao.get_by_id(box_id)

        if not is_data_steward:
            # Check if user has access to this box
            accessible_boxes = await self._claims_client.get_accessible_upload_boxes(
                user_id
            )
            if box_id not in accessible_boxes:
                raise PermissionError(
                    f"User {user_id} does not have access to upload box {box_id}"
                )

        # Get file list from UCS
        wot = ViewFileBoxWorkOrder(box_id=upload_box.file_upload_box_id)
        signed_wot = sign_work_order_token(wot, self._signing_key)
        encrypted_wot = encrypt(signed_wot, self._ucs_public_key)
        file_ids = await self._ucs_client.get_file_upload_list(
            box_id=upload_box.file_upload_box_id,
            work_order=encrypted_wot,
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
