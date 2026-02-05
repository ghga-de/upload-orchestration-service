# Copyright 2021 - 2026 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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
from uuid import UUID

from ghga_service_commons.auth.ghga import AuthContext
from ghga_service_commons.utils.utc_dates import UTCDatetime
from hexkit.protocols.dao import (
    NoHitsFoundError,
    ResourceNotFoundError,
    UniqueConstraintViolationError,
)
from hexkit.utils import now_utc_ms_prec
from pydantic import UUID4

from uos.core.models import (
    AccessionMap,
    BoxRetrievalResults,
    FileUploadBox,
    FileUploadWithAccession,
    GrantWithBoxInfo,
    ResearchDataUploadBox,
    UpdateUploadBoxRequest,
    UploadBoxState,
)
from uos.ports.inbound.orchestrator import UploadOrchestratorPort
from uos.ports.outbound.audit import AuditRepositoryPort
from uos.ports.outbound.dao import AccessionMapDao, BoxDao
from uos.ports.outbound.http import AccessClientPort, FileBoxClientPort

log = logging.getLogger(__name__)

__all__ = ["UploadOrchestrator"]


def is_data_steward(auth_context: AuthContext) -> bool:
    """Returns a bool indicating if the auth context is for a Data Steward"""
    return "data_steward" in auth_context.roles


class UploadOrchestrator(UploadOrchestratorPort):
    """A class for orchestrating upload operations."""

    def __init__(
        self,
        *,
        box_dao: BoxDao,
        accession_map_dao: AccessionMapDao,
        audit_repository: AuditRepositoryPort,
        file_upload_box_client: FileBoxClientPort,
        access_client: AccessClientPort,
    ):
        self._box_dao = box_dao
        self._accession_map_dao = accession_map_dao
        self._audit_repository = audit_repository
        self._file_upload_box_client = file_upload_box_client
        self._access_client = access_client

    async def create_research_data_upload_box(
        self,
        *,
        title: str,
        description: str,
        storage_alias: str,
        data_steward_id: UUID4,
    ) -> UUID4:
        """Create a new research data upload box.

        This operation:
        1. Creates a FileUploadBox in the service that owns them
        2. Creates a ResearchDataUploadBox locally
        3. Emits events and audit records

        Returns:
            The UUID of the newly created research data upload box

        Raises:
            OperationError: If there's a problem creating a corresponding FileUploadBox.
        """
        # Create FileUploadBox in external service
        file_upload_box_id = await self._file_upload_box_client.create_file_upload_box(
            storage_alias=storage_alias
        )

        # Create ResearchDataUploadBox
        box = ResearchDataUploadBox(
            version=0,
            state="open",
            title=title,
            description=description,
            last_changed=now_utc_ms_prec(),
            changed_by=data_steward_id,
            file_upload_box_id=file_upload_box_id,
            file_upload_box_version=0,
            file_upload_box_state="open",
            storage_alias=storage_alias,
        )

        # Store in repository & create audit record
        await self._box_dao.insert(box)
        await self._audit_repository.log_box_created(box=box, user_id=data_steward_id)
        return box.id

    async def update_research_data_upload_box(
        self,
        *,
        box_id: UUID4,
        request: UpdateUploadBoxRequest,
        auth_context: AuthContext,
    ) -> None:
        """Update a research data upload box.

        Raises:
            BoxNotFoundError: If the research data upload box doesn't exist.
            BoxAccessError: If the user doesn't have access to the research data upload box.
            OperationError: If there's a problem updating the corresponding FileUploadBox.
        """
        # Get existing box if user has access to it
        box = await self.get_research_data_upload_box(
            box_id=box_id, auth_context=auth_context
        )
        changed_fields = {
            k: v for k, v in request.model_dump().items() if v and getattr(box, k) != v
        }
        if not changed_fields:
            log.info(
                "RDUB update request for box %s did not contain any changes.", box_id
            )
            return

        updated_box = box.model_copy(update=changed_fields)

        # If not a data steward, the only acceptable update is to move from OPEN to LOCKED
        is_ds = is_data_steward(auth_context)
        if not is_ds and not (
            changed_fields == {"state": "locked"} and box.state == "open"
        ):
            raise self.BoxAccessError("Unauthorized")

        # Update the research data upload box in the DB
        user_id = UUID(auth_context.id)
        updated_box.changed_by = user_id
        updated_box.last_changed = now_utc_ms_prec()
        updated_box.version += 1

        # If locking or unlocking, communicate with service that owns file upload boxes
        #  (errors handled in file_upload_box_client)
        if box.state == "open" and updated_box.state == "locked":
            updated_box.file_upload_box_state = "locked"
            await self._box_dao.update(updated_box)
            try:
                await self._file_upload_box_client.lock_file_upload_box(
                    box_id=box.file_upload_box_id
                )
            except Exception:
                log.warning(
                    "Failed to update FUB %s, rolling back changed for RDUB %s",
                    box.file_upload_box_id,
                    box_id,
                )
                await self._box_dao.update(box)
                raise
        elif box.state == "locked" and updated_box.state == "open":
            updated_box.file_upload_box_state = "open"
            await self._box_dao.update(updated_box)
            try:
                await self._file_upload_box_client.unlock_file_upload_box(
                    box_id=box.file_upload_box_id
                )
            except Exception:
                log.warning(
                    "Failed to update FUB %s, rolling back changed for RDUB %s",
                    box.file_upload_box_id,
                    box_id,
                )
                await self._box_dao.update(box)
                raise
        else:
            await self._box_dao.update(updated_box)

        # Create audit record
        await self._audit_repository.log_box_updated(box=updated_box, user_id=user_id)

    async def archive_research_data_upload_box(
        self,
        *,
        box_id: UUID4,
        version: int,
        data_steward_id: UUID4,
    ) -> None:
        """Archive a research data upload box.

        Raises:
            BoxNotFoundError: If the research data upload box doesn't exist.
            OutdatedInfoError: If the box version differs from `version`.
            ArchivalPrereqsError: If there are any files in the box that don't yet have
                an accession assigned OR if the box is still in the 'open' state.
            OperationError: If there's a problem querying the file box service.
        """
        # Get RDUB
        try:
            box = await self._box_dao.get_by_id(box_id)
        except ResourceNotFoundError as err:
            raise self.BoxNotFoundError(box_id=box_id) from err

        # Return early (with a log) if the box has already been archived
        if box.state == "archived":
            log.warning(
                "RDUB %s has already been archived.",
                box_id,
                extra={"box_id": box_id, "version": version},
            )
            return

        # Make sure the request is not based on outdated info
        if box.version != version:
            log.error(
                "Can't archive RDUB %s because the request is outdated.",
                box_id,
                extra={
                    "box_id": box_id,
                    "box_version": box.version,
                    "request_version": version,
                },
            )
            raise self.OutdatedInfoError(
                f"Research Data Upload Box {box_id} has changed"
            )

        # Make sure the box is locked
        if box.state != "locked":
            log.error(
                "Can't archive RDUB %s because it's still open.",
                box_id,
                extra={"box_id": box_id, "version": version},
            )
            raise self.ArchivalPrereqsError("Box must be locked before archival.")

        try:
            db_map = await self._accession_map_dao.get_by_id(box_id)
        except ResourceNotFoundError as err:
            log.error(
                "Can't archive RDUB %s because no accession map could be found.",
                box_id,
                extra={"box_id": box_id, "version": version},
            )
            raise self.ArchivalPrereqsError(
                "Accessions have not been assigned"
            ) from err

        # Get files list from File Box API
        files = await self._file_upload_box_client.get_file_upload_list(
            box_id=box.file_upload_box_id
        )

        # Make sure all files have an accession number
        file_ids_in_box = set(f.id for f in files)
        file_ids_in_map = set(mapping.file_id for mapping in db_map.mappings)
        unassigned_files = file_ids_in_box - file_ids_in_map

        if unassigned_files:
            log.error(
                "Can't archive RDUB %s because not all files have been assigned an accession.",
                box_id,
                extra={
                    "box_id": box_id,
                    "version": version,
                    "file_ids": unassigned_files,
                },
            )
            raise self.ArchivalPrereqsError(
                f"The following files are missing an accession: {unassigned_files}"
            )

        # Trigger the FileUploadBox archival
        try:
            await self._file_upload_box_client.archive_file_upload_box(
                box_id=box.file_upload_box_id, version=box.file_upload_box_version
            )
        except FileBoxClientPort.VersionError as version_err:
            log.error(
                "Can't archive RDUB %s because the associated FileUploadBox version has changed.",
                box_id,
                extra={
                    "box_id": box_id,
                    "file_upload_box_version": box.file_upload_box_version,
                },
            )
            raise self.OutdatedInfoError(
                f"File Upload Box {box.file_upload_box_id} has changed."
            ) from version_err

        # Update box attributes
        box.version += 1
        box.state = "archived"
        box.last_changed = now_utc_ms_prec()
        box.changed_by = data_steward_id
        box.file_upload_box_version += 1
        box.file_upload_box_state = "archived"
        await self._box_dao.update(box)

        # Publish audit event
        await self._audit_repository.log_box_updated(box=box, user_id=data_steward_id)

    async def grant_upload_access(  # noqa: PLR0913
        self,
        *,
        user_id: UUID4,
        iva_id: UUID4,
        box_id: UUID4,
        valid_from: UTCDatetime,
        valid_until: UTCDatetime,
        granting_user_id: UUID4,
    ) -> None:
        """Grant upload access to a user for a specific research data upload box.

        Raises:
            AccessAPIError: if there's a problem communicating with the access API.
            BoxNotFoundError: If the box doesn't exist.
        """
        # TODO: Should we block access to archived boxes, or let that be handled IRL?
        # Verify the upload box exists
        await self._box_dao.get_by_id(box_id)

        # Grant access via Claims Repository Service (errors handled by access client)
        await self._access_client.grant_upload_access(
            user_id=user_id,
            iva_id=iva_id,
            box_id=box_id,
            valid_from=valid_from,
            valid_until=valid_until,
        )
        await self._audit_repository.log_access_granted(
            box_id=box_id, grantor_id=granting_user_id, grantee_id=user_id
        )
        log.info(
            "Access grant operation successful for user %s and box %s", user_id, box_id
        )

    async def revoke_upload_access_grant(self, grant_id: UUID4) -> None:
        """Revoke a user's access to an upload box.

        Raises:
            GrantNotFoundError: if the grant wasn't found in the access API.
            AccessAPIError: if there's a problem communicating with the access API.
        """
        try:
            await self._access_client.revoke_upload_access(grant_id=grant_id)
        except AccessClientPort.GrantNotFoundError as err:
            raise self.GrantNotFoundError(grant_id=grant_id) from err

    async def get_upload_access_grants(
        self,
        *,
        user_id: UUID4 | None = None,
        iva_id: UUID4 | None = None,
        box_id: UUID4 | None = None,
        valid: bool | None = None,
    ) -> list[GrantWithBoxInfo]:
        """Get a list of upload grants with the associated box titles and descriptions.
        Results are sorted by validity, user ID, IVA ID, box ID, and grant ID.

        Raises:
            AccessAPIError: If there's a problem communicating with the access API.
        """
        grants = await self._access_client.get_upload_access_grants(
            user_id=user_id,
            iva_id=iva_id,
            box_id=box_id,
            valid=valid,
        )

        grants_with_info: list[GrantWithBoxInfo] = []
        for grant in grants:
            try:
                box = await self._box_dao.get_by_id(grant.box_id)
                grant_with_info = GrantWithBoxInfo(
                    **grant.model_dump(),
                    box_title=box.title,
                    box_description=box.description,
                )
                grants_with_info.append(grant_with_info)
            except ResourceNotFoundError:
                log.warning(
                    "Access grant %s has a box ID (%s) that doesn't exist in UOS.",
                    grant.id,
                    grant.box_id,
                    extra={
                        "grant_id": grant.id,
                        "user_id": user_id,
                        "iva_id": iva_id,
                        "box_id": box_id,
                        "valid": valid,
                    },
                )
                continue

        # Sort grants for predictability
        return sorted(
            grants_with_info,
            key=lambda x: (
                -x.valid_until.timestamp(),  # DESC valid_until, rest is ASC
                x.user_id,
                x.iva_id,
                x.box_id,
                x.id,
            ),
        )

    async def get_upload_box_files(
        self,
        *,
        box_id: UUID4,
        auth_context: AuthContext,
    ) -> list[FileUploadWithAccession]:
        """Get list of file uploads for a research data upload box.

        Returns a list of file uploads in the upload box.

        Raises:
            BoxNotFoundError: If the box doesn't exist.
            BoxAccessError: If the user doesn't have access to the box.
            OperationError: If there's a problem querying the file box service.
            AccessAPIError: If there's a problem querying the access api
        """
        # Verify access
        upload_box = await self.get_research_data_upload_box(
            box_id=box_id, auth_context=auth_context
        )

        # Get file list from file box service
        file_uploads = await self._file_upload_box_client.get_file_upload_list(
            box_id=upload_box.file_upload_box_id,
        )

        # Get accessions from database
        try:
            accessions = await self._accession_map_dao.get_by_id(box_id)
        except ResourceNotFoundError:
            log.warning("No accession map found for box ID %s", box_id)
        else:
            acc_dict = {item.file_id: item.accession for item in accessions.mappings}
            for i in range(len(file_uploads)):
                file_id = file_uploads[i].id
                if file_id in acc_dict:
                    file_uploads[i].accession = acc_dict.get(file_id)

        # Sort files by alias for predictability
        return sorted(file_uploads, key=lambda x: x.alias)

    async def upsert_file_upload_box(self, file_upload_box: FileUploadBox) -> None:
        """Handle FileUploadBox update events from file box service.

        Updates the corresponding ResearchDataUploadBox with latest file count and size.
        """
        try:
            research_data_upload_box = await self._box_dao.find_one(
                mapping={"file_upload_box_id": file_upload_box.id}
            )
            # Get the fields that matter (ID and storage alias don't change)
            new = {
                "file_upload_box_version": file_upload_box.version,
                "file_upload_box_state": file_upload_box.state,
                "file_count": file_upload_box.file_count,
                "size": file_upload_box.size,
                "storage_alias": file_upload_box.storage_alias,
            }
            updated_model = research_data_upload_box.model_copy(update=new)

            # Conditionally update data
            if updated_model.model_dump() != research_data_upload_box.model_dump():
                updated_model.version += 1
                await self._box_dao.update(updated_model)
        except NoHitsFoundError:
            # This might happen during initial creation - ignore
            log.info(
                "Did not find a matching ResearchDataUploadBox for inbound"
                + " FileUploadBox with ID %s. Was it just created?",
                file_upload_box.id,
            )

    async def get_research_data_upload_box(
        self, *, box_id: UUID4, auth_context: AuthContext
    ) -> ResearchDataUploadBox:
        """Retrieve a Research Data Upload Box by ID.

        For regular users, the access api will be queried. For Data Stewards, this check
        is skipped.

        Raises:
            BoxAccessError: If the user doesn't have access to the box
            BoxNotFoundError: If the box doesn't exist
            AccessAPIError: If there's a problem querying the access api
        """
        # Check that the user has access to this box (if nonexistent, show unauthorized)
        is_ds = is_data_steward(auth_context)
        user_id = UUID(auth_context.id)
        has_access = (
            True
            if is_ds
            else (
                await self._access_client.check_box_access(
                    box_id=box_id, user_id=user_id
                )
            )
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

    async def get_research_data_upload_boxes(
        self,
        *,
        auth_context: AuthContext,
        skip: int | None = None,
        limit: int | None = None,
        state: UploadBoxState | None = None,
    ) -> BoxRetrievalResults:
        """Retrieve all Research Data Upload Boxes, optionally paginated.

        For data stewards, returns all boxes. For regular users, only returns boxes
        they have access to according to the Access API.

        Results are sorted first by state ("open" first), then by most
        recently changed, and then by box ID. Results can also be filtered to show boxes
        with a chosen state.

        Returns a BoxRetrievalResults instance with the boxes and unpaginated count.
        """
        if skip is not None and skip < 0:
            log.warning(
                "Received invalid arg %i for skip parameter, setting to None", skip
            )
            skip = None

        if limit is not None and limit < 0:
            log.warning(
                "Received invalid arg %i for limit parameter, setting to None", limit
            )
            limit = None

        # Check if user is a data steward
        is_ds = is_data_steward(auth_context)

        # Filter by state if specified
        mapping = {"state": state} if state is not None else {}

        if is_ds:
            # Data stewards can see all boxes
            boxes = [x async for x in self._box_dao.find_all(mapping=mapping)]
        else:
            # Regular users can only see boxes they have access to
            user_id = UUID(auth_context.id)
            accessible_box_ids = await self._access_client.get_accessible_upload_boxes(
                user_id=user_id
            )

            # Generally very few boxes per user, so make distinct call for each
            boxes = [
                await self._box_dao.get_by_id(box_id) for box_id in accessible_box_ids
            ]
            if state is not None:
                boxes = [x for x in boxes if x.state == state]

        count = len(boxes)
        boxes.sort(
            key=lambda x: (
                tuple(-ord(c) for c in x.state),  # Reverse alphabetical
                -x.last_changed.timestamp(),  # DESC by last_changed
                x.id,  # ASC by ID
            )
        )

        if skip:
            boxes = boxes[skip:]

        if limit:
            boxes = boxes[:limit]

        return BoxRetrievalResults(count=count, boxes=boxes)

    async def update_accession_map(self, *, accession_map: AccessionMap) -> None:
        """Update the file accession map for a given box.

        This method makes a call to the File Box API to get the latest list of
        files in that upload box. Then, it verifies that each file ID in the mapping
        exists in the retrieved list of files. Finally, it stores the mapping in the DB.

        **Files with a state of *cancelled* or *failed* are ignored.**

        Raises:
            BoxNotFoundError: If the box doesn't exist
            AccessionMapError: If the accession map includes a file ID that doesn't
                exist or if there are duplicate accessions.
        """
        # Make sure the box exists
        box_id = accession_map.box_id
        try:
            box = await self._box_dao.get_by_id(box_id)
        except ResourceNotFoundError as err:
            raise self.BoxNotFoundError(box_id=box_id) from err

        # Don't allow changes to archived boxes
        if box.state == "archived":
            log.error(
                "Cannot update accessions for RDUB %s because it is already archived",
                box_id,
            )
            raise self.AccessionMapError(
                "Data already archived - accessions cannot be modified."
            )

        # Check for duplicate accession numbers within this set before storing
        accessions = set(mapping.accession for mapping in accession_map.mappings)
        if len(accessions) < len(accession_map.mappings):
            raise self.AccessionMapError("Duplicate accessions detected in mapping")

        # Get files list from File Box API
        files = await self._file_upload_box_client.get_file_upload_list(
            box_id=box.file_upload_box_id
        )

        files = [f for f in files if f.state not in ("cancelled", "failed")]
        file_ids_in_box = set(f.id for f in files)
        file_ids_in_map = set(mapping.file_id for mapping in accession_map.mappings)
        invalid_ids = file_ids_in_map - file_ids_in_box

        if invalid_ids:
            raise self.AccessionMapError(
                "Invalid accession map. These file IDs are not in the box:"
                + f" {', '.join(map(str, invalid_ids))}"
            )

        try:
            await self._accession_map_dao.upsert(accession_map)
        except UniqueConstraintViolationError as err:
            error = self.AccessionMapError(
                "Failed to update accession mapping. At least one accession included"
                + " in the supplied mapping already exists in the database."
            )
            log.error(error, extra={"box_id": accession_map.box_id})
            raise error from err
