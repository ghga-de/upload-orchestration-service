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

"""Port definition for the Upload Orchestrator."""

from abc import ABC, abstractmethod
from collections.abc import Sequence

from ghga_service_commons.auth.ghga import AuthContext
from pydantic import UUID4

from uos.core.models import (
    FileUploadBox,
    GrantAccessRequest,
    ResearchDataUploadBox,
    UpdateUploadBoxRequest,
)


class UploadOrchestratorPort(ABC):
    """Port for the Upload Orchestrator service."""

    class BoxAccessError(RuntimeError):
        """Raised when a ResearchDataUploadBox cannot be accessed."""

    class BoxNotFoundError(RuntimeError):
        """Raised when a ResearchDataUploadBox is not found in the DB."""

        def __init__(self, *, box_id: UUID4):
            msg = f"The ResearchDataUploadBox with ID {box_id} was not found in the DB."
            super().__init__(msg)

    @abstractmethod
    async def create_research_data_upload_box(
        self,
        title: str,
        description: str,
        storage_alias: str,
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
        ...

    @abstractmethod
    async def update_research_data_upload_box(
        self,
        box_id: UUID4,
        request: UpdateUploadBoxRequest,
        auth_context: AuthContext,
    ) -> None:
        """Update a research data upload box.

        Raises:
            BoxNotFoundError: If the box doesn't exist.
            BoxAccessError: If the user doesn't have access to the box.
            UCSCallError: if there's a problem updating the corresponding box in the UCS.
        """
        ...

    @abstractmethod
    async def grant_upload_access(
        self,
        request: GrantAccessRequest,
        granting_user_id: UUID4,
    ) -> None:
        """Grant upload access to a user for a specific upload box.

        Raises:
            BoxNotFoundError: If the box doesn't exist.
        """
        ...

    @abstractmethod
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
        ...

    @abstractmethod
    async def upsert_file_upload_box(self, file_upload_box: FileUploadBox) -> None:
        """Handle FileUploadBox update events from UCS.

        Updates the corresponding ResearchDataUploadBox with latest file count and size.
        """

    @abstractmethod
    async def get_research_data_upload_box(
        self, *, box_id: UUID4, user_id: UUID4
    ) -> ResearchDataUploadBox:
        """Retrieve a Research Data Upload Box by ID

        Raises:
            BoxAccessError: If the user doesn't have access to the box
            BoxNotFoundError: If the box doesn't exist
        """
        ...
