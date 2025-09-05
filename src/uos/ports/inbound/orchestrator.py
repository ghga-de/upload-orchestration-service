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
from uuid import UUID

from pydantic import UUID4

from uos.core.models import (
    CreateUploadBoxRequest,
    FileUploadBox,
    GrantAccessRequest,
    ResearchDataUploadBox,
    UpdateUploadBoxRequest,
)


class UploadOrchestratorPort(ABC):
    """Port for the Upload Orchestrator service."""

    @abstractmethod
    async def create_upload_box(
        self,
        request: CreateUploadBoxRequest,
        user_id: str,
    ) -> UUID:
        """Create a new research data upload box.

        This operation:
        1. Creates a FileUploadBox in the UCS
        2. Creates a ResearchDataUploadBox locally
        3. Emits events and audit records

        Args:
            request: The upload box creation request
            user_id: ID of the user creating the box
            correlation_id: Correlation ID for tracing

        Returns:
            The UUID of the newly created upload box
        """
        ...

    @abstractmethod
    async def update_upload_box(
        self,
        box_id: UUID4,
        request: UpdateUploadBoxRequest,
        user_id: UUID4,
    ) -> None:
        """Update a research data upload box.

        Args:
            box_id: The UUID of the upload box to update
            request: The update request containing changes
            user_id: ID of the user making the update
            correlation_id: Correlation ID for tracing

        Raises:
            UploadBoxNotFoundError: If the box doesn't exist
        """
        ...

    @abstractmethod
    async def grant_upload_access(
        self,
        request: GrantAccessRequest,
        granting_user_id: str,
    ) -> None:
        """Grant upload access to a user for a specific upload box.

        Args:
            request: The access grant request
            granting_user_id: ID of the user granting access (must be Data Steward)
            correlation_id: Correlation ID for tracing

        Raises:
            UploadBoxNotFoundError: If the box doesn't exist
        """
        ...

    @abstractmethod
    async def get_upload_box_files(
        self,
        box_id: UUID,
        user_id: str,
        is_data_steward: bool,
    ) -> Sequence[str]:
        """Get list of file IDs for an upload box.

        Args:
            box_id: The UUID of the upload box
            user_id: ID of the user requesting the list
            is_data_steward: Whether the user has Data Steward role

        Returns:
            Sequence of file IDs in the upload box

        Raises:
            UploadBoxNotFoundError: If the box doesn't exist
            PermissionError: If the user doesn't have access to the box
        """
        ...

    @abstractmethod
    async def upsert_file_upload_box(self, file_upload_box: FileUploadBox) -> None:
        """Update the FileUploadBox portion of a ResearchDataUploadBox"""
