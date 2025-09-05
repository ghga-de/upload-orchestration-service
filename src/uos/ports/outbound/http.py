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

"""Ports centered around outbound http calls"""

from abc import ABC, abstractmethod
from collections.abc import Sequence

from pydantic import UUID4


class ClaimsClientPort(ABC):
    """An adapter for interacting with the access API to manage upload access claims"""

    @abstractmethod
    async def grant_upload_access(
        self, *, user_id: UUID4, iva_id: UUID4, box_id: UUID4
    ) -> None:
        """Grant upload access to a user for a box."""
        ...

    @abstractmethod
    async def get_accessible_upload_boxes(self, user_id: UUID4) -> Sequence[UUID4]:
        """Get list of upload box IDs accessible to a user."""
        ...

    @abstractmethod
    async def check_box_access(self, *, user_id: UUID4, box_id: UUID4) -> bool:
        """Check if a user has access to a specific upload box."""
        ...


class UCSClientPort(ABC):
    """An adapter for interacting with the UCS"""

    @abstractmethod
    async def create_file_upload_box(self, *, storage_alias: str) -> UUID4:
        """Create a new FileUploadBox in UCS."""
        ...

    @abstractmethod
    async def lock_file_upload_box(self, *, box_id: UUID4) -> None:
        """Lock a FileUploadBox in UCS."""
        ...

    @abstractmethod
    async def unlock_file_upload_box(self, *, box_id: UUID4) -> None:
        """Unlock a FileUploadBox in UCS."""
        ...

    @abstractmethod
    async def get_file_upload_list(self, *, box_id: UUID4) -> Sequence[str]:
        """Get list of file IDs in a FileUploadBox."""
        ...
