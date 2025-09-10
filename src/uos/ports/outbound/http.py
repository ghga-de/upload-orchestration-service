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

from ghga_service_commons.utils.utc_dates import UTCDatetime
from pydantic import UUID4


class AccessClientPort(ABC):
    """An adapter for interacting with the access API to manage upload access claims"""

    class AccessAPIError(RuntimeError):
        """Raised when there's an error while communicating with the Access API"""

    @abstractmethod
    async def grant_upload_access(
        self,
        *,
        user_id: UUID4,
        iva_id: UUID4,
        box_id: UUID4,
        valid_from: UTCDatetime,
        valid_until: UTCDatetime,
    ) -> None:
        """Grant upload access to a user for a box.

        Raises:
            AccessAPIError if there's a problem during the operation.
        """
        ...

    @abstractmethod
    async def get_accessible_upload_boxes(self, user_id: UUID4) -> list[UUID4]:
        """Get list of upload box IDs accessible to a user.

        Raises:
            AccessAPIError if there's a problem during the operation.
        """
        ...

    @abstractmethod
    async def check_box_access(self, *, user_id: UUID4, box_id: UUID4) -> bool:
        """Check if a user has access to a specific upload box.

        Raises:
            AccessAPIError if there's a problem during the operation.
        """
        ...


class UCSClientPort(ABC):
    """An adapter for interacting with the UCS.

    This class is responsible for WOT generation and all pertinent error handling.
    """

    class UCSCallError(RuntimeError):
        """Raised when there's an error while communicating with the UCS"""

    @abstractmethod
    async def create_file_upload_box(self, *, storage_alias: str) -> UUID4:
        """Create a new FileUploadBox in UCS.

        Raises:
            UCSCallError if there's a problem with the operation.
        """
        ...

    @abstractmethod
    async def lock_file_upload_box(self, *, box_id: UUID4) -> None:
        """Lock a FileUploadBox in UCS.

        Raises:
            UCSCallError if there's a problem with the operation.
        """
        ...

    @abstractmethod
    async def unlock_file_upload_box(self, *, box_id: UUID4) -> None:
        """Unlock a FileUploadBox in UCS.

        Raises:
            UCSCallError if there's a problem with the operation.
        """
        ...

    @abstractmethod
    async def get_file_upload_list(self, *, box_id: UUID4) -> list[UUID4]:
        """Get list of file IDs in a FileUploadBox.

        Raises:
            UCSCallError if there's a problem with the operation.
        """
        ...
