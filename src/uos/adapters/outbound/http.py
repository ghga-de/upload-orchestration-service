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

"""Outbound HTTP calls"""

from collections.abc import Sequence

from pydantic import UUID4, Field
from pydantic_settings import BaseSettings

from uos.ports.outbound.http import ClaimsClientPort, UCSClientPort

TIMEOUT = 60


class AccessApiConfig(BaseSettings):
    """Config parameters for managing upload access grants."""

    access_url: str = Field(
        ...,
        description="URL pointing to the internal access API.",
        examples=["http://127.0.0.1/access"],
    )


class UCSApiConfig(BaseSettings):
    """Config parameters for interacting with the UCS."""

    # maybe this should be a WKVS call? solve later
    ucs_url: str = Field(
        ...,
        description="URL pointing to the UCS API.",
        examples=["http://127.0.0.1/upload"],
    )


class ClaimsClient(ClaimsClientPort):
    """An adapter for interacting with the access API to manage upload access grants"""

    def __init__(self, *, config: AccessApiConfig):
        self.access_url = config.access_url

    async def grant_upload_access(
        self, *, user_id: UUID4, iva_id: UUID4, box_id: UUID4
    ) -> None:
        """Grant upload access to a user for a box."""

    async def get_accessible_upload_boxes(self, user_id: str) -> Sequence[UUID4]:
        """Get list of upload box IDs accessible to a user."""


class UCSClient(UCSClientPort):
    """An adapter for communicating with the Upload Controller Service"""

    def __init__(self, *, config: UCSApiConfig):
        self.ucs_url = config.ucs_url

    async def create_file_upload_box(
        self, *, storage_alias: str, work_order: str
    ) -> UUID4:
        """Create a new FileUploadBox in UCS."""
        pass

    async def lock_file_upload_box(self, *, box_id: UUID4, work_order: str) -> None:
        """Lock a FileUploadBox in UCS."""
        pass

    async def unlock_file_upload_box(self, *, box_id: UUID4, work_order: str) -> None:
        """Unlock a FileUploadBox in UCS."""
        pass

    async def get_file_upload_list(
        self, *, box_id: UUID4, work_order: str
    ) -> Sequence[str]:
        """Get list of file IDs in a FileUploadBox."""
        pass
