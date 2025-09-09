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

import logging
from collections.abc import Sequence
from uuid import UUID

import httpx
from ghga_service_commons.utils.crypt import encrypt
from jwcrypto import jwk
from pydantic import UUID4, Field, SecretStr
from pydantic_settings import BaseSettings

from uos.core.models import (
    ChangeFileBoxWorkOrder,
    CreateFileBoxWorkOrder,
    ViewFileBoxWorkOrder,
)
from uos.core.tokens import sign_work_order_token
from uos.ports.outbound.http import ClaimsClientPort, UCSClientPort

TIMEOUT = 60

log = logging.getLogger(__name__)


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


class ClaimsClient(ClaimsClientPort):
    """An adapter for interacting with the access API to manage upload access grants"""

    def __init__(self, *, config: AccessApiConfig):
        self.access_url = config.access_url

    async def grant_upload_access(
        self, *, user_id: UUID4, iva_id: UUID4, box_id: UUID4
    ) -> None:
        """Grant upload access to a user for a box."""
        raise NotImplementedError()

    async def get_accessible_upload_boxes(self, user_id: UUID4) -> Sequence[UUID4]:
        """Get list of upload box IDs accessible to a user."""
        raise NotImplementedError()

    async def check_box_access(self, *, user_id: UUID4, box_id: UUID4) -> bool:
        """Check if a user has access to a specific upload box."""
        raise NotImplementedError()


class UCSClient(UCSClientPort):
    """An adapter for interacting with the UCS.

    This class is responsible for WOT generation and all pertinent error handling.
    """

    def __init__(self, *, config: UCSApiConfig):
        self._ucs_url = config.ucs_url
        self._ucs_public_key = config.ucs_public_key
        self._signing_key = jwk.JWK.from_json(
            config.work_order_signing_key.get_secret_value()
        )
        if not self._signing_key.has_private:
            key_error = KeyError("No private work order signing key found.")
            log.error(key_error)
            raise key_error

    def _auth_header(self, signed_wot: str) -> dict[str, str]:
        encrypted_wot = encrypt(signed_wot, self._ucs_public_key)
        headers = {"Authorization": f"Bearer {encrypted_wot}"}
        return headers

    async def create_file_upload_box(self, *, storage_alias: str) -> UUID4:
        """Create a new FileUploadBox in UCS.

        Raises:
            UCSCallError if there's a problem with the operation.
        """
        signed_wot = sign_work_order_token(CreateFileBoxWorkOrder(), self._signing_key)
        headers = self._auth_header(signed_wot)
        body = {"storage_alias": storage_alias}
        response = httpx.post(f"{self._ucs_url}/boxes", headers=headers, json=body)
        if response.status_code != 201:
            log.error(
                "Error creating new FileUploadBox in the UCS with storage alias %s.",
                storage_alias,
                extra={
                    "status_code": response.status_code,
                    "response_body": response.json(),
                },
            )
            raise self.UCSCallError("Failed to create new FileUploadBox.")
        try:
            box_id = response.json()
            return UUID(box_id)
        except Exception as err:
            msg = "Failed to extract box ID from response body."
            log.error(msg, exc_info=True)
            raise self.UCSCallError(msg) from err

    async def lock_file_upload_box(self, *, box_id: UUID4) -> None:
        """Lock a FileUploadBox in UCS.

        Raises:
            UCSCallError if there's a problem with the operation.
        """
        wot = ChangeFileBoxWorkOrder(work_type="lock", box_id=box_id)
        signed_wot = sign_work_order_token(wot, self._signing_key)
        headers = self._auth_header(signed_wot)
        body = {"lock": True}
        response = httpx.patch(
            f"{self._ucs_url}/boxes/{box_id}", headers=headers, json=body
        )
        if response.status_code != 204:
            log.error(
                "Error locking FileUploadBox ID %s in the UCS.",
                box_id,
                extra={
                    "status_code": response.status_code,
                    "response_body": response.json(),
                },
            )
            raise self.UCSCallError("Failed to lock FileUploadBox.")

    async def unlock_file_upload_box(self, *, box_id: UUID4) -> None:
        """Unlock a FileUploadBox in UCS.

        Raises:
            UCSCallError if there's a problem with the operation.
        """
        wot = ChangeFileBoxWorkOrder(work_type="unlock", box_id=box_id)
        signed_wot = sign_work_order_token(wot, self._signing_key)
        headers = self._auth_header(signed_wot)
        body = {"lock": False}
        response = httpx.patch(
            f"{self._ucs_url}/boxes/{box_id}", headers=headers, json=body
        )
        if response.status_code != 204:
            log.error(
                "Error unlocking FileUploadBox ID %s in the UCS.",
                box_id,
                extra={
                    "status_code": response.status_code,
                    "response_body": response.json(),
                },
            )
            raise self.UCSCallError("Failed to unlock FileUploadBox.")

    async def get_file_upload_list(self, *, box_id: UUID4) -> Sequence[UUID4]:
        """Get list of file IDs in a FileUploadBox.

        Raises:
            UCSCallError if there's a problem with the operation.
        """
        wot = ViewFileBoxWorkOrder(box_id=box_id)
        signed_wot = sign_work_order_token(wot, self._signing_key)
        headers = self._auth_header(signed_wot)
        response = httpx.get(f"{self._ucs_url}/boxes/{box_id}/uploads", headers=headers)
        if response.status_code != 200:
            log.error(
                "Error unlocking FileUploadBox ID %s in the UCS.",
                box_id,
                extra={
                    "status_code": response.status_code,
                    "response_body": response.json(),
                },
            )
            raise self.UCSCallError("Failed to unlock FileUploadBox.")

        try:
            files = response.json()
            return [UUID(file) for file in files]
        except Exception as err:
            msg = "Failed to extract list of file IDs from response body."
            log.error(msg, exc_info=True)
            raise self.UCSCallError(msg) from err
