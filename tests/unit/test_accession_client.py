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
"""Unit tests for the AccessionClient"""

from datetime import timedelta
from typing import Literal, cast
from uuid import UUID, uuid4

import httpx
import pytest
from ghga_service_commons.auth.jwt_auth import JWTAuthConfig, JWTAuthContextProvider
from ghga_service_commons.utils.utc_dates import UTCDatetime
from hexkit.utils import now_utc_ms_prec
from pydantic import BaseModel
from pytest_httpx import HTTPXMock

from tests.fixtures import ConfigFixture
from uos.adapters.outbound.http import AccessionClient
from uos.constants import JWT_ISS, JWT_SUB
from uos.core.models import AccessionMap

pytestmark = pytest.mark.asyncio

TEST_BOX_ID = UUID("a1b2c3d4-e5f6-4890-abcd-ef1234567890")

ACCESSION_MAP = AccessionMap(
    box_id=TEST_BOX_ID,
    mapping={"GHGA:file1": uuid4(), "GHGA:file2": uuid4()},
)


class JWTClaimsModel(BaseModel):
    """Model which defines the expected JWT format"""

    aud: Literal["GHGA"]
    iss: Literal["GHGA"]
    sub: str
    iat: UTCDatetime
    exp: UTCDatetime


async def test_submission(
    config: ConfigFixture, httpx_mock: HTTPXMock, httpx_client: httpx.AsyncClient
):
    """Test that the AccessionClient sends a request to the right URL with the right
    payload given an AccessionMap.
    """
    accession_client = AccessionClient(config=config.config, httpx_client=httpx_client)

    # Happy path
    httpx_mock.add_response(204)
    await accession_client.submit_accession_map(
        accession_map=ACCESSION_MAP
    )  # no error == success

    # Check off-normal status code
    httpx_mock.add_response(500, json={"error": "Some error occurred."})
    with pytest.raises(AccessionClient.OperationError):
        await accession_client.submit_accession_map(accession_map=ACCESSION_MAP)

    # Check 400 status code
    httpx_mock.add_response(400, json={"error": "Bad request"})
    with pytest.raises(AccessionClient.OperationError):
        await accession_client.submit_accession_map(accession_map=ACCESSION_MAP)

    # Check 404 status code
    httpx_mock.add_response(404, json={"error": "Not found"})
    with pytest.raises(AccessionClient.OperationError):
        await accession_client.submit_accession_map(accession_map=ACCESSION_MAP)


async def test_jwt_formation(
    config: ConfigFixture, httpx_mock: HTTPXMock, httpx_client: httpx.AsyncClient
):
    """Test that the AccessionClient class formulates proper JWTs"""
    # Create a mock JWTAuthContextProvider so we can inspect the JWT sent by this service
    accession_api_auth_config = JWTAuthConfig(
        auth_key=config.signing_jwk.export_public(),
        auth_check_claims=dict.fromkeys(["iss", "iat", "sub", "aud", "exp"]),
    )
    auth_context_provider = JWTAuthContextProvider(
        config=accession_api_auth_config, context_class=JWTClaimsModel
    )

    # Define a callback that can inspect the request from the accession client
    async def callback(request: httpx.Request):
        """Callback function that decrypts the JWT in the bearer token"""
        token = cast(str, request.headers.get("Authorization"))
        token = token.removeprefix("Bearer ")
        context = await auth_context_provider.get_context(token)
        assert context
        assert context.iss == context.aud == JWT_ISS
        assert context.sub == JWT_SUB
        assert context.iat - now_utc_ms_prec() < timedelta(seconds=3)
        return httpx.Response(204)

    # Register the callback
    httpx_mock.add_callback(callback=callback)
    accession_client = AccessionClient(config=config.config, httpx_client=httpx_client)
    await accession_client.submit_accession_map(accession_map=ACCESSION_MAP)
