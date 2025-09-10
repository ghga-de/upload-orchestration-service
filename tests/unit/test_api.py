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
"""Tests that check the REST API's behavior and auth handling"""

from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from ghga_service_commons.api.testing import AsyncTestClient
from ghga_service_commons.utils.jwt_helpers import (
    generate_jwk,
    sign_and_serialize_token,
)
from hexkit.utils import now_utc_ms_prec

from tests.fixtures import ConfigFixture
from uos.core.models import ResearchDataUploadBox
from uos.inject import prepare_rest_app
from uos.ports.inbound.orchestrator import UploadOrchestratorPort
from uos.ports.outbound.http import UCSClientPort

pytestmark = pytest.mark.asyncio()
TEST_DS_ID = UUID("f698158d-8417-4368-bb45-349277bc45ee")
TEST_BOX_ID = UUID("bf344cd4-0c1b-434a-93d1-36a11b6b02d9")
INVALID_HEADER: dict[str, str] = {"Authorization": "Bearer ab12"}

SIGNING_KEY_PAIR = generate_jwk()
DS_AUTH_CLAIMS = {
    "name": "John Doe",
    "email": "john@home.org",
    "title": "Dr.",
    "id": str(TEST_DS_ID),
    "roles": ["data_steward"],
}
USER_AUTH_CLAIMS = DS_AUTH_CLAIMS.copy()
del USER_AUTH_CLAIMS["roles"]


def headers_for_token(token: str) -> dict[str, str]:
    """Get the Authorization headers for the given token."""
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(name="user_auth_headers")
def fixture_user_auth_headers(config: ConfigFixture) -> dict[str, str]:
    """Get auth headers for testing"""
    token = sign_and_serialize_token(USER_AUTH_CLAIMS, config.jwk)
    return headers_for_token(token)


@pytest.fixture(name="ds_auth_headers")
def fixture_ds_auth_headers(config: ConfigFixture) -> dict[str, str]:
    """Get auth headers for testing"""
    token = sign_and_serialize_token(DS_AUTH_CLAIMS, config.jwk)
    return headers_for_token(token)


@pytest.fixture(name="bad_auth_headers")
def fixture_bad_auth_headers(config: ConfigFixture) -> dict[str, str]:
    """Get a invalid auth headers for testing"""
    claims = DS_AUTH_CLAIMS.copy()
    del claims["id"]
    token = sign_and_serialize_token(claims, config.jwk)
    return headers_for_token(token)


async def test_health(config: ConfigFixture):
    """Test the health endpoint returns a 200"""
    async with (
        prepare_rest_app(
            config=config.config, upload_orchestrator_override=AsyncMock()
        ) as app,
        AsyncTestClient(app=app) as rest_client,
    ):
        response = await rest_client.get("/health")
        assert response.status_code == 200


async def test_get_research_data_upload_box(
    config: ConfigFixture, user_auth_headers, bad_auth_headers
):
    """Test the GET /boxes/{box_id} endpoint."""
    orchestrator = AsyncMock()
    async with (
        prepare_rest_app(
            config=config.config, upload_orchestrator_override=orchestrator
        ) as app,
        AsyncTestClient(app=app) as rest_client,
    ):
        # unauthenticated
        url = f"/boxes/{TEST_BOX_ID}"
        response = await rest_client.get(url)
        assert response.status_code == 403

        # bad credentials
        response = await rest_client.get(url, headers=bad_auth_headers)
        assert response.status_code == 401

        # normal response (patch mock)
        box = ResearchDataUploadBox(
            state="open",
            title="test",
            description="desc",
            last_changed=now_utc_ms_prec(),
            changed_by=TEST_DS_ID,
            id=TEST_BOX_ID,
            file_upload_box_id=uuid4(),
            storage_alias="HD",
        )
        orchestrator.get_research_data_upload_box.return_value = box
        response = await rest_client.get(url, headers=user_auth_headers)
        assert response.status_code == 200
        assert response.json() == box.model_dump(mode="json")

        # handle box access error from core
        orchestrator.reset_mock()
        orchestrator.get_research_data_upload_box.side_effect = (
            UploadOrchestratorPort.BoxAccessError()
        )
        response = await rest_client.get(url, headers=user_auth_headers)
        assert response.status_code == 403

        # handle box not found error from core
        orchestrator.reset_mock()
        orchestrator.get_research_data_upload_box.side_effect = (
            UploadOrchestratorPort.BoxNotFoundError(box_id=box.id)
        )
        response = await rest_client.get(url, headers=user_auth_headers)
        assert response.status_code == 404

        # handle other exception
        orchestrator.reset_mock()
        orchestrator.get_research_data_upload_box.side_effect = TypeError()
        response = await rest_client.get(url, headers=user_auth_headers)
        assert response.status_code == 500


async def test_create_research_data_upload_box(
    config: ConfigFixture, ds_auth_headers, user_auth_headers, bad_auth_headers
):
    """Test the POST /boxes endpoint"""
    orchestrator = AsyncMock()
    async with (
        prepare_rest_app(
            config=config.config, upload_orchestrator_override=orchestrator
        ) as app,
        AsyncTestClient(app=app) as rest_client,
    ):
        url = "/boxes"
        request_data = {
            "title": "Test Box",
            "description": "Test description",
            "storage_alias": "HD01",
        }

        # unauthenticated
        response = await rest_client.post(url, json=request_data)
        assert response.status_code == 403

        # bad credentials
        response = await rest_client.post(
            url, json=request_data, headers=bad_auth_headers
        )
        assert response.status_code == 401

        # normal response but user is not a data steward (no data_steward role)
        response = await rest_client.post(
            url, json=request_data, headers=user_auth_headers
        )
        assert response.status_code == 403

        # normal response with data steward role
        # Mock the orchestrator to return a box ID
        test_box_id = uuid4()
        orchestrator.create_research_data_upload_box.return_value = test_box_id
        response = await rest_client.post(
            url, json=request_data, headers=ds_auth_headers
        )
        assert response.status_code == 201
        assert response.json() == str(test_box_id)

        # handle UCS error from core
        orchestrator.reset_mock()
        orchestrator.create_research_data_upload_box.side_effect = (
            UCSClientPort.UCSCallError()
        )
        response = await rest_client.post(
            url, json=request_data, headers=ds_auth_headers
        )
        assert response.status_code == 500

        # handle other exception
        orchestrator.reset_mock()
        orchestrator.create_research_data_upload_box.side_effect = TypeError()
        response = await rest_client.post(
            url, json=request_data, headers=ds_auth_headers
        )
        assert response.status_code == 500


async def test_update_research_data_upload_box(
    config: ConfigFixture, ds_auth_headers, user_auth_headers, bad_auth_headers
):
    """Test the PATCH /boxes/{box_id} endpoint."""
    orchestrator = AsyncMock()
    async with (
        prepare_rest_app(
            config=config.config, upload_orchestrator_override=orchestrator
        ) as app,
        AsyncTestClient(app=app) as rest_client,
    ):
        url = f"/boxes/{TEST_BOX_ID}"
        request_data = {"title": "Updated Title", "description": "Updated description"}

        # unauthenticated
        response = await rest_client.patch(url, json=request_data)
        assert response.status_code == 403

        # bad credentials
        response = await rest_client.patch(
            url, json=request_data, headers=bad_auth_headers
        )
        assert response.status_code == 401

        # normal response with user auth (should work for regular users too)
        orchestrator.update_research_data_upload_box.return_value = None
        response = await rest_client.patch(
            url, json=request_data, headers=user_auth_headers
        )
        assert response.status_code == 204

        # normal response with data steward auth
        orchestrator.reset_mock()
        orchestrator.update_research_data_upload_box.return_value = None
        response = await rest_client.patch(
            url, json=request_data, headers=ds_auth_headers
        )
        assert response.status_code == 204

        # handle box access error from core
        orchestrator.reset_mock()
        orchestrator.update_research_data_upload_box.side_effect = (
            UploadOrchestratorPort.BoxAccessError()
        )
        response = await rest_client.patch(
            url, json=request_data, headers=user_auth_headers
        )
        assert response.status_code == 403

        # handle box not found error from core
        orchestrator.reset_mock()
        orchestrator.update_research_data_upload_box.side_effect = (
            UploadOrchestratorPort.BoxNotFoundError(box_id=TEST_BOX_ID)
        )
        response = await rest_client.patch(
            url, json=request_data, headers=user_auth_headers
        )
        assert response.status_code == 404

        # handle UCS error from core
        orchestrator.reset_mock()
        orchestrator.update_research_data_upload_box.side_effect = (
            UCSClientPort.UCSCallError()
        )
        response = await rest_client.patch(
            url, json=request_data, headers=user_auth_headers
        )
        assert response.status_code == 500

        # handle other exception
        orchestrator.reset_mock()
        orchestrator.update_research_data_upload_box.side_effect = TypeError()
        response = await rest_client.patch(
            url, json=request_data, headers=user_auth_headers
        )
        assert response.status_code == 500


async def test_grant_upload_access(
    config: ConfigFixture, ds_auth_headers, user_auth_headers, bad_auth_headers
):
    """Test the POST /access-grant endpoint"""
    orchestrator = AsyncMock()
    async with (
        prepare_rest_app(
            config=config.config, upload_orchestrator_override=orchestrator
        ) as app,
        AsyncTestClient(app=app) as rest_client,
    ):
        url = "/access-grant"
        request_data = {
            "user_id": str(uuid4()),
            "iva_id": str(uuid4()),
            "box_id": str(TEST_BOX_ID),
        }

        # unauthenticated
        response = await rest_client.post(url, json=request_data)
        assert response.status_code == 403

        # bad credentials
        response = await rest_client.post(
            url, json=request_data, headers=bad_auth_headers
        )
        assert response.status_code == 401

        # normal response but user is not a data steward (no data_steward role)
        response = await rest_client.post(
            url, json=request_data, headers=user_auth_headers
        )
        assert response.status_code == 403

        # normal response with data steward role
        orchestrator.grant_upload_access.return_value = None
        response = await rest_client.post(
            url, json=request_data, headers=ds_auth_headers
        )
        assert response.status_code == 201
        assert response.json() == {"message": "Upload access granted successfully"}

        # handle other exception
        orchestrator.reset_mock()
        orchestrator.grant_upload_access.side_effect = TypeError()
        response = await rest_client.post(
            url, json=request_data, headers=ds_auth_headers
        )
        assert response.status_code == 500


async def test_list_upload_box_files(
    config: ConfigFixture, ds_auth_headers, user_auth_headers, bad_auth_headers
):
    """Test the GET /boxes/{box_id}/uploads endpoint."""
    orchestrator = AsyncMock()
    async with (
        prepare_rest_app(
            config=config.config, upload_orchestrator_override=orchestrator
        ) as app,
        AsyncTestClient(app=app) as rest_client,
    ):
        url = f"/boxes/{TEST_BOX_ID}/uploads"

        # unauthenticated
        response = await rest_client.get(url)
        assert response.status_code == 403

        # bad credentials
        response = await rest_client.get(url, headers=bad_auth_headers)
        assert response.status_code == 401

        # normal response with user auth
        file_list = [uuid4() for _ in range(3)]
        file_list_json = [str(file) for file in file_list]
        orchestrator.get_upload_box_files.return_value = file_list
        response = await rest_client.get(url, headers=user_auth_headers)
        assert response.status_code == 200
        assert response.json() == file_list_json

        # normal response with data steward auth
        response = await rest_client.get(url, headers=ds_auth_headers)
        assert response.status_code == 200
        assert response.json() == file_list_json

        # handle box access error from core
        orchestrator.reset_mock()
        orchestrator.get_upload_box_files.side_effect = (
            UploadOrchestratorPort.BoxAccessError()
        )
        response = await rest_client.get(url, headers=user_auth_headers)
        assert response.status_code == 403

        # handle box not found error from core
        orchestrator.reset_mock()
        orchestrator.get_upload_box_files.side_effect = (
            UploadOrchestratorPort.BoxNotFoundError(box_id=TEST_BOX_ID)
        )
        response = await rest_client.get(url, headers=user_auth_headers)
        assert response.status_code == 404

        # handle other exception (including UCS errors that bubble up)
        orchestrator.reset_mock()
        orchestrator.get_upload_box_files.side_effect = TypeError()
        response = await rest_client.get(url, headers=user_auth_headers)
        assert response.status_code == 500
