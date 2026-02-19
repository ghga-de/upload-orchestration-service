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

from uuid import UUID, uuid4

import httpx
import pytest
from pytest_httpx import HTTPXMock

from tests.fixtures import ConfigFixture
from uos.adapters.outbound.http import AccessionClient
from uos.core.models import AccessionMap

pytestmark = pytest.mark.asyncio

TEST_BOX_ID = UUID("a1b2c3d4-e5f6-4890-abcd-ef1234567890")

ACCESSION_MAP = AccessionMap(
    box_id=TEST_BOX_ID,
    mapping={"GHGA:file1": uuid4(), "GHGA:file2": uuid4()},
)


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
