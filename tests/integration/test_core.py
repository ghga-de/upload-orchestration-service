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

"""Integration tests for the core (aside from the typical journey)"""

from uuid import uuid4

import pytest
from hexkit.utils import now_utc_ms_prec
from pydantic import UUID4
from pytest_httpx import HTTPXMock

from tests.fixtures.joint import JointFixture
from uos.core.models import AccessionMapRequest, FileUploadWithAccession
from uos.ports.inbound.orchestrator import UploadOrchestratorPort


def make_file_upload(
    *, box_id: UUID4, file_id: UUID4 | None = None
) -> FileUploadWithAccession:
    """Make a FileUpload instance"""
    return FileUploadWithAccession(
        id=file_id or uuid4(),
        box_id=box_id,
        alias="file1",
        state="inbox",
        state_updated=now_utc_ms_prec(),
        storage_alias="HD01",
        bucket_id="inbox",
        decrypted_size=1024,
        part_size=200,
    )


@pytest.mark.httpx_mock(can_send_already_matched_responses=True)
@pytest.mark.asyncio()
async def test_accession_map_index(joint_fixture: JointFixture, httpx_mock: HTTPXMock):
    """Make sure indexing works on the accession map DAO.

    This has to be tested with the testcontainer because the InMemDao doesn't
    support index features.
    """
    file_upload_box_id1 = uuid4()
    file_upload_box_id2 = uuid4()
    file_box_service_url = joint_fixture.config.ucs_url

    # Creating a box (requires data steward)
    httpx_mock.add_response(
        method="POST",
        url=f"{file_box_service_url}/boxes",
        status_code=201,
        json=str(file_upload_box_id1),
    )
    rdub_id1 = await joint_fixture.upload_orchestrator.create_research_data_upload_box(
        title="a box",
        description="a description",
        storage_alias="HD01",
        data_steward_id=uuid4(),
    )

    httpx_mock.add_response(
        method="POST",
        url=f"{file_box_service_url}/boxes",
        status_code=201,
        json=str(file_upload_box_id2),
    )
    rdub_id2 = await joint_fixture.upload_orchestrator.create_research_data_upload_box(
        title="a box",
        description="a description",
        storage_alias="HD01",
        data_steward_id=uuid4(),
    )

    file_upload1 = make_file_upload(box_id=file_upload_box_id1)
    file_upload2 = make_file_upload(box_id=file_upload_box_id1)
    file_upload3 = make_file_upload(box_id=file_upload_box_id2)

    # Mock the response from UCS for when UOS fetches the list files
    httpx_mock.add_response(
        method="GET",
        url=f"{file_box_service_url}/boxes/{file_upload_box_id1}/uploads",
        status_code=200,
        json=[
            file_upload1.model_dump(mode="json"),
            file_upload2.model_dump(mode="json"),
        ],
    )
    httpx_mock.add_response(
        method="GET",
        url=f"{file_box_service_url}/boxes/{file_upload_box_id2}/uploads",
        status_code=200,
        json=[file_upload3.model_dump(mode="json")],
    )

    # Make accession map with a duplicate file ID
    map_dupe_file = AccessionMapRequest(
        version=0,
        mapping={"GHGA001": file_upload1.id, "GHGA002": file_upload1.id},
    )
    with pytest.raises(UploadOrchestratorPort.AccessionMapError):
        await joint_fixture.upload_orchestrator.update_accession_map(
            box_id=rdub_id1, request=map_dupe_file
        )

    # Make accession map with a file ID that doesn't belong
    map_no_such_file = AccessionMapRequest(
        version=0, mapping={"GHGA003": file_upload3.id}
    )
    with pytest.raises(UploadOrchestratorPort.AccessionMapError):
        await joint_fixture.upload_orchestrator.update_accession_map(
            box_id=rdub_id1, request=map_no_such_file
        )

    # Update database for rdub2's only file
    map_for_rdub2 = AccessionMapRequest(version=0, mapping={"GHGA003": file_upload3.id})
    await joint_fixture.upload_orchestrator.update_accession_map(
        box_id=rdub_id2, request=map_for_rdub2
    )

    # Successfully insert map for rdub1
    map_for_rdub1 = AccessionMapRequest(
        version=0, mapping={"GHGA001": file_upload1.id, "GHGA002": file_upload2.id}
    )
    await joint_fixture.upload_orchestrator.update_accession_map(
        box_id=rdub_id1, request=map_for_rdub1
    )

    # Confirm that we can update this mapping
    map_for_rdub1.mapping["GHGA007"] = map_for_rdub1.mapping.pop("GHGA001")
    await joint_fixture.upload_orchestrator.update_accession_map(
        box_id=rdub_id1, request=map_for_rdub1
    )
