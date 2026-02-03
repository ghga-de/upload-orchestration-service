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

"""Integration tests for the core (aside from the typical journey)"""

from uuid import uuid4

import pytest
from hexkit.utils import now_utc_ms_prec
from pydantic import UUID4
from pytest_httpx import HTTPXMock

from tests.fixtures.joint import JointFixture
from uos.core.models import AccessionMap, FileIdToAccession, FileUploadWithAccession
from uos.ports.inbound.orchestrator import UploadOrchestratorPort


def make_file_upload(
    *, box_id: UUID4, file_id: UUID4 = uuid4()
) -> FileUploadWithAccession:
    """Make a FileUpload instance"""
    return FileUploadWithAccession(
        id=file_id,
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

    # Make accession map with a local duplicate accession
    map_local_dupe = AccessionMap(
        box_id=rdub_id1,
        mappings=[
            FileIdToAccession(file_id=file_upload1.id, accession="FILE1"),
            FileIdToAccession(file_id=file_upload2.id, accession="FILE1"),
        ],
    )
    with pytest.raises(UploadOrchestratorPort.AccessionMapError):
        await joint_fixture.upload_orchestrator.update_accession_map(
            accession_map=map_local_dupe
        )

    # Make accession map with a file ID that doesn't belong
    map_no_such_file = AccessionMap(
        box_id=rdub_id1,
        mappings=[
            FileIdToAccession(file_id=file_upload3.id, accession="FILE1"),
        ],
    )
    await joint_fixture.upload_orchestrator.update_accession_map(
        accession_map=map_no_such_file
    )

    # Update database for rdub2's only file
    map_for_rdub2 = AccessionMap(
        box_id=rdub_id2,
        mappings=[
            FileIdToAccession(file_id=file_upload3.id, accession="FILE3"),
        ],
    )
    await joint_fixture.upload_orchestrator.update_accession_map(
        accession_map=map_for_rdub2
    )

    # Make accession map with a global duplicate accession
    map_global_dupe = AccessionMap(
        box_id=rdub_id1,
        mappings=[
            FileIdToAccession(file_id=file_upload1.id, accession="FILE3"),
        ],
    )
    with pytest.raises(UploadOrchestratorPort.AccessionMapError):
        await joint_fixture.upload_orchestrator.update_accession_map(
            accession_map=map_global_dupe
        )

    # Successfully insert map for rdub1
    map_for_rdub1 = AccessionMap(
        box_id=rdub_id1,
        mappings=[
            FileIdToAccession(file_id=file_upload1.id, accession="FILE1"),
            FileIdToAccession(file_id=file_upload2.id, accession="FILE2"),
        ],
    )
    await joint_fixture.upload_orchestrator.update_accession_map(
        accession_map=map_for_rdub1
    )

    # Confirm that we can update this mapping
    map_for_rdub1.mappings[0].accession = "FILE1UPDATED"
    await joint_fixture.upload_orchestrator.update_accession_map(
        accession_map=map_for_rdub1
    )
