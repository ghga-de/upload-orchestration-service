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

"""Unit tests for the main core class"""

from dataclasses import dataclass
from datetime import timedelta
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest
from hexkit.utils import now_utc_ms_prec

from tests.fixtures import ConfigFixture
from tests.fixtures.in_mem_dao import BaseInMemDao, InMemBoxDao
from uos.config import Config
from uos.core import models
from uos.core.orchestrator import UploadOrchestrator
from uos.ports.outbound.http import AccessClientPort, UCSClientPort

pytestmark = pytest.mark.asyncio()

TEST_UCS_BOX_ID = UUID("2735c960-5e15-45dc-b27a-59162fbb2fd7")
TEST_DS_ID = UUID("f698158d-8417-4368-bb45-349277bc45ee")


@dataclass
class JointRig:
    """Test fixture containing all components needed for controller testing."""

    config: Config
    box_dao: BaseInMemDao[models.ResearchDataUploadBox]
    ucs_client: UCSClientPort
    access_client: AccessClientPort
    controller: UploadOrchestrator


@pytest.fixture()
def rig(config: ConfigFixture) -> JointRig:
    """Return a joint fixture with in-memory dependency mocks"""
    _config = config.config
    ucs_client_mock = AsyncMock()
    ucs_client_mock.create_file_upload_box.return_value = TEST_UCS_BOX_ID
    access_client_mock = AsyncMock()

    controller = UploadOrchestrator(
        box_dao=(box_dao := InMemBoxDao()),  # type: ignore
        ucs_client=ucs_client_mock,
        access_client=access_client_mock,
        audit_repository=AsyncMock(),
    )

    return JointRig(
        config=_config,
        box_dao=box_dao,
        ucs_client=ucs_client_mock,
        access_client=access_client_mock,
        controller=controller,
    )


async def test_create_research_data_upload_box(rig: JointRig):
    """Test the normal path of creating a research data upload box."""
    box_id = await rig.controller.create_research_data_upload_box(
        title="Test",
        description="Just a test",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    box = rig.box_dao.latest
    assert box.id == box_id
    assert box.title == "Test"
    assert box.description == "Just a test"
    assert box.storage_alias == "HD01"
    assert box.changed_by == TEST_DS_ID
    assert box.file_count == 0
    assert box.size == 0
    assert box.file_upload_box_id == TEST_UCS_BOX_ID
    assert box.last_changed - now_utc_ms_prec() < timedelta(seconds=5)
    assert box.locked == False
    assert box.state == "open"


async def test_update_research_data_upload_box_happy(rig: JointRig):
    """Test the normal path of updating box attributes."""
    # First create a box to update
    box_id = await rig.controller.create_research_data_upload_box(
        title="Original Title",
        description="Original Description",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    # Mock the access client to return that the user has access
    rig.access_client.check_box_access.return_value = True  # type: ignore

    # Create a mock auth context for a data steward
    from unittest.mock import Mock

    auth_context = Mock()
    auth_context.id = str(TEST_DS_ID)
    auth_context.roles = ["data_steward"]

    # Create an update request
    from uos.core.models import UpdateUploadBoxRequest

    update_request = UpdateUploadBoxRequest(
        title="Updated Title", description="Updated Description"
    )

    # Call the update method
    await rig.controller.update_research_data_upload_box(
        box_id=box_id, request=update_request, auth_context=auth_context
    )

    # Verify the box was updated
    updated_box = await rig.box_dao.get_by_id(box_id)
    assert updated_box.title == "Updated Title"
    assert updated_box.description == "Updated Description"
    assert updated_box.changed_by == TEST_DS_ID
    assert updated_box.last_changed - now_utc_ms_prec() < timedelta(seconds=5)

    # Verify access client was called to check access
    rig.access_client.check_box_access.assert_called_once()  # type: ignore


async def test_update_research_data_upload_box_not_found(rig: JointRig):
    """Test the box not found error case in the update method."""
    # Mock the access client to return that the user has access (but box doesn't exist)
    rig.access_client.check_box_access.return_value = True  # type: ignore

    # Create a mock auth context for a data steward
    auth_context = Mock()
    auth_context.id = str(TEST_DS_ID)
    auth_context.roles = ["data_steward"]

    # Create an update request
    update_request = models.UpdateUploadBoxRequest(
        title="Updated Title", description="Updated Description"
    )

    # Try to update a non-existent box ID
    non_existent_box_id = uuid4()

    # This should raise BoxNotFoundError since the box doesn't exist
    with pytest.raises(rig.controller.BoxNotFoundError):
        await rig.controller.update_research_data_upload_box(
            box_id=non_existent_box_id,
            request=update_request,
            auth_context=auth_context,
        )


async def test_get_upload_box_files_happy(rig: JointRig):
    """Test the normal path of getting a list of file IDs for a box from the UCS."""
    # First create a box
    box_id = await rig.controller.create_research_data_upload_box(
        title="Test Box",
        description="Test Description",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    # Mock the UCS client to return a list of file IDs
    test_file_ids = [uuid4(), uuid4(), uuid4()]
    rig.ucs_client.get_file_upload_list.return_value = test_file_ids  # type: ignore

    # Mock the access client for non-data steward case
    rig.access_client.get_accessible_upload_boxes.return_value = [box_id]  # type: ignore

    # Create a mock auth context for a regular user (not data steward)
    auth_context = Mock()
    auth_context.id = str(TEST_DS_ID)
    auth_context.roles = ["regular_user"]

    # Call the method
    result = await rig.controller.get_upload_box_files(
        box_id=box_id, auth_context=auth_context
    )

    # Verify the results
    assert result == test_file_ids

    # Verify the UCS client was called
    rig.ucs_client.get_file_upload_list.assert_called_once()  # type: ignore

    # Verify access check was performed for non-data steward
    rig.access_client.get_accessible_upload_boxes.assert_called_once()  # type: ignore


async def test_get_upload_box_files_access_error(rig: JointRig):
    """Test the case where getting box files fails because the user doesn't have access."""
    # First create a box
    box_id = await rig.controller.create_research_data_upload_box(
        title="Test Box",
        description="Test Description",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    # Mock the access client to return that the user does NOT have access to this box
    rig.access_client.get_accessible_upload_boxes.return_value = []  # type: ignore

    # Create a mock auth context for a regular user (not data steward)
    auth_context = Mock()
    different_user_id = uuid4()
    auth_context.id = str(different_user_id)
    auth_context.roles = ["regular_user"]

    # This should raise BoxAccessError since the user doesn't have access
    with pytest.raises(rig.controller.BoxAccessError):
        await rig.controller.get_upload_box_files(
            box_id=box_id, auth_context=auth_context
        )

    # Verify that access check was performed
    rig.access_client.get_accessible_upload_boxes.assert_called_once()  # type: ignore

    # Verify that UCS client was NOT called since access was denied
    rig.ucs_client.get_file_upload_list.assert_not_called()  # type: ignore


async def test_get_upload_box_files_box_not_found(rig: JointRig):
    """Test the case where getting box files fails because the box doesn't exist."""
    # Create a mock auth context for a data steward (to bypass access checks)
    auth_context = Mock()
    auth_context.id = str(TEST_DS_ID)
    auth_context.roles = ["data_steward"]

    # Try to get files from a non-existent box ID
    non_existent_box_id = uuid4()

    # This should raise BoxNotFoundError since the box doesn't exist
    # The error comes from the initial get_by_id call in get_upload_box_files
    with pytest.raises(rig.controller.BoxNotFoundError):
        await rig.controller.get_upload_box_files(
            box_id=non_existent_box_id, auth_context=auth_context
        )

    # Verify that access client was NOT called since the box lookup failed first
    rig.access_client.get_accessible_upload_boxes.assert_not_called()  # type: ignore

    # Verify that UCS client was NOT called since the box lookup failed
    rig.ucs_client.get_file_upload_list.assert_not_called()  # type: ignore


async def test_upsert_file_upload_box_happy(rig: JointRig):
    """Test the method that consumes FileUploadBox data and uses it to update RDUBoxes."""
    # First create a research data upload box
    box_id = await rig.controller.create_research_data_upload_box(
        title="Test Box",
        description="Test Description",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    # Get the created box to verify initial state
    initial_box = await rig.box_dao.get_by_id(box_id)
    assert initial_box.file_count == 0
    assert initial_box.size == 0
    assert initial_box.locked == False

    # Create a FileUploadBox with updated data
    updated_file_upload_box = models.FileUploadBox(
        id=TEST_UCS_BOX_ID,  # This should match the file_upload_box_id in our research box
        locked=True,
        file_count=5,
        size=1024000,
        storage_alias="HD01",
    )

    # Call upsert_file_upload_box
    await rig.controller.upsert_file_upload_box(updated_file_upload_box)

    # Verify the research data upload box was updated
    updated_box = await rig.box_dao.get_by_id(box_id)
    assert updated_box.file_count == 5
    assert updated_box.size == 1024000
    assert updated_box.locked == True

    # Verify other fields remain unchanged
    assert updated_box.title == "Test Box"
    assert updated_box.description == "Test Description"
    assert updated_box.storage_alias == "HD01"


async def test_upsert_file_upload_box_not_found(rig: JointRig):
    """Test the edge case where a matching Research Data Upload Box doesn't exist."""
    # Create a FileUploadBox with a random ID
    orphaned_file_upload_box = models.FileUploadBox(
        id=uuid4(),
        locked=False,
        file_count=3,
        size=512000,
        storage_alias="HD02",
    )

    # This should not raise an error, just log and continue
    await rig.controller.upsert_file_upload_box(orphaned_file_upload_box)

    # Verify nothing was inserted in the DB
    assert not [x async for x in rig.box_dao.find_all(mapping={})]


async def test_get_research_data_upload_box_happy(rig: JointRig):
    """Test the normal path of getting a research data upload box."""
    # First create a research data upload box
    box_id = await rig.controller.create_research_data_upload_box(
        title="Test Box",
        description="Test Description",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    # Test case where user has access
    rig.access_client.check_box_access.return_value = True  # type: ignore

    result = await rig.controller.get_research_data_upload_box(
        box_id=box_id, user_id=TEST_DS_ID
    )

    # Verify we got the correct box back
    assert result.id == box_id
    assert result.title == "Test Box"
    assert result.description == "Test Description"
    assert result.storage_alias == "HD01"
    assert result.changed_by == TEST_DS_ID
    assert result.file_upload_box_id == TEST_UCS_BOX_ID

    # Verify access check was called
    rig.access_client.check_box_access.assert_called_once()  # type: ignore


async def test_get_research_data_upload_box_access_denied(rig: JointRig):
    """Test the case where the user doesn't have access to the box."""
    # First create a research data upload box
    box_id = await rig.controller.create_research_data_upload_box(
        title="Test Box",
        description="Test Description",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    # Mock the access client to return that the user does NOT have access
    rig.access_client.check_box_access.return_value = False  # type: ignore

    # Try to get the box with a different user ID
    different_user_id = uuid4()

    # This should raise BoxAccessError since the user doesn't have access
    with pytest.raises(rig.controller.BoxAccessError):
        await rig.controller.get_research_data_upload_box(
            box_id=box_id, user_id=different_user_id
        )

    # Verify access check was called
    rig.access_client.check_box_access.assert_called_once()  # type: ignore


async def test_get_research_data_upload_box_not_found(rig: JointRig):
    """Test the case where the research data upload box doesn't exist."""
    # Mock the access client to return that the user has access
    rig.access_client.check_box_access.return_value = True  # type: ignore

    # Try to get a non-existent box
    non_existent_box_id = uuid4()

    # This should raise BoxNotFoundError since the box doesn't exist
    with pytest.raises(rig.controller.BoxNotFoundError):
        await rig.controller.get_research_data_upload_box(
            box_id=non_existent_box_id, user_id=TEST_DS_ID
        )

    # Verify access check was called first
    rig.access_client.check_box_access.assert_called_once()  # type: ignore


async def test_get_upload_access_grants_happy(rig: JointRig):
    """Test the normal path for getting upload access grants."""
    # First create a research data upload box
    box_id = await rig.controller.create_research_data_upload_box(
        title="Test Box",
        description="Test Description",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    # Create mock upload grants that would be returned by access client
    test_user_id = uuid4()
    test_iva_id = uuid4()
    test_grant_id = uuid4()

    mock_grants = [
        models.UploadGrant(
            id=test_grant_id,
            user_id=test_user_id,
            iva_id=test_iva_id,
            box_id=box_id,
            created=now_utc_ms_prec(),
            valid_from=now_utc_ms_prec(),
            valid_until=now_utc_ms_prec() + timedelta(days=7),
            user_name="Test User",
            user_email="test@example.com",
            user_title="Dr.",
        )
    ]

    # Mock the access client to return these grants
    rig.access_client.get_upload_access_grants.return_value = mock_grants  # type: ignore

    # Call the method
    result = await rig.controller.get_upload_access_grants(
        user_id=test_user_id,
        iva_id=test_iva_id,
        box_id=box_id,
        valid=True,
    )

    # Verify the results
    assert len(result) == 1
    grant_with_info = result[0]
    assert grant_with_info.id == test_grant_id
    assert grant_with_info.user_id == test_user_id
    assert grant_with_info.iva_id == test_iva_id
    assert grant_with_info.box_id == box_id
    assert grant_with_info.user_name == "Test User"
    assert grant_with_info.user_email == "test@example.com"
    assert grant_with_info.user_title == "Dr."
    # These should come from the box
    assert grant_with_info.title == "Test Box"
    assert grant_with_info.description == "Test Description"

    # Verify access client was called with correct parameters
    rig.access_client.get_upload_access_grants.assert_called_once_with(  # type: ignore
        user_id=test_user_id,
        iva_id=test_iva_id,
        box_id=box_id,
        valid=True,
    )


async def test_get_upload_access_grants_box_missing(rig: JointRig, caplog):
    """Test the case where grants returned from the access API include a grant with
    a box ID that doesn't exist in the UOS. This test also checks that we emit a
    WARNING log (but don't raise an error).
    """
    # Create one valid box
    valid_box_id = await rig.controller.create_research_data_upload_box(
        title="Valid Box",
        description="Valid Description",
        storage_alias="HD01",
        user_id=TEST_DS_ID,
    )

    # Create mock upload grants - one with a valid box ID, one with an invalid box ID
    test_user_id = uuid4()
    invalid_box_id = uuid4()  # This box doesn't/won't exist

    mock_grants = [
        models.UploadGrant(
            id=uuid4(),
            user_id=test_user_id,
            iva_id=uuid4(),
            box_id=valid_box_id,  # This box exists
            created=now_utc_ms_prec(),
            valid_from=now_utc_ms_prec(),
            valid_until=now_utc_ms_prec() + timedelta(days=7),
            user_name="Test User",
            user_email="test@example.com",
            user_title="Dr.",
        ),
        models.UploadGrant(
            id=uuid4(),
            user_id=test_user_id,
            iva_id=uuid4(),
            box_id=invalid_box_id,  # This box doesn't exist
            created=now_utc_ms_prec(),
            valid_from=now_utc_ms_prec(),
            valid_until=now_utc_ms_prec() + timedelta(days=7),
            user_name="Test User 2",
            user_email="test2@example.com",
            user_title="Prof.",
        ),
    ]

    # Mock the access client to return these grants
    rig.access_client.get_upload_access_grants.return_value = mock_grants  # type: ignore

    # Call the method
    result = await rig.controller.get_upload_access_grants()

    # Verify the results - should only contain the grant with the valid box
    assert len(result) == 1
    grant_with_info = result[0]
    assert grant_with_info.box_id == valid_box_id
    assert grant_with_info.title == "Valid Box"
    assert grant_with_info.description == "Valid Description"

    # Verify a warning was logged for the invalid box
    assert caplog.records
    warning_messages = [
        record.message for record in caplog.records if record.levelname == "WARNING"
    ]
    assert len(warning_messages) >= 1
    assert any(str(invalid_box_id) in msg for msg in warning_messages)
    assert any("doesn't exist in UOS" in msg for msg in warning_messages)

    # Verify access client was called
    rig.access_client.get_upload_access_grants.assert_called_once()  # type: ignore
