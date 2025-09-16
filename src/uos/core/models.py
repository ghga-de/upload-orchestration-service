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

"""Data models for the Upload Orchestration Service."""

from enum import Enum, StrEnum
from typing import Literal

from ghga_service_commons.utils.utc_dates import UTCDatetime
from hexkit.protocols.dao import UUID4Field
from pydantic import (
    UUID4,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    ValidationInfo,
    field_validator,
)


class FileUploadBox(BaseModel):
    """A class representing a box that bundles files belonging to the same upload."""

    id: UUID4 = Field(..., description="Unique identifier for the instance")
    locked: bool = Field(
        default=False,
        description="Whether or not changes to the files in the box are allowed",
    )
    file_count: int = Field(default=0, description="The number of files in the box")
    size: int = Field(default=0, description="The total size of all files in the box")
    storage_alias: str = Field(..., description="S3 storage alias to use for uploads")


class FileUpload(BaseModel):
    """A File Upload."""

    upload_id: UUID4 = Field(..., description="Unique identifier for the file upload")
    completed: bool = Field(
        default=False, description="Whether or not the file upload has finished"
    )
    alias: str = Field(
        ..., description="The submitted alias from the metadata (unique within the box)"
    )
    checksum: str = Field(..., description="Unencrypted checksum")
    size: int = Field(..., description="File size in bytes")


class ResearchDataUploadBoxState(StrEnum):
    """The allowed states for a ResearchDataUploadBox instance."""

    OPEN = "open"
    LOCKED = "locked"
    CLOSED = "closed"


class ResearchDataUploadBox(BaseModel):
    """A class representing a ResearchDataUploadBox.

    Contains all fields from the FileUploadBox.
    """

    id: UUID4 = UUID4Field(
        description="Unique identifier for the research data upload box"
    )
    state: ResearchDataUploadBoxState = Field(
        ..., description="Current state of the upload box"
    )
    title: str = Field(..., description="Short meaningful name for the box")
    description: str = Field(..., description="Describes the upload box in more detail")
    last_changed: UTCDatetime = Field(..., description="Timestamp of the latest change")
    changed_by: UUID4 = Field(
        ..., description="ID of the user who performed the latest change"
    )
    file_upload_box_id: UUID4 = Field(..., description="The ID of the file upload box.")
    locked: bool = Field(
        default=False,
        description="Whether or not changes to the files in the file upload box are allowed",
    )
    file_count: int = Field(default=0, description="The number of files in the box")
    size: int = Field(default=0, description="The total size of all files in the box")
    storage_alias: str = Field(..., description="S3 storage alias to use for uploads")


class AuditRecord(BaseModel):
    """A generic record for audit purposes."""

    id: UUID4 = UUID4Field(description="A unique identifier for the record")
    created: UTCDatetime = Field(
        ..., description="Timestamp when the record was created"
    )
    service: str = Field(
        ..., description="Name of the service that generated the record"
    )
    label: str = Field(..., description="Short label describing the action")
    description: str = Field(..., description="Detailed description of the action")
    user_id: UUID4 | None = Field(
        default=None, description="ID of the user who performed the action"
    )
    correlation_id: UUID4 = Field(
        ..., description="Correlation ID for tracing requests"
    )
    action: Literal["C", "R", "U", "D"] | None = Field(
        default=None, description="CRUD operation type"
    )
    entity: str | None = Field(default=None, description="Type of entity affected")
    entity_id: str | None = Field(default=None, description="ID of the entity affected")


class BaseWorkOrderToken(BaseModel):
    """Base model for work order tokens."""

    work_type: str
    model_config = ConfigDict(frozen=True)


class CreateFileBoxWorkOrder(BaseWorkOrderToken):
    """Work order token for creating a new FileUploadBox."""

    work_type: Literal["create"] = "create"


class ChangeFileBoxWorkOrder(BaseWorkOrderToken):
    """Work order token for changing FileUploadBox state."""

    work_type: Literal["lock", "unlock"]
    box_id: UUID4 = Field(..., description="ID of the box to change")


class ViewFileBoxWorkOrder(BaseWorkOrderToken):
    """Work order token for viewing FileUploadBox contents."""

    work_type: Literal["view"] = "view"
    box_id: UUID4 = Field(..., description="ID of the box to view")


# API Request/Response models
class CreateUploadBoxRequest(BaseModel):
    """Request model for creating a new research data upload box."""

    title: str = Field(
        ..., description="Short meaningful name for the box", min_length=1
    )
    description: str = Field(..., description="Describes the upload box in more detail")
    storage_alias: str = Field(
        ..., description="S3 storage alias to use for uploads", min_length=1
    )


class CreateUploadBoxResponse(BaseModel):
    """Response model for creating a new research data upload box."""

    box_id: UUID4 = Field(..., description="ID of the newly created upload box")


class UpdateUploadBoxRequest(BaseModel):
    """Request model for updating a research data upload box."""

    title: str | None = Field(default=None, description="Updated title")
    description: str | None = Field(default=None, description="Updated description")
    state: ResearchDataUploadBoxState | None = Field(
        default=None, description="Updated state"
    )


class ClaimValidity(BaseModel):
    """Start and end dates for validating claims."""

    valid_from: UTCDatetime = Field(
        default=...,
        description="Start date of validity",
        examples=["2023-01-01T00:00:00Z"],
    )
    valid_until: UTCDatetime = Field(
        default=...,
        description="End date of validity",
        examples=["2023-12-31T23:59:59Z"],
    )

    @field_validator("valid_until")
    @classmethod
    def period_is_valid(cls, value: UTCDatetime, info: ValidationInfo):
        """Validate that the dates of the period are in the right order."""
        data = info.data
        if "valid_from" in data and value <= data["valid_from"]:
            raise ValueError("'valid_until' must be later than 'valid_from'")
        return value


class GrantAccessRequest(BaseModel):
    """Request model for granting upload access to a user."""

    validity: ClaimValidity
    user_id: UUID4 = Field(..., description="ID of the user to grant access to")
    iva_id: UUID4 = Field(..., description="ID of the IVA verification")
    box_id: UUID4 = Field(..., description="ID of the upload box")


class UploadGrant(BaseModel):
    """An upload access grant."""

    id: UUID4 = Field(..., description="Internal grant ID (same as claim ID)")
    user_id: UUID4 = Field(default=..., description="Internal user ID")
    iva_id: UUID4 | None = Field(
        default=None, description="ID of an IVA associated with this grant"
    )
    box_id: UUID4 = Field(
        default=..., description="ID of the upload box this grant is for"
    )
    created: UTCDatetime = Field(
        default=..., description="Date of creation of this grant"
    )
    valid_from: UTCDatetime = Field(default=..., description="Start date of validity")
    valid_until: UTCDatetime = Field(default=..., description="End date of validity")

    user_name: str = Field(default=..., description="Full name of the user")
    user_email: EmailStr = Field(
        default=...,
        description="The email address of the user",
    )
    user_title: str | None = Field(
        default=None, description="Academic title of the user"
    )


class GrantWithBoxInfo(UploadGrant):
    """An UploadGrant with the ResearchDataUploadBox title and description."""

    title: str = Field(..., description="Short meaningful name for the box")
    description: str = Field(..., description="Describes the upload box in more detail")


class SortOrder(Enum):
    """Represents the possible sorting orders"""

    ASCENDING = "ascending"
    DESCENDING = "descending"


class BoxRetrievalResults(BaseModel):
    """A model encapsulating retrieved research data upload boxes and the count thereof."""

    count: int = Field(..., description="The total number of unpaginated results")
    boxes: list[ResearchDataUploadBox] = Field(
        ..., description="The retrieved research data upload boxes"
    )
