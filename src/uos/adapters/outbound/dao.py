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
"""DAO implementation"""

from hexkit.protocols.dao import DaoFactoryProtocol

from uos.constants import BOX_COLLECTION
from uos.core.models import ResearchDataUploadBox
from uos.ports.outbound.dao import BoxDao

__all__ = ["get_box_dao"]


async def get_box_dao(
    *, dao_factory: DaoFactoryProtocol | None = None, override: BoxDao | None = None
) -> BoxDao:
    """Construct a ResearchDataUploadBox DAO from the provided dao_factory"""
    if override:
        return override

    if not dao_factory:
        raise RuntimeError("No DAO Factory and no override provided for BoxDao")

    return await dao_factory.get_dao(
        name=BOX_COLLECTION,
        dto_model=ResearchDataUploadBox,
        id_field="id",
    )
