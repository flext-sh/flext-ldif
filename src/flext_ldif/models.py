"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``_models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence
from typing import Annotated, ClassVar

from flext_core import FlextModels
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif import (
    FlextLdifModelsCollections,
    FlextLdifModelsConversions,
    FlextLdifModelsDomains,
    FlextLdifModelsDomainSchema,
    FlextLdifModelsEvents,
    FlextLdifModelsMetadata,
    FlextLdifModelsProcessing,
    FlextLdifModelsResults,
    FlextLdifModelsSettings,
    t,
)


class FlextLdifModels(FlextModels):
    """LDIF domain models — flat façade with MRO class inheritance.

    Architecture: Domain layer helper
    All nested classes inherit via MRO from their ``_models`` implementations.
    Types live in ``typings.py``, constants in ``constants.py``.
    """

    class Ldif(
        FlextLdifModelsDomains,
        FlextLdifModelsMetadata,
        FlextLdifModelsSettings,
        FlextLdifModelsEvents,
        FlextLdifModelsResults,
        FlextLdifModelsCollections,
        FlextLdifModelsProcessing,
        FlextLdifModelsConversions,
        FlextLdifModelsDomainSchema,
    ):
        """LDIF namespace for cross-project access."""

        class FlexibleCategories(FlextLdifModelsCollections.FlexibleCategories):
            """Flexible categories."""

            def get_entries(
                self,
                category: str,
            ) -> MutableSequence[FlextLdifModelsDomains.Entry]:
                """Backward-compatible accessor for category entries."""
                return [
                    FlextLdifModelsDomains.Entry.model_validate(value)
                    for value in self.get(category)
                ]

            def set_entries(
                self,
                category: str,
                entries: MutableSequence[FlextLdifModelsDomains.Entry],
            ) -> None:
                """Backward-compatible setter for full category replacement."""
                self.categories[category] = list(entries)

        # =================================================================
        # COMPOSITE MODELS — defined here, not in _models
        # =================================================================

        class Stats(BaseModel):
            """Write statistics for batch content operations."""

            model_config: ClassVar[ConfigDict] = ConfigDict(validate_default=True)
            total_entries: Annotated[t.NonNegativeInt, Field()] = 0
            successful: Annotated[t.NonNegativeInt, Field()] = 0
            failed: Annotated[t.NonNegativeInt, Field()] = 0

        class OidAclMetadataConfig(BaseModel):
            """Configuration model for OID ACL metadata parsing."""

            acl_line: Annotated[str, Field()] = ""
            oid_subject_type: Annotated[str, Field()] = ""
            rfc_subject_type: Annotated[str, Field()] = ""
            oid_subject_value: Annotated[str, Field()] = ""
            perms_dict: Annotated[
                MutableMapping[str, bool],
                Field(default_factory=dict),
            ]
            target_dn: Annotated[str, Field()] = "entry"
            target_attrs: MutableSequence[str] = Field(default_factory=list)
            acl_filter: Annotated[str, Field()] = ""
            acl_constraint: Annotated[str, Field()] = ""
            bindmode: Annotated[str, Field()] = ""
            deny_group_override: Annotated[bool, Field()] = False
            append_to_all: Annotated[bool, Field()] = False
            bind_ip_filter: Annotated[str, Field()] = ""
            constrain_to_added_object: Annotated[str, Field()] = ""

        class QuirksByServerDict(FlextModels.ArbitraryTypesModel):
            """Quirks by server dictionary model."""

            schema_type: Annotated[
                str | None,
                Field(alias="schema", description="Schema quirk type"),
            ] = None
            acl_type: Annotated[
                str | None,
                Field(alias="acl", description="ACL quirk type"),
            ] = None
            entry_type: Annotated[
                str | None,
                Field(alias="entry", description="Entry quirk type"),
            ] = None

        class RegistryStatsDict(FlextModels.ArbitraryTypesModel):
            """Registry statistics dictionary model."""

            total_servers: Annotated[t.NonNegativeInt, Field()] = 0
            quirks_by_server: Annotated[
                MutableMapping[str, FlextLdifModels.Ldif.QuirksByServerDict],
                Field(default_factory=dict),
            ]
            server_priorities: Annotated[
                MutableMapping[str, int],
                Field(default_factory=dict),
            ]


__all__ = ["FlextLdifModels", "m"]

m = FlextLdifModels
