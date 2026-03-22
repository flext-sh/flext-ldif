"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``_models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Final

from flext_core import FlextModels
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif import (
    FlextLdifModelsCollections,
    FlextLdifModelsDomains,
    FlextLdifModelsEvents,
    FlextLdifModelsMetadata,
    FlextLdifModelsProcessing,
    FlextLdifModelsResults,
    FlextLdifModelsSettings,
    c,
    p,
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
    ):
        """LDIF namespace for cross-project access."""

        WriteFormatOptions: Final = FlextLdifModelsSettings.WriteFormatOptions
        StatisticsResult: Final = FlextLdifModelsResults.StatisticsResult

        class ProcessingResult(FlextLdifModelsProcessing.ProcessingResult):
            """Processing result with DN and attributes."""

        class FlexibleCategories(FlextLdifModelsCollections.FlexibleCategories):
            """Flexible categories."""

            def get_entries(
                self,
                category: str,
            ) -> Sequence[FlextLdifModelsDomains.Entry]:
                """Backward-compatible accessor for category entries."""
                return [
                    FlextLdifModelsDomains.Entry.model_validate(value)
                    for value in self.get(category)
                ]

            def set_entries(
                self,
                category: str,
                entries: Sequence[FlextLdifModelsDomains.Entry],
            ) -> None:
                """Backward-compatible setter for full category replacement."""
                self.categories[category] = list(entries)

        class LdifResults:
            """Backward-compatible results/settings namespace alias."""

            ParseResponse = FlextLdifModelsResults.ParseResponse
            WriteResponse = FlextLdifModelsResults.WriteResponse
            MigrationPipelineResult = FlextLdifModelsResults.MigrationPipelineResult
            MigrationComparisonResult = FlextLdifModelsResults.MigrationComparisonResult
            MigrationWorkflowResult = FlextLdifModelsResults.MigrationWorkflowResult
            AutoDetectionResult = FlextLdifModelsResults.AutoDetectionResult
            ServerComparisonSummary = FlextLdifModelsResults.ServerComparisonSummary
            SchemaServiceStatus = FlextLdifModelsResults.SchemaServiceStatus
            ValidationServiceStatus = FlextLdifModelsResults.ValidationServiceStatus
            ValidationResult = FlextLdifModelsResults.ValidationResult
            EntryResult = FlextLdifModelsResults.EntryResult
            StatisticsResult = FlextLdifModelsResults.StatisticsResult
            WhitelistRules = FlextLdifModelsSettings.WhitelistRules
            WriteFormatOptions = FlextLdifModelsSettings.WriteFormatOptions

        # =================================================================
        # COMPOSITE MODELS — defined here, not in _models
        # =================================================================

        class Stats(BaseModel):
            """Write statistics for batch content operations."""

            model_config: ClassVar[ConfigDict] = ConfigDict(validate_default=True)
            total_entries: Annotated[int, Field(default=0, ge=0)]
            successful: Annotated[int, Field(default=0, ge=0)]
            failed: Annotated[int, Field(default=0, ge=0)]

        class OidAclMetadataConfig(BaseModel):
            """Configuration model for OID ACL metadata parsing."""

            acl_line: Annotated[str, Field(default="")]
            oid_subject_type: Annotated[str, Field(default="")]
            rfc_subject_type: Annotated[str, Field(default="")]
            oid_subject_value: Annotated[str, Field(default="")]
            perms_dict: Annotated[Mapping[str, bool], Field(default_factory=dict)]
            target_dn: Annotated[str, Field(default="entry")]
            target_attrs: Annotated[list[str], Field(default_factory=list)]
            acl_filter: Annotated[str, Field(default="")]
            acl_constraint: Annotated[str, Field(default="")]
            bindmode: Annotated[str, Field(default="")]
            deny_group_override: Annotated[bool, Field(default=False)]
            append_to_all: Annotated[bool, Field(default=False)]
            bind_ip_filter: Annotated[str, Field(default="")]
            constrain_to_added_object: Annotated[str, Field(default="")]

        class QuirksByServerDict(FlextModels.ArbitraryTypesModel):
            """Quirks by server dictionary model."""

            schema_type: Annotated[
                str | None,
                Field(
                    default=None,
                    alias="schema",
                    description="Schema quirk type",
                ),
            ]
            acl_type: Annotated[
                str | None,
                Field(
                    default=None,
                    alias="acl",
                    description="ACL quirk type",
                ),
            ]
            entry_type: Annotated[
                str | None,
                Field(
                    default=None,
                    alias="entry",
                    description="Entry quirk type",
                ),
            ]

        class RegistryStatsDict(FlextModels.ArbitraryTypesModel):
            """Registry statistics dictionary model."""

            total_servers: Annotated[int, Field(default=0)]
            quirks_by_server: Annotated[
                dict[str, FlextLdifModels.Ldif.QuirksByServerDict],
                Field(default_factory=dict),
            ]
            server_priorities: Annotated[dict[str, int], Field(default_factory=dict)]

        # =================================================================
        # NON-CLASS TYPE ALIASES — type unions, protocol references
        # =================================================================

        class Schema:
            """Schema element type with protocol references."""

            type SchemaElement = (
                FlextLdifModels.Ldif.SchemaAttribute
                | FlextLdifModels.Ldif.SchemaObjectClass
                | str
                | int
                | float
                | bool
                | None
            )

        class Registry:
            """Registry-related type aliases using protocols."""

            type QuirksDict = Mapping[
                str,
                p.Ldif.SchemaQuirk | p.Ldif.AclQuirk | p.Ldif.EntryQuirk | None,
            ]

        class ProcessingConfig:
            """Processing configuration models namespace."""

            EntryTransformConfig: Final = FlextLdifModelsSettings.EntryTransformConfig
            FlextLdifUtilitiesFiltersConfig: Final = (
                FlextLdifModelsSettings.FlextLdifUtilitiesFiltersConfig
            )
            CaseFoldOption: Final = c.Ldif.CaseFoldOption


# =========================================================================
# MODULE ALIASES - Runtime access patterns
# =========================================================================


__all__ = ["FlextLdifModels", "m"]

m = FlextLdifModels
