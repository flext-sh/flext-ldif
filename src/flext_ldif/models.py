"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``_models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Final, TypeAlias

from flext_core import FlextModels
from pydantic import Field

from flext_ldif import c, p, t
from flext_ldif._models.collections import FlextLdifModelsCollections
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.processing import FlextLdifModelsProcessing
from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif._models.settings import FlextLdifModelsSettings

ProcessingResult = FlextLdifModelsProcessing.ProcessingResult


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

        # =================================================================
        # TYPE ALIASES — non-class types only (enums, unions, containers)
        # Class-level types moved to FlextLdifTypes.Ldif in typings.py
        # =================================================================

        EntryAttributesDict: TypeAlias = t.Ldif.EntryAttributesDict
        RawEntryDict: TypeAlias = t.Ldif.RawEntryDict

        ServerType: TypeAlias = c.Ldif.ServerTypes
        SpaceHandlingOption: TypeAlias = c.Ldif.SpaceHandlingOption
        EscapeHandlingOption: TypeAlias = c.Ldif.EscapeHandlingOption
        SortOption: TypeAlias = c.Ldif.SortOption
        OutputFormat: TypeAlias = c.Ldif.Domain.OutputFormat

        class ProcessingResult(ProcessingResult):
            """Processing result with DN and attributes."""

        class FlexibleCategories(FlextLdifModelsCollections.FlexibleCategories):
            """Flexible categories."""

            def get_entries(
                self,
                category: str,
            ) -> Sequence[FlextLdifModelsDomains.Entry]:
                """Backward-compatible accessor for category entries."""
                return [
                    FlextLdifModelsDomains.Entry.model_validate(value) for value in self.get(category)
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
            WhitelistRules = FlextLdifModelsSettings.WhitelistRules
            WriteFormatOptions = FlextLdifModelsSettings.WriteFormatOptions

        # =================================================================
        # COMPOSITE MODELS — defined here, not in _models
        # =================================================================

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
            EntryFilterConfig: Final = FlextLdifModelsSettings.EntryFilterConfig
            CaseFoldOption: Final = c.Ldif.CaseFoldOption


# =========================================================================
# MODULE ALIASES - Runtime access patterns
# =========================================================================

m = FlextLdifModels

__all__ = ["FlextLdifModels", "m"]
