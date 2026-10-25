# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import FlextCliModels

from flext_ldif._models import (
    FlextLdifModelsAclConvert,
    FlextLdifModelsBases,
    FlextLdifModelsBasesParts,
    FlextLdifModelsCollections,
    FlextLdifModelsComposite,
    FlextLdifModelsConfig,
    FlextLdifModelsDomainAcl,
    FlextLdifModelsDomainAttributes,
    FlextLdifModelsDomainDN,
    FlextLdifModelsDomainEntry,
    FlextLdifModelsDomainEntryChangeOperation,
    FlextLdifModelsDomainEntryChangeOperationValue,
    FlextLdifModelsDomainEntryControl,
    FlextLdifModelsDomainEntryStatistics,
    FlextLdifModelsDomainMetadata,
    FlextLdifModelsDomainSchema,
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsEvents,
    FlextLdifModelsProcessing,
    FlextLdifModelsResults,
    FlextLdifModelsResultsStatistics,
    FlextLdifModelsSettings,
    FlextLdifModelsSettingsAcl,
    FlextLdifModelsSettingsCriteria,
    FlextLdifModelsSettingsMigrate,
    FlextLdifModelsSettingsMisc,
    FlextLdifModelsSettingsNormalization,
    FlextLdifModelsSettingsProcessing,
    FlextLdifModelsSettingsRules,
    FlextLdifModelsSettingsValidation,
)


class FlextLdifModels(FlextCliModels):
    """LDIF domain models — flat façade with MRO class inheritance.

    Architecture: Domain layer helper
    All nested classes inherit via MRO from their ``models`` implementations.
    Types live in ``typings.py``, constants in ``constants.py``.
    """

    class Ldif(
        FlextLdifModelsBases,
        FlextLdifModelsBasesParts,
        FlextLdifModelsCollections,
        FlextLdifModelsComposite,
        FlextLdifModelsConfig,
        FlextLdifModelsDomainsEntries,
        FlextLdifModelsDomainEntry,
        FlextLdifModelsDomainEntryChangeOperation,
        FlextLdifModelsDomainMetadata,
        FlextLdifModelsAclConvert,
        FlextLdifModelsDomainAcl,
        FlextLdifModelsDomainAttributes,
        FlextLdifModelsDomainSchema,
        FlextLdifModelsDomainDN,
        FlextLdifModelsDomainEntryChangeOperationValue,
        FlextLdifModelsDomainEntryControl,
        FlextLdifModelsDomainEntryStatistics,
        FlextLdifModelsEvents,
        FlextLdifModelsProcessing,
        FlextLdifModelsResults,
        FlextLdifModelsResultsStatistics,
        FlextLdifModelsSettings,
        FlextLdifModelsSettingsAcl,
        FlextLdifModelsSettingsNormalization,
        FlextLdifModelsSettingsProcessing,
        FlextLdifModelsSettingsCriteria,
        FlextLdifModelsSettingsRules,
        FlextLdifModelsSettingsMigrate,
        FlextLdifModelsSettingsValidation,
        FlextLdifModelsSettingsMisc,
    ):
        """LDIF namespace for cross-project access."""


m = FlextLdifModels
__all__: list[str] = ["FlextLdifModels", "m"]
