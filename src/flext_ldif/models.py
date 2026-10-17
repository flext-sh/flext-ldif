# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, TypeAliasType

from flext_cli import FlextCliModels

from flext_ldif._models import (
    FlextLdifModelsAclConvert,
    FlextLdifModelsBases,
    FlextLdifModelsBasesParts,
    FlextLdifModelsCollections,
    FlextLdifModelsComposite,
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
    FlextLdifNamespace,
)


class FlextLdifModels(FlextCliModels):
    """LDIF domain models — flat façade with MRO class inheritance.

    Architecture: Domain layer helper
    All nested classes inherit via MRO from their ``models`` implementations.
    Types live in ``typings.py``, constants in ``constants.py``.
    """

    # The composite namespace carries only ``m.BaseModel`` descendants whose
    # ``model_config`` is the models-facade ``ConfigDict``; the settings-derived
    # and value/control model classes stay reachable through their owning
    # aliases (``Ldif.Control`` / ``Ldif.ChangeOperationValue``) instead of
    # direct inheritance, which would clash on ``model_config``/``value``.
    class Ldif(
        FlextLdifModelsBases,
        FlextLdifModelsBasesParts,
        FlextLdifModelsCollections,
        FlextLdifModelsComposite,
        FlextLdifNamespace,
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

        # =================================================================
        # COMPOSITE MODELS — owned by ``_models/composite.py``
        # =================================================================

        Stats: ClassVar[type[FlextCliModels.BaseModel]] = FlextLdifModelsComposite.Stats

        OidAclMetadataConfig: ClassVar[type[FlextCliModels.BaseModel]] = (
            FlextLdifModelsComposite.OidAclMetadataConfig
        )

    # Top-level facade aliases: the api-freeze contract requires
    # ``flext_ldif.m.X`` and ``flext_ldif.FlextLdifModels.X`` to be the same
    # object for every published model.
    Entry: ClassVar[TypeAliasType] = FlextLdifModelsComposite.Entry


m = FlextLdifModels

__all__: list[str] = ["FlextLdifModels", "m"]
