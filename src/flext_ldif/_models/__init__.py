# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Models package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._models._ldif_namespace import LdifNamespace
    from flext_ldif._models._settings_acl import FlextLdifModelsSettingsAcl
    from flext_ldif._models._settings_criteria import FlextLdifModelsSettingsCriteria
    from flext_ldif._models._settings_migrate import FlextLdifModelsSettingsMigrate
    from flext_ldif._models._settings_misc import FlextLdifModelsSettingsMisc
    from flext_ldif._models._settings_normalization import (
        FlextLdifModelsSettingsNormalization,
    )
    from flext_ldif._models._settings_processing import (
        FlextLdifModelsSettingsProcessing,
    )
    from flext_ldif._models._settings_rules import FlextLdifModelsSettingsRules
    from flext_ldif._models._settings_validation import (
        FlextLdifModelsSettingsValidation,
    )
    from flext_ldif._models.acl_convert import FlextLdifModelsAclConvert
    from flext_ldif._models.base import FlextLdifModelsBases
    from flext_ldif._models.collections import FlextLdifModelsCollections
    from flext_ldif._models.domain_acl import FlextLdifModelsDomainAcl
    from flext_ldif._models.domain_attributes import FlextLdifModelsDomainAttributes
    from flext_ldif._models.domain_dn import FlextLdifModelsDomainDN
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries
    from flext_ldif._models.domain_entry import FlextLdifModelsDomainEntry
    from flext_ldif._models.domain_entry_change import (
        FlextLdifModelsDomainEntryChangeOperation,
    )
    from flext_ldif._models.domain_entry_change_value import (
        FlextLdifModelsDomainEntryChangeOperationValue,
    )
    from flext_ldif._models.domain_entry_control import (
        FlextLdifModelsDomainEntryControl,
    )
    from flext_ldif._models.domain_entry_statistics import (
        FlextLdifModelsDomainEntryStatistics,
    )
    from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata
    from flext_ldif._models.domain_schema import FlextLdifModelsDomainSchema
    from flext_ldif._models.events import FlextLdifModelsEvents
    from flext_ldif._models.processing import FlextLdifModelsProcessing
    from flext_ldif._models.results import FlextLdifModelsResults
    from flext_ldif._models.results_statistics import FlextLdifModelsResultsStatistics
    from flext_ldif._models.settings import FlextLdifModelsSettings


__all__: tuple[str, ...] = (
    "FlextLdifModelsAclConvert",
    "FlextLdifModelsBases",
    "FlextLdifModelsCollections",
    "FlextLdifModelsDomainAcl",
    "FlextLdifModelsDomainAttributes",
    "FlextLdifModelsDomainDN",
    "FlextLdifModelsDomainEntry",
    "FlextLdifModelsDomainEntryChangeOperation",
    "FlextLdifModelsDomainEntryChangeOperationValue",
    "FlextLdifModelsDomainEntryControl",
    "FlextLdifModelsDomainEntryStatistics",
    "FlextLdifModelsDomainMetadata",
    "FlextLdifModelsDomainSchema",
    "FlextLdifModelsDomainsEntries",
    "FlextLdifModelsEvents",
    "FlextLdifModelsProcessing",
    "FlextLdifModelsResults",
    "FlextLdifModelsResultsStatistics",
    "FlextLdifModelsSettings",
    "FlextLdifModelsSettingsAcl",
    "FlextLdifModelsSettingsCriteria",
    "FlextLdifModelsSettingsMigrate",
    "FlextLdifModelsSettingsMisc",
    "FlextLdifModelsSettingsNormalization",
    "FlextLdifModelsSettingsProcessing",
    "FlextLdifModelsSettingsRules",
    "FlextLdifModelsSettingsValidation",
    "LdifNamespace",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifModelsAclConvert": ".acl_convert",
        "FlextLdifModelsBases": ".base",
        "FlextLdifModelsCollections": ".collections",
        "FlextLdifModelsDomainAcl": ".domain_acl",
        "FlextLdifModelsDomainAttributes": ".domain_attributes",
        "FlextLdifModelsDomainDN": ".domain_dn",
        "FlextLdifModelsDomainEntry": ".domain_entry",
        "FlextLdifModelsDomainEntryChangeOperation": ".domain_entry_change",
        "FlextLdifModelsDomainEntryChangeOperationValue": ".domain_entry_change_value",
        "FlextLdifModelsDomainEntryControl": ".domain_entry_control",
        "FlextLdifModelsDomainEntryStatistics": ".domain_entry_statistics",
        "FlextLdifModelsDomainMetadata": ".domain_metadata",
        "FlextLdifModelsDomainSchema": ".domain_schema",
        "FlextLdifModelsDomainsEntries": ".domain_entries",
        "FlextLdifModelsEvents": ".events",
        "FlextLdifModelsProcessing": ".processing",
        "FlextLdifModelsResults": ".results",
        "FlextLdifModelsResultsStatistics": ".results_statistics",
        "FlextLdifModelsSettings": ".settings",
        "FlextLdifModelsSettingsAcl": "._settings_acl",
        "FlextLdifModelsSettingsCriteria": "._settings_criteria",
        "FlextLdifModelsSettingsMigrate": "._settings_migrate",
        "FlextLdifModelsSettingsMisc": "._settings_misc",
        "FlextLdifModelsSettingsNormalization": "._settings_normalization",
        "FlextLdifModelsSettingsProcessing": "._settings_processing",
        "FlextLdifModelsSettingsRules": "._settings_rules",
        "FlextLdifModelsSettingsValidation": "._settings_validation",
        "LdifNamespace": "._ldif_namespace",
    }),
    public_exports=__all__,
)
