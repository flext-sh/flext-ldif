# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Models package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
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
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._settings_acl": ("FlextLdifModelsSettingsAcl",),
            "._settings_criteria": ("FlextLdifModelsSettingsCriteria",),
            "._settings_migrate": ("FlextLdifModelsSettingsMigrate",),
            "._settings_misc": ("FlextLdifModelsSettingsMisc",),
            "._settings_normalization": ("FlextLdifModelsSettingsNormalization",),
            "._settings_processing": ("FlextLdifModelsSettingsProcessing",),
            "._settings_rules": ("FlextLdifModelsSettingsRules",),
            "._settings_validation": ("FlextLdifModelsSettingsValidation",),
            ".acl_convert": ("FlextLdifModelsAclConvert",),
            ".base": ("FlextLdifModelsBases",),
            ".collections": ("FlextLdifModelsCollections",),
            ".domain_acl": ("FlextLdifModelsDomainAcl",),
            ".domain_attributes": ("FlextLdifModelsDomainAttributes",),
            ".domain_dn": ("FlextLdifModelsDomainDN",),
            ".domain_entries": ("FlextLdifModelsDomainsEntries",),
            ".domain_entry": ("FlextLdifModelsDomainEntry",),
            ".domain_metadata": ("FlextLdifModelsDomainMetadata",),
            ".domain_schema": ("FlextLdifModelsDomainSchema",),
            ".events": ("FlextLdifModelsEvents",),
            ".processing": ("FlextLdifModelsProcessing",),
            ".results": ("FlextLdifModelsResults",),
            ".results_statistics": ("FlextLdifModelsResultsStatistics",),
            ".settings": ("FlextLdifModelsSettings",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
