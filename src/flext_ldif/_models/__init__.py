# AUTO-GENERATED FILE — Regenerate with: make gen
"""Models package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

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
    from flext_ldif._models.metadata import FlextLdifModelsMetadata
    from flext_ldif._models.processing import FlextLdifModelsProcessing
    from flext_ldif._models.results import FlextLdifModelsResults
    from flext_ldif._models.settings import FlextLdifModelsSettings
_LAZY_IMPORTS = build_lazy_import_map(
    {
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
        ".metadata": ("FlextLdifModelsMetadata",),
        ".processing": ("FlextLdifModelsProcessing",),
        ".results": ("FlextLdifModelsResults",),
        ".settings": ("FlextLdifModelsSettings",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
