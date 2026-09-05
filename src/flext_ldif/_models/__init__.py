# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Models package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from ._settings_acl import FlextLdifModelsSettingsAcl
    from ._settings_criteria import FlextLdifModelsSettingsCriteria
    from ._settings_migrate import FlextLdifModelsSettingsMigrate
    from ._settings_misc import FlextLdifModelsSettingsMisc
    from ._settings_normalization import FlextLdifModelsSettingsNormalization
    from ._settings_processing import FlextLdifModelsSettingsProcessing
    from ._settings_rules import FlextLdifModelsSettingsRules
    from ._settings_validation import FlextLdifModelsSettingsValidation
    from .acl_convert import FlextLdifModelsAclConvert
    from .base import FlextLdifModelsBases
    from .collections import FlextLdifModelsCollections
    from .domain_acl import FlextLdifModelsDomainAcl
    from .domain_attributes import FlextLdifModelsDomainAttributes
    from .domain_dn import FlextLdifModelsDomainDN
    from .domain_entries import FlextLdifModelsDomainsEntries
    from .domain_entry import FlextLdifModelsDomainEntry
    from .domain_metadata import FlextLdifModelsDomainMetadata
    from .domain_schema import FlextLdifModelsDomainSchema
    from .events import FlextLdifModelsEvents
    from .processing import FlextLdifModelsProcessing
    from .results import FlextLdifModelsResults
    from .settings import FlextLdifModelsSettings
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
            ".settings": ("FlextLdifModelsSettings",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
