# AUTO-GENERATED FILE — Regenerate with: make gen
"""Models package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._models._settings_acl import (
        FlextLdifModelsSettingsAcl as FlextLdifModelsSettingsAcl,
    )
    from flext_ldif._models._settings_criteria import (
        FlextLdifModelsSettingsCriteria as FlextLdifModelsSettingsCriteria,
    )
    from flext_ldif._models._settings_migrate import (
        FlextLdifModelsSettingsMigrate as FlextLdifModelsSettingsMigrate,
    )
    from flext_ldif._models._settings_misc import (
        FlextLdifModelsSettingsMisc as FlextLdifModelsSettingsMisc,
    )
    from flext_ldif._models._settings_normalization import (
        FlextLdifModelsSettingsNormalization as FlextLdifModelsSettingsNormalization,
    )
    from flext_ldif._models._settings_processing import (
        FlextLdifModelsSettingsProcessing as FlextLdifModelsSettingsProcessing,
    )
    from flext_ldif._models._settings_rules import (
        FlextLdifModelsSettingsRules as FlextLdifModelsSettingsRules,
    )
    from flext_ldif._models._settings_validation import (
        FlextLdifModelsSettingsValidation as FlextLdifModelsSettingsValidation,
    )
    from flext_ldif._models.acl_convert import (
        FlextLdifModelsAclConvert as FlextLdifModelsAclConvert,
    )
    from flext_ldif._models.base import FlextLdifModelsBases as FlextLdifModelsBases
    from flext_ldif._models.collections import (
        FlextLdifModelsCollections as FlextLdifModelsCollections,
    )
    from flext_ldif._models.domain_acl import (
        FlextLdifModelsDomainAcl as FlextLdifModelsDomainAcl,
    )
    from flext_ldif._models.domain_attributes import (
        FlextLdifModelsDomainAttributes as FlextLdifModelsDomainAttributes,
    )
    from flext_ldif._models.domain_dn import (
        FlextLdifModelsDomainDN as FlextLdifModelsDomainDN,
    )
    from flext_ldif._models.domain_entries import (
        FlextLdifModelsDomainsEntries as FlextLdifModelsDomainsEntries,
    )
    from flext_ldif._models.domain_entry import (
        FlextLdifModelsDomainEntry as FlextLdifModelsDomainEntry,
    )
    from flext_ldif._models.domain_metadata import (
        FlextLdifModelsDomainMetadata as FlextLdifModelsDomainMetadata,
    )
    from flext_ldif._models.domain_schema import (
        FlextLdifModelsDomainSchema as FlextLdifModelsDomainSchema,
    )
    from flext_ldif._models.events import FlextLdifModelsEvents as FlextLdifModelsEvents
    from flext_ldif._models.processing import (
        FlextLdifModelsProcessing as FlextLdifModelsProcessing,
    )
    from flext_ldif._models.results import (
        FlextLdifModelsResults as FlextLdifModelsResults,
    )
    from flext_ldif._models.settings import (
        FlextLdifModelsSettings as FlextLdifModelsSettings,
    )
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
