# AUTO-GENERATED FILE — Regenerate with: make gen
"""Models package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
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
