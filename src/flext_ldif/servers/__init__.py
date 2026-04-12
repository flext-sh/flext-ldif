# AUTO-GENERATED FILE — Regenerate with: make gen
"""Servers package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

_LAZY_IMPORTS = merge_lazy_imports(
    (
        "._base",
        "._oid",
        "._oud",
        "._rfc",
    ),
    build_lazy_import_map(
        {
            ".ad": ("FlextLdifServersAd",),
            ".apache": ("FlextLdifServersApache",),
            ".base": ("FlextLdifServersBase",),
            ".ds389": ("FlextLdifServersDs389",),
            ".novell": ("FlextLdifServersNovell",),
            ".oid": ("FlextLdifServersOid",),
            ".openldap": ("FlextLdifServersOpenldap",),
            ".openldap1": ("FlextLdifServersOpenldap1",),
            ".oud": ("FlextLdifServersOud",),
            ".relaxed": ("FlextLdifServersRelaxed",),
            ".rfc": ("FlextLdifServersRfc",),
            ".tivoli": ("FlextLdifServersTivoli",),
        },
    ),
    exclude_names=(
        "FlextDispatcher",
        "FlextLogger",
        "FlextRegistry",
        "FlextRuntime",
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
