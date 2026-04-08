# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Servers package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

_LAZY_IMPORTS = merge_lazy_imports(
    (
        "flext_ldif.servers._base",
        "flext_ldif.servers._oid",
        "flext_ldif.servers._oud",
        "flext_ldif.servers._rfc",
    ),
    {
        "FlextLdifServersAd": ("flext_ldif.servers.ad", "FlextLdifServersAd"),
        "FlextLdifServersApache": (
            "flext_ldif.servers.apache",
            "FlextLdifServersApache",
        ),
        "FlextLdifServersBase": ("flext_ldif.servers.base", "FlextLdifServersBase"),
        "FlextLdifServersDs389": ("flext_ldif.servers.ds389", "FlextLdifServersDs389"),
        "FlextLdifServersNovell": (
            "flext_ldif.servers.novell",
            "FlextLdifServersNovell",
        ),
        "FlextLdifServersOid": ("flext_ldif.servers.oid", "FlextLdifServersOid"),
        "FlextLdifServersOpenldap": (
            "flext_ldif.servers.openldap",
            "FlextLdifServersOpenldap",
        ),
        "FlextLdifServersOpenldap1": (
            "flext_ldif.servers.openldap1",
            "FlextLdifServersOpenldap1",
        ),
        "FlextLdifServersOud": ("flext_ldif.servers.oud", "FlextLdifServersOud"),
        "FlextLdifServersRelaxed": (
            "flext_ldif.servers.relaxed",
            "FlextLdifServersRelaxed",
        ),
        "FlextLdifServersRfc": ("flext_ldif.servers.rfc", "FlextLdifServersRfc"),
        "FlextLdifServersTivoli": (
            "flext_ldif.servers.tivoli",
            "FlextLdifServersTivoli",
        ),
        "_base": "flext_ldif.servers._base",
        "_oid": "flext_ldif.servers._oid",
        "_oud": "flext_ldif.servers._oud",
        "_rfc": "flext_ldif.servers._rfc",
        "ad": "flext_ldif.servers.ad",
        "apache": "flext_ldif.servers.apache",
        "base": "flext_ldif.servers.base",
        "ds389": "flext_ldif.servers.ds389",
        "novell": "flext_ldif.servers.novell",
        "oid": "flext_ldif.servers.oid",
        "openldap": "flext_ldif.servers.openldap",
        "openldap1": "flext_ldif.servers.openldap1",
        "oud": "flext_ldif.servers.oud",
        "relaxed": "flext_ldif.servers.relaxed",
        "rfc": "flext_ldif.servers.rfc",
        "tivoli": "flext_ldif.servers.tivoli",
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("logger", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
