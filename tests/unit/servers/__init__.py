# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit.servers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from .test_apache_servers import TestsFlextLdifApacheServers
    from .test_ds389_servers import TestsFlextLdifDs389Servers
    from .test_edge_cases import TestsFlextLdifEdgeCases, ldif_api
    from .test_novell_servers import TestsFlextLdifNovellServers
    from .test_oid_acl_assemble import TestsFlextLdifOidAclAssemble
    from .test_oid_acl_convert import TestsFlextLdifOidAclConvert
    from .test_oid_acl_convert_oud import TestsFlextLdifOidAclConvertOud
    from .test_oid_acl_endtoend import TestsFlextLdifOidAclEndToEnd
    from .test_oid_servers import TestsFlextLdifOidServers
    from .test_relaxed_servers import TestsFlextLdifRelaxed
    from .test_schema_transformer import TestsFlextLdifSchemaTransformer
__all__: tuple[str, ...] = (
    "TestsFlextLdifApacheServers",
    "TestsFlextLdifDs389Servers",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifNovellServers",
    "TestsFlextLdifOidAclAssemble",
    "TestsFlextLdifOidAclConvert",
    "TestsFlextLdifOidAclConvertOud",
    "TestsFlextLdifOidAclEndToEnd",
    "TestsFlextLdifOidServers",
    "TestsFlextLdifRelaxed",
    "TestsFlextLdifSchemaTransformer",
    "c",
    "d",
    "e",
    "h",
    "ldif_api",
    "m",
    "p",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".test_apache_servers": ("TestsFlextLdifApacheServers",),
            ".test_ds389_servers": ("TestsFlextLdifDs389Servers",),
            ".test_edge_cases": ("TestsFlextLdifEdgeCases", "ldif_api"),
            ".test_novell_servers": ("TestsFlextLdifNovellServers",),
            ".test_oid_acl_assemble": ("TestsFlextLdifOidAclAssemble",),
            ".test_oid_acl_convert": ("TestsFlextLdifOidAclConvert",),
            ".test_oid_acl_convert_oud": ("TestsFlextLdifOidAclConvertOud",),
            ".test_oid_acl_endtoend": ("TestsFlextLdifOidAclEndToEnd",),
            ".test_oid_servers": ("TestsFlextLdifOidServers",),
            ".test_relaxed_servers": ("TestsFlextLdifRelaxed",),
            ".test_schema_transformer": ("TestsFlextLdifSchemaTransformer",),
            "flext_tests": (
                "c",
                "d",
                "e",
                "h",
                "m",
                "p",
                "r",
                "s",
                "t",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
                "u",
                "x",
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
