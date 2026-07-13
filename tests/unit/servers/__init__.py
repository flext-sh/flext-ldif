# AUTO-GENERATED FILE — Regenerate with: make gen
"""Servers package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_apache_servers": ("TestsFlextLdifApacheServers",),
        ".test_ds389_servers": ("TestsFlextLdifDs389Servers",),
        ".test_edge_cases": ("TestsFlextLdifEdgeCases",),
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
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
