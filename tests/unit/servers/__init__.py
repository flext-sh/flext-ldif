# AUTO-GENERATED FILE — Regenerate with: make gen
"""Servers package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_apache_servers": ("TestsTestFlextLdifApacheServers",),
        ".test_ds389_servers": ("TestsTestFlextLdifDs389Servers",),
        ".test_edge_cases": ("TestsFlextLdifEdgeCases",),
        ".test_novell_servers": ("TestsFlextLdifNovellServers",),
        ".test_oid_acl_assemble": (
            "TestsFlextLdifOidAclAssemble",
            "TestsFlextLdifOidAclBuild",
            "TestsFlextLdifOidAclConvertEntryAcls",
            "TestsFlextLdifOidAclConvertValues",
        ),
        ".test_oid_acl_convert": ("TestsFlextLdifOidAclConvertParse",),
        ".test_oid_acl_convert_oud": (
            "TestsFlextLdifOidAclConvertPermissions",
            "TestsFlextLdifOidAclConvertSubject",
            "TestsFlextLdifOidAclConvertTarget",
        ),
        ".test_oid_acl_endtoend": ("TestsFlextLdifOidAclEndToEnd",),
        ".test_oid_servers": ("TestsTestFlextLdifOidServers",),
        ".test_relaxed_servers": ("TestsTestFlextLdifRelaxedServers",),
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
