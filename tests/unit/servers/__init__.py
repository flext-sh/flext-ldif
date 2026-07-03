# AUTO-GENERATED FILE — Regenerate with: make gen
"""Servers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.tests.unit.servers.test_apache_servers import (
        TestsTestFlextLdifApacheServers as TestsTestFlextLdifApacheServers,
    )
    from flext_ldif.tests.unit.servers.test_ds389_servers import (
        TestsTestFlextLdifDs389Servers as TestsTestFlextLdifDs389Servers,
    )
    from flext_ldif.tests.unit.servers.test_edge_cases import (
        TestsFlextLdifEdgeCases as TestsFlextLdifEdgeCases,
    )
    from flext_ldif.tests.unit.servers.test_novell_servers import (
        TestsFlextLdifNovellServers as TestsFlextLdifNovellServers,
    )
    from flext_ldif.tests.unit.servers.test_oid_acl_assemble import (
        TestsFlextLdifOidAclAssemble as TestsFlextLdifOidAclAssemble,
        TestsFlextLdifOidAclBuild as TestsFlextLdifOidAclBuild,
        TestsFlextLdifOidAclConvertEntryAcls as TestsFlextLdifOidAclConvertEntryAcls,
        TestsFlextLdifOidAclConvertValues as TestsFlextLdifOidAclConvertValues,
    )
    from flext_ldif.tests.unit.servers.test_oid_acl_convert import (
        TestsFlextLdifOidAclConvertParse as TestsFlextLdifOidAclConvertParse,
    )
    from flext_ldif.tests.unit.servers.test_oid_acl_convert_oud import (
        TestsFlextLdifOidAclConvertPermissions as TestsFlextLdifOidAclConvertPermissions,
        TestsFlextLdifOidAclConvertSubject as TestsFlextLdifOidAclConvertSubject,
        TestsFlextLdifOidAclConvertTarget as TestsFlextLdifOidAclConvertTarget,
    )
    from flext_ldif.tests.unit.servers.test_oid_acl_endtoend import (
        TestsFlextLdifOidAclEndToEnd as TestsFlextLdifOidAclEndToEnd,
    )
    from flext_ldif.tests.unit.servers.test_oid_servers import (
        TestsTestFlextLdifOidServers as TestsTestFlextLdifOidServers,
    )
    from flext_ldif.tests.unit.servers.test_relaxed_servers import (
        TestsTestFlextLdifRelaxedServers as TestsTestFlextLdifRelaxedServers,
    )
    from flext_ldif.tests.unit.servers.test_schema_transformer import (
        TestsFlextLdifSchemaTransformer as TestsFlextLdifSchemaTransformer,
    )
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
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
