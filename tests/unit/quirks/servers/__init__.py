# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Servers package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.unit.quirks.servers.test_apache_quirks as _tests_unit_quirks_servers_test_apache_quirks

    test_apache_quirks = _tests_unit_quirks_servers_test_apache_quirks
    import tests.unit.quirks.servers.test_ds389_quirks as _tests_unit_quirks_servers_test_ds389_quirks
    from tests.unit.quirks.servers.test_apache_quirks import (
        TestsTestFlextLdifApacheQuirks,
    )

    test_ds389_quirks = _tests_unit_quirks_servers_test_ds389_quirks
    import tests.unit.quirks.servers.test_edge_cases as _tests_unit_quirks_servers_test_edge_cases
    from tests.unit.quirks.servers.test_ds389_quirks import (
        TestsTestFlextLdifDs389Quirks,
    )

    test_edge_cases = _tests_unit_quirks_servers_test_edge_cases
    import tests.unit.quirks.servers.test_novell_quirks as _tests_unit_quirks_servers_test_novell_quirks
    from tests.unit.quirks.servers.test_edge_cases import (
        TestsFlextLdifEdgeCases,
        cleanup_state,
        ldif_api,
    )

    test_novell_quirks = _tests_unit_quirks_servers_test_novell_quirks
    import tests.unit.quirks.servers.test_oid_quirks as _tests_unit_quirks_servers_test_oid_quirks
    from tests.unit.quirks.servers.test_novell_quirks import (
        TestNovellAcls,
        TestNovellEntryDetection,
        TestNovellSchemaAttributeDetection,
        TestNovellSchemaAttributeParsing,
        TestNovellSchemaObjectClassDetection,
        TestNovellSchemaObjectClassParsing,
        TestsFlextLdifNovellInitialization,
        entry_quirk,
        novell_server,
        schema_quirk,
    )

    test_oid_quirks = _tests_unit_quirks_servers_test_oid_quirks
    import tests.unit.quirks.servers.test_relaxed_quirks as _tests_unit_quirks_servers_test_relaxed_quirks
    from tests.unit.quirks.servers.test_oid_quirks import TestsTestFlextLdifOidQuirks

    test_relaxed_quirks = _tests_unit_quirks_servers_test_relaxed_quirks
    import tests.unit.quirks.servers.test_schema_transformer as _tests_unit_quirks_servers_test_schema_transformer
    from tests.unit.quirks.servers.test_relaxed_quirks import (
        TestsTestFlextLdifRelaxedQuirks,
    )

    test_schema_transformer = _tests_unit_quirks_servers_test_schema_transformer
    from tests.unit.quirks.servers.test_schema_transformer import (
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )

    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
_LAZY_IMPORTS = {
    "TestNovellAcls": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellEntryDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaAttributeDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaAttributeParsing": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaObjectClassDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaObjectClassParsing": "tests.unit.quirks.servers.test_novell_quirks",
    "TestSchemaTransformerNormalizeMatchingRule": "tests.unit.quirks.servers.test_schema_transformer",
    "TestSchemaTransformerNormalizeSyntaxOid": "tests.unit.quirks.servers.test_schema_transformer",
    "TestsFlextLdifEdgeCases": "tests.unit.quirks.servers.test_edge_cases",
    "TestsFlextLdifNovellInitialization": "tests.unit.quirks.servers.test_novell_quirks",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": "tests.unit.quirks.servers.test_schema_transformer",
    "TestsTestFlextLdifApacheQuirks": "tests.unit.quirks.servers.test_apache_quirks",
    "TestsTestFlextLdifDs389Quirks": "tests.unit.quirks.servers.test_ds389_quirks",
    "TestsTestFlextLdifOidQuirks": "tests.unit.quirks.servers.test_oid_quirks",
    "TestsTestFlextLdifRelaxedQuirks": "tests.unit.quirks.servers.test_relaxed_quirks",
    "c": ("flext_core.constants", "FlextConstants"),
    "cleanup_state": "tests.unit.quirks.servers.test_edge_cases",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "entry_quirk": "tests.unit.quirks.servers.test_novell_quirks",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "ldif_api": "tests.unit.quirks.servers.test_edge_cases",
    "m": ("flext_core.models", "FlextModels"),
    "novell_server": "tests.unit.quirks.servers.test_novell_quirks",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "schema_quirk": "tests.unit.quirks.servers.test_novell_quirks",
    "t": ("flext_core.typings", "FlextTypes"),
    "test_apache_quirks": "tests.unit.quirks.servers.test_apache_quirks",
    "test_ds389_quirks": "tests.unit.quirks.servers.test_ds389_quirks",
    "test_edge_cases": "tests.unit.quirks.servers.test_edge_cases",
    "test_novell_quirks": "tests.unit.quirks.servers.test_novell_quirks",
    "test_oid_quirks": "tests.unit.quirks.servers.test_oid_quirks",
    "test_relaxed_quirks": "tests.unit.quirks.servers.test_relaxed_quirks",
    "test_schema_transformer": "tests.unit.quirks.servers.test_schema_transformer",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "TestNovellAcls",
    "TestNovellEntryDetection",
    "TestNovellSchemaAttributeDetection",
    "TestNovellSchemaAttributeParsing",
    "TestNovellSchemaObjectClassDetection",
    "TestNovellSchemaObjectClassParsing",
    "TestSchemaTransformerNormalizeMatchingRule",
    "TestSchemaTransformerNormalizeSyntaxOid",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifNovellInitialization",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    "TestsTestFlextLdifApacheQuirks",
    "TestsTestFlextLdifDs389Quirks",
    "TestsTestFlextLdifOidQuirks",
    "TestsTestFlextLdifRelaxedQuirks",
    "c",
    "cleanup_state",
    "d",
    "e",
    "entry_quirk",
    "h",
    "ldif_api",
    "m",
    "novell_server",
    "p",
    "r",
    "s",
    "schema_quirk",
    "t",
    "test_apache_quirks",
    "test_ds389_quirks",
    "test_edge_cases",
    "test_novell_quirks",
    "test_oid_quirks",
    "test_relaxed_quirks",
    "test_schema_transformer",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
