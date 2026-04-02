# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit tests for servers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from tests.unit.quirks.servers import (
        test_apache_quirks,
        test_ds389_quirks,
        test_edge_cases,
        test_novell_quirks,
        test_oid_quirks,
        test_relaxed_quirks,
        test_schema_transformer,
    )
    from tests.unit.quirks.servers.test_apache_quirks import (
        TestsTestFlextLdifApacheQuirks,
    )
    from tests.unit.quirks.servers.test_ds389_quirks import (
        ACL_TEST_CASES,
        AclScenario,
        AclTestCase,
        TestsTestFlextLdifDs389Quirks,
    )
    from tests.unit.quirks.servers.test_edge_cases import (
        TestsFlextLdifEdgeCases,
        cleanup_state,
        ldif_api,
    )
    from tests.unit.quirks.servers.test_novell_quirks import (
        ATTRIBUTE_TEST_CASES,
        ENTRY_TEST_CASES,
        OBJECTCLASS_TEST_CASES,
        AttributeScenario,
        AttributeTestCase,
        EntryScenario,
        EntryTestCase,
        ObjectClassScenario,
        ObjectClassTestCase,
        RfcTestHelpers,
        TestDeduplicationHelpers,
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
    from tests.unit.quirks.servers.test_oid_quirks import TestsTestFlextLdifOidQuirks
    from tests.unit.quirks.servers.test_relaxed_quirks import (
        ParseScenario,
        TestsTestFlextLdifRelaxedQuirks,
        WriteScenario,
        meta_keys,
    )
    from tests.unit.quirks.servers.test_schema_transformer import (
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )

    from flext_core import FlextTypes

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "ACL_TEST_CASES": "tests.unit.quirks.servers.test_ds389_quirks",
    "ATTRIBUTE_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "AclScenario": "tests.unit.quirks.servers.test_ds389_quirks",
    "AclTestCase": "tests.unit.quirks.servers.test_ds389_quirks",
    "AttributeScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "AttributeTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "ENTRY_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "EntryScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "EntryTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "OBJECTCLASS_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "ObjectClassScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "ObjectClassTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "ParseScenario": "tests.unit.quirks.servers.test_relaxed_quirks",
    "RfcTestHelpers": "tests.unit.quirks.servers.test_novell_quirks",
    "TestDeduplicationHelpers": "tests.unit.quirks.servers.test_novell_quirks",
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
    "WriteScenario": "tests.unit.quirks.servers.test_relaxed_quirks",
    "cleanup_state": "tests.unit.quirks.servers.test_edge_cases",
    "entry_quirk": "tests.unit.quirks.servers.test_novell_quirks",
    "ldif_api": "tests.unit.quirks.servers.test_edge_cases",
    "meta_keys": "tests.unit.quirks.servers.test_relaxed_quirks",
    "novell_server": "tests.unit.quirks.servers.test_novell_quirks",
    "schema_quirk": "tests.unit.quirks.servers.test_novell_quirks",
    "test_apache_quirks": "tests.unit.quirks.servers.test_apache_quirks",
    "test_ds389_quirks": "tests.unit.quirks.servers.test_ds389_quirks",
    "test_edge_cases": "tests.unit.quirks.servers.test_edge_cases",
    "test_novell_quirks": "tests.unit.quirks.servers.test_novell_quirks",
    "test_oid_quirks": "tests.unit.quirks.servers.test_oid_quirks",
    "test_relaxed_quirks": "tests.unit.quirks.servers.test_relaxed_quirks",
    "test_schema_transformer": "tests.unit.quirks.servers.test_schema_transformer",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
