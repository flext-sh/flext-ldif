# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit tests for servers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "ACL_TEST_CASES": ["tests.unit.quirks.servers.test_ds389_quirks", "ACL_TEST_CASES"],
    "ATTRIBUTE_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ATTRIBUTE_TEST_CASES",
    ],
    "AclScenario": ["tests.unit.quirks.servers.test_ds389_quirks", "AclScenario"],
    "AclTestCase": ["tests.unit.quirks.servers.test_ds389_quirks", "AclTestCase"],
    "AttributeScenario": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeScenario",
    ],
    "AttributeTestCase": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeTestCase",
    ],
    "ENTRY_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ENTRY_TEST_CASES",
    ],
    "EntryScenario": ["tests.unit.quirks.servers.test_novell_quirks", "EntryScenario"],
    "EntryTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "EntryTestCase"],
    "OBJECTCLASS_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "OBJECTCLASS_TEST_CASES",
    ],
    "ObjectClassScenario": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassScenario",
    ],
    "ObjectClassTestCase": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassTestCase",
    ],
    "ParseScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "ParseScenario"],
    "RfcTestHelpers": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "RfcTestHelpers",
    ],
    "TestDeduplicationHelpers": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestDeduplicationHelpers",
    ],
    "TestNovellAcls": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellAcls",
    ],
    "TestNovellEntryDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellEntryDetection",
    ],
    "TestNovellSchemaAttributeDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeDetection",
    ],
    "TestNovellSchemaAttributeParsing": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeParsing",
    ],
    "TestNovellSchemaObjectClassDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassDetection",
    ],
    "TestNovellSchemaObjectClassParsing": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassParsing",
    ],
    "TestSchemaTransformerNormalizeMatchingRule": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeMatchingRule",
    ],
    "TestSchemaTransformerNormalizeSyntaxOid": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeSyntaxOid",
    ],
    "TestsFlextLdifEdgeCases": [
        "tests.unit.quirks.servers.test_edge_cases",
        "TestsFlextLdifEdgeCases",
    ],
    "TestsFlextLdifNovellInitialization": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestsFlextLdifNovellInitialization",
    ],
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    ],
    "TestsTestFlextLdifApacheQuirks": [
        "tests.unit.quirks.servers.test_apache_quirks",
        "TestsTestFlextLdifApacheQuirks",
    ],
    "TestsTestFlextLdifDs389Quirks": [
        "tests.unit.quirks.servers.test_ds389_quirks",
        "TestsTestFlextLdifDs389Quirks",
    ],
    "TestsTestFlextLdifOidQuirks": [
        "tests.unit.quirks.servers.test_oid_quirks",
        "TestsTestFlextLdifOidQuirks",
    ],
    "TestsTestFlextLdifRelaxedQuirks": [
        "tests.unit.quirks.servers.test_relaxed_quirks",
        "TestsTestFlextLdifRelaxedQuirks",
    ],
    "WriteScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "WriteScenario"],
    "cleanup_state": ["tests.unit.quirks.servers.test_edge_cases", "cleanup_state"],
    "entry_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "entry_quirk"],
    "ldif_api": ["tests.unit.quirks.servers.test_edge_cases", "ldif_api"],
    "meta_keys": ["tests.unit.quirks.servers.test_relaxed_quirks", "meta_keys"],
    "novell_server": ["tests.unit.quirks.servers.test_novell_quirks", "novell_server"],
    "schema_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "schema_quirk"],
    "test_apache_quirks": ["tests.unit.quirks.servers.test_apache_quirks", ""],
    "test_ds389_quirks": ["tests.unit.quirks.servers.test_ds389_quirks", ""],
    "test_edge_cases": ["tests.unit.quirks.servers.test_edge_cases", ""],
    "test_novell_quirks": ["tests.unit.quirks.servers.test_novell_quirks", ""],
    "test_oid_quirks": ["tests.unit.quirks.servers.test_oid_quirks", ""],
    "test_relaxed_quirks": ["tests.unit.quirks.servers.test_relaxed_quirks", ""],
    "test_schema_transformer": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "",
    ],
}

_EXPORTS: Sequence[str] = [
    "ACL_TEST_CASES",
    "ATTRIBUTE_TEST_CASES",
    "AclScenario",
    "AclTestCase",
    "AttributeScenario",
    "AttributeTestCase",
    "ENTRY_TEST_CASES",
    "EntryScenario",
    "EntryTestCase",
    "OBJECTCLASS_TEST_CASES",
    "ObjectClassScenario",
    "ObjectClassTestCase",
    "ParseScenario",
    "RfcTestHelpers",
    "TestDeduplicationHelpers",
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
    "WriteScenario",
    "cleanup_state",
    "entry_quirk",
    "ldif_api",
    "meta_keys",
    "novell_server",
    "schema_quirk",
    "test_apache_quirks",
    "test_ds389_quirks",
    "test_edge_cases",
    "test_novell_quirks",
    "test_oid_quirks",
    "test_relaxed_quirks",
    "test_schema_transformer",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
