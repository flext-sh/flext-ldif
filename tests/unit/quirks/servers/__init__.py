# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit tests for servers."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes
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
        TestSchemaTransformerApplyAttributeTransformations,
        TestSchemaTransformerApplyObjectClassTransformations,
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "ACL_TEST_CASES": ["tests.unit.quirks.servers.test_ds389_quirks", "ACL_TEST_CASES"],
    "ATTRIBUTE_TEST_CASES": ["tests.unit.quirks.servers.test_novell_quirks", "ATTRIBUTE_TEST_CASES"],
    "AclScenario": ["tests.unit.quirks.servers.test_ds389_quirks", "AclScenario"],
    "AclTestCase": ["tests.unit.quirks.servers.test_ds389_quirks", "AclTestCase"],
    "AttributeScenario": ["tests.unit.quirks.servers.test_novell_quirks", "AttributeScenario"],
    "AttributeTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "AttributeTestCase"],
    "ENTRY_TEST_CASES": ["tests.unit.quirks.servers.test_novell_quirks", "ENTRY_TEST_CASES"],
    "EntryScenario": ["tests.unit.quirks.servers.test_novell_quirks", "EntryScenario"],
    "EntryTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "EntryTestCase"],
    "OBJECTCLASS_TEST_CASES": ["tests.unit.quirks.servers.test_novell_quirks", "OBJECTCLASS_TEST_CASES"],
    "ObjectClassScenario": ["tests.unit.quirks.servers.test_novell_quirks", "ObjectClassScenario"],
    "ObjectClassTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "ObjectClassTestCase"],
    "ParseScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "ParseScenario"],
    "RfcTestHelpers": ["tests.unit.quirks.servers.test_novell_quirks", "RfcTestHelpers"],
    "TestDeduplicationHelpers": ["tests.unit.quirks.servers.test_novell_quirks", "TestDeduplicationHelpers"],
    "TestNovellAcls": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellAcls"],
    "TestNovellEntryDetection": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellEntryDetection"],
    "TestNovellSchemaAttributeDetection": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellSchemaAttributeDetection"],
    "TestNovellSchemaAttributeParsing": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellSchemaAttributeParsing"],
    "TestNovellSchemaObjectClassDetection": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellSchemaObjectClassDetection"],
    "TestNovellSchemaObjectClassParsing": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellSchemaObjectClassParsing"],
    "TestSchemaTransformerApplyAttributeTransformations": ["tests.unit.quirks.servers.test_schema_transformer", "TestSchemaTransformerApplyAttributeTransformations"],
    "TestSchemaTransformerApplyObjectClassTransformations": ["tests.unit.quirks.servers.test_schema_transformer", "TestSchemaTransformerApplyObjectClassTransformations"],
    "TestSchemaTransformerNormalizeMatchingRule": ["tests.unit.quirks.servers.test_schema_transformer", "TestSchemaTransformerNormalizeMatchingRule"],
    "TestSchemaTransformerNormalizeSyntaxOid": ["tests.unit.quirks.servers.test_schema_transformer", "TestSchemaTransformerNormalizeSyntaxOid"],
    "TestsFlextLdifEdgeCases": ["tests.unit.quirks.servers.test_edge_cases", "TestsFlextLdifEdgeCases"],
    "TestsFlextLdifNovellInitialization": ["tests.unit.quirks.servers.test_novell_quirks", "TestsFlextLdifNovellInitialization"],
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": ["tests.unit.quirks.servers.test_schema_transformer", "TestsFlextLdifSchemaTransformerNormalizeAttributeName"],
    "TestsTestFlextLdifApacheQuirks": ["tests.unit.quirks.servers.test_apache_quirks", "TestsTestFlextLdifApacheQuirks"],
    "TestsTestFlextLdifDs389Quirks": ["tests.unit.quirks.servers.test_ds389_quirks", "TestsTestFlextLdifDs389Quirks"],
    "TestsTestFlextLdifOidQuirks": ["tests.unit.quirks.servers.test_oid_quirks", "TestsTestFlextLdifOidQuirks"],
    "TestsTestFlextLdifRelaxedQuirks": ["tests.unit.quirks.servers.test_relaxed_quirks", "TestsTestFlextLdifRelaxedQuirks"],
    "WriteScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "WriteScenario"],
    "cleanup_state": ["tests.unit.quirks.servers.test_edge_cases", "cleanup_state"],
    "entry_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "entry_quirk"],
    "ldif_api": ["tests.unit.quirks.servers.test_edge_cases", "ldif_api"],
    "meta_keys": ["tests.unit.quirks.servers.test_relaxed_quirks", "meta_keys"],
    "novell_server": ["tests.unit.quirks.servers.test_novell_quirks", "novell_server"],
    "schema_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "schema_quirk"],
}

__all__ = [
    "ACL_TEST_CASES",
    "ATTRIBUTE_TEST_CASES",
    "ENTRY_TEST_CASES",
    "OBJECTCLASS_TEST_CASES",
    "AclScenario",
    "AclTestCase",
    "AttributeScenario",
    "AttributeTestCase",
    "EntryScenario",
    "EntryTestCase",
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
    "TestSchemaTransformerApplyAttributeTransformations",
    "TestSchemaTransformerApplyObjectClassTransformations",
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
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
