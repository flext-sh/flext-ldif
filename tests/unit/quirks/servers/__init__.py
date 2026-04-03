# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Servers package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
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
    from flext_ldif import (
        test_apache_quirks,
        test_ds389_quirks,
        test_edge_cases,
        test_novell_quirks,
        test_oid_quirks,
        test_relaxed_quirks,
        test_schema_transformer,
    )
    from flext_ldif.test_apache_quirks import TestsTestFlextLdifApacheQuirks
    from flext_ldif.test_ds389_quirks import (
        ACL_TEST_CASES,
        AclScenario,
        TestsTestFlextLdifDs389Quirks,
        acl_line,
        expected_kind,
        expected_success,
    )
    from flext_ldif.test_edge_cases import cleanup_state, ldif_api
    from flext_ldif.test_novell_quirks import (
        ATTRIBUTE_TEST_CASES,
        ENTRY_TEST_CASES,
        OBJECTCLASS_TEST_CASES,
        AttributeScenario,
        EntryScenario,
        ObjectClassScenario,
        RfcTestHelpers,
        TestDeduplicationHelpers,
        attr_definition,
        attributes,
        entry_dn,
        entry_quirk,
        expected_can_handle,
        expected_name,
        expected_oid,
        novell_server,
        oc_definition,
        quirk,
        scenario,
        schema_quirk,
    )
    from flext_ldif.test_oid_quirks import TestsTestFlextLdifOidQuirks
    from flext_ldif.test_relaxed_quirks import (
        ParseScenario,
        TestsTestFlextLdifRelaxedQuirks,
        WriteScenario,
        meta_keys,
    )
    from flext_ldif.test_schema_transformer import (
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "ACL_TEST_CASES": "flext_ldif.test_ds389_quirks",
    "ATTRIBUTE_TEST_CASES": "flext_ldif.test_novell_quirks",
    "AclScenario": "flext_ldif.test_ds389_quirks",
    "AttributeScenario": "flext_ldif.test_novell_quirks",
    "ENTRY_TEST_CASES": "flext_ldif.test_novell_quirks",
    "EntryScenario": "flext_ldif.test_novell_quirks",
    "OBJECTCLASS_TEST_CASES": "flext_ldif.test_novell_quirks",
    "ObjectClassScenario": "flext_ldif.test_novell_quirks",
    "ParseScenario": "flext_ldif.test_relaxed_quirks",
    "RfcTestHelpers": "flext_ldif.test_novell_quirks",
    "TestDeduplicationHelpers": "flext_ldif.test_novell_quirks",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": "flext_ldif.test_schema_transformer",
    "TestsTestFlextLdifApacheQuirks": "flext_ldif.test_apache_quirks",
    "TestsTestFlextLdifDs389Quirks": "flext_ldif.test_ds389_quirks",
    "TestsTestFlextLdifOidQuirks": "flext_ldif.test_oid_quirks",
    "TestsTestFlextLdifRelaxedQuirks": "flext_ldif.test_relaxed_quirks",
    "WriteScenario": "flext_ldif.test_relaxed_quirks",
    "acl_line": "flext_ldif.test_ds389_quirks",
    "attr_definition": "flext_ldif.test_novell_quirks",
    "attributes": "flext_ldif.test_novell_quirks",
    "c": ("flext_core.constants", "FlextConstants"),
    "cleanup_state": "flext_ldif.test_edge_cases",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "entry_dn": "flext_ldif.test_novell_quirks",
    "entry_quirk": "flext_ldif.test_novell_quirks",
    "expected_can_handle": "flext_ldif.test_novell_quirks",
    "expected_kind": "flext_ldif.test_ds389_quirks",
    "expected_name": "flext_ldif.test_novell_quirks",
    "expected_oid": "flext_ldif.test_novell_quirks",
    "expected_success": "flext_ldif.test_ds389_quirks",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "ldif_api": "flext_ldif.test_edge_cases",
    "m": ("flext_core.models", "FlextModels"),
    "meta_keys": "flext_ldif.test_relaxed_quirks",
    "novell_server": "flext_ldif.test_novell_quirks",
    "oc_definition": "flext_ldif.test_novell_quirks",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "quirk": "flext_ldif.test_novell_quirks",
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "scenario": "flext_ldif.test_novell_quirks",
    "schema_quirk": "flext_ldif.test_novell_quirks",
    "t": ("flext_core.typings", "FlextTypes"),
    "test_apache_quirks": "flext_ldif.test_apache_quirks",
    "test_ds389_quirks": "flext_ldif.test_ds389_quirks",
    "test_edge_cases": "flext_ldif.test_edge_cases",
    "test_novell_quirks": "flext_ldif.test_novell_quirks",
    "test_oid_quirks": "flext_ldif.test_oid_quirks",
    "test_relaxed_quirks": "flext_ldif.test_relaxed_quirks",
    "test_schema_transformer": "flext_ldif.test_schema_transformer",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
