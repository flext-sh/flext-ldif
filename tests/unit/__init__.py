# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

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
        constants,
        protocols,
        services,
        test_acl_registry,
        test_migration_pipeline,
        test_migration_pipeline_quirks,
        test_protocols,
        test_quirks_standardization,
        test_typings,
        test_utilities_comprehensive,
        test_utilities_core,
        test_version,
        utilities,
    )
    from flext_ldif.__init__ import TestsFlextLdifVersion
    from flext_ldif._utilities.oid import TestFlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import TestFlextLdifUtilitiesParser
    from flext_ldif._utilities.server import OidServer
    from flext_ldif.constants import (
        GetAclAttributesServerType,
        IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry,
    )
    from flext_ldif.quirks.servers import (
        ACL_TEST_CASES,
        ATTRIBUTE_TEST_CASES,
        ENTRY_TEST_CASES,
        OBJECTCLASS_TEST_CASES,
        AclScenario,
        AttributeScenario,
        EntryScenario,
        ObjectClassScenario,
        ParseScenario,
        RfcTestHelpers,
        TestDeduplicationHelpers,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
        TestsTestFlextLdifApacheQuirks,
        TestsTestFlextLdifDs389Quirks,
        TestsTestFlextLdifOidQuirks,
        TestsTestFlextLdifRelaxedQuirks,
        WriteScenario,
        acl_line,
        attr_definition,
        attributes,
        cleanup_state,
        entry_dn,
        entry_quirk,
        expected_can_handle,
        expected_kind,
        expected_name,
        expected_oid,
        expected_success,
        ldif_api,
        meta_keys,
        novell_server,
        oc_definition,
        quirk,
        scenario,
        schema_quirk,
    )
    from flext_ldif.services import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants,
        TestsTestFlextLdifMigrationPipeline,
    )
    from flext_ldif.test_migration_pipeline import TestsFlextLdifMigrationPipeline
    from flext_ldif.test_migration_pipeline_quirks import OidTestConstants
    from flext_ldif.test_typings import TestFlextLdifTypesStructure
    from flext_ldif.utilities import (
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestFlextLdifUtilitiesComprehensive,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
    )

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    (
        "flext_ldif.__init__",
        "flext_ldif.constants",
        "flext_ldif.protocols",
        "flext_ldif.services",
        "flext_ldif.utilities",
    ),
    {
        "ACL_TEST_CASES": "flext_ldif.quirks.servers.test_ds389_quirks",
        "ATTRIBUTE_TEST_CASES": "flext_ldif.quirks.servers.test_novell_quirks",
        "AclScenario": "flext_ldif.quirks.servers.test_ds389_quirks",
        "AttributeScenario": "flext_ldif.quirks.servers.test_novell_quirks",
        "ENTRY_TEST_CASES": "flext_ldif.quirks.servers.test_novell_quirks",
        "EntryScenario": "flext_ldif.quirks.servers.test_novell_quirks",
        "OBJECTCLASS_TEST_CASES": "flext_ldif.quirks.servers.test_novell_quirks",
        "ObjectClassScenario": "flext_ldif.quirks.servers.test_novell_quirks",
        "OidServer": "flext_ldif._utilities.server.test_server_utilities",
        "OidTestConstants": "flext_ldif.test_migration_pipeline_quirks",
        "ParseScenario": "flext_ldif.quirks.servers.test_relaxed_quirks",
        "RfcTestHelpers": "flext_ldif.quirks.servers.test_novell_quirks",
        "TestDeduplicationHelpers": "flext_ldif.quirks.servers.test_novell_quirks",
        "TestFlextLdifTypesStructure": "flext_ldif.test_typings",
        "TestFlextLdifUtilitiesOID": "flext_ldif._utilities.oid.test_oid_utilities",
        "TestFlextLdifUtilitiesParser": "flext_ldif._utilities.parser.test_parser_utilities",
        "TestsFlextLdifMigrationPipeline": "flext_ldif.test_migration_pipeline",
        "TestsFlextLdifSchemaTransformerNormalizeAttributeName": "flext_ldif.quirks.servers.test_schema_transformer",
        "TestsTestFlextLdifApacheQuirks": "flext_ldif.quirks.servers.test_apache_quirks",
        "TestsTestFlextLdifDs389Quirks": "flext_ldif.quirks.servers.test_ds389_quirks",
        "TestsTestFlextLdifOidQuirks": "flext_ldif.quirks.servers.test_oid_quirks",
        "TestsTestFlextLdifRelaxedQuirks": "flext_ldif.quirks.servers.test_relaxed_quirks",
        "WriteScenario": "flext_ldif.quirks.servers.test_relaxed_quirks",
        "acl_line": "flext_ldif.quirks.servers.test_ds389_quirks",
        "attr_definition": "flext_ldif.quirks.servers.test_novell_quirks",
        "attributes": "flext_ldif.quirks.servers.test_novell_quirks",
        "c": ("flext_core.constants", "FlextConstants"),
        "cleanup_state": "flext_ldif.quirks.servers.test_edge_cases",
        "constants": "flext_ldif.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "entry_dn": "flext_ldif.quirks.servers.test_novell_quirks",
        "entry_quirk": "flext_ldif.quirks.servers.test_novell_quirks",
        "expected_can_handle": "flext_ldif.quirks.servers.test_novell_quirks",
        "expected_kind": "flext_ldif.quirks.servers.test_ds389_quirks",
        "expected_name": "flext_ldif.quirks.servers.test_novell_quirks",
        "expected_oid": "flext_ldif.quirks.servers.test_novell_quirks",
        "expected_success": "flext_ldif.quirks.servers.test_ds389_quirks",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "ldif_api": "flext_ldif.quirks.servers.test_edge_cases",
        "m": ("flext_core.models", "FlextModels"),
        "meta_keys": "flext_ldif.quirks.servers.test_relaxed_quirks",
        "novell_server": "flext_ldif.quirks.servers.test_novell_quirks",
        "oc_definition": "flext_ldif.quirks.servers.test_novell_quirks",
        "p": ("flext_core.protocols", "FlextProtocols"),
        "protocols": "flext_ldif.protocols",
        "quirk": "flext_ldif.quirks.servers.test_novell_quirks",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "scenario": "flext_ldif.quirks.servers.test_novell_quirks",
        "schema_quirk": "flext_ldif.quirks.servers.test_novell_quirks",
        "services": "flext_ldif.services",
        "t": ("flext_core.typings", "FlextTypes"),
        "test_acl_registry": "flext_ldif.test_acl_registry",
        "test_migration_pipeline": "flext_ldif.test_migration_pipeline",
        "test_migration_pipeline_quirks": "flext_ldif.test_migration_pipeline_quirks",
        "test_protocols": "flext_ldif.test_protocols",
        "test_quirks_standardization": "flext_ldif.test_quirks_standardization",
        "test_typings": "flext_ldif.test_typings",
        "test_utilities_comprehensive": "flext_ldif.test_utilities_comprehensive",
        "test_utilities_core": "flext_ldif.test_utilities_core",
        "test_version": "flext_ldif.test_version",
        "u": ("flext_core.utilities", "FlextUtilities"),
        "utilities": "flext_ldif.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
