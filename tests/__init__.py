# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.base as _tests_base

    base = _tests_base
    import tests.conftest as _tests_conftest
    from tests.base import FlextLdifTestsServiceBase, s

    conftest = _tests_conftest
    import tests.conftest_shared as _tests_conftest_shared
    from tests.conftest import (
        FIXTURES_DIR,
        OID_FIXTURES_DIR,
        FlextLdifFixtures,
        pytest_configure,
        pytest_plugins,
    )

    conftest_shared = _tests_conftest_shared
    import tests.constants as _tests_constants

    constants = _tests_constants
    import tests.models as _tests_models
    from tests.constants import FlextLdifTestConstants, FlextLdifTestConstants as c
    from tests.integration.test_config_integration import ConfigTestData, logger
    from tests.integration.test_cross_direction_conversion import (
        TestsTestFlextLdifCrossDirectionConversion,
    )
    from tests.integration.test_cross_quirk_conversion import (
        TestOidToOudAclConversion,
        TestOidToOudIntegrationConversion,
        TestOidToOudSchemaConversion,
        TestQuirksConversionMatrixFacade,
    )
    from tests.integration.test_dn_case_handling import (
        TestDnCaseNormalizationScenarios,
        TestDnCaseRegistry,
    )
    from tests.integration.test_edge_cases import (
        TestBoundaryValues,
        TestEmptyAndMinimalCases,
        TestLargeAndComplexCases,
        TestRoundtripEdgeCases,
        TestUnicodeBoundaries,
    )
    from tests.integration.test_error_recovery import (
        TestEncodingErrors,
        TestIncompleteEntries,
        TestInvalidSchemaDefinitions,
        TestMalformedLdifHandling,
    )
    from tests.integration.test_minimal_differences_metadata import (
        TestMinimalDifferencesOidOud,
    )
    from tests.integration.test_oid_integration import (
        TestOidEntryIntegration,
        TestOidRoundTripIntegration,
        TestOidSchemaIntegration,
    )
    from tests.integration.test_oud_integration import (
        TestOudAclIntegration,
        TestOudEntryIntegration,
        TestOudMetadataPreservation,
        TestOudRoundTripIntegration,
        TestOudSchemaIntegration,
    )
    from tests.integration.test_oud_to_oid_migration import (
        TestOudToOidAclMigration,
        TestOudToOidEntryMigration,
        TestOudToOidFullMigration,
        TestOudToOidSchemaMigration,
    )
    from tests.integration.test_real_ldap_config import (
        TestRealLdapConfigurationFromEnv,
        TestRealLdapRailwayComposition,
    )
    from tests.integration.test_real_ldap_crud import (
        TestRealLdapBatchOperations,
        TestRealLdapCRUD,
    )
    from tests.integration.test_real_ldap_export import TestRealLdapExport
    from tests.integration.test_real_ldap_import import TestRealLdapImport
    from tests.integration.test_real_ldap_roundtrip import TestRealLdapRoundtrip
    from tests.integration.test_systematic_fixture_coverage import (
        TestSystematicFixtureCoverage,
    )

    models = _tests_models
    import tests.protocols as _tests_protocols
    from tests.models import FlextLdifTestModels, FlextLdifTestModels as m

    protocols = _tests_protocols
    import tests.test_factory as _tests_test_factory
    from tests.protocols import FlextLdifTestProtocols, FlextLdifTestProtocols as p
    from tests.support.conftest_factory import FlextLdifTestConftest, tk
    from tests.support.ldif_data import LdifTestData
    from tests.support.test_files import FileManager
    from tests.support.validators import MockFlextUtilitiesResultHelpers, MockMatchers

    test_factory = _tests_test_factory
    import tests.test_helpers as _tests_test_helpers
    from tests.test_factory import FlextLdifTestFactory

    test_helpers = _tests_test_helpers
    import tests.typings as _tests_typings
    from tests.test_helpers import (
        TestsFlextLdifFixtures,
        TestsFlextLdifMatchers,
        TestsFlextLdifTypes,
        TestsFlextLdifValidators,
        tf,
        tm,
        tt,
        tv,
    )

    typings = _tests_typings
    import tests.utilities as _tests_utilities
    from tests.typings import (
        FlextLdifTestTypes,
        FlextLdifTestTypes as t,
        GenericFieldsDict,
    )
    from tests.unit.__init__ import version_module
    from tests.unit.quirks.servers.test_oid_quirks import TestsTestFlextLdifOidQuirks

    utilities = _tests_utilities
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from tests.utilities import FlextLdifTestUtilities, FlextLdifTestUtilities as u
_LAZY_IMPORTS = {
    "ConfigTestData": ("tests.integration.test_config_integration", "ConfigTestData"),
    "FIXTURES_DIR": ("tests.conftest", "FIXTURES_DIR"),
    "FileManager": ("tests.support.test_files", "FileManager"),
    "FlextLdifFixtures": ("tests.conftest", "FlextLdifFixtures"),
    "FlextLdifTestConftest": (
        "tests.support.conftest_factory",
        "FlextLdifTestConftest",
    ),
    "FlextLdifTestConstants": ("tests.constants", "FlextLdifTestConstants"),
    "FlextLdifTestFactory": ("tests.test_factory", "FlextLdifTestFactory"),
    "FlextLdifTestModels": ("tests.models", "FlextLdifTestModels"),
    "FlextLdifTestProtocols": ("tests.protocols", "FlextLdifTestProtocols"),
    "FlextLdifTestTypes": ("tests.typings", "FlextLdifTestTypes"),
    "FlextLdifTestUtilities": ("tests.utilities", "FlextLdifTestUtilities"),
    "FlextLdifTestsServiceBase": ("tests.base", "FlextLdifTestsServiceBase"),
    "GenericFieldsDict": ("tests.typings", "GenericFieldsDict"),
    "LdifTestData": ("tests.support.ldif_data", "LdifTestData"),
    "MockFlextUtilitiesResultHelpers": (
        "tests.support.validators",
        "MockFlextUtilitiesResultHelpers",
    ),
    "MockMatchers": ("tests.support.validators", "MockMatchers"),
    "OID_FIXTURES_DIR": ("tests.conftest", "OID_FIXTURES_DIR"),
    "TestBoundaryValues": ("tests.integration.test_edge_cases", "TestBoundaryValues"),
    "TestDnCaseNormalizationScenarios": (
        "tests.integration.test_dn_case_handling",
        "TestDnCaseNormalizationScenarios",
    ),
    "TestDnCaseRegistry": (
        "tests.integration.test_dn_case_handling",
        "TestDnCaseRegistry",
    ),
    "TestEmptyAndMinimalCases": (
        "tests.integration.test_edge_cases",
        "TestEmptyAndMinimalCases",
    ),
    "TestEncodingErrors": (
        "tests.integration.test_error_recovery",
        "TestEncodingErrors",
    ),
    "TestIncompleteEntries": (
        "tests.integration.test_error_recovery",
        "TestIncompleteEntries",
    ),
    "TestInvalidSchemaDefinitions": (
        "tests.integration.test_error_recovery",
        "TestInvalidSchemaDefinitions",
    ),
    "TestLargeAndComplexCases": (
        "tests.integration.test_edge_cases",
        "TestLargeAndComplexCases",
    ),
    "TestMalformedLdifHandling": (
        "tests.integration.test_error_recovery",
        "TestMalformedLdifHandling",
    ),
    "TestMinimalDifferencesOidOud": (
        "tests.integration.test_minimal_differences_metadata",
        "TestMinimalDifferencesOidOud",
    ),
    "TestOidEntryIntegration": (
        "tests.integration.test_oid_integration",
        "TestOidEntryIntegration",
    ),
    "TestOidRoundTripIntegration": (
        "tests.integration.test_oid_integration",
        "TestOidRoundTripIntegration",
    ),
    "TestOidSchemaIntegration": (
        "tests.integration.test_oid_integration",
        "TestOidSchemaIntegration",
    ),
    "TestOidToOudAclConversion": (
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudAclConversion",
    ),
    "TestOidToOudIntegrationConversion": (
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudIntegrationConversion",
    ),
    "TestOidToOudSchemaConversion": (
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudSchemaConversion",
    ),
    "TestOudAclIntegration": (
        "tests.integration.test_oud_integration",
        "TestOudAclIntegration",
    ),
    "TestOudEntryIntegration": (
        "tests.integration.test_oud_integration",
        "TestOudEntryIntegration",
    ),
    "TestOudMetadataPreservation": (
        "tests.integration.test_oud_integration",
        "TestOudMetadataPreservation",
    ),
    "TestOudRoundTripIntegration": (
        "tests.integration.test_oud_integration",
        "TestOudRoundTripIntegration",
    ),
    "TestOudSchemaIntegration": (
        "tests.integration.test_oud_integration",
        "TestOudSchemaIntegration",
    ),
    "TestOudToOidAclMigration": (
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidAclMigration",
    ),
    "TestOudToOidEntryMigration": (
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidEntryMigration",
    ),
    "TestOudToOidFullMigration": (
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidFullMigration",
    ),
    "TestOudToOidSchemaMigration": (
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidSchemaMigration",
    ),
    "TestQuirksConversionMatrixFacade": (
        "tests.integration.test_cross_quirk_conversion",
        "TestQuirksConversionMatrixFacade",
    ),
    "TestRealLdapBatchOperations": (
        "tests.integration.test_real_ldap_crud",
        "TestRealLdapBatchOperations",
    ),
    "TestRealLdapCRUD": ("tests.integration.test_real_ldap_crud", "TestRealLdapCRUD"),
    "TestRealLdapConfigurationFromEnv": (
        "tests.integration.test_real_ldap_config",
        "TestRealLdapConfigurationFromEnv",
    ),
    "TestRealLdapExport": (
        "tests.integration.test_real_ldap_export",
        "TestRealLdapExport",
    ),
    "TestRealLdapImport": (
        "tests.integration.test_real_ldap_import",
        "TestRealLdapImport",
    ),
    "TestRealLdapRailwayComposition": (
        "tests.integration.test_real_ldap_config",
        "TestRealLdapRailwayComposition",
    ),
    "TestRealLdapRoundtrip": (
        "tests.integration.test_real_ldap_roundtrip",
        "TestRealLdapRoundtrip",
    ),
    "TestRoundtripEdgeCases": (
        "tests.integration.test_edge_cases",
        "TestRoundtripEdgeCases",
    ),
    "TestSystematicFixtureCoverage": (
        "tests.integration.test_systematic_fixture_coverage",
        "TestSystematicFixtureCoverage",
    ),
    "TestUnicodeBoundaries": (
        "tests.integration.test_edge_cases",
        "TestUnicodeBoundaries",
    ),
    "TestsFlextLdifFixtures": ("tests.test_helpers", "TestsFlextLdifFixtures"),
    "TestsFlextLdifMatchers": ("tests.test_helpers", "TestsFlextLdifMatchers"),
    "TestsFlextLdifTypes": ("tests.test_helpers", "TestsFlextLdifTypes"),
    "TestsFlextLdifValidators": ("tests.test_helpers", "TestsFlextLdifValidators"),
    "TestsTestFlextLdifCrossDirectionConversion": (
        "tests.integration.test_cross_direction_conversion",
        "TestsTestFlextLdifCrossDirectionConversion",
    ),
    "TestsTestFlextLdifOidQuirks": (
        "tests.unit.quirks.servers.test_oid_quirks",
        "TestsTestFlextLdifOidQuirks",
    ),
    "base": "tests.base",
    "c": ("tests.constants", "FlextLdifTestConstants"),
    "conftest": "tests.conftest",
    "conftest_shared": "tests.conftest_shared",
    "constants": "tests.constants",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "logger": ("tests.integration.test_config_integration", "logger"),
    "m": ("tests.models", "FlextLdifTestModels"),
    "models": "tests.models",
    "p": ("tests.protocols", "FlextLdifTestProtocols"),
    "protocols": "tests.protocols",
    "pytest_configure": ("tests.conftest", "pytest_configure"),
    "pytest_plugins": ("tests.conftest", "pytest_plugins"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("tests.base", "s"),
    "t": ("tests.typings", "FlextLdifTestTypes"),
    "test_factory": "tests.test_factory",
    "test_helpers": "tests.test_helpers",
    "tf": ("tests.test_helpers", "tf"),
    "tk": ("tests.support.conftest_factory", "tk"),
    "tm": ("tests.test_helpers", "tm"),
    "tt": ("tests.test_helpers", "tt"),
    "tv": ("tests.test_helpers", "tv"),
    "typings": "tests.typings",
    "u": ("tests.utilities", "FlextLdifTestUtilities"),
    "utilities": "tests.utilities",
    "version_module": ("tests.unit.__init__.test_version", "version_module"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "FIXTURES_DIR",
    "OID_FIXTURES_DIR",
    "ConfigTestData",
    "FileManager",
    "FlextLdifFixtures",
    "FlextLdifTestConftest",
    "FlextLdifTestConstants",
    "FlextLdifTestFactory",
    "FlextLdifTestModels",
    "FlextLdifTestProtocols",
    "FlextLdifTestTypes",
    "FlextLdifTestUtilities",
    "FlextLdifTestsServiceBase",
    "GenericFieldsDict",
    "LdifTestData",
    "MockFlextUtilitiesResultHelpers",
    "MockMatchers",
    "TestBoundaryValues",
    "TestDnCaseNormalizationScenarios",
    "TestDnCaseRegistry",
    "TestEmptyAndMinimalCases",
    "TestEncodingErrors",
    "TestIncompleteEntries",
    "TestInvalidSchemaDefinitions",
    "TestLargeAndComplexCases",
    "TestMalformedLdifHandling",
    "TestMinimalDifferencesOidOud",
    "TestOidEntryIntegration",
    "TestOidRoundTripIntegration",
    "TestOidSchemaIntegration",
    "TestOidToOudAclConversion",
    "TestOidToOudIntegrationConversion",
    "TestOidToOudSchemaConversion",
    "TestOudAclIntegration",
    "TestOudEntryIntegration",
    "TestOudMetadataPreservation",
    "TestOudRoundTripIntegration",
    "TestOudSchemaIntegration",
    "TestOudToOidAclMigration",
    "TestOudToOidEntryMigration",
    "TestOudToOidFullMigration",
    "TestOudToOidSchemaMigration",
    "TestQuirksConversionMatrixFacade",
    "TestRealLdapBatchOperations",
    "TestRealLdapCRUD",
    "TestRealLdapConfigurationFromEnv",
    "TestRealLdapExport",
    "TestRealLdapImport",
    "TestRealLdapRailwayComposition",
    "TestRealLdapRoundtrip",
    "TestRoundtripEdgeCases",
    "TestSystematicFixtureCoverage",
    "TestUnicodeBoundaries",
    "TestsFlextLdifFixtures",
    "TestsFlextLdifMatchers",
    "TestsFlextLdifTypes",
    "TestsFlextLdifValidators",
    "TestsTestFlextLdifCrossDirectionConversion",
    "TestsTestFlextLdifOidQuirks",
    "base",
    "c",
    "conftest",
    "conftest_shared",
    "constants",
    "d",
    "e",
    "h",
    "logger",
    "m",
    "models",
    "p",
    "protocols",
    "pytest_configure",
    "pytest_plugins",
    "r",
    "s",
    "t",
    "test_factory",
    "test_helpers",
    "tf",
    "tk",
    "tm",
    "tt",
    "tv",
    "typings",
    "u",
    "utilities",
    "version_module",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
