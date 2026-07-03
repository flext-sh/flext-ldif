# AUTO-GENERATED FILE — Regenerate with: make gen
"""Integration package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.tests.integration.test_acl_metadata_preservation import (
        TestsFlextLdifAclMetadataPreservation as TestsFlextLdifAclMetadataPreservation,
    )
    from flext_ldif.tests.integration.test_api_integration import (
        TestsFlextLdifApiIntegration as TestsFlextLdifApiIntegration,
    )
    from flext_ldif.tests.integration.test_categorization_real_data import (
        TestsFlextLdifCategorizationRealData as TestsFlextLdifCategorizationRealData,
    )
    from flext_ldif.tests.integration.test_config_integration import (
        TestsFlextLdifConfigIntegration as TestsFlextLdifConfigIntegration,
    )
    from flext_ldif.tests.integration.test_cross_direction_conversion import (
        TestsTestFlextLdifCrossDirectionConversion as TestsTestFlextLdifCrossDirectionConversion,
    )
    from flext_ldif.tests.integration.test_cross_server_conversion import (
        TestsFlextLdifCrossServerConversion as TestsFlextLdifCrossServerConversion,
    )
    from flext_ldif.tests.integration.test_dn_case_handling import (
        TestsFlextLdifDnCaseHandling as TestsFlextLdifDnCaseHandling,
    )
    from flext_ldif.tests.integration.test_edge_cases import (
        TestsFlextLdifEdgeCasesInt as TestsFlextLdifEdgeCasesInt,
    )
    from flext_ldif.tests.integration.test_error_recovery import (
        TestsFlextLdifErrorRecovery as TestsFlextLdifErrorRecovery,
    )
    from flext_ldif.tests.integration.test_ldif_fixtures_integration import (
        TestsFlextLdifLdifFixturesIntegration as TestsFlextLdifLdifFixturesIntegration,
    )
    from flext_ldif.tests.integration.test_minimal_differences_metadata import (
        TestsFlextLdifMinimalDifferencesMetadata as TestsFlextLdifMinimalDifferencesMetadata,
    )
    from flext_ldif.tests.integration.test_oid_integration import (
        TestsFlextLdifOidIntegration as TestsFlextLdifOidIntegration,
    )
    from flext_ldif.tests.integration.test_oud_integration import (
        TestsFlextLdifOudIntegration as TestsFlextLdifOudIntegration,
    )
    from flext_ldif.tests.integration.test_oud_to_oid_migration import (
        TestsFlextLdifOudToOidMigration as TestsFlextLdifOudToOidMigration,
    )
    from flext_ldif.tests.integration.test_pipeline_integration import (
        TestsFlextLdifPipelineIntegration as TestsFlextLdifPipelineIntegration,
    )
    from flext_ldif.tests.integration.test_real_ldap_config import (
        TestsFlextLdifRealLdapConfig as TestsFlextLdifRealLdapConfig,
    )
    from flext_ldif.tests.integration.test_real_ldap_export import (
        TestsFlextLdifRealLdapExport as TestsFlextLdifRealLdapExport,
    )
    from flext_ldif.tests.integration.test_real_ldap_import import (
        TestsFlextLdifRealLdapImport as TestsFlextLdifRealLdapImport,
    )
    from flext_ldif.tests.integration.test_real_ldap_roundtrip import (
        TestsFlextLdifRealLdapRoundtrip as TestsFlextLdifRealLdapRoundtrip,
    )
    from flext_ldif.tests.integration.test_rfc_docker_real import (
        TestsFlextLdifRfcDockerReal as TestsFlextLdifRfcDockerReal,
    )
    from flext_ldif.tests.integration.test_rfc_docker_real_integration import (
        TestsFlextLdifRfcDockerRealIntegration as TestsFlextLdifRfcDockerRealIntegration,
    )
    from flext_ldif.tests.integration.test_simple_ldap import (
        TestsFlextLdifSimpleLdap as TestsFlextLdifSimpleLdap,
    )
    from flext_ldif.tests.integration.test_systematic_fixture_coverage import (
        TestsFlextLdifSystematicFixtureCoverage as TestsFlextLdifSystematicFixtureCoverage,
    )
    from flext_ldif.tests.integration.test_zero_data_loss_oid_oud import (
        TestsFlextLdifZeroDataLossOidOud as TestsFlextLdifZeroDataLossOidOud,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".fixtures": ("fixtures",),
        ".test_acl_metadata_preservation": ("TestsFlextLdifAclMetadataPreservation",),
        ".test_api_integration": ("TestsFlextLdifApiIntegration",),
        ".test_categorization_real_data": ("TestsFlextLdifCategorizationRealData",),
        ".test_config_integration": ("TestsFlextLdifConfigIntegration",),
        ".test_cross_direction_conversion": (
            "TestsTestFlextLdifCrossDirectionConversion",
        ),
        ".test_cross_server_conversion": ("TestsFlextLdifCrossServerConversion",),
        ".test_dn_case_handling": ("TestsFlextLdifDnCaseHandling",),
        ".test_edge_cases": ("TestsFlextLdifEdgeCasesInt",),
        ".test_error_recovery": ("TestsFlextLdifErrorRecovery",),
        ".test_ldif_fixtures_integration": ("TestsFlextLdifLdifFixturesIntegration",),
        ".test_minimal_differences_metadata": (
            "TestsFlextLdifMinimalDifferencesMetadata",
        ),
        ".test_oid_integration": ("TestsFlextLdifOidIntegration",),
        ".test_oud_integration": ("TestsFlextLdifOudIntegration",),
        ".test_oud_to_oid_migration": ("TestsFlextLdifOudToOidMigration",),
        ".test_pipeline_integration": ("TestsFlextLdifPipelineIntegration",),
        ".test_real_ldap_config": ("TestsFlextLdifRealLdapConfig",),
        ".test_real_ldap_crud": ("test_real_ldap_crud",),
        ".test_real_ldap_export": ("TestsFlextLdifRealLdapExport",),
        ".test_real_ldap_import": ("TestsFlextLdifRealLdapImport",),
        ".test_real_ldap_roundtrip": ("TestsFlextLdifRealLdapRoundtrip",),
        ".test_rfc_docker_real": ("TestsFlextLdifRfcDockerReal",),
        ".test_rfc_docker_real_integration": (
            "TestsFlextLdifRfcDockerRealIntegration",
        ),
        ".test_simple_ldap": ("TestsFlextLdifSimpleLdap",),
        ".test_systematic_fixture_coverage": (
            "TestsFlextLdifSystematicFixtureCoverage",
        ),
        ".test_zero_data_loss_oid_oud": ("TestsFlextLdifZeroDataLossOidOud",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
