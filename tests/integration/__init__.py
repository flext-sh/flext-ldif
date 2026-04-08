# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Integration package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "c": ("flext_core.constants", "FlextConstants"),
    "conftest": "tests.integration.conftest",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_acl_metadata_preservation": "tests.integration.test_acl_metadata_preservation",
    "test_api_integration": "tests.integration.test_api_integration",
    "test_categorization_real_data": "tests.integration.test_categorization_real_data",
    "test_config_integration": "tests.integration.test_config_integration",
    "test_cross_direction_conversion": "tests.integration.test_cross_direction_conversion",
    "test_cross_quirk_conversion": "tests.integration.test_cross_quirk_conversion",
    "test_dn_case_handling": "tests.integration.test_dn_case_handling",
    "test_edge_cases": "tests.integration.test_edge_cases",
    "test_error_recovery": "tests.integration.test_error_recovery",
    "test_ldif_fixtures_integration": "tests.integration.test_ldif_fixtures_integration",
    "test_minimal_differences_metadata": "tests.integration.test_minimal_differences_metadata",
    "test_oid_integration": "tests.integration.test_oid_integration",
    "test_oud_integration": "tests.integration.test_oud_integration",
    "test_oud_to_oid_migration": "tests.integration.test_oud_to_oid_migration",
    "test_pipeline_integration": "tests.integration.test_pipeline_integration",
    "test_quirks_transformations": "tests.integration.test_quirks_transformations",
    "test_real_ldap_config": "tests.integration.test_real_ldap_config",
    "test_real_ldap_crud": "tests.integration.test_real_ldap_crud",
    "test_real_ldap_export": "tests.integration.test_real_ldap_export",
    "test_real_ldap_import": "tests.integration.test_real_ldap_import",
    "test_real_ldap_roundtrip": "tests.integration.test_real_ldap_roundtrip",
    "test_rfc_docker_real": "tests.integration.test_rfc_docker_real",
    "test_rfc_docker_real_integration": "tests.integration.test_rfc_docker_real_integration",
    "test_simple_ldap": "tests.integration.test_simple_ldap",
    "test_systematic_fixture_coverage": "tests.integration.test_systematic_fixture_coverage",
    "test_zero_data_loss_oid_oud": "tests.integration.test_zero_data_loss_oid_oud",
    "test_zero_data_loss_schema": "tests.integration.test_zero_data_loss_schema",
    "typings": "tests.integration.typings",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
