# AUTO-GENERATED FILE — Regenerate with: make gen
"""Integration package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_acl_metadata_preservation": ("test_acl_metadata_preservation",),
        ".test_api_integration": ("test_api_integration",),
        ".test_categorization_real_data": ("test_categorization_real_data",),
        ".test_config_integration": ("test_config_integration",),
        ".test_cross_direction_conversion": ("test_cross_direction_conversion",),
        ".test_cross_quirk_conversion": ("test_cross_quirk_conversion",),
        ".test_dn_case_handling": ("test_dn_case_handling",),
        ".test_edge_cases": ("test_edge_cases",),
        ".test_error_recovery": ("test_error_recovery",),
        ".test_ldif_fixtures_integration": ("test_ldif_fixtures_integration",),
        ".test_minimal_differences_metadata": ("test_minimal_differences_metadata",),
        ".test_oid_integration": ("test_oid_integration",),
        ".test_oud_integration": ("test_oud_integration",),
        ".test_oud_to_oid_migration": ("test_oud_to_oid_migration",),
        ".test_pipeline_integration": ("test_pipeline_integration",),
        ".test_quirks_transformations": ("test_quirks_transformations",),
        ".test_real_ldap_config": ("test_real_ldap_config",),
        ".test_real_ldap_crud": ("test_real_ldap_crud",),
        ".test_real_ldap_export": ("test_real_ldap_export",),
        ".test_real_ldap_import": ("test_real_ldap_import",),
        ".test_real_ldap_roundtrip": ("test_real_ldap_roundtrip",),
        ".test_rfc_docker_real": ("test_rfc_docker_real",),
        ".test_rfc_docker_real_integration": ("test_rfc_docker_real_integration",),
        ".test_simple_ldap": ("test_simple_ldap",),
        ".test_systematic_fixture_coverage": ("test_systematic_fixture_coverage",),
        ".test_zero_data_loss_oid_oud": ("test_zero_data_loss_oid_oud",),
        ".test_zero_data_loss_schema": ("test_zero_data_loss_schema",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
