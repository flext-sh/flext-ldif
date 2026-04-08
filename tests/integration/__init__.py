# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Integration package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.integration.conftest as _tests_integration_conftest

    conftest = _tests_integration_conftest
    import tests.integration.test_acl_metadata_preservation as _tests_integration_test_acl_metadata_preservation

    test_acl_metadata_preservation = _tests_integration_test_acl_metadata_preservation
    import tests.integration.test_api_integration as _tests_integration_test_api_integration

    test_api_integration = _tests_integration_test_api_integration
    import tests.integration.test_categorization_real_data as _tests_integration_test_categorization_real_data

    test_categorization_real_data = _tests_integration_test_categorization_real_data
    import tests.integration.test_config_integration as _tests_integration_test_config_integration

    test_config_integration = _tests_integration_test_config_integration
    import tests.integration.test_cross_direction_conversion as _tests_integration_test_cross_direction_conversion

    test_cross_direction_conversion = _tests_integration_test_cross_direction_conversion
    import tests.integration.test_cross_quirk_conversion as _tests_integration_test_cross_quirk_conversion

    test_cross_quirk_conversion = _tests_integration_test_cross_quirk_conversion
    import tests.integration.test_dn_case_handling as _tests_integration_test_dn_case_handling

    test_dn_case_handling = _tests_integration_test_dn_case_handling
    import tests.integration.test_edge_cases as _tests_integration_test_edge_cases

    test_edge_cases = _tests_integration_test_edge_cases
    import tests.integration.test_error_recovery as _tests_integration_test_error_recovery

    test_error_recovery = _tests_integration_test_error_recovery
    import tests.integration.test_ldif_fixtures_integration as _tests_integration_test_ldif_fixtures_integration

    test_ldif_fixtures_integration = _tests_integration_test_ldif_fixtures_integration
    import tests.integration.test_minimal_differences_metadata as _tests_integration_test_minimal_differences_metadata

    test_minimal_differences_metadata = (
        _tests_integration_test_minimal_differences_metadata
    )
    import tests.integration.test_oid_integration as _tests_integration_test_oid_integration

    test_oid_integration = _tests_integration_test_oid_integration
    import tests.integration.test_oud_integration as _tests_integration_test_oud_integration

    test_oud_integration = _tests_integration_test_oud_integration
    import tests.integration.test_oud_to_oid_migration as _tests_integration_test_oud_to_oid_migration

    test_oud_to_oid_migration = _tests_integration_test_oud_to_oid_migration
    import tests.integration.test_pipeline_integration as _tests_integration_test_pipeline_integration

    test_pipeline_integration = _tests_integration_test_pipeline_integration
    import tests.integration.test_quirks_transformations as _tests_integration_test_quirks_transformations

    test_quirks_transformations = _tests_integration_test_quirks_transformations
    import tests.integration.test_real_ldap_config as _tests_integration_test_real_ldap_config

    test_real_ldap_config = _tests_integration_test_real_ldap_config
    import tests.integration.test_real_ldap_crud as _tests_integration_test_real_ldap_crud

    test_real_ldap_crud = _tests_integration_test_real_ldap_crud
    import tests.integration.test_real_ldap_export as _tests_integration_test_real_ldap_export

    test_real_ldap_export = _tests_integration_test_real_ldap_export
    import tests.integration.test_real_ldap_import as _tests_integration_test_real_ldap_import

    test_real_ldap_import = _tests_integration_test_real_ldap_import
    import tests.integration.test_real_ldap_roundtrip as _tests_integration_test_real_ldap_roundtrip

    test_real_ldap_roundtrip = _tests_integration_test_real_ldap_roundtrip
    import tests.integration.test_rfc_docker_real as _tests_integration_test_rfc_docker_real

    test_rfc_docker_real = _tests_integration_test_rfc_docker_real
    import tests.integration.test_rfc_docker_real_integration as _tests_integration_test_rfc_docker_real_integration

    test_rfc_docker_real_integration = (
        _tests_integration_test_rfc_docker_real_integration
    )
    import tests.integration.test_simple_ldap as _tests_integration_test_simple_ldap

    test_simple_ldap = _tests_integration_test_simple_ldap
    import tests.integration.test_systematic_fixture_coverage as _tests_integration_test_systematic_fixture_coverage

    test_systematic_fixture_coverage = (
        _tests_integration_test_systematic_fixture_coverage
    )
    import tests.integration.test_zero_data_loss_oid_oud as _tests_integration_test_zero_data_loss_oid_oud

    test_zero_data_loss_oid_oud = _tests_integration_test_zero_data_loss_oid_oud
    import tests.integration.test_zero_data_loss_schema as _tests_integration_test_zero_data_loss_schema

    test_zero_data_loss_schema = _tests_integration_test_zero_data_loss_schema
    import tests.integration.typings as _tests_integration_typings

    typings = _tests_integration_typings
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

__all__ = [
    "c",
    "conftest",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "test_acl_metadata_preservation",
    "test_api_integration",
    "test_categorization_real_data",
    "test_config_integration",
    "test_cross_direction_conversion",
    "test_cross_quirk_conversion",
    "test_dn_case_handling",
    "test_edge_cases",
    "test_error_recovery",
    "test_ldif_fixtures_integration",
    "test_minimal_differences_metadata",
    "test_oid_integration",
    "test_oud_integration",
    "test_oud_to_oid_migration",
    "test_pipeline_integration",
    "test_quirks_transformations",
    "test_real_ldap_config",
    "test_real_ldap_crud",
    "test_real_ldap_export",
    "test_real_ldap_import",
    "test_real_ldap_roundtrip",
    "test_rfc_docker_real",
    "test_rfc_docker_real_integration",
    "test_simple_ldap",
    "test_systematic_fixture_coverage",
    "test_zero_data_loss_oid_oud",
    "test_zero_data_loss_schema",
    "typings",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
