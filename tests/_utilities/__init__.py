# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import defer_lazy_bases, install_lazy_exports

if TYPE_CHECKING:
    from tests._utilities.utilities_entries import TestsFlextLdifEntryBuilders
    from tests._utilities.utilities_ldap import TestsFlextLdifLdapClient
    from tests._utilities.utilities_schema import (
        PARSE_DISPATCH,
        TestsFlextLdifSchemaExpectations,
        TestsSchemaAclAssertionsMixin,
        assert_field_eq,
        assert_must_contain,
    )


__all__: tuple[str, ...] = (
    "PARSE_DISPATCH",
    "TestsFlextLdifEntryBuilders",
    "TestsFlextLdifLdapClient",
    "TestsFlextLdifSchemaExpectations",
    "TestsSchemaAclAssertionsMixin",
    "assert_field_eq",
    "assert_must_contain",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "PARSE_DISPATCH": ".utilities_schema",
        "TestsFlextLdifEntryBuilders": ".utilities_entries",
        "TestsFlextLdifLdapClient": ".utilities_ldap",
        "TestsFlextLdifSchemaExpectations": ".utilities_schema",
        "TestsSchemaAclAssertionsMixin": ".utilities_schema",
        "assert_field_eq": ".utilities_schema",
        "assert_must_contain": ".utilities_schema",
    },
    public_exports=__all__,
    deferred_members={
        "TestsFlextLdifEntryBuilders": (
            "_FIXTURES_ROOT",
            "_FILE_EXTENSION",
            "_fixture_metadata_cache",
            "create_real_entry",
            "orclaci_base_dn_entry",
            "oid_security_group_entry",
            "create_real_ldif_content",
            "parametrize_real_data",
            "fixture_metadata",
        ),
        "TestsFlextLdifLdapClient": (
            "_LDAP_CLIENT_MODULE",
            "_LDAP_ENTRY_ADAPTER_MODULE",
            "_LDAP_CLIENT_MISSING_REASON",
            "_resolved_admin_credentials",
            "ldap_client_available",
            "require_ldap_client",
            "create_ldap_entry_adapter",
            "ldap_connectivity_errors",
            "create_server_from_url",
            "create_bare_server",
            "create_connection",
            "_probe_admin_credentials",
            "get_admin_credentials",
            "get_docker_control",
        ),
        "TestsSchemaAclAssertionsMixin": (
            "_schema_definition_is_objectclass",
            "_parse_schema_definition",
            "_assert_common_expectations",
            "_assert_attribute_expectations",
            "_assert_objectclass_expectations",
            "assert_server_schema_parse_and_properties",
            "server_parse_and_unwrap",
            "acl_parse_and_unwrap",
            "server_write_and_unwrap",
            "acl_write_and_unwrap",
            "SchemaExpectations",
        ),
    },
)

defer_lazy_bases(
    __name__,
    {
        "TestsFlextLdifEntryBuilders": (
            ("flext_tests", "FlextTestsUtilitiesFixturesDSL"),
        ),
    },
)
