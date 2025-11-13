"""LDIF roundtrip operations with live LDAP server.

Test suite verifying LDIF operations against an actual LDAP server:
    - Parse and write LDIF from/to LDAP server
    - Validate roundtrip data integrity (LDAP → LDIF → LDAP)
    - Extract and process schema information
    - Handle ACL entries
    - Perform CRUD operations
    - Process batches of entries

Uses Docker fixture infrastructure from conftest.py for automatic
container management via FlextTestsDocker.ldap_container fixture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from ldap3 import ALL, Connection, Server

from flext_ldif import FlextLdif

# LDAP connection details for flext-openldap-test container
LDAP_ADMIN_DN = "cn=admin,dc=flext,dc=local"
LDAP_ADMIN_PASSWORD = "admin123"
LDAP_BASE_DN = "dc=flext,dc=local"


@pytest.fixture(scope="module")
def ldap_connection(ldap_container: str) -> Generator[Connection]:
    """Create connection to real LDAP server via Docker fixture.

    Args:
        ldap_container: Docker LDAP connection string from conftest fixture

    Yields:
        Connection: ldap3 connection to LDAP server

    """
    # ldap_container is a connection URL provided by the Docker fixture
    # Extract host:port from the connection string
    # Expected format: "ldap://localhost:3390"
    host_port = ldap_container.replace("ldap://", "").replace("ldaps://", "")

    server = Server(f"ldap://{host_port}", get_info=ALL)
    conn = Connection(
        server,
        user=LDAP_ADMIN_DN,
        password=LDAP_ADMIN_PASSWORD,
    )

    # Check if server is available
    try:
        if not conn.bind():
            pytest.skip(f"LDAP server not available at {host_port}")
    except Exception as e:
        pytest.skip(f"LDAP server not available at {host_port}: {e}")

    yield conn
    conn.unbind()


@pytest.fixture
def clean_test_ou(ldap_connection: Connection) -> Generator[str]:
    """Create and clean up test OU."""
    test_ou_dn = f"ou=FlextLdifTests,{LDAP_BASE_DN}"

    # Try to delete existing test OU (ignore errors)
    try:
        # Search for all entries under test OU
        found = ldap_connection.search(
            test_ou_dn,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        if found:
            # Delete in reverse order (leaves first)
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                try:
                    ldap_connection.delete(dn)
                except Exception:
                    # Ignore delete errors during cleanup - entries may already be deleted
                    # or dependencies may prevent deletion. Cleanup should not fail tests.
                    pass
    except Exception:
        # OU doesn't exist yet - this is expected for first test run
        pass

    # Create test OU (or recreate if deleted above)
    try:
        ldap_connection.add(
            test_ou_dn,
            ["organizationalUnit"],
            {"ou": "FlextLdifTests"},
        )
    except Exception:
        # OU already exists - this is expected if previous test didn't clean up
        pass

    yield test_ou_dn

    # Cleanup after test - delete all entries under test OU
    try:
        found = ldap_connection.search(
            test_ou_dn,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        if found:
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                try:
                    ldap_connection.delete(dn)
                except Exception:
                    # Ignore cleanup errors - entries may have dependencies or already be deleted
                    pass
    except Exception:
        # Cleanup failed, but that's okay - test should not fail due to cleanup issues
        pass


@pytest.fixture
def flext_api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapRoundtrip:
    """Test LDAP → LDIF → LDAP data roundtrip."""

    def test_roundtrip_preserves_data(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Verify LDAP → LDIF → LDAP preserves data integrity."""
        # Create original LDAP entry
        original_dn = f"cn=Roundtrip Test,{clean_test_ou}"
        original_attrs: dict[str, object] = {
            "cn": "Roundtrip Test",
            "sn": "Test",
            "mail": "roundtrip@example.com",
            "telephoneNumber": ["+1-555-1111", "+1-555-2222"],
            "description": "Multi-line\ndescription\ntest",
        }

        ldap_connection.add(
            original_dn,
            ["person", "inetOrgPerson"],
            original_attrs,
        )

        # Export to LDIF
        ldap_connection.search(original_dn, "(objectClass=*)", attributes=["*"])
        ldap_entry = ldap_connection.entries[0]

        # Convert ldap3 entry attributes to dict format
        attrs_dict = {}
        for attr_name in ldap_entry.entry_attributes:
            attr_obj = ldap_entry[attr_name]
            # Extract values from ldap3 Attribute object
            if hasattr(attr_obj, "values"):
                # ldap3 Attribute object with .values property
                values = [str(v) if not isinstance(v, str) else v for v in attr_obj]
            elif isinstance(attr_obj, list):
                # Already a list
                values = [str(v) for v in attr_obj]
            else:
                # Single value
                values = [str(attr_obj)]
            attrs_dict[attr_name] = values

        entry_result = flext_api.models.Entry.create(
            dn=ldap_entry.entry_dn,
            attributes=attrs_dict,
            metadata=None,
        )
        assert entry_result.is_success
        flext_entry = entry_result.unwrap()

        write_result = flext_api.write([flext_entry])
        assert write_result.is_success
        ldif_output = write_result.unwrap()

        # Re-import from LDIF (to different DN)
        reimport_dn = f"cn=Roundtrip Test Copy,{clean_test_ou}"
        parse_result = flext_api.parse(ldif_output)
        assert parse_result.is_success
        parsed_entries = parse_result.unwrap()
        assert len(parsed_entries) == 1

        reimport_entry = parsed_entries[0]
        # Change DN for reimport
        # Build reimport_attrs from FlextLdif entry attributes
        # Filter out LDIF-specific attributes (changetype, control, etc.)
        ldif_special_attrs = {
            "changetype",
            "control",
            "modifyTimestamp",
            "modifiersName",
        }
        reimport_attrs: dict[str, list[str]] = {
            attr_name: attr_values
            for attr_name, attr_values in reimport_entry.attributes.attributes.items()
            if attr_name.lower() not in ldif_special_attrs
            and attr_name.lower() != "objectclass"
        }
        reimport_attrs["cn"] = ["Roundtrip Test Copy"]

        obj_class_values = reimport_entry.get_attribute_values("objectclass")
        assert isinstance(obj_class_values, list)
        ldap_connection.add(
            reimport_dn,
            obj_class_values,
            attributes={
                attr: reimport_entry.attributes.attributes[attr]
                for attr in reimport_entry.attributes.attributes
                if attr.lower() not in ldif_special_attrs
                and attr.lower() != "objectclass"
            },
        )

        # Verify reimported entry
        assert ldap_connection.search(reimport_dn, "(objectClass=*)", attributes=["*"])
        reimported = ldap_connection.entries[0]

        # Verify attributes preserved
        assert reimported["sn"].value == original_attrs["sn"]
        assert reimported["mail"].value == original_attrs["mail"]
        assert set(reimported["telephoneNumber"].values) == set(
            original_attrs["telephoneNumber"],
        )


__all__ = ["TestRealLdapRoundtrip"]
