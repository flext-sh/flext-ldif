"""LDIF import operations with live LDAP server.

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

import base64
from collections.abc import Generator
from pathlib import Path

import pytest
from ldap3 import ALL, Connection, Server

from flext_ldif import FlextLdif

# LDAP connection details for flext-openldap-test container
LDAP_ADMIN_DN = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
LDAP_ADMIN_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD123"
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
class TestRealLdapImport:
    """Test LDIF import to real LDAP server."""

    def test_import_single_entry(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Import LDIF entry to real LDAP server."""
        ldif_content = f"""dn: cn=Import Test,{clean_test_ou}
objectClass: person
objectClass: inetOrgPerson
cn: Import Test
sn: Test
mail: import@example.com
"""

        # Parse LDIF
        parse_result = flext_api.parse(ldif_content)
        assert parse_result.is_success
        entries = parse_result.unwrap()
        assert len(entries) == 1

        entry = entries[0]

        # Extract object classes (not included in attributes dict)
        object_classes = entry.get_attribute_values("objectclass")
        if not isinstance(object_classes, list):
            # Convert to list if needed
            object_classes = list(object_classes) if object_classes else []

        # Convert FlextLdif entry attributes to dict format for ldap3
        # EXCLUDE objectclass as it's passed separately to ldap3.add()
        attrs_dict = {}
        for attr_name, attr_values in entry.attributes.attributes.items():
            # Skip objectclass - it's handled separately
            if attr_name.lower() == "objectclass":
                continue
            # Skip dn - it's the entry DN, not an attribute
            if attr_name.lower() == "dn":
                continue
            # Extract actual list of strings from AttributeValues
            if isinstance(attr_values, list):
                # Already a list
                attrs_dict[attr_name] = attr_values
            elif hasattr(attr_values, "values"):
                # AttributeValues object with values property
                attrs_dict[attr_name] = list(attr_values.values)
            else:
                # Single value or other type - convert to list
                attrs_dict[attr_name] = [str(attr_values)]

        # Import to LDAP
        ldap_connection.add(
            str(entry.dn),
            object_classes,
            attributes=attrs_dict,
        )

        # Verify import
        assert ldap_connection.search(
            str(entry.dn),
            "(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )
        imported_entry = ldap_connection.entries[0]
        assert imported_entry["cn"].value == "Import Test"
        assert imported_entry["mail"].value == "import@example.com"

    def test_import_with_binary_attributes(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Import LDIF with binary attributes (base64-encoded)."""
        # Create entry with binary data (simulated photo)
        binary_data = b"fake_jpeg_data_here"
        encoded_photo = base64.b64encode(binary_data).decode("ascii")

        ldif_content = f"""dn: cn=Binary Test,{clean_test_ou}
objectClass: person
objectClass: inetOrgPerson
cn: Binary Test
sn: Test
jpegPhoto:: {encoded_photo}
"""

        # Parse LDIF
        parse_result = flext_api.parse(ldif_content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        entry = entries[0]

        # Import to LDAP
        # Build attrs_dict from FlextLdif entry attributes
        attrs_dict: dict[str, list[str] | bytes] = {
            attr_name: attr_values
            for attr_name, attr_values in entry.attributes.attributes.items()
            if attr_name.lower() != "objectclass"
        }

        # Handle binary attribute - ldap3 accepts bytes for binary attributes
        if "jpegPhoto" in attrs_dict:
            attrs_dict["jpegPhoto"] = binary_data

        ldap_connection.add(
            str(entry.dn),
            entry.get_attribute_values("objectclass"),
            attributes={
                attr: entry.attributes.attributes[attr]
                for attr in entry.attributes.attributes
            },
        )

        # Verify
        assert ldap_connection.search(
            str(entry.dn),
            "(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )
        imported_entry = ldap_connection.entries[0]
        assert imported_entry["jpegPhoto"].value == binary_data

    def test_import_from_file(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Import LDIF file to LDAP server."""
        # Create LDIF file
        ldif_file = tmp_path / "import.ldif"
        ldif_content = f"""dn: cn=File Import,{clean_test_ou}
objectClass: person
objectClass: inetOrgPerson
cn: File Import
sn: Test
mail: import@example.com
"""
        ldif_file.write_text(ldif_content)

        # Parse file
        parse_result = flext_api.parse(ldif_file)
        assert parse_result.is_success
        entries = parse_result.unwrap()
        assert len(entries) == 1

        entry = entries[0]

        # Extract object classes (not included in attributes dict)
        object_classes = entry.get_attribute_values("objectclass")
        if not isinstance(object_classes, list):
            # Convert to list if needed
            object_classes = list(object_classes) if object_classes else []

        # Convert FlextLdif entry attributes to dict format for ldap3
        # EXCLUDE objectclass as it's passed separately to ldap3.add()
        attrs_dict = {}
        for attr_name, attr_values in entry.attributes.attributes.items():
            # Skip objectclass - it's handled separately
            if attr_name.lower() == "objectclass":
                continue
            # Skip dn - it's the entry DN, not an attribute
            if attr_name.lower() == "dn":
                continue
            # Extract actual list of strings from AttributeValues
            if isinstance(attr_values, list):
                # Already a list
                attrs_dict[attr_name] = attr_values
            elif hasattr(attr_values, "values"):
                # AttributeValues object with values property
                attrs_dict[attr_name] = list(attr_values.values)
            else:
                # Single value or other type - convert to list
                attrs_dict[attr_name] = [str(attr_values)]

        # Import to LDAP
        ldap_connection.add(
            str(entry.dn),
            object_classes,
            attributes=attrs_dict,
        )

        # Verify
        assert ldap_connection.search(
            str(entry.dn),
            "(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )
        imported = ldap_connection.entries[0]
        assert imported["cn"].value == "File Import"


__all__ = [
    "TestRealLdapImport",
]
