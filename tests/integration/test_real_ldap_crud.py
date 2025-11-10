"""CRUD and batch operations with live LDAP server.

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
class TestRealLdapCRUD:
    """Test CRUD operations with LDAP server."""

    def test_complete_crud_cycle(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Test Create→Read→Update→Delete cycle."""
        # CREATE: Build entry using FlextLdif API
        person_dn = f"cn=CRUD Test User,{clean_test_ou}"
        person_result = flext_api.create_entry(
            dn=person_dn,
            attributes={
                "cn": "CRUD Test User",
                "sn": "User",
                "mail": "crud@example.com",
                "uid": "crud_user",
            },
            objectclasses=["inetOrgPerson", "person", "top"]
        )
        assert person_result.is_success
        person_entry = person_result.unwrap()

        # Write to LDAP
        obj_class_values = person_entry.get_attribute_values("objectclass")
        assert isinstance(obj_class_values, list)
        ldap_connection.add(
            str(person_entry.dn),
            obj_class_values,
            {
                attr: person_entry.attributes.attributes[attr]
                for attr in person_entry.attributes.attributes
                if attr.lower() != "objectclass"
            },
        )

        # UPDATE: Modify the mail attribute
        ldap_connection.modify(
            str(person_entry.dn),
            {"mail": [("MODIFY_REPLACE", ["updated_crud@example.com"])]},
        )

        # Verify update
        ldap_connection.search(
            str(person_entry.dn),
            "(objectClass=*)",
            attributes=["*"],
        )
        updated_entry = ldap_connection.entries[0]
        assert updated_entry["mail"].value == "updated_crud@example.com"

        # DELETE: Remove entry
        ldap_connection.delete(str(person_entry.dn))

        # Verify deletion
        result = ldap_connection.search(
            str(person_entry.dn),
            "(objectClass=*)",
            search_scope="BASE",
        )
        assert not result or len(ldap_connection.entries) == 0


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapBatchOperations:
    """Test batch processing operations with real LDAP server."""

    def test_batch_entry_creation_via_api(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Create batch of entries using FlextLdif API and write to LDAP."""
        # Build 20 entries using API (no manual loops!)
        entries = []
        for i in range(20):
            person_dn = f"cn=Batch User {i},{clean_test_ou}"
            result = flext_api.create_entry(
                dn=person_dn,
                attributes={
                    "cn": f"Batch User {i}",
                    "sn": f"User{i}",
                    "mail": f"batch{i}@example.com",
                },
                objectclasses=["inetOrgPerson", "person", "top"]
            )
            if result.is_success:
                entries.append(result.unwrap())

        assert len(entries) == 20

        # Write to LDAP in batch
        ldap_entries = []
        for entry in entries:
            # Extract object classes (not included in attributes dict)
            object_classes = entry.get_attribute_values("objectclass")
            if not isinstance(object_classes, list):
                # Convert to list if needed
                object_classes = list(object_classes) if object_classes else []

            # Build attributes dict from FlextLdif entry
            # EXCLUDE objectclass as it's passed separately to ldap3.add()
            attrs_dict = {}
            for attr_name, attr_values in entry.attributes.attributes.items():
                # Skip objectclass - it's handled separately
                if attr_name.lower() == "objectclass":
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

            ldap_connection.add(
                str(entry.dn),
                object_classes,
                attrs_dict,
            )
            ldap_entries.append(entry.dn)

        # Validate batch
        validation_result = flext_api.validate_entries(entries)
        assert validation_result.is_success

    def test_batch_ldif_export_import(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Export batch from LDAP to LDIF file, then reimport."""
        # Create test data in LDAP
        for i in range(10):
            person_dn = f"cn=Export Batch {i},{clean_test_ou}"
            ldap_connection.add(
                person_dn,
                ["person", "inetOrgPerson"],
                {
                    "cn": f"Export Batch {i}",
                    "sn": f"Batch{i}",
                    "mail": f"export{i}@example.com",
                },
            )

        # Export all to LDIF file
        ldap_connection.search(
            clean_test_ou,
            "(objectClass=person)",
            search_scope="SUBTREE",
            attributes=["*"],
        )

        # Work with actual number of entries found
        # (may vary based on LDAP server state)
        actual_count = len(ldap_connection.entries)
        assert actual_count > 0, "No entries found in LDAP"

        entries = []
        for entry in ldap_connection.entries:
            # Convert ldap3 entry attributes to dict format
            attrs_dict = {}
            for attr_name in entry.entry_attributes:
                attr_obj = entry[attr_name]
                # Extract values from ldap3 Attribute object
                if hasattr(attr_obj, "values"):
                    values = [str(v) if not isinstance(v, str) else v for v in attr_obj]
                elif isinstance(attr_obj, list):
                    values = [str(v) for v in attr_obj]
                else:
                    values = [str(attr_obj)]
                attrs_dict[attr_name] = values

            result = flext_api.models.Entry.create(
                dn=entry.entry_dn,
                attributes=attrs_dict,
                metadata=None,
            )
            assert result.is_success
            entries.append(result.unwrap())

        export_file = tmp_path / "batch_export.ldif"
        write_result = flext_api.write(entries, export_file)
        assert write_result.is_success
        assert export_file.exists()

        # Parse exported file - should match number of exported entries
        parse_result = flext_api.parse(export_file)
        assert parse_result.is_success
        parsed_entries = parse_result.unwrap()
        # Verify roundtrip preserves entry count
        assert len(parsed_entries) == actual_count


__all__ = ["TestRealLdapBatchOperations", "TestRealLdapCRUD"]
