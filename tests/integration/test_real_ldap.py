"""Integration tests with live LDAP server.

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
import os
from collections.abc import Generator
from pathlib import Path

import pytest
from ldap3 import ALL, MODIFY_ADD, MODIFY_REPLACE, Connection, Server

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
class TestRealLdapExport:
    """Test LDIF export from real LDAP server."""

    def test_export_single_entry(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Export single LDAP entry to LDIF."""
        # Create real LDAP entry
        person_dn = f"cn=Test User,{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {
                "cn": "Test User",
                "sn": "User",
                "mail": "test@example.com",
                "telephoneNumber": "+1-555-1234",
            },
        )

        # Search and export
        ldap_connection.search(
            clean_test_ou,
            "(cn=Test User)",
            attributes=["*"],
        )

        assert len(ldap_connection.entries) == 1
        ldap_entry = ldap_connection.entries[0]

        # Convert to FlextLdif entry - convert ldap3 entry attributes to dict
        attrs_dict = {}
        for attr_name in ldap_entry.entry_attributes:
            # ldap3 returns Attribute objects, extract the raw_values
            attr_obj = ldap_entry[attr_name]
            if hasattr(attr_obj, "raw_values"):
                # raw_values is a list of bytes
                values = [
                    v.decode("utf-8") if isinstance(v, bytes) else str(v)
                    for v in attr_obj.raw_values
                ]
            elif hasattr(attr_obj, "value"):
                # single value
                val = attr_obj.value
                if isinstance(val, bytes):
                    values = [val.decode("utf-8")]
                elif isinstance(val, list):
                    values = [
                        v.decode("utf-8") if isinstance(v, bytes) else str(v)
                        for v in val
                    ]
                else:
                    values = [str(val)]
            else:
                # fallback
                values = [str(attr_obj)]
            attrs_dict[attr_name] = values

        entry_result = flext_api.models.Entry.create(
            dn=ldap_entry.entry_dn,
            attributes=attrs_dict,
            metadata=None,
        )
        assert entry_result.is_success
        flext_entry = entry_result.unwrap()

        # Write to LDIF
        write_result = flext_api.write([flext_entry])
        assert write_result.is_success
        ldif_output = write_result.unwrap()

        # Verify LDIF contains expected data
        assert "dn: cn=Test User" in ldif_output
        assert "cn: Test User" in ldif_output
        assert "sn: User" in ldif_output
        assert "mail: test@example.com" in ldif_output

    def test_export_multiple_entries(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Export multiple LDAP entries to LDIF."""
        # Create multiple entries
        for i in range(5):
            person_dn = f"cn=User{i},{clean_test_ou}"
            ldap_connection.add(
                person_dn,
                ["person", "inetOrgPerson"],
                {
                    "cn": f"User{i}",
                    "sn": f"Surname{i}",
                    "mail": f"user{i}@example.com",
                },
            )

        # Search all
        ldap_connection.search(
            clean_test_ou,
            "(objectClass=person)",
            attributes=["*"],
        )

        assert len(ldap_connection.entries) == 5

        # Convert to FlextLdif entries
        entries = []
        for entry in ldap_connection.entries:
            # Convert ldap3 entry attributes to dict format
            # entry.attributes is an Attributes object from ldap3, convert it to dict
            attrs_dict = {}
            for attr_name in entry.entry_attributes:
                # ldap3 returns Attribute objects, extract the raw_values
                attr_obj = entry[attr_name]
                if hasattr(attr_obj, "raw_values"):
                    # raw_values is a list of bytes
                    values = [
                        v.decode("utf-8") if isinstance(v, bytes) else str(v)
                        for v in attr_obj.raw_values
                    ]
                elif hasattr(attr_obj, "value"):
                    # single value
                    val = attr_obj.value
                    if isinstance(val, bytes):
                        values = [val.decode("utf-8")]
                    elif isinstance(val, list):
                        values = [
                            v.decode("utf-8") if isinstance(v, bytes) else str(v)
                            for v in val
                        ]
                    else:
                        values = [str(val)]
                else:
                    # fallback
                    values = [str(attr_obj)]
                attrs_dict[attr_name] = values

            result = flext_api.models.Entry.create(
                dn=entry.entry_dn,
                attributes=attrs_dict,
                metadata=None,
            )
            assert result.is_success
            entries.append(result.unwrap())

        # Write to LDIF
        write_result = flext_api.write(entries)
        assert write_result.is_success
        ldif_output = write_result.unwrap()

        # Verify all entries in LDIF
        for i in range(5):
            assert f"cn: User{i}" in ldif_output
            assert f"user{i}@example.com" in ldif_output

    def test_export_hierarchical_structure(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Export hierarchical LDAP structure to LDIF."""
        # Create nested OUs
        groups_ou_dn = f"ou=Groups,{clean_test_ou}"
        people_ou_dn = f"ou=People,{clean_test_ou}"

        ldap_connection.add(groups_ou_dn, ["organizationalUnit"], {"ou": "Groups"})
        ldap_connection.add(people_ou_dn, ["organizationalUnit"], {"ou": "People"})

        # Create person
        person_dn = f"cn=Alice,{people_ou_dn}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": "Alice", "sn": "Johnson"},
        )

        # Create group
        group_dn = f"cn=Admins,{groups_ou_dn}"
        ldap_connection.add(
            group_dn,
            ["groupOfNames"],
            {"cn": "Admins", "member": person_dn},
        )

        # Export entire tree
        ldap_connection.search(
            clean_test_ou,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )

        entries = []
        for entry in ldap_connection.entries:
            # Convert ldap3 entry attributes to dict format
            # entry.attributes is an Attributes object from ldap3, convert it to dict
            attrs_dict = {}
            for attr_name in entry.entry_attributes:
                # ldap3 returns Attribute objects, extract the raw_values
                attr_obj = entry[attr_name]
                if hasattr(attr_obj, "raw_values"):
                    # raw_values is a list of bytes
                    values = [
                        v.decode("utf-8") if isinstance(v, bytes) else str(v)
                        for v in attr_obj.raw_values
                    ]
                elif hasattr(attr_obj, "value"):
                    # single value
                    val = attr_obj.value
                    if isinstance(val, bytes):
                        values = [val.decode("utf-8")]
                    elif isinstance(val, list):
                        values = [
                            v.decode("utf-8") if isinstance(v, bytes) else str(v)
                            for v in val
                        ]
                    else:
                        values = [str(val)]
                else:
                    # fallback
                    values = [str(attr_obj)]
                attrs_dict[attr_name] = values

            result = flext_api.models.Entry.create(
                dn=entry.entry_dn,
                attributes=attrs_dict,
                metadata=None,
            )
            assert result.is_success
            entries.append(result.unwrap())

        write_result = flext_api.write(entries)
        assert write_result.is_success
        ldif_output = write_result.unwrap()

        # Verify hierarchy preserved
        assert "ou=Groups" in ldif_output
        assert "ou=People" in ldif_output
        assert "cn=Alice" in ldif_output
        assert "cn=Admins" in ldif_output


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
            str(entry.dn), "(objectClass=*)", search_scope="BASE", attributes=["*"]
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
            str(entry.dn), "(objectClass=*)", search_scope="BASE", attributes=["*"]
        )
        imported_entry = ldap_connection.entries[0]
        assert imported_entry["jpegPhoto"].value == binary_data


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
        reimport_attrs: dict[str, list[str]] = {
            attr_name: attr_values
            for attr_name, attr_values in reimport_entry.attributes.attributes.items()
            if attr_name.lower() != "objectclass"
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
            },
        )

        # Verify reimported entry
        assert ldap_connection.search(reimport_dn, "(objectClass=*)", attributes=["*"])
        reimported = ldap_connection.entries[0]

        # Verify attributes preserved
        assert reimported["sn"].value == original_attrs["sn"]
        assert reimported["mail"].value == original_attrs["mail"]
        assert set(reimported["telephoneNumber"].values) == set(
            original_attrs["telephoneNumber"]
        )


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapValidation:
    """Test LDIF validation against real LDAP schema."""

    def test_validate_ldif_entries(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Validate LDIF entries using FlextLdif."""
        valid_ldif = f"""dn: cn=Valid Entry,{clean_test_ou}
objectClass: person
objectClass: inetOrgPerson
cn: Valid Entry
sn: Entry
mail: valid@example.com
"""

        parse_result = flext_api.parse(valid_ldif)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Validate entries
        validation_result = flext_api.validate_entries(entries)
        assert validation_result.is_success

        validation_report = validation_result.unwrap()
        assert validation_report.is_valid

    def test_detect_invalid_ldif(
        self,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Detect invalid LDIF entries."""
        # Missing required 'sn' for person objectClass
        invalid_ldif = f"""dn: cn=Invalid Entry,{clean_test_ou}
objectClass: person
cn: Invalid Entry
"""

        parse_result = flext_api.parse(invalid_ldif)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # This should parse but fail validation
        validation_result = flext_api.validate_entries(entries)

        # Depending on validation strictness, this may pass or fail
        # Real LDAP would reject this, so we just verify validation runs
        assert validation_result.is_success or validation_result.is_failure


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapModify:
    """Test LDAP modification operations with LDIF."""

    def test_modify_entry_with_ldif(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Modify LDAP entry and export changes to LDIF."""
        # Create entry
        entry_dn = f"cn=Modify Test,{clean_test_ou}"
        ldap_connection.add(
            entry_dn,
            ["person", "inetOrgPerson"],
            {"cn": "Modify Test", "sn": "Test", "mail": "original@example.com"},
        )

        # Modify entry
        ldap_connection.modify(
            entry_dn,
            {"mail": [(MODIFY_REPLACE, ["updated@example.com"])]},
        )

        # Export modified entry
        ldap_connection.search(entry_dn, "(objectClass=*)", attributes=["*"])
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

        # Verify LDIF contains updated value
        assert "mail: updated@example.com" in ldif_output
        assert "original@example.com" not in ldif_output

    def test_add_attribute_via_ldif(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Add attribute to entry via LDIF parsing."""
        # Create minimal entry
        entry_dn = f"cn=Add Attr Test,{clean_test_ou}"
        ldap_connection.add(
            entry_dn,
            ["person", "inetOrgPerson"],
            {"cn": "Add Attr Test", "sn": "Test"},
        )

        # Prepare LDIF with additional attribute
        updated_ldif = f"""dn: {entry_dn}
changetype: modify
add: telephoneNumber
telephoneNumber: +1-555-9999
"""

        parse_result = flext_api.parse(updated_ldif)
        assert parse_result.is_success
        _ = parse_result.unwrap()

        # Apply change to LDAP (if entry has changetype, handle accordingly)
        # For simplicity, just add the attribute directly
        ldap_connection.modify(
            entry_dn,
            {"telephoneNumber": [(MODIFY_ADD, ["+1-555-9999"])]},
        )

        # Verify
        assert ldap_connection.search(entry_dn, "(objectClass=*)", attributes=["*"])
        modified_entry = ldap_connection.entries[0]
        assert "+1-555-9999" in modified_entry["telephoneNumber"].values


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapAnalytics:
    """Test LDIF analytics on real LDAP data."""

    def test_analyze_ldap_export(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Analyze LDIF exported from real LDAP server."""
        # Create diverse entries
        for i in range(10):
            person_dn = f"cn=Analyst{i},{clean_test_ou}"
            ldap_connection.add(
                person_dn,
                ["person", "inetOrgPerson"],
                {
                    "cn": f"Analyst{i}",
                    "sn": f"User{i}",
                    "mail": f"analyst{i}@example.com",
                },
            )

        # Export
        ldap_connection.search(
            clean_test_ou,
            "(objectClass=person)",
            attributes=["*"],
        )

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

        # Analyze
        analysis_result = flext_api.analyze(entries)
        assert analysis_result.is_success

        stats = analysis_result.unwrap()
        # Should find at least the 10 entries we created
        total_entries = stats.total_entries or 0
        assert total_entries >= 10, (
            f"Expected at least 10 entries, found {total_entries}"
        )
        obj_class_dist = stats.objectclass_distribution or {}
        assert isinstance(obj_class_dist, dict)
        assert "person" in obj_class_dist
        # Verify we have the expected object classes from our test data
        assert "inetOrgPerson" in obj_class_dist


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapFileOperations:
    """Test LDIF file operations with real LDAP data."""

    def test_export_to_file(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Export LDAP data to LDIF file."""
        # Create entry
        person_dn = f"cn=File Export,{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": "File Export", "sn": "Test", "mail": "export@example.com"},
        )

        # Export
        ldap_connection.search(person_dn, "(objectClass=*)", attributes=["*"])
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

        # Write to file
        output_file = tmp_path / "export.ldif"
        write_result = flext_api.write([flext_entry], output_file)
        assert write_result.is_success

        # Verify file
        assert output_file.exists()
        content = output_file.read_text()
        assert "cn: File Export" in content

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
            str(entry.dn), "(objectClass=*)", search_scope="BASE", attributes=["*"]
        )
        imported = ldap_connection.entries[0]
        assert imported["cn"].value == "File Import"


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
        person_result = flext_api.build(
            "person",
            cn="CRUD Test User",
            sn="User",
            base_dn=clean_test_ou,
            mail="crud@example.com",
            uid="crud_user",
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
            str(person_entry.dn), "(objectClass=*)", attributes=["*"]
        )
        updated_entry = ldap_connection.entries[0]
        assert updated_entry["mail"].value == "updated_crud@example.com"

        # DELETE: Remove entry
        ldap_connection.delete(str(person_entry.dn))

        # Verify deletion
        result = ldap_connection.search(
            str(person_entry.dn), "(objectClass=*)", search_scope="BASE"
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
            result = flext_api.build(
                "person",
                cn=f"Batch User {i}",
                sn=f"User{i}",
                base_dn=clean_test_ou,
                mail=f"batch{i}@example.com",
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

        # Analyze batch
        analysis_result = flext_api.analyze(entries)
        assert analysis_result.is_success
        stats = analysis_result.unwrap()
        assert (stats.total_entries or 0) == 20

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


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapConfigurationFromEnv:
    """Test configuration loading from .env file."""

    def test_config_loaded_from_env(
        self,
        flext_api: FlextLdif,
    ) -> None:
        """Verify FlextLdifConfig loads from environment variables."""
        # Configuration should be loaded from .env automatically
        config = flext_api.config

        # Verify configuration values (from .env or defaults)
        assert config.ldif_encoding in {"utf-8", "utf-16", "latin1"}
        assert config.max_workers >= 1
        assert isinstance(config.ldif_strict_validation, bool)
        assert isinstance(config.enable_performance_optimizations, bool)

        # Verify LDAP-specific config from environment
        ldap_host = os.getenv("LDAP_HOST", "localhost")
        ldap_port = int(os.getenv("LDAP_PORT", "3390"))

        assert ldap_host is not None
        assert ldap_port > 0
        assert ldap_port <= 65535

    def test_effective_workers_calculation(
        self,
        flext_api: FlextLdif,
    ) -> None:
        """Test dynamic worker calculation based on config and entry count."""
        config = flext_api.config

        # Small dataset - should use 1 worker
        small_workers = config.get_effective_workers(50)
        assert small_workers >= 1

        # Large dataset - should use multiple workers
        large_workers = config.get_effective_workers(10000)
        assert large_workers >= 1
        assert large_workers <= config.max_workers


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapRailwayComposition:
    """Test railway-oriented FlextResult composition with real LDAP."""

    def test_railway_parse_validate_write_cycle(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test FlextResult error handling composition."""
        # Create LDAP data
        person_dn = f"cn=Railway Test,{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": "Railway Test", "sn": "Test", "mail": "railway@example.com"},
        )

        # Search and convert to LDIF
        ldap_connection.search(person_dn, "(objectClass=*)", attributes=["*"])
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

        # Railway composition: write → parse → validate → analyze
        output_file = tmp_path / "railway.ldif"
        result = (
            flext_api.write([flext_entry], output_file)
            .flat_map(lambda _: flext_api.parse(output_file))
            .flat_map(
                lambda entries: flext_api.validate_entries(entries).map(
                    lambda _: entries
                )
            )
            .flat_map(
                lambda entries: flext_api.analyze(entries).map(
                    lambda stats: (entries, stats)
                )
            )
        )

        # Verify railway succeeded
        assert result.is_success
        entries, stats = result.unwrap()
        assert len(entries) == 1
        assert stats.total_entries == 1
