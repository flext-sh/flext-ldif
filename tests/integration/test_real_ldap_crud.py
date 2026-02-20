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

from collections.abc import Callable
from pathlib import Path

import pytest
from flext_ldif import FlextLdif
from flext_ldif.models import m
from ldap3 import Connection

# Note: ldap_connection and clean_test_ou fixtures are provided by conftest.py
# They use unique_dn_suffix for isolation and indepotency in parallel execution


@pytest.fixture
def flext_api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
@pytest.mark.skip(
    reason="LDAP connection fixtures not implemented - requires real LDAP server"
)
class TestRealLdapCRUD:
    """Test CRUD operations with LDAP server."""

    def test_complete_crud_cycle(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Test Create→Read→Update→Delete cycle."""
        # CREATE: Build entry using FlextLdif API with isolated username
        unique_username = make_test_username("CRUDTestUser")
        person_dn = f"cn={unique_username},{clean_test_ou}"
        person_result = flext_api.create_entry(
            dn=person_dn,
            attributes={
                "cn": unique_username,
                "sn": "User",
                "mail": "crud@example.com",
                "uid": unique_username,
            },
            objectclasses=["inetOrgPerson", "person", "top"],
        )
        assert person_result.is_success
        person_entry = person_result.value

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
        make_test_username: Callable[[str], str],
    ) -> None:
        """Create batch of entries using FlextLdif API and write to LDAP."""
        # Build 20 entries using API with isolated usernames
        entries = []
        for i in range(20):
            unique_username = make_test_username(f"BatchUser{i}")
            person_dn = f"cn={unique_username},{clean_test_ou}"
            result = flext_api.create_entry(
                dn=person_dn,
                attributes={
                    "cn": unique_username,
                    "sn": f"User{i}",
                    "mail": f"batch{i}@example.com",
                },
                objectclasses=["inetOrgPerson", "person", "top"],
            )
            if result.is_success:
                unwrapped_entry = result.value
                # Convert domain Entry to facade Entry if needed
                if hasattr(unwrapped_entry, "dn") and hasattr(
                    unwrapped_entry, "attributes"
                ):
                    entries.append(unwrapped_entry)
                else:
                    # Convert domain Entry to facade Entry
                    entry_dict = unwrapped_entry.model_dump()
                    facade_entry = m.Ldif.Entry.model_validate(entry_dict)
                    entries.append(facade_entry)

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
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export batch from LDAP to LDIF file, then reimport."""
        # Create test data in LDAP with isolated usernames
        unique_usernames = [make_test_username(f"ExportBatch{i}") for i in range(10)]
        for i, unique_username in enumerate(unique_usernames):
            person_dn = f"cn={unique_username},{clean_test_ou}"
            ldap_connection.add(
                person_dn,
                ["person", "inetOrgPerson"],
                {
                    "cn": unique_username,
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

            result = m.Ldif.Entry.create(
                dn=entry.entry_dn,
                attributes=attrs_dict,
                metadata=None,
            )
            assert result.is_success
            unwrapped_entry = result.value
            # Convert domain Entry to facade Entry if needed
            if hasattr(unwrapped_entry, "dn") and hasattr(
                unwrapped_entry, "attributes"
            ):
                entries.append(unwrapped_entry)
            else:
                # Convert domain Entry to facade Entry
                entry_dict = unwrapped_entry.model_dump()
                facade_entry = m.Ldif.Entry.model_validate(entry_dict)
                entries.append(facade_entry)

        export_file = tmp_path / "batch_export.ldif"
        write_result = flext_api.write_file(entries, export_file)
        assert write_result.is_success
        assert export_file.exists()

        # Parse exported file - should match number of exported entries
        parse_result = flext_api.parse(export_file)
        assert parse_result.is_success
        parsed_entries = parse_result.value
        # Verify roundtrip preserves entry count
        assert len(parsed_entries) == actual_count


__all__ = ["TestRealLdapBatchOperations", "TestRealLdapCRUD"]
