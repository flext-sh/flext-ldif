"""CRUD and batch operations with live LDAP server.

Test suite verifying LDIF operations against an actual LDAP server:
    - Parse and write LDIF from/to LDAP server
    - Validate roundtrip data integrity (LDAP → LDIF → LDAP)
    - Extract and process schema information
    - Handle ACL entries
    - Perform CRUD operations
    - Process batches of entries

Uses Docker fixture infrastructure from conftest.py for automatic
container management via tk.ldap_container fixture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest
from ldap3 import Connection

from flext_ldif import FlextLdif, m


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
        make_test_username: Callable[[str], str],
    ) -> None:
        """Test Create→Read→Update→Delete cycle."""
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
        obj_class_values = person_entry.get_attribute_values("objectclass")
        assert isinstance(obj_class_values, list)
        assert person_entry.attributes is not None
        ldap_connection.add(
            str(person_entry.dn),
            obj_class_values,
            {
                attr: person_entry.attributes.attributes[attr]
                for attr in person_entry.attributes.attributes
                if attr.lower() != "objectclass"
            },
        )
        ldap_connection.modify(
            str(person_entry.dn),
            {"mail": [("MODIFY_REPLACE", ["updated_crud@example.com"])]},
        )
        ldap_connection.search(
            str(person_entry.dn), "(objectClass=*)", attributes=["*"]
        )
        updated_entry = ldap_connection.entries[0]
        assert updated_entry["mail"].value == "updated_crud@example.com"
        ldap_connection.delete(str(person_entry.dn))
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
        make_test_username: Callable[[str], str],
    ) -> None:
        """Create batch of entries using FlextLdif API and write to LDAP."""
        entries: Sequence[m.Ldif.Entry] = []
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
                if hasattr(unwrapped_entry, "dn") and hasattr(
                    unwrapped_entry, "attributes"
                ):
                    entries.append(unwrapped_entry)
                else:
                    entry_dict = unwrapped_entry.model_dump()
                    facade_entry = m.Ldif.Entry.model_validate(entry_dict)
                    entries.append(facade_entry)
        assert len(entries) == 20
        ldap_entries: Sequence[m.Ldif.DN | None] = []
        for entry in entries:
            object_classes = entry.get_attribute_values("objectclass")
            if not isinstance(object_classes, list):
                object_classes_typed: Sequence[str] = (
                    list(object_classes) if object_classes else []
                )
                object_classes = object_classes_typed
            attrs_dict: Mapping[str, Sequence[str]] = {}
            assert entry.attributes is not None
            for attr_name, attr_values in entry.attributes.attributes.items():
                if attr_name.lower() == "objectclass":
                    continue
                if isinstance(attr_values, list):
                    attrs_dict[attr_name] = attr_values
                elif hasattr(attr_values, "values"):
                    attrs_dict[attr_name] = list(attr_values.values)
                else:
                    attrs_dict[attr_name] = [str(attr_values)]
            ldap_connection.add(str(entry.dn), object_classes, attrs_dict)
            ldap_entries.append(entry.dn)
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
        ldap_connection.search(
            clean_test_ou,
            "(objectClass=person)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        actual_count = len(ldap_connection.entries)
        assert actual_count > 0, "No entries found in LDAP"
        entries: Sequence[m.Ldif.Entry] = []
        for entry in ldap_connection.entries:
            attrs_dict = {}
            for attr_name in entry.entry_attributes:
                attr_obj = entry[attr_name]
                if hasattr(attr_obj, "values"):
                    values = [str(v) if not isinstance(v, str) else v for v in attr_obj]
                elif isinstance(attr_obj, list):
                    values = [str(v) for v in attr_obj]
                else:
                    values = [str(attr_obj)]
                attrs_dict[attr_name] = values
            result = m.Ldif.Entry.create(
                dn=entry.entry_dn, attributes=attrs_dict, metadata=None
            )
            assert result.is_success
            unwrapped_entry = result.value
            if hasattr(unwrapped_entry, "dn") and hasattr(
                unwrapped_entry, "attributes"
            ):
                entries.append(unwrapped_entry)
            else:
                entry_dict = unwrapped_entry.model_dump()
                facade_entry = m.Ldif.Entry.model_validate(entry_dict)
                entries.append(facade_entry)
        export_file = tmp_path / "batch_export.ldif"
        write_result = flext_api.write_file(entries, export_file)
        assert write_result.is_success
        assert export_file.exists()
        parse_result = flext_api.parse(export_file)
        assert parse_result.is_success
        parsed_entries = parse_result.value
        assert len(parsed_entries) == actual_count


__all__ = ["TestRealLdapBatchOperations", "TestRealLdapCRUD"]
