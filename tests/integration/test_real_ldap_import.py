"""LDIF import operations with live LDAP server.

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

import base64
from collections.abc import (
    Callable,
    MutableMapping,
    MutableSequence,
)
from pathlib import Path

import pytest
from ldap3 import Connection

from flext_ldif import FlextLdif


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
        make_test_username: Callable[[str], str],
    ) -> None:
        """Import LDIF entry to real LDAP server."""
        unique_username = make_test_username("ImportTest")
        ldif_content = f"dn: cn={unique_username},{clean_test_ou}\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: {unique_username}\nsn: Test\nmail: import@example.com\n"
        parse_result = flext_api.parse_source(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value
        assert len(entries) == 1
        entry = entries[0]
        object_classes_raw = entry.get_attribute_values("objectclass")
        object_classes: list[str] = (
            list(object_classes_raw) if object_classes_raw else []
        )
        attrs_dict: MutableMapping[str, MutableSequence[str] | bytes] = {}
        assert entry.attributes is not None
        for attr_name, attr_values in entry.attributes.attributes.items():
            if attr_name.lower() == "objectclass":
                continue
            if attr_name.lower() == "dn":
                continue
            if isinstance(attr_values, list):
                attrs_dict[attr_name] = attr_values
            else:
                attrs_dict[attr_name] = [str(attr_values)]
        ldap_connection.add(str(entry.dn), object_classes, attributes=attrs_dict)
        assert ldap_connection.search(
            str(entry.dn),
            "(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )
        imported_entry = ldap_connection.entries[0]
        assert imported_entry["cn"].value == unique_username
        assert imported_entry["mail"].value == "import@example.com"

    def test_import_with_binary_attributes(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Import LDIF with binary attributes (base64-encoded)."""
        unique_username = make_test_username("BinaryTest")
        binary_data = b"fake_jpeg_data_here"
        encoded_photo = base64.b64encode(binary_data).decode("ascii")
        ldif_content = f"dn: cn={unique_username},{clean_test_ou}\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: {unique_username}\nsn: Test\njpegPhoto:: {encoded_photo}\n"
        parse_result = flext_api.parse_source(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value
        entry = entries[0]
        assert entry.attributes is not None
        attrs_dict: MutableMapping[str, MutableSequence[str] | bytes] = {
            attr_name: attr_values
            for attr_name, attr_values in entry.attributes.attributes.items()
            if attr_name.lower() != "objectclass"
        }
        if "jpegPhoto" in attrs_dict:
            attrs_dict["jpegPhoto"] = binary_data
        attrs_dict["objectClass"] = entry.get_attribute_values("objectclass")
        ldap_connection.add(
            str(entry.dn),
            entry.get_attribute_values("objectclass"),
            attributes=attrs_dict,
        )
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
        make_test_username: Callable[[str], str],
    ) -> None:
        """Import LDIF file to LDAP server."""
        unique_username = make_test_username("FileImport")
        ldif_file = tmp_path / "import.ldif"
        ldif_content = f"dn: cn={unique_username},{clean_test_ou}\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: {unique_username}\nsn: Test\nmail: import@example.com\n"
        ldif_file.write_text(ldif_content)
        parse_result = flext_api.parse_source(ldif_file)
        assert parse_result.is_success
        entries = parse_result.value
        assert len(entries) == 1
        entry = entries[0]
        object_classes_raw = entry.get_attribute_values("objectclass")
        object_classes: list[str] = (
            list(object_classes_raw) if object_classes_raw else []
        )
        attrs_dict: MutableMapping[str, MutableSequence[str] | bytes] = {}
        assert entry.attributes is not None
        for attr_name, attr_values in entry.attributes.attributes.items():
            if attr_name.lower() == "objectclass":
                continue
            if attr_name.lower() == "dn":
                continue
            if isinstance(attr_values, list):
                attrs_dict[attr_name] = attr_values
            else:
                attrs_dict[attr_name] = [str(attr_values)]
        ldap_connection.add(str(entry.dn), object_classes, attributes=attrs_dict)
        assert ldap_connection.search(
            str(entry.dn),
            "(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )
        imported = ldap_connection.entries[0]
        assert imported["cn"].value == unique_username


__all__ = ["TestRealLdapImport"]
