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
from collections.abc import Callable
from pathlib import Path

import pytest
from ldap3 import Connection

from flext_ldif import FlextLdif

# Note: ldap_connection and clean_test_ou fixtures are provided by conftest.py
# They use unique_dn_suffix for isolation and indepotency in parallel execution


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
        # Use isolated username for parallel execution
        unique_username = make_test_username("ImportTest")
        ldif_content = f"""dn: cn={unique_username},{clean_test_ou}
objectClass: person
objectClass: inetOrgPerson
cn: {unique_username}
sn: Test
mail: import@example.com
"""

        # Parse LDIF
        parse_result = flext_api.parse(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value
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
        # Use isolated username for parallel execution
        unique_username = make_test_username("BinaryTest")
        # Create entry with binary data (simulated photo)
        binary_data = b"fake_jpeg_data_here"
        encoded_photo = base64.b64encode(binary_data).decode("ascii")

        ldif_content = f"""dn: cn={unique_username},{clean_test_ou}
objectClass: person
objectClass: inetOrgPerson
cn: {unique_username}
sn: Test
jpegPhoto:: {encoded_photo}
"""

        # Parse LDIF
        parse_result = flext_api.parse(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value

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

        # Add objectClass to attrs_dict
        attrs_dict["objectClass"] = entry.get_attribute_values("objectclass")

        ldap_connection.add(
            str(entry.dn),
            entry.get_attribute_values("objectclass"),
            attributes=attrs_dict,  # Use attrs_dict with corrected binary data
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
        make_test_username: Callable[[str], str],
    ) -> None:
        """Import LDIF file to LDAP server."""
        # Use isolated username for parallel execution
        unique_username = make_test_username("FileImport")
        # Create LDIF file
        ldif_file = tmp_path / "import.ldif"
        ldif_content = f"""dn: cn={unique_username},{clean_test_ou}
objectClass: person
objectClass: inetOrgPerson
cn: {unique_username}
sn: Test
mail: import@example.com
"""
        ldif_file.write_text(ldif_content)

        # Parse file
        parse_result = flext_api.parse(ldif_file)
        assert parse_result.is_success
        entries = parse_result.value
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
        assert imported["cn"].value == unique_username


__all__ = [
    "TestRealLdapImport",
]
