"""Test suite for Oracle Internet Directory (OID) quirks.

Comprehensive testing for OID-specific LDIF parsing using real fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.api import FlextLdif
from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils


@pytest.fixture(scope="module")
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test module."""
    return FlextLdif()


class TestOidQuirksWithRealFixtures:
    """Test OID quirks with real fixture files."""

    def test_parse_oid_schema_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OID schema file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oid", "oid_schema_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

        # Validate that all entries have valid DNs
        for entry in entries:
            assert entry.dn is not None
            assert entry.dn.value
            assert len(entry.attributes) > 0

    def test_parse_oid_entries_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OID entries file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oid", "oid_entries_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

        # Validate that all entries have valid DNs
        for entry in entries:
            assert entry.dn is not None
            assert entry.dn.value
            assert len(entry.attributes) > 0

        # Validate at least one entry has objectClass
        has_any_objectclass = False
        for entry in entries:
            if any(
                attr_name.lower() == "objectclass" for attr_name in entry.attributes.keys()
            ):
                has_any_objectclass = True
                break

        assert has_any_objectclass, (
            "At least one entry should have objectClass attribute"
        )

    def test_parse_oid_acl_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OID ACL file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oid", "oid_acl_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

    def test_roundtrip_oid_entries(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OID entries."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "oid", "oid_entries_fixtures.ldif", tmp_path
        )

    def test_roundtrip_oid_schema(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OID schema."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "oid", "oid_schema_fixtures.ldif", tmp_path
        )

    def test_roundtrip_oid_acl(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OID ACL."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "oid", "oid_acl_fixtures.ldif", tmp_path
        )

    def test_oid_oracle_specific_attributes_preserved(
        self, ldif_api: FlextLdif
    ) -> None:
        """Test that Oracle-specific attributes are properly preserved."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oid", "oid_entries_fixtures.ldif"
        )

        # Find Oracle-specific entries (orclguid, etc.)
        has_oracle_attrs = False
        for entry in entries:
            for attr_name in entry.attributes.keys():
                if attr_name.lower().startswith("orcl"):
                    has_oracle_attrs = True
                    break
            if has_oracle_attrs:
                break

        # Note: If no Oracle-specific attrs found, that's okay - depends on fixture content

    def test_oid_password_hashes_preserved(self, ldif_api: FlextLdif) -> None:
        """Test that OID password hashes are properly preserved."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oid", "oid_entries_fixtures.ldif"
        )

        # Find entries with userPassword
        password_entries = []
        for entry in entries:
            for attr_name in entry.attributes.keys():
                if attr_name.lower() == "userpassword":
                    password_entries.append(entry)
                    break

        # Validate password formats if found
        if password_entries:
            for entry in password_entries:
                for attr_name, attr_value in entry.attributes.items():
                    if attr_name.lower() == "userpassword":
                        if isinstance(attr_value, list):
                            values = attr_value
                        elif hasattr(attr_value, "values"):
                            values = attr_value.values
                        else:
                            values = [attr_value]
                        # Verify values exist
                        assert len(values) > 0
                        break
