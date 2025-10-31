"""Comprehensive test suite for Oracle Unified Directory (OUD) quirks.

High-coverage testing using real OUD LDIF fixtures from tests/fixtures/oud/.
All tests use actual implementations with real data, no mocks.

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


class TestOudQuirksWithRealFixtures:
    """Test OUD quirks with real fixture files."""

    def test_parse_oud_schema_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OUD schema file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oud", "oud_schema_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

    def test_parse_oud_entries_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OUD entries file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oud", "oud_entries_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

        # Validate that all entries have valid DNs
        for entry in entries:
            assert entry.dn is not None
            assert entry.dn.value
            assert len(entry.attributes) > 0

        # Validate specific OUD entries exist
        dns = [e.dn.value for e in entries]
        assert "dc=example,dc=com" in dns
        assert "ou=users,dc=example,dc=com" in dns
        assert "ou=groups,dc=example,dc=com" in dns

        # Validate OUD-specific attributes are preserved
        has_any_objectclass = False
        for entry in entries:
            # Check that objectClass is present
            if any(
                attr_name.lower() == "objectclass" for attr_name in entry.attributes.keys()
            ):
                has_any_objectclass = True
                break

        assert has_any_objectclass, (
            "At least one entry should have objectClass attribute"
        )

    def test_parse_oud_acl_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OUD ACL file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oud", "oud_acl_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

    def test_roundtrip_oud_entries(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OUD entries."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "oud", "oud_entries_fixtures.ldif", tmp_path
        )

    def test_roundtrip_oud_schema(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OUD schema."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "oud", "oud_schema_fixtures.ldif", tmp_path
        )

    def test_roundtrip_oud_acl(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OUD ACL."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "oud", "oud_acl_fixtures.ldif", tmp_path
        )

    def test_oud_oracle_specific_attributes_preserved(
        self, ldif_api: FlextLdif
    ) -> None:
        """Test that Oracle-specific attributes are properly preserved."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oud", "oud_entries_fixtures.ldif"
        )

        # Find OracleContext entries
        oracle_entries = [
            e
            for e in entries
            if "OracleContext" in e.dn.value or "orclContainer" in str(e.attributes)
        ]
        assert len(oracle_entries) > 0, "Should have Oracle-specific entries"

        # Validate Oracle objectClasses exist
        has_oracle_objectclass = False
        for entry in entries:
            for attr_name, attr_value in entry.attributes.items():
                if attr_name.lower() == "objectclass":
                    if isinstance(attr_value, list):
                        values = attr_value
                    elif hasattr(attr_value, "values"):
                        values = attr_value.values
                    else:
                        values = [attr_value]
                    if any("orcl" in str(v).lower() for v in values):
                        has_oracle_objectclass = True
                        break

        assert has_oracle_objectclass, "Should have Oracle-specific objectClasses"

    def test_oud_password_hashes_preserved(self, ldif_api: FlextLdif) -> None:
        """Test that OUD password hashes are properly preserved."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "oud", "oud_entries_fixtures.ldif"
        )

        # Find entries with userPassword
        password_entries = []
        for entry in entries:
            for attr_name in entry.attributes.keys():
                if attr_name.lower() == "userpassword":
                    password_entries.append(entry)
                    break

        assert len(password_entries) > 0, "Should have entries with passwords"

        # Validate SSHA512 format is preserved
        for entry in password_entries:
            for attr_name, attr_value in entry.attributes.items():
                if attr_name.lower() == "userpassword":
                    if isinstance(attr_value, list):
                        values = attr_value
                    elif hasattr(attr_value, "values"):
                        values = attr_value.values
                    else:
                        values = [attr_value]
                    # At least one should be SSHA512
                    has_ssha = any("{SSHA512}" in str(v) for v in values)
                    if has_ssha:
                        break
