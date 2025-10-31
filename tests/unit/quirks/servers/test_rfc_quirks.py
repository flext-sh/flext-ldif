"""Test suite for RFC 2849/4512 baseline quirks.

Comprehensive testing for RFC-compliant LDIF parsing using real fixtures.

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


class TestRfcQuirksWithRealFixtures:
    """Test RFC quirks with real fixture files."""

    def test_parse_rfc_schema_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real RFC schema file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "rfc", "rfc_schema_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

        # Validate that all entries have valid DNs
        for entry in entries:
            assert entry.dn is not None
            assert entry.dn.value
            assert len(entry.attributes) > 0

    def test_parse_rfc_entries_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real RFC entries file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "rfc", "rfc_entries_fixtures.ldif"
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
                attr_name.lower() == "objectclass" for attr_name in entry.attributes
            ):
                has_any_objectclass = True
                break

        assert has_any_objectclass, (
            "At least one entry should have objectClass attribute"
        )

    def test_parse_rfc_acl_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real RFC ACL file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "rfc", "rfc_acl_fixtures.ldif"
        )
        assert entries is not None
        assert len(entries) > 0

    def test_roundtrip_rfc_entries(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of RFC entries."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "rfc", "rfc_entries_fixtures.ldif", tmp_path
        )

    def test_roundtrip_rfc_schema(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of RFC schema."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "rfc", "rfc_schema_fixtures.ldif", tmp_path
        )

    def test_roundtrip_rfc_acl(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of RFC ACL."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "rfc", "rfc_acl_fixtures.ldif", tmp_path
        )

    def test_rfc_compliance_validation(self, ldif_api: FlextLdif) -> None:
        """Test that RFC parsing follows RFC 2849 and RFC 4512 standards."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api, "rfc", "rfc_entries_fixtures.ldif"
        )

        # All entries should have proper structure
        for entry in entries:
            # DN is required per RFC 2849
            assert entry.dn is not None
            assert entry.dn.value

            # Attributes should be present (can be dict-like or LdifAttributes model)
            assert entry.attributes is not None
            assert len(entry.attributes) > 0
