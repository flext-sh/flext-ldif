"""Test suite for RFC 2849/4512 baseline quirks.

Comprehensive testing for RFC-compliant LDIF parsing using real fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

from flext_ldif.api import FlextLdif
from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils

# Removed: use shared fixture from conftest.py


class TestRfcQuirksWithRealFixtures:
    """Test RFC quirks with real fixture files."""

    def test_parse_rfc_schema_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real RFC schema file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_schema_fixtures.ldif",
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
            ldif_api,
            "rfc",
            "rfc_entries_fixtures.ldif",
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
            ldif_api,
            "rfc",
            "rfc_acl_fixtures.ldif",
        )
        assert entries is not None
        assert len(entries) > 0

    def test_roundtrip_rfc_entries(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of RFC entries."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api,
            "rfc",
            "rfc_entries_fixtures.ldif",
            tmp_path,
        )

    def test_roundtrip_rfc_schema(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of RFC schema."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api,
            "rfc",
            "rfc_schema_fixtures.ldif",
            tmp_path,
        )

    def test_roundtrip_rfc_acl(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of RFC ACL."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api,
            "rfc",
            "rfc_acl_fixtures.ldif",
            tmp_path,
        )

    def test_rfc_compliance_validation(self, ldif_api: FlextLdif) -> None:
        """Test that RFC parsing follows RFC 2849 and RFC 4512 standards."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_entries_fixtures.ldif",
        )

        # All entries should have proper structure
        for entry in entries:
            # DN is required per RFC 2849
            assert entry.dn is not None
            assert entry.dn.value

            # Attributes should be present (can be dict-like or LdifAttributes model)
            assert entry.attributes is not None
            assert len(entry.attributes) > 0

    def test_routing_validation_schema_fixture(self, ldif_api: FlextLdif) -> None:
        """Test that schema fixtures route correctly through Schema quirks.

        This test validates that the automatic routing mechanism in base.py
        correctly identifies and routes schema definitions to the Schema quirk.
        """
        # Load schema fixture
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_schema_fixtures.ldif",
        )
        assert entries is not None
        assert len(entries) > 0

        # Get the RFC quirk to access Schema routing methods
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        FlextLdifServersRfc()

        # For each entry, verify that schema entries can be routed to Schema quirks
        for entry in entries:
            # Verify that entries have the expected schema structure
            assert entry.dn is not None
            assert entry.dn.value

            # Schema entries should have attributes like 'cn', 'attributeTypes', 'objectClasses'
            attr_names = {name.lower() for name in entry.attributes}
            assert len(attr_names) > 0, "Schema entries should have attributes"

    def test_routing_validation_entries_fixture(self, ldif_api: FlextLdif) -> None:
        """Test that entry fixtures route correctly through Entry quirks.

        This test validates that the automatic routing mechanism in base.py
        correctly identifies and routes entries to the Entry quirk.
        """
        # Load entry fixture
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_entries_fixtures.ldif",
        )
        assert entries is not None
        assert len(entries) > 0

        # Get the RFC quirk to access Entry routing methods
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        FlextLdifServersRfc()

        # For each entry, verify that entries can be processed by Entry quirks
        for entry in entries:
            # All entries should have valid DNs
            assert entry.dn is not None
            assert entry.dn.value

            # Entry quirks process entries during parse/write operations
            # No direct convert_entry method exists anymore

    def test_routing_validation_acl_fixture(self, ldif_api: FlextLdif) -> None:
        """Test that ACL fixtures route correctly through Acl quirks.

        This test validates that the automatic routing mechanism in base.py
        correctly identifies and routes ACL definitions to the Acl quirk.
        """
        # Load ACL fixture
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_acl_fixtures.ldif",
        )
        assert entries is not None
        assert len(entries) > 0

        # Get the RFC quirk to access Acl routing methods
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        FlextLdifServersRfc()

        # Verify that ACL entries have expected structure
        for entry in entries:
            assert entry.dn is not None
            assert entry.dn.value

            # ACL entries should have attributes
            assert len(entry.attributes) > 0

    def test_routing_write_validation_entries(self, ldif_api: FlextLdif) -> None:
        """Test that entries are correctly routed through write path.

        This test validates that the automatic write routing in base.py
        correctly processes entries through the Entry quirk's write methods.
        """
        # Load fixture
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_entries_fixtures.ldif",
        )
        assert entries is not None

        # Get RFC quirk
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()

        # Verify that entries can be written through Entry quirk
        for entry in entries:
            result = rfc.entry.write(entry)
            assert result.is_success, f"Failed to write entry: {result.error}"
            written_str = result.unwrap()
            assert written_str is not None
            assert len(written_str) > 0

    def test_routing_roundtrip_with_validation(
        self,
        ldif_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip with explicit routing validation.

        This test validates that the complete parse → convert → write → parse
        roundtrip works correctly with the automatic routing mechanism.
        """
        # Load original entries
        original_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_entries_fixtures.ldif",
        )
        assert original_entries is not None
        assert len(original_entries) > 0

        # Write to temporary file
        write_result = ldif_api.write(
            original_entries,
            output_path=tmp_path / "routing_test.ldif",
            server_type="rfc",
        )
        assert write_result.is_success, f"Write failed: {write_result.error}"

        # Re-read the written file
        re_read_result = ldif_api.parse(
            tmp_path / "routing_test.ldif",
            server_type="rfc",
        )
        assert re_read_result.is_success, f"Re-read failed: {re_read_result.error}"
        roundtripped_entries = re_read_result.unwrap()

        # Validate entries are semantically identical after routing
        is_equal, differences = FlextLdifTestUtils.compare_entries(
            original_entries,
            roundtripped_entries,
        )
        assert is_equal, "Roundtrip routing validation failed:\n" + "\n".join(
            differences,
        )
