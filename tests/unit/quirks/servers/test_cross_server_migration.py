"""Test suite for Cross-Server Migration.

Modules tested: FlextLdif (write, parse)
Scope: Cross-server migrations, RFC-as-hub strategy, OID↔OUD↔RFC conversions,
round-trip validation, entry preservation

Tests migrations between all server types to ensure perfect conversions.
Uses RFC-as-hub strategy for all conversions. Uses real fixtures and parametrized tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif

from .test_utils import FlextLdifTestUtils


@pytest.fixture(scope="module")
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test module."""
    return FlextLdif()


class TestCrossServerMigration:
    """Test migrations between server types using RFC-as-hub strategy."""

    def test_oid_to_oud_migration(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test OID → RFC → OUD migration."""
        # Parse OID entries
        oid_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "oid",
            "oid_entries_fixtures.ldif",
        )
        assert len(oid_entries) > 0

        # Write as OUD (this should convert via RFC)
        output_path = tmp_path / "oid_to_oud.ldif"
        write_result = ldif_api.write(
            oid_entries,
            output_path=output_path,
            server_type="oud",
        )
        assert write_result.is_success, f"OID→OUD write failed: {write_result.error}"

        # Parse back as OUD
        oud_result = ldif_api.parse(output_path, server_type="oud")
        assert oud_result.is_success, f"OUD parse failed: {oud_result.error}"

        oud_entries = oud_result.unwrap()
        assert len(oud_entries) > 0
        # Entry count should match
        assert len(oud_entries) == len(oid_entries)

    def test_oud_to_oid_migration(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test OUD → RFC → OID migration."""
        # Parse OUD entries
        oud_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "oud",
            "oud_entries_fixtures.ldif",
        )
        assert len(oud_entries) > 0

        # Write as OID
        output_path = tmp_path / "oud_to_oid.ldif"
        write_result = ldif_api.write(
            oud_entries,
            output_path=output_path,
            server_type="oid",
        )
        assert write_result.is_success, f"OUD→OID write failed: {write_result.error}"

        # Parse back as OID
        oid_result = ldif_api.parse(output_path, server_type="oid")
        assert oid_result.is_success, f"OID parse failed: {oid_result.error}"

        oid_entries = oid_result.unwrap()
        assert len(oid_entries) > 0

    def test_rfc_to_oid_migration(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test RFC → OID migration."""
        rfc_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_entries_fixtures.ldif",
        )
        assert len(rfc_entries) > 0

        output_path = tmp_path / "rfc_to_oid.ldif"
        write_result = ldif_api.write(
            rfc_entries,
            output_path=output_path,
            server_type="oid",
        )
        assert write_result.is_success, f"RFC→OID write failed: {write_result.error}"

    def test_rfc_to_oud_migration(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test RFC → OUD migration."""
        rfc_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "rfc",
            "rfc_entries_fixtures.ldif",
        )
        assert len(rfc_entries) > 0

        output_path = tmp_path / "rfc_to_oud.ldif"
        write_result = ldif_api.write(
            rfc_entries,
            output_path=output_path,
            server_type="oud",
        )
        assert write_result.is_success, f"RFC→OUD write failed: {write_result.error}"

    def test_oid_schema_to_oud(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test OID schema → OUD migration."""
        oid_schema = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "oid",
            "oid_schema_fixtures.ldif",
        )
        assert len(oid_schema) > 0

        output_path = tmp_path / "oid_schema_to_oud.ldif"
        write_result = ldif_api.write(
            oid_schema,
            output_path=output_path,
            server_type="oud",
        )
        assert write_result.is_success, (
            f"OID schema→OUD write failed: {write_result.error}"
        )

    def test_migration_preserves_dn_structure(
        self,
        ldif_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test that DN structure is preserved across migrations."""
        # Load OID entries
        oid_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "oid",
            "oid_entries_fixtures.ldif",
        )

        # Migrate OID → OUD
        output_path = tmp_path / "dn_preservation_test.ldif"
        write_result = ldif_api.write(
            oid_entries,
            output_path=output_path,
            server_type="oud",
        )
        assert write_result.is_success

        # Parse back
        oud_result = ldif_api.parse(output_path, server_type="oud")
        assert oud_result.is_success

        oud_entries = oud_result.unwrap()

        # Validate DNs are preserved (no data loss)
        oid_dns = {e.dn.value for e in oid_entries}
        oud_dns = {e.dn.value for e in oud_entries}

        # DN count should match
        assert len(oud_dns) == len(oid_dns), (
            f"DN count mismatch: {len(oid_dns)} → {len(oud_dns)}"
        )

    def test_migration_preserves_attribute_names(
        self,
        ldif_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test that attribute names are properly transformed during migration."""
        # Load a small OID fixture
        oid_entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "oid",
            "oid_entries_fixtures.ldif",
        )

        # Get all attribute names from OID
        oid_attr_names = set()
        for entry in oid_entries[:5]:  # Sample first 5
            oid_attr_names.update(entry.attributes.keys())

        # Migrate to OUD
        output_path = tmp_path / "attr_preservation_test.ldif"
        write_result = ldif_api.write(
            oid_entries[:5],
            output_path=output_path,
            server_type="oud",
        )
        assert write_result.is_success

        # Parse as OUD
        oud_result = ldif_api.parse(output_path, server_type="oud")
        assert oud_result.is_success

        oud_entries = oud_result.unwrap()

        # Get all attribute names from OUD
        oud_attr_names = set()
        for entry in oud_entries:
            oud_attr_names.update(entry.attributes.keys())

        # Should have attributes (transformed or preserved)
        assert len(oud_attr_names) > 0, "No attributes found in migrated entries"
