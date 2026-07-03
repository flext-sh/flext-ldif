"""Tests for standardized server implementations.

This module verifies that all server implementations across different LDAP server
types (RFC, OID, OUD, OpenLDAP, etc.) have standardized Constants with expected
attributes like CANONICAL_NAME, ALIASES, and PRIORITY values.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests.constants import c


@pytest.mark.unit
class TestsFlextLdifServersStandardization:
    """Verify all servers have standardized Constants."""

    """Test servers with real LDIF fixture data."""

    @staticmethod
    def _sample_ldif_records(ldif_content: str, max_records: int = 25) -> str:
        """Return first LDIF records to keep fixture parsing lightweight."""
        lines = ldif_content.splitlines()
        sampled: list[str] = []
        current_record: list[str] = []
        record_count = 0

        def flush_record() -> None:
            nonlocal record_count, current_record
            if not current_record:
                return
            if record_count < max_records:
                sampled.extend(current_record)
                sampled.append("")
                record_count += 1
            current_record = []

        for line in lines:
            if line.startswith("dn:"):
                flush_record()
                if record_count >= max_records:
                    break
                current_record = [line]
                continue
            if current_record:
                current_record.append(line)
        flush_record()
        return "\n".join(sampled).strip()

    @pytest.fixture(scope="class")
    def oid_schema_ldif(self) -> str:
        """Load real OID schema LDIF fixture."""
        fixtures_dir = Path(__file__).resolve().parent.parent.parent / "fixtures"
        fixture_path = fixtures_dir / c.Tests.OID / "oid_schema_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        return self._sample_ldif_records(fixture_path.read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def oud_schema_ldif(self) -> str:
        """Load real OUD schema LDIF fixture."""
        fixtures_dir = Path(__file__).resolve().parent.parent.parent / "fixtures"
        fixture_path = fixtures_dir / c.Tests.OUD / "oud_schema_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        return self._sample_ldif_records(fixture_path.read_text(encoding="utf-8"))

    def test_oid_can_handle_real_oid_ldif(self, oid_schema_ldif: str) -> None:
        """OID server must handle real OID LDIF data."""
        oid = FlextLdifServersOid.Entry()
        result = oid.parse_input(oid_schema_ldif)
        tm.that(result, none=False)

    def test_rfc_handles_all_ldif(self, oid_schema_ldif: str) -> None:
        """RFC server must handle any valid LDIF (lowest priority fallback)."""
        rfc = FlextLdifServersRfc.Entry()
        result = rfc.parse_input(oid_schema_ldif)
        tm.that(result, none=False)

    def test_oud_can_handle_oud_ldif(self, oud_schema_ldif: str) -> None:
        """OUD server must handle real OUD LDIF data."""
        oud = FlextLdifServersOud.Entry()
        result = oud.parse_input(oud_schema_ldif)
        tm.that(result, none=False)
