"""Tests for standardized quirk implementations.

This module verifies that all quirk implementations across different LDAP server
types (RFC, OID, OUD, OpenLDAP, etc.) have standardized Constants with expected
attributes like CANONICAL_NAME, ALIASES, and PRIORITY values.
"""

from __future__ import annotations

from collections.abc import (
    Sequence,
)
from pathlib import Path
from typing import Final

import pytest
from flext_tests import tm

from flext_ldif import (
    FlextLdifServersOid,
    FlextLdifServersOud,
    FlextLdifServersRfc,
)
from tests import c


@pytest.mark.unit
class TestsFlextLdifServersStandardizedConstants:
    """Verify all quirks have standardized Constants."""

    def test_rfc_schema_constants(self) -> None:
        """RFC Schema must have standardized Constants."""
        constants = FlextLdifServersRfc.Constants
        tm.that(constants.CANONICAL_NAME, eq="rfc")
        tm.that(constants.ALIASES, has="rfc")
        tm.that(constants.PRIORITY, eq=100)
        tm.that(constants.CAN_NORMALIZE_FROM, has="rfc")
        tm.that(constants.CAN_DENORMALIZE_TO, has="rfc")

    def test_rfc_acl_constants(self) -> None:
        """RFC Acl must have standardized Constants."""
        constants = FlextLdifServersRfc.Constants
        tm.that(constants.CANONICAL_NAME, eq="rfc")
        tm.that(constants.ALIASES, has="rfc")

    def test_rfc_entry_constants(self) -> None:
        """RFC Entry must have standardized Constants."""
        constants = FlextLdifServersRfc.Constants
        tm.that(constants.CANONICAL_NAME, eq="rfc")
        tm.that(constants.ALIASES, has="rfc")

    def test_oid_schema_constants(self) -> None:
        """OID Schema must have standardized Constants."""
        global_constants = FlextLdifServersOid.Constants
        tm.that(global_constants.CANONICAL_NAME, eq="oid")
        tm.that(global_constants.ALIASES, has="oid")
        tm.that(global_constants.ALIASES, has="oracle_oid")
        tm.that(global_constants.PRIORITY, eq=10)
        tm.that(global_constants.CAN_NORMALIZE_FROM, has="oid")
        tm.that(global_constants.CAN_DENORMALIZE_TO, has="rfc")

    def test_oud_schema_constants(self) -> None:
        """OUD must have standardized Constants."""
        global_constants = FlextLdifServersOud.Constants
        tm.that(global_constants.CANONICAL_NAME, eq="oud")
        tm.that(global_constants.ALIASES, has="oud")
        tm.that(global_constants.ALIASES, has="oracle_oud")
        tm.that(global_constants.PRIORITY, eq=10)
        tm.that(global_constants.CAN_NORMALIZE_FROM, has="oud")
        tm.that(global_constants.CAN_DENORMALIZE_TO, has="rfc")

    def test_constants_include_canonical_name(self) -> None:
        """Canonical name must be in aliases."""
        quirks: Final[
            Sequence[
                tuple[
                    type[
                        FlextLdifServersRfc | FlextLdifServersOid | FlextLdifServersOud
                    ],
                    str,
                ]
            ]
        ] = [
            (FlextLdifServersRfc, "rfc"),
            (FlextLdifServersOid, c.Ldif.Tests.OID),
            (FlextLdifServersOud, c.Ldif.Tests.OUD),
        ]
        for quirk_class, expected_canonical in quirks:
            constants = quirk_class.Constants
            tm.that(expected_canonical, eq=constants.CANONICAL_NAME)
            tm.that(constants.ALIASES, has=expected_canonical)

    def test_conversion_capabilities_valid(self) -> None:
        """Server must be able to convert itself."""
        quirks = [
            FlextLdifServersRfc.Constants,
            FlextLdifServersOid.Constants,
            FlextLdifServersOud.Constants,
        ]
        for constants in quirks:
            canonical = constants.CANONICAL_NAME
            _ = tm.that(constants.CAN_NORMALIZE_FROM, has=canonical)
            _ = tm.that(constants.CAN_DENORMALIZE_TO, has=canonical)


@pytest.mark.unit
class TestQuirksAutoInterchange:
    """Test automatic interchange between quirks via RFC intermediate."""

    def test_oid_to_oud_interchange_path(self) -> None:
        """OID → RFC → OUD conversion path must be possible."""
        oid_constants = FlextLdifServersOid.Constants
        rfc_constants = FlextLdifServersRfc.Constants
        oud_constants = FlextLdifServersOud.Constants
        tm.that(oid_constants.CAN_DENORMALIZE_TO, has="rfc")
        tm.that(rfc_constants.CAN_NORMALIZE_FROM, has="rfc")
        tm.that(oud_constants.CAN_NORMALIZE_FROM, has="rfc")
        tm.that(oud_constants.CAN_DENORMALIZE_TO, has="oud")


@pytest.mark.unit
@pytest.mark.ldif
class TestQuirksWithRealLdifFixtures:
    """Test quirks with real LDIF fixture data."""

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
        fixture_path = fixtures_dir / c.Ldif.Tests.OID / "oid_schema_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        return self._sample_ldif_records(fixture_path.read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def oud_schema_ldif(self) -> str:
        """Load real OUD schema LDIF fixture."""
        fixtures_dir = Path(__file__).resolve().parent.parent.parent / "fixtures"
        fixture_path = fixtures_dir / c.Ldif.Tests.OUD / "oud_schema_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        return self._sample_ldif_records(fixture_path.read_text(encoding="utf-8"))

    def test_oid_can_handle_real_oid_ldif(self, oid_schema_ldif: str) -> None:
        """OID quirk must handle real OID LDIF data."""
        oid = FlextLdifServersOid.Entry()
        result = oid.parse_input(oid_schema_ldif)
        tm.that(result, none=False)

    def test_rfc_handles_all_ldif(self, oid_schema_ldif: str) -> None:
        """RFC quirk must handle any valid LDIF (lowest priority fallback)."""
        rfc = FlextLdifServersRfc.Entry()
        result = rfc.parse_input(oid_schema_ldif)
        tm.that(result, none=False)

    def test_oud_can_handle_oud_ldif(self, oud_schema_ldif: str) -> None:
        """OUD quirk must handle real OUD LDIF data."""
        oud = FlextLdifServersOud.Entry()
        result = oud.parse_input(oud_schema_ldif)
        tm.that(result, none=False)


@pytest.mark.unit
class TestAliasDiscovery:
    """Test that Registry will discover aliases from quirk Constants."""

    def test_oid_aliases_discoverable(self) -> None:
        """OID aliases must be discoverable for normalization."""
        constants = FlextLdifServersOid.Constants
        tm.that(constants.ALIASES, has="oid")
        tm.that(constants.ALIASES, has="oracle_oid")
        tm.that(constants.ALIASES, has=constants.CANONICAL_NAME)

    def test_oud_aliases_discoverable(self) -> None:
        """OUD aliases must be discoverable for normalization."""
        constants = FlextLdifServersOud.Constants
        tm.that(constants.ALIASES, has="oud")
        tm.that(constants.ALIASES, has="oracle_oud")
        tm.that(constants.ALIASES, has=constants.CANONICAL_NAME)

    def test_rfc_aliases_discoverable(self) -> None:
        """RFC aliases must be discoverable."""
        constants = FlextLdifServersRfc.Constants
        tm.that(constants.ALIASES, has="rfc")
        tm.that(constants.ALIASES, has="generic")
        tm.that(constants.ALIASES, has=constants.CANONICAL_NAME)
