"""Tests for standardized quirk implementations.

This module verifies that all quirk implementations across different LDAP server
types (RFC, OID, OUD, OpenLDAP, etc.) have standardized Constants with expected
attributes like CANONICAL_NAME, ALIASES, and PRIORITY values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
from flext_tests import c, u

from flext_ldif.servers import (
    FlextLdifServersOid,
    FlextLdifServersOud,
    FlextLdifServersRfc,
)
from tests import c, s


@pytest.mark.unit
class TestsFlextLdifQuirksStandardizedConstants(s):
    """Verify all quirks have standardized Constants."""

    def test_rfc_schema_constants(self) -> None:
        """RFC Schema must have standardized Constants."""
        u.Tests.Matchers.that(hasattr(FlextLdifServersRfc, "Constants"), eq=True)
        constants = FlextLdifServersRfc.Constants
        u.Tests.Matchers.that(hasattr(constants, "CANONICAL_NAME"), eq=True)
        u.Tests.Matchers.that(constants.CANONICAL_NAME == "rfc", eq=True)
        u.Tests.Matchers.that("rfc" in constants.ALIASES, eq=True)
        u.Tests.Matchers.that(constants.PRIORITY == 100, eq=True)
        u.Tests.Matchers.that("rfc" in constants.CAN_NORMALIZE_FROM, eq=True)
        u.Tests.Matchers.that("rfc" in constants.CAN_DENORMALIZE_TO, eq=True)

    def test_rfc_acl_constants(self) -> None:
        """RFC Acl must have standardized Constants."""
        u.Tests.Matchers.that(hasattr(FlextLdifServersRfc, "Constants"), eq=True)
        constants = FlextLdifServersRfc.Constants
        u.Tests.Matchers.that(constants.CANONICAL_NAME == "rfc", eq=True)
        u.Tests.Matchers.that("rfc" in constants.ALIASES, eq=True)

    def test_rfc_entry_constants(self) -> None:
        """RFC Entry must have standardized Constants."""
        u.Tests.Matchers.that(hasattr(FlextLdifServersRfc, "Constants"), eq=True)
        constants = FlextLdifServersRfc.Constants
        u.Tests.Matchers.that(constants.CANONICAL_NAME == "rfc", eq=True)
        u.Tests.Matchers.that("rfc" in constants.ALIASES, eq=True)

    def test_oid_schema_constants(self) -> None:
        """OID Schema must have standardized Constants."""
        u.Tests.Matchers.that(hasattr(FlextLdifServersOid, "Constants"), eq=True)
        global_constants = FlextLdifServersOid.Constants
        u.Tests.Matchers.that(global_constants.CANONICAL_NAME == "oid", eq=True)
        u.Tests.Matchers.that("oid" in global_constants.ALIASES, eq=True)
        u.Tests.Matchers.that("oracle_oid" in global_constants.ALIASES, eq=True)
        u.Tests.Matchers.that(global_constants.PRIORITY == 10, eq=True)
        u.Tests.Matchers.that("oid" in global_constants.CAN_NORMALIZE_FROM, eq=True)
        u.Tests.Matchers.that("rfc" in global_constants.CAN_DENORMALIZE_TO, eq=True)

    def test_oud_schema_constants(self) -> None:
        """OUD must have standardized Constants."""
        u.Tests.Matchers.that(hasattr(FlextLdifServersOud, "Constants"), eq=True)
        global_constants = FlextLdifServersOud.Constants
        u.Tests.Matchers.that(global_constants.CANONICAL_NAME == "oud", eq=True)
        u.Tests.Matchers.that("oud" in global_constants.ALIASES, eq=True)
        u.Tests.Matchers.that("oracle_oud" in global_constants.ALIASES, eq=True)
        u.Tests.Matchers.that(global_constants.PRIORITY == 10, eq=True)
        u.Tests.Matchers.that("oud" in global_constants.CAN_NORMALIZE_FROM, eq=True)
        u.Tests.Matchers.that("rfc" in global_constants.CAN_DENORMALIZE_TO, eq=True)

    def test_constants_include_canonical_name(self) -> None:
        """Canonical name must be in aliases."""
        quirks: Final[
            list[
                tuple[
                    type[
                        FlextLdifServersRfc | FlextLdifServersOid | FlextLdifServersOud
                    ],
                    str,
                ]
            ]
        ] = [
            (FlextLdifServersRfc, "rfc"),
            (FlextLdifServersOid, c.Fixtures.OID),
            (FlextLdifServersOud, c.Fixtures.OUD),
        ]
        for quirk_class, expected_canonical in quirks:
            constants = quirk_class.Constants
            u.Tests.Matchers.that(
                expected_canonical == constants.CANONICAL_NAME, eq=True
            )
            u.Tests.Matchers.that(expected_canonical in constants.ALIASES, eq=True)

    def test_conversion_capabilities_valid(self) -> None:
        """Server must be able to convert itself."""
        quirks = [
            FlextLdifServersRfc.Constants,
            FlextLdifServersOid.Constants,
            FlextLdifServersOud.Constants,
        ]
        for constants in quirks:
            canonical = constants.CANONICAL_NAME
            (
                u.Tests.Matchers.that(
                    canonical in constants.CAN_NORMALIZE_FROM, eq=True
                ),
                (f"{canonical} must be in CAN_NORMALIZE_FROM"),
            )
            (
                u.Tests.Matchers.that(
                    canonical in constants.CAN_DENORMALIZE_TO, eq=True
                ),
                (f"{canonical} must be in CAN_DENORMALIZE_TO"),
            )


@pytest.mark.unit
class TestQuirksAutoInterchange:
    """Test automatic interchange between quirks via RFC intermediate."""

    def test_oid_to_oud_interchange_path(self) -> None:
        """OID → RFC → OUD conversion path must be possible."""
        oid_constants = FlextLdifServersOid.Constants
        rfc_constants = FlextLdifServersRfc.Constants
        oud_constants = FlextLdifServersOud.Constants
        u.Tests.Matchers.that("rfc" in oid_constants.CAN_DENORMALIZE_TO, eq=True)
        u.Tests.Matchers.that("rfc" in rfc_constants.CAN_NORMALIZE_FROM, eq=True)
        u.Tests.Matchers.that("rfc" in oud_constants.CAN_NORMALIZE_FROM, eq=True)
        u.Tests.Matchers.that("oud" in oud_constants.CAN_DENORMALIZE_TO, eq=True)


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
        fixture_path = Path(f"tests/fixtures/{c.Fixtures.OID}/oid_schema_fixtures.ldif")
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        return self._sample_ldif_records(fixture_path.read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def oud_schema_ldif(self) -> str:
        """Load real OUD schema LDIF fixture."""
        fixture_path = Path(f"tests/fixtures/{c.Fixtures.OUD}/oud_schema_fixtures.ldif")
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        return self._sample_ldif_records(fixture_path.read_text(encoding="utf-8"))

    def test_oid_can_handle_real_oid_ldif(self, oid_schema_ldif: str) -> None:
        """OID quirk must handle real OID LDIF data."""
        oid = FlextLdifServersOid.Entry()
        result = oid.parse(oid_schema_ldif)
        u.Tests.Matchers.that(result is not None, eq=True)

    def test_rfc_handles_all_ldif(self, oid_schema_ldif: str) -> None:
        """RFC quirk must handle any valid LDIF (lowest priority fallback)."""
        rfc = FlextLdifServersRfc.Entry()
        result = rfc.parse(oid_schema_ldif)
        u.Tests.Matchers.that(result is not None, eq=True)

    def test_oud_can_handle_oud_ldif(self, oud_schema_ldif: str) -> None:
        """OUD quirk must handle real OUD LDIF data."""
        oud = FlextLdifServersOud.Entry()
        result = oud.parse(oud_schema_ldif)
        u.Tests.Matchers.that(result is not None, eq=True)


@pytest.mark.unit
class TestAliasDiscovery:
    """Test that Registry will discover aliases from quirk Constants."""

    def test_oid_aliases_discoverable(self) -> None:
        """OID aliases must be discoverable for normalization."""
        constants = FlextLdifServersOid.Constants
        u.Tests.Matchers.that("oid" in constants.ALIASES, eq=True)
        u.Tests.Matchers.that("oracle_oid" in constants.ALIASES, eq=True)
        u.Tests.Matchers.that(constants.CANONICAL_NAME in constants.ALIASES, eq=True)

    def test_oud_aliases_discoverable(self) -> None:
        """OUD aliases must be discoverable for normalization."""
        constants = FlextLdifServersOud.Constants
        u.Tests.Matchers.that("oud" in constants.ALIASES, eq=True)
        u.Tests.Matchers.that("oracle_oud" in constants.ALIASES, eq=True)
        u.Tests.Matchers.that(constants.CANONICAL_NAME in constants.ALIASES, eq=True)

    def test_rfc_aliases_discoverable(self) -> None:
        """RFC aliases must be discoverable."""
        constants = FlextLdifServersRfc.Constants
        u.Tests.Matchers.that("rfc" in constants.ALIASES, eq=True)
        u.Tests.Matchers.that("generic" in constants.ALIASES, eq=True)
        u.Tests.Matchers.that(constants.CANONICAL_NAME in constants.ALIASES, eq=True)
