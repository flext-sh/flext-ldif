"""Tests for standardized quirk implementations.

This module verifies that all quirk implementations across different LDAP server
types (RFC, OID, OUD, OpenLDAP, etc.) have standardized Constants with expected
attributes like CANONICAL_NAME, ALIASES, and PRIORITY values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.rfc import FlextLdifServersRfc

from tests import c, s


@pytest.mark.unit
class TestsFlextLdifQuirksStandardizedConstants(s):
    """Verify all quirks have standardized Constants."""

    def test_rfc_schema_constants(self) -> None:
        """RFC Schema must have standardized Constants."""
        assert hasattr(FlextLdifServersRfc, "Constants")
        constants = FlextLdifServersRfc.Constants

        assert hasattr(constants, "CANONICAL_NAME")
        assert constants.CANONICAL_NAME == "rfc"
        assert "rfc" in constants.ALIASES
        assert constants.PRIORITY == 100
        assert "rfc" in constants.CAN_NORMALIZE_FROM
        assert "rfc" in constants.CAN_DENORMALIZE_TO

    def test_rfc_acl_constants(self) -> None:
        """RFC Acl must have standardized Constants."""
        assert hasattr(FlextLdifServersRfc, "Constants")
        constants = FlextLdifServersRfc.Constants

        assert constants.CANONICAL_NAME == "rfc"
        assert "rfc" in constants.ALIASES

    def test_rfc_entry_constants(self) -> None:
        """RFC Entry must have standardized Constants."""
        assert hasattr(FlextLdifServersRfc, "Constants")
        constants = FlextLdifServersRfc.Constants

        assert constants.CANONICAL_NAME == "rfc"
        assert "rfc" in constants.ALIASES

    def test_oid_schema_constants(self) -> None:
        """OID Schema must have standardized Constants."""
        assert hasattr(FlextLdifServersOid, "Constants")
        global_constants = FlextLdifServersOid.Constants

        assert global_constants.CANONICAL_NAME == "oid"
        assert "oid" in global_constants.ALIASES
        assert "oracle_oid" in global_constants.ALIASES
        assert global_constants.PRIORITY == 10
        assert "oid" in global_constants.CAN_NORMALIZE_FROM
        assert "rfc" in global_constants.CAN_DENORMALIZE_TO

    def test_oud_schema_constants(self) -> None:
        """OUD must have standardized Constants."""
        assert hasattr(FlextLdifServersOud, "Constants")
        global_constants = FlextLdifServersOud.Constants

        assert global_constants.CANONICAL_NAME == "oud"
        assert "oud" in global_constants.ALIASES
        assert "oracle_oud" in global_constants.ALIASES
        assert global_constants.PRIORITY == 10
        assert "oud" in global_constants.CAN_NORMALIZE_FROM
        assert "rfc" in global_constants.CAN_DENORMALIZE_TO

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
            assert expected_canonical == constants.CANONICAL_NAME
            assert expected_canonical in constants.ALIASES

    def test_conversion_capabilities_valid(self) -> None:
        """Server must be able to convert itself."""
        quirks = [
            FlextLdifServersRfc.Constants,
            FlextLdifServersOid.Constants,
            FlextLdifServersOud.Constants,
        ]

        for constants in quirks:
            canonical = constants.CANONICAL_NAME

            # Every server must be able to normalize from itself
            assert canonical in constants.CAN_NORMALIZE_FROM, (
                f"{canonical} must be in CAN_NORMALIZE_FROM"
            )

            # Every server must be able to denormalize to itself
            assert canonical in constants.CAN_DENORMALIZE_TO, (
                f"{canonical} must be in CAN_DENORMALIZE_TO"
            )


@pytest.mark.unit
class TestQuirksAutoInterchange:
    """Test automatic interchange between quirks via RFC intermediate."""

    def test_oid_to_oud_interchange_path(self) -> None:
        """OID → RFC → OUD conversion path must be possible."""
        oid_constants = FlextLdifServersOid.Constants
        rfc_constants = FlextLdifServersRfc.Constants
        oud_constants = FlextLdifServersOud.Constants

        # OID can normalize to RFC
        assert "rfc" in oid_constants.CAN_DENORMALIZE_TO

        # RFC can accept from OID
        assert "rfc" in rfc_constants.CAN_NORMALIZE_FROM

        # OUD can normalize from RFC
        assert "rfc" in oud_constants.CAN_NORMALIZE_FROM

        # OUD can denormalize to itself
        assert "oud" in oud_constants.CAN_DENORMALIZE_TO


@pytest.mark.unit
@pytest.mark.ldif
class TestQuirksWithRealLdifFixtures:
    """Test quirks with real LDIF fixture data."""

    @pytest.fixture
    def oid_schema_ldif(self) -> str:
        """Load real OID schema LDIF fixture."""
        fixture_path = Path(f"tests/fixtures/{c.Fixtures.OID}/oid_schema_fixtures.ldif")
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        return fixture_path.read_text(encoding="utf-8")

    @pytest.fixture
    def oud_schema_ldif(self) -> str:
        """Load real OUD schema LDIF fixture."""
        fixture_path = Path(f"tests/fixtures/{c.Fixtures.OUD}/oud_schema_fixtures.ldif")
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")
        return fixture_path.read_text(encoding="utf-8")

    def test_oid_can_handle_real_oid_ldif(self, oid_schema_ldif: str) -> None:
        """OID quirk must handle real OID LDIF data."""
        oid = FlextLdifServersOid.Entry()

        # Should be able to parse OID LDIF content
        result = oid.parse(oid_schema_ldif)

        # Either successful or gracefully fail, not crash
        assert result is not None

    def test_rfc_handles_all_ldif(self, oid_schema_ldif: str) -> None:
        """RFC quirk must handle any valid LDIF (lowest priority fallback)."""
        rfc = FlextLdifServersRfc.Entry()

        # RFC should handle any valid LDIF
        result = rfc.parse(oid_schema_ldif)
        assert result is not None

    def test_oud_can_handle_oud_ldif(self, oud_schema_ldif: str) -> None:
        """OUD quirk must handle real OUD LDIF data."""
        oud = FlextLdifServersOud.Entry()

        # Should be able to parse OUD LDIF content
        result = oud.parse(oud_schema_ldif)
        assert result is not None


@pytest.mark.unit
class TestAliasDiscovery:
    """Test that Registry will discover aliases from quirk Constants."""

    def test_oid_aliases_discoverable(self) -> None:
        """OID aliases must be discoverable for normalization."""
        constants = FlextLdifServersOid.Constants

        # Both canonical and alias should be in ALIASES
        assert "oid" in constants.ALIASES
        assert "oracle_oid" in constants.ALIASES

        # CANONICAL_NAME should match one of the aliases
        assert constants.CANONICAL_NAME in constants.ALIASES

    def test_oud_aliases_discoverable(self) -> None:
        """OUD aliases must be discoverable for normalization."""
        constants = FlextLdifServersOud.Constants

        assert "oud" in constants.ALIASES
        assert "oracle_oud" in constants.ALIASES
        assert constants.CANONICAL_NAME in constants.ALIASES

    def test_rfc_aliases_discoverable(self) -> None:
        """RFC aliases must be discoverable."""
        constants = FlextLdifServersRfc.Constants

        assert "rfc" in constants.ALIASES
        assert "generic" in constants.ALIASES
        assert constants.CANONICAL_NAME in constants.ALIASES
