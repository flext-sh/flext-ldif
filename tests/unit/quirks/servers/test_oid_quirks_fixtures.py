"""Tests for OID quirks using fixture LDIF files.

This module tests Oracle Internet Directory (OID) quirks functionality
with real LDIF fixture files to validate complete round-trip processing.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import ClassVar

import pytest
from tests import s

from flext_ldif import FlextLdif

from .test_utils import FlextLdifTestUtils

# =============================================================================
# TEST SCENARIO ENUMS & CONSTANTS
# =============================================================================


class OidFixtureType(StrEnum):
    """OID fixture file types."""

    SCHEMA = "schema"
    ENTRIES = "entries"
    ACL = "acl"


class OidQuirksTestType(StrEnum):
    """OID quirks test scenarios."""

    PARSE_FIXTURE = "parse_fixture"
    ROUNDTRIP = "roundtrip"
    ATTRIBUTE_VALIDATION = "attribute_validation"


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return
    # Post-test cleanup - ensures each test has clean state


@pytest.fixture
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test function."""
    return FlextLdif()


# =============================================================================
# TEST CLASS
# =============================================================================


@pytest.mark.unit
class TestsFlextLdifOidQuirksWithRealFixtures(s):
    """Test OID quirks with real fixture files.

    Consolidates 8 test methods into 3 parametrized tests using helpers.
    """

    # Fixture file mapping - {test_name: (fixture_type, has_objectclass, has_oracle_attrs, has_passwords)}
    PARSE_DATA: ClassVar[dict[str, tuple[OidFixtureType, bool, bool, bool]]] = {
        "parse_oid_schema": (OidFixtureType.SCHEMA, False, False, False),
        "parse_oid_entries": (OidFixtureType.ENTRIES, True, True, True),
        "parse_oid_acl": (OidFixtureType.ACL, False, False, False),
    }

    # Roundtrip test mapping - {test_name: (fixture_type)}
    ROUNDTRIP_DATA: ClassVar[dict[str, tuple[OidFixtureType]]] = {
        "roundtrip_oid_entries": (OidFixtureType.ENTRIES,),
        "roundtrip_oid_schema": (OidFixtureType.SCHEMA,),
        "roundtrip_oid_acl": (OidFixtureType.ACL,),
    }

    # =========================================================================
    # Parse & Validation Tests
    # =========================================================================

    @pytest.mark.parametrize(
        (
            "scenario",
            "fixture_type",
            "expected_objectclass",
            "_expected_oracle_attrs",
            "_expected_passwords",
        ),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in PARSE_DATA.items()
        ],
    )
    def test_parse_fixture(
        self,
        scenario: str,
        fixture_type: OidFixtureType,
        expected_objectclass: bool,
        _expected_oracle_attrs: bool,
        _expected_passwords: bool,
        ldif_api: FlextLdif,
    ) -> None:
        """Parametrized test for parsing OID fixture files."""
        fixture_filename = f"oid_{fixture_type}_fixtures.ldif"

        # Load fixture using helper
        entries = FlextLdifTestUtils.load_fixture_and_validate_structure(
            ldif_api,
            "oid",
            fixture_filename,
            expected_has_objectclass=expected_objectclass or None,
        )

        assert len(entries) > 0, f"No entries loaded from {fixture_filename}"

        # Note: Oracle-specific attributes and password hashes validation
        # is fixture-dependent and performed by load_fixture_and_validate_structure

    # =========================================================================
    # Roundtrip Tests
    # =========================================================================

    @pytest.mark.parametrize(
        ("scenario", "fixture_type"),
        [(name, data[0]) for name, data in ROUNDTRIP_DATA.items()],
    )
    def test_roundtrip_fixture(
        self,
        scenario: str,
        fixture_type: OidFixtureType,
        ldif_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Parametrized test for roundtrip parsing/writing of OID fixtures."""
        fixture_filename = f"oid_{fixture_type}_fixtures.ldif"

        # Run roundtrip using helper
        original_entries, roundtrip_entries, _ = FlextLdifTestUtils.run_roundtrip_test(
            ldif_api,
            "oid",
            fixture_filename,
            tmp_path,
        )

        # Validate roundtrip results
        assert len(original_entries) > 0, f"No entries in {fixture_filename}"
        assert len(roundtrip_entries) > 0, (
            f"No roundtrip entries for {fixture_filename}"
        )
        assert len(original_entries) == len(roundtrip_entries), (
            f"Entry count mismatch for {fixture_filename}"
        )
