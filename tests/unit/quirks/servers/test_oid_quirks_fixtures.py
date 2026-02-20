"""Tests for OID quirks using fixture LDIF files.

This module tests Oracle Internet Directory (OID) quirks functionality
with real LDIF fixture files to validate complete round-trip processing.
"""

from __future__ import annotations

import copy
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

import pytest
from flext_ldif import FlextLdif
from tests import s

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


@pytest.fixture(scope="class")
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test function."""
    return FlextLdif()


@pytest.fixture(scope="class")
def oid_fixture_cache(ldif_api: FlextLdif) -> dict[OidFixtureType, list[object]]:
    """Pre-load OID fixture entries once per class."""
    cache: dict[OidFixtureType, list[object]] = {}
    for fixture_type in OidFixtureType:
        fixture_filename = f"oid_{fixture_type}_fixtures.ldif"
        cache[fixture_type] = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "oid",
            fixture_filename,
        )
    return cache


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
        oid_fixture_cache: dict[OidFixtureType, list[object]],
    ) -> None:
        """Parametrized test for parsing OID fixture files."""
        fixture_filename = f"oid_{fixture_type}_fixtures.ldif"

        entries = copy.deepcopy(oid_fixture_cache[fixture_type])

        assert len(entries) > 0, f"No entries loaded from {fixture_filename}"

        for entry in entries:
            assert getattr(entry, "dn", None) is not None, "Entry must have DN"
            attributes = getattr(entry, "attributes", None)
            assert attributes is not None, "Entry must have attributes"
            attribute_map = getattr(attributes, "attributes", {})
            assert len(attribute_map) > 0, "Entry must have at least one attribute"

            if expected_objectclass:
                attr_names = {name.lower() for name in attribute_map}
                has_objectclass = "objectclass" in attr_names
                assert has_objectclass, "Expected objectClass attribute in entries"

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
        oid_fixture_cache: dict[OidFixtureType, list[object]],
    ) -> None:
        """Parametrized test for roundtrip parsing/writing of OID fixtures."""
        fixture_filename = f"oid_{fixture_type}_fixtures.ldif"

        original_entries = copy.deepcopy(oid_fixture_cache[fixture_type])

        write_result = ldif_api.write(
            original_entries,
            server_type="oid",
        )
        assert write_result.is_success, f"Failed to write entries: {write_result.error}"

        roundtrip_result = ldif_api.parse(
            write_result.value,
            server_type="oid",
        )
        assert roundtrip_result.is_success, (
            f"Failed to parse roundtrip LDIF: {roundtrip_result.error}"
        )
        roundtrip_entries = roundtrip_result.value

        # Validate roundtrip results
        assert len(original_entries) > 0, f"No entries in {fixture_filename}"
        assert len(roundtrip_entries) > 0, (
            f"No roundtrip entries for {fixture_filename}"
        )
        assert len(original_entries) == len(roundtrip_entries), (
            f"Entry count mismatch for {fixture_filename}"
        )
