"""Tests for quirks handling of operational attributes.

This module tests how operational attributes (system-generated, non-user-modifiable)
are handled across different LDAP server implementations.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from enum import IntEnum
from typing import TypeVar

import pytest
from flext import FlextResult

from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif.models import m
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.services.conversion import FlextLdifConversion
from tests import c, p, s, tf

# TypeVar for generic validation methods
T = TypeVar("T")

extract_oid = FlextLdifUtilitiesParser.extract_oid


# Test scenario enums
class FixtureType(IntEnum):
    """Fixture data types for parametrized testing."""

    ATTRIBUTES = 1
    OBJECTCLASSES = 2


class ConversionScenario(IntEnum):
    """Conversion scenarios for OID/OUD testing."""

    OID_TO_OUD = 1
    OUD_TO_OID = 2
    ROUNDTRIP = 3


# Test data structures
@dataclasses.dataclass(frozen=True)
class SchemaTestConfig:
    """Configuration for schema testing."""

    attr_test_count: int = 5
    oc_test_count: int = 5
    min_success_rate: float = 0.90
    roundtrip_test_count: int = 1


# Module-level test configuration
DEFAULT_TEST_CONFIG = SchemaTestConfig()


# Factory functions
def create_server(
    server_type: str,
) -> FlextLdifServersOid | FlextLdifServersOud:
    """Create server instance by type."""
    if server_type == c.Fixtures.OID:
        return FlextLdifServersOid()
    if server_type == c.Fixtures.OUD:
        return FlextLdifServersOud()
    msg = f"Unknown server type: {server_type}"
    raise ValueError(msg)


def extract_schema_data(
    fixtures: tf.OID,
    data_type: FixtureType,
) -> list[str]:
    """Extract schema data from fixtures.

    Returns raw definition strings from LDIF content for testing.
    """
    try:
        schema = fixtures.schema()
    except AttributeError:
        pytest.skip(f"Schema fixture not available for {data_type.name}")

    # Extract raw definition strings from LDIF content
    lines: list[str] = []
    if data_type == FixtureType.ATTRIBUTES:
        # Extract attributetypes lines
        for raw_line in schema.split("\n"):
            line = raw_line.strip()
            if line.lower().startswith("attributetypes:"):
                lines.append(line.split(":", 1)[1].strip())
    elif data_type == FixtureType.OBJECTCLASSES:
        # Extract objectclasses lines
        for raw_line in schema.split("\n"):
            line = raw_line.strip()
            if line.lower().startswith("objectclasses:"):
                lines.append(line.split(":", 1)[1].strip())
    else:
        msg = f"Unknown data type: {data_type}"
        raise ValueError(msg)

    return lines


# Validator class
class SchemaValidator:
    """Validators for schema parsing and conversion tests."""

    @staticmethod
    def validate_parse_result(
        result: FlextResult[T],
        expected_type: type[T],
        description: str,
    ) -> T:
        """Validate parsing result with common assertions."""
        assert result.is_success, f"Failed to parse {description}: {result.error}"
        parsed = result.value
        assert isinstance(parsed, expected_type), (
            f"Expected {expected_type.__name__}, got {type(parsed).__name__}"
        )
        return parsed

    @staticmethod
    def validate_oid_preservation(
        original_def: str,
        parsed_model: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Validate OID is preserved in parsed model."""
        original_oid = extract_oid(original_def)
        if original_oid and hasattr(parsed_model, "oid"):
            # Both SchemaAttribute and SchemaObjectClass have oid attribute
            parsed_oid = parsed_model.oid
            assert parsed_oid == original_oid, (
                f"OID mismatch: {original_oid} → {parsed_oid}"
            )

    @staticmethod
    def validate_success_rate(
        items: list[str],
        parse_func: Callable[[str], FlextResult[T]],
        min_rate: float = 0.90,
    ) -> None:
        """Validate parsing success rate meets minimum threshold."""
        if not items:
            pytest.skip("No items in fixture")

        successes = sum(1 for item in items if parse_func(item).is_success)
        success_rate = successes / len(items)

        assert success_rate >= min_rate, (
            f"Success rate {success_rate:.1%} "
            f"({successes}/{len(items)}) below {min_rate:.1%}"
        )

    @staticmethod
    def validate_conversion_result(
        result: FlextResult[T],
        expected_type: type[T],
        description: str,
    ) -> T:
        """Validate conversion result with common assertions."""
        assert result.is_success, f"Conversion failed for {description}: {result.error}"
        converted = result.value
        assert isinstance(converted, expected_type), (
            f"Expected {expected_type.__name__}, got {type(converted).__name__}"
        )
        return converted

    @staticmethod
    def validate_roundtrip_preservation(
        original_model: m.Ldif.SchemaAttribute,
        final_model: m.Ldif.SchemaAttribute,
        attributes_to_check: list[str],
    ) -> None:
        """Validate that specified attributes are preserved in roundtrip."""
        for attr in attributes_to_check:
            if hasattr(original_model, attr) and hasattr(final_model, attr):
                orig_value = getattr(original_model, attr)
                final_value = getattr(final_model, attr)
                assert orig_value == final_value, (
                    f"{attr} not preserved: {orig_value} → {final_value}"
                )


# Parametrization functions
def get_attribute_indices() -> list[int]:
    """Generate attribute test indices for parametrization."""
    return list(range(DEFAULT_TEST_CONFIG.attr_test_count))


def get_objectclass_indices() -> list[int]:
    """Generate objectClass test indices for parametrization."""
    return list(range(DEFAULT_TEST_CONFIG.oc_test_count))


def get_roundtrip_indices() -> list[int]:
    """Generate roundtrip test indices for parametrization."""
    return list(range(DEFAULT_TEST_CONFIG.roundtrip_test_count))


# Module-level fixtures
@pytest.fixture
def oid_server() -> FlextLdifServersOid:
    """Create OID server instance."""
    return create_server(c.Fixtures.OID)


@pytest.fixture
def oud_server() -> FlextLdifServersOud:
    """Create OUD server instance."""
    return create_server(c.Fixtures.OUD)


@pytest.fixture
def conversion_service() -> FlextLdifConversion:
    """Create conversion service instance."""
    return FlextLdifConversion()


@pytest.fixture
def oid_schema_attributes(
    oid_fixtures: tf.OID,
) -> list[str]:
    """Extract OID attributes from schema fixture."""
    return extract_schema_data(oid_fixtures, FixtureType.ATTRIBUTES)


@pytest.fixture
def oid_schema_objectclasses(
    oid_fixtures: tf.OID,
) -> list[str]:
    """Extract OID objectClasses from schema fixture."""
    return extract_schema_data(oid_fixtures, FixtureType.OBJECTCLASSES)


@pytest.fixture
def oid_conversion_attributes(
    oid_fixtures: tf.OID,
) -> list[str]:
    """Extract OID attributes for conversion testing."""
    return extract_schema_data(oid_fixtures, FixtureType.ATTRIBUTES)


# Test classes
class TestsFlextLdifOperationalSchemaAttributeParsing(s):
    """Test parsing real OID attributes from fixtures."""

    @pytest.mark.parametrize("attr_index", get_attribute_indices())
    def test_parse_oid_attributes_from_fixtures(
        self,
        oid_server: FlextLdifServersOid,
        oid_schema_attributes: list[str],
        attr_index: int,
    ) -> None:
        """Test parsing real OID attributes with dynamic parametrization."""
        if attr_index >= len(oid_schema_attributes):
            pytest.skip(f"Insufficient attributes (need {attr_index + 1})")

        attr_def = oid_schema_attributes[attr_index]
        result = oid_server.schema_quirk.parse(attr_def)
        parsed = SchemaValidator.validate_parse_result(
            result,
            m.Ldif.SchemaAttribute,
            f"attribute[{attr_index}]",
        )

        SchemaValidator.validate_oid_preservation(attr_def, parsed)

    def test_parse_all_oid_attributes_success_rate(
        self,
        oid_server: FlextLdifServersOid,
        oid_schema_attributes: list[str],
    ) -> None:
        """Test that high percentage of real OID attributes parse successfully."""

        def parse_attribute(attr: str) -> FlextResult[object]:
            return oid_server.parse(attr)

        SchemaValidator.validate_success_rate(
            oid_schema_attributes,
            parse_attribute,
            DEFAULT_TEST_CONFIG.min_success_rate,
        )


class TestOperationalSchemaObjectClassParsing:
    """Test parsing real OID objectClasses from fixtures."""

    @pytest.mark.parametrize("oc_index", get_objectclass_indices())
    def test_parse_oid_objectclasses_from_fixtures(
        self,
        oid_server: FlextLdifServersOid,
        oid_schema_objectclasses: list[str],
        oc_index: int,
    ) -> None:
        """Test parsing real OID objectClasses with dynamic parametrization."""
        if oc_index >= len(oid_schema_objectclasses):
            pytest.skip(f"Insufficient objectClasses (need {oc_index + 1})")

        oc_def = oid_schema_objectclasses[oc_index]
        result = oid_server.schema_quirk.parse(oc_def)
        SchemaValidator.validate_parse_result(
            result,
            m.Ldif.SchemaObjectClass,
            f"objectClass[{oc_index}]",
        )

    def test_parse_all_oid_objectclasses_success_rate(
        self,
        oid_server: FlextLdifServersOid,
        oid_schema_objectclasses: list[str],
    ) -> None:
        """Test that high percentage of OID objectClasses parse successfully."""

        def parse_objectclass(oc: str) -> FlextResult[object]:
            return oid_server.parse(oc)

        SchemaValidator.validate_success_rate(
            oid_schema_objectclasses,
            parse_objectclass,
            DEFAULT_TEST_CONFIG.min_success_rate,
        )


class TestOperationalServerConversion:
    """Test OID↔OUD server conversion operations."""

    def test_oid_to_oud_conversion_with_real_attributes(
        self,
        conversion_service: FlextLdifConversion,
        oid_server: FlextLdifServersOid,
        oud_server: FlextLdifServersOud,
        oid_conversion_attributes: list[str],
    ) -> None:
        """Test OID→OUD conversion with real fixture attributes."""
        if not oid_conversion_attributes:
            pytest.skip("No OID attributes in fixture")

        test_count = min(
            DEFAULT_TEST_CONFIG.attr_test_count,
            len(oid_conversion_attributes),
        )
        test_attributes = oid_conversion_attributes[:test_count]

        successes = 0
        failures: list[tuple[str, str]] = []

        for i, attr_def in enumerate(test_attributes):
            try:
                parse_result = oid_server.schema_quirk.parse(attr_def)
                parsed_model = SchemaValidator.validate_parse_result(
                    parse_result,
                    m.Ldif.SchemaAttribute,
                    f"attribute[{i}]",
                )

                conv_result = conversion_service.convert(
                    oid_server,
                    oud_server,
                    parsed_model,
                )
                converted_model = SchemaValidator.validate_conversion_result(
                    conv_result,
                    m.Ldif.SchemaAttribute,
                    f"conversion[{i}]",
                )

                # Validate OID preservation
                original_oid = extract_oid(attr_def)
                if original_oid and hasattr(converted_model, "oid"):
                    converted_oid = converted_model.oid
                    assert original_oid == converted_oid, (
                        f"OID mismatch: {original_oid} → {converted_oid}"
                    )

                successes += 1

            except AssertionError as e:
                failures.append((attr_def[:50], str(e)))

        assert not failures, f"Conversion failures: {failures}"
        assert successes > 0, "No successful conversions"


class TestOperationalServerRoundtrip:
    """Test roundtrip conversions between OID and OUD servers."""

    @pytest.mark.parametrize("roundtrip_index", get_roundtrip_indices())
    def test_roundtrip_oid_oud_oid_with_real_data(
        self,
        conversion_service: FlextLdifConversion,
        oid_server: FlextLdifServersOid,
        oud_server: FlextLdifServersOud,
        oid_conversion_attributes: list[str],
        roundtrip_index: int,
    ) -> None:
        """Test OID→OUD→OID roundtrip with real fixture data."""
        if roundtrip_index >= len(oid_conversion_attributes):
            pytest.skip(
                f"Insufficient attributes for roundtrip (need {roundtrip_index + 1})",
            )

        original_attr = oid_conversion_attributes[roundtrip_index]

        # Parse original
        parse_result = oid_server.schema_quirk.parse(original_attr)
        original_model = SchemaValidator.validate_parse_result(
            parse_result,
            m.Ldif.SchemaAttribute,
            f"roundtrip[{roundtrip_index}] original",
        )

        # Forward conversion (OID → OUD)
        forward_result = conversion_service.convert(
            oid_server,
            oud_server,
            original_model,
        )
        forward_model = SchemaValidator.validate_conversion_result(
            forward_result,
            m.Ldif.SchemaAttribute,
            f"roundtrip[{roundtrip_index}] forward",
        )

        # Backward conversion (OUD → OID)
        backward_result = conversion_service.convert(
            oud_server,
            oid_server,
            forward_model,
        )
        final_model = SchemaValidator.validate_conversion_result(
            backward_result,
            m.Ldif.SchemaAttribute,
            f"roundtrip[{roundtrip_index}] backward",
        )

        # Validate roundtrip preservation
        # Type narrowing: original_model and final_model are guaranteed to be SchemaAttribute
        assert isinstance(original_model, m.Ldif.SchemaAttribute)
        assert isinstance(final_model, m.Ldif.SchemaAttribute)
        SchemaValidator.validate_roundtrip_preservation(
            original_model,
            final_model,
            ["oid", "name"],
        )


__all__ = [
    "ConversionScenario",
    "FixtureType",
    "SchemaTestConfig",
    "SchemaValidator",
    "TestOperationalSchemaAttributeParsing",
    "TestOperationalSchemaObjectClassParsing",
    "TestOperationalServerConversion",
    "TestOperationalServerRoundtrip",
]
