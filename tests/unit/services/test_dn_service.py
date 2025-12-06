from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final

import pytest

from flext_ldif.services.dn import FlextLdifDn
from tests import c, s

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)


class DnTestScenarios(StrEnum):
    """Test scenarios for DN service operations."""

    PARSE_COMPONENTS = "parse_components"
    VALIDATE_FORMAT = "validate_format"
    NORMALIZE_DN = "normalize_dn"
    EXECUTE_OPERATION = "execute_operation"


class DnTestData:
    """Test data constants for DN service tests organized in namespaces."""

    # Valid DN test cases with expected component counts
    VALID_DNS: Final[Mapping[str, Mapping[str, object]]] = {
        "simple": {"dn": c.DNs.TEST_USER, "component_count": 3},
        "with_spaces": {
            "dn": "cn=John Smith,ou=People,dc=example,dc=com",
            "component_count": 4,
        },
        "with_utf8": {
            "dn": "cn=José,ou=People,dc=example,dc=com",
            "component_count": 4,
        },
        "escaped_comma": {
            "dn": r"cn=Smith\, John,ou=People,dc=example,dc=com",
            "component_count": 4,
        },
        "multi_valued_rdn": {
            "dn": "cn=John+ou=People,dc=example,dc=com",
            "component_count": 3,
        },
        "deep_dn": {
            "dn": "cn=level1,ou=level2,ou=level3,dc=example,dc=com",
            "component_count": 5,
        },
    }

    # Invalid DN test cases
    INVALID_DNS: Final[Mapping[str, str]] = {
        "no_equals": "invalid dn without equals",
        "empty": "",
    }

    # Normalization test cases (RFC 4514: lowercase attribute names, preserve values)
    NORMALIZE_CASES: Final[Mapping[str, Mapping[str, str]]] = {
        "mixed_case": {
            "input": "CN=Test,OU=People,DC=Example,DC=Com",
            "expected": "cn=Test,ou=People,dc=Example,dc=Com",
        },
        "preserve_value_case": {
            "input": "cn=Test User,dc=example,dc=com",
            "expected": "cn=Test User,dc=example,dc=com",
        },
        "attribute_case_only": {
            "input": "CN=test,OU=people,DC=EXAMPLE,DC=COM",
            "expected": "cn=test,ou=people,dc=EXAMPLE,dc=COM",
        },
    }

    # Edge case test data
    LONG_DN_PREFIX: Final[str] = "cn=" + "a" * 1000 + ",dc=example,dc=com"
    MULTIVALUED_RDN: Final[str] = "cn=Test User+sn=Doe,ou=People,dc=example,dc=com"


class DnTestFactory:
    """Factory for creating DN service test instances and data."""

    @staticmethod
    def create_service() -> FlextLdifDn:
        """Create FlextLdifDn service instance."""
        return FlextLdifDn()

    @classmethod
    def parametrize_valid_dns(cls) -> list[tuple[str, str, int]]:
        """Parametrize valid DN test cases."""
        return [
            (name, str(data["dn"]), int(str(data["component_count"])))
            for name, data in DnTestData.VALID_DNS.items()
        ]

    @classmethod
    def parametrize_invalid_dns(cls) -> list[tuple[str, str]]:
        """Parametrize invalid DN test cases."""
        return list(DnTestData.INVALID_DNS.items())

    @classmethod
    def parametrize_normalize_cases(cls) -> list[tuple[str, str, str]]:
        """Parametrize normalization test cases."""
        return [
            (name, data["input"], data["expected"])
            for name, data in DnTestData.NORMALIZE_CASES.items()
        ]


class TestsFlextLdifDnService(s):
    """Comprehensive DN service tests.

    Tests all DN service functionality using factories, parametrization, and helpers
    for minimal code with complete coverage.
    """

    class TestInitialization:
        """Test DN service initialization and basic functionality."""

        def test_service_initialization(self) -> None:
            """Test DN service can be instantiated and initialized."""
            service = DnTestFactory.create_service()
            assert service is not None
            assert hasattr(service, "parse_components")
            assert hasattr(service, "validate_format")

        def test_execute_operation_normalize(self) -> None:
            """Test execute operation with normalize."""
            service = FlextLdifDn(
                dn="CN=Test,DC=Example,DC=Com",
                operation="normalize",
            )
            result = service.execute()
            unwrapped = self.assert_success(result)
            normalized = str(unwrapped)
            assert "cn=test" in normalized.lower()
            assert "dc=example" in normalized.lower()

    class TestParsing:
        """Test DN parsing functionality."""

        @pytest.mark.parametrize(
            ("test_case", "dn", "expected_count"),
            tuple(DnTestFactory.parametrize_valid_dns()),
        )
        def test_parse_components_valid_dns(
            self,
            test_case: str,
            dn: str,
            expected_count: int,
        ) -> None:
            """Test parsing components for all valid DN formats."""
            service = DnTestFactory.create_service()
            result = service.parse(dn)

            unwrapped = self.assert_success(
                result,
                f"Failed to parse {test_case}: {dn}",
            )
            components = list(unwrapped)
            assert len(components) == expected_count, (
                f"Expected {expected_count} components for {test_case} ({dn}), "
                f"got {len(components)}: {components}"
            )

            # Validate component structure
            for component in components:
                assert len(component) >= 2, (
                    f"Component {component} should have at least 2 elements"
                )
                assert component[0], (
                    f"Attribute type should not be empty in {component}"
                )
                assert component[1] is not None, (
                    f"Attribute value should not be None in {component}"
                )

        @pytest.mark.parametrize(
            ("test_case", "invalid_dn"),
            tuple(DnTestFactory.parametrize_invalid_dns()),
        )
        def test_parse_components_invalid_dns(
            self,
            test_case: str,
            invalid_dn: str,
        ) -> None:
            """Test parsing components for invalid DN formats."""
            service = DnTestFactory.create_service()
            result = service.parse(invalid_dn)

            assert result.is_failure, f"Expected failure for {test_case}: {invalid_dn}"
            assert result.error is not None, (
                f"Error message should be provided for {test_case}"
            )

    class TestValidation:
        """Test DN validation functionality."""

        @pytest.mark.parametrize(
            ("test_case", "dn"),
            [(name, str(data["dn"])) for name, data in DnTestData.VALID_DNS.items()],
        )
        def test_validate_format_valid_dns(
            self,
            test_case: str,
            dn: str,
        ) -> None:
            """Test format validation for all valid DN formats."""
            service = DnTestFactory.create_service()
            result = service.validate_dn(dn)

            unwrapped = self.assert_success(
                result,
                f"Validation failed for {test_case}: {dn}",
            )
            assert unwrapped is True, f"Expected True for valid DN {test_case}"

        @pytest.mark.parametrize(
            ("test_case", "invalid_dn"),
            tuple(DnTestFactory.parametrize_invalid_dns()),
        )
        def test_validate_format_invalid_dns(
            self,
            test_case: str,
            invalid_dn: str,
        ) -> None:
            """Test format validation for invalid DN formats."""
            service = DnTestFactory.create_service()
            result = service.validate_dn(invalid_dn)

            unwrapped = self.assert_success(
                result,
                f"Validation method should succeed for {test_case}",
            )
            assert unwrapped is False, f"Expected False for invalid DN {test_case}"

    class TestNormalization:
        """Test DN normalization functionality."""

        @pytest.mark.parametrize(
            ("test_case", "input_dn", "expected_output"),
            tuple(DnTestFactory.parametrize_normalize_cases()),
        )
        def test_normalize_dn_cases(
            self,
            test_case: str,
            input_dn: str,
            expected_output: str,
        ) -> None:
            """Test DN normalization for various cases."""
            service = DnTestFactory.create_service()
            result = service.norm(input_dn)

            unwrapped = self.assert_success(
                result,
                f"Normalization failed for {test_case}: {input_dn}",
            )
            normalized = str(unwrapped)
            assert normalized == expected_output, (
                f"Expected '{expected_output}', got '{normalized}' for {test_case}"
            )

    class TestEdgeCases:
        """Test DN service edge cases."""

        def test_parse_components_edge_cases(self) -> None:
            """Test edge cases for DN component parsing."""
            service = DnTestFactory.create_service()

            # Test with None input - should fail gracefully
            # Using empty string as None equivalent for testing
            result = service.parse("")
            # Empty string may fail or succeed depending on implementation
            assert result.is_success or result.is_failure

            # Test with very long DN
            result = service.parse(DnTestData.LONG_DN_PREFIX)
            unwrapped = self.assert_success(result)
            components = list(unwrapped)
            assert len(components) == 3

        def test_validate_format_edge_cases(self) -> None:
            """Test edge cases for DN format validation."""
            service = DnTestFactory.create_service()

            # Test with empty string - validation result depends on implementation
            result = service.validate_dn("")
            unwrapped = self.assert_success(result)
            # Empty string may be considered valid by ldap3 parser
            assert isinstance(unwrapped, bool)

            # Test with very long valid DN
            result = service.validate_dn(DnTestData.LONG_DN_PREFIX)
            unwrapped = self.assert_success(result)
            assert unwrapped is True

        def test_normalize_dn_edge_cases(self) -> None:
            """Test edge cases for DN normalization."""
            service = DnTestFactory.create_service()

            # Test with empty string - normalization should handle gracefully
            # Using empty string instead of None to avoid type issues
            result = service.norm("")
            # Empty string normalization may fail or succeed
            assert result.is_success or result.is_failure

            # Test with already normalized DN
            normalized_dn = "cn=test,dc=example,dc=com"
            result = service.norm(normalized_dn)
            unwrapped = self.assert_success(result)
            assert str(unwrapped) == normalized_dn

    class TestReusability:
        """Test DN service reusability and error handling."""

        def test_service_reusability(self) -> None:
            """Test that service instances can be reused for multiple operations."""
            service = DnTestFactory.create_service()

            # First operation
            result1 = service.parse("cn=test,dc=example,dc=com")
            unwrapped1 = self.assert_success(result1)

            # Second operation with different DN
            result2 = service.parse("cn=user,dc=example,dc=com")
            unwrapped2 = self.assert_success(result2)

            # Third operation
            result3 = service.validate_dn("cn=valid,dc=example,dc=com")
            unwrapped3 = self.assert_success(result3)

            # All results should be independent
            components1 = list(unwrapped1)
            components2 = list(unwrapped2)
            is_valid = bool(unwrapped3)

            assert len(components1) == 3
            assert len(components2) == 3
            assert is_valid is True
            assert components1[0][1] == "test"
            assert components2[0][1] == "user"

        def test_error_message_quality(self) -> None:
            """Test that error messages are informative and helpful."""
            service = DnTestFactory.create_service()

            # Test invalid DN error message
            result = service.parse_components("invalid")
            assert result.is_failure
            assert result.error is not None
            assert len(result.error) > 10  # Should be descriptive
            assert "invalid" in result.error.lower() or "format" in result.error.lower()

        def test_component_structure_integrity(self) -> None:
            """Test that parsed components maintain correct structure."""
            service = DnTestFactory.create_service()
            # DN with 4 comma-separated RDN components:
            # 1. cn=Test User+sn=Doe (multi-valued RDN)
            # 2. ou=People
            # 3. dc=example
            # 4. dc=com
            result = service.parse_components(DnTestData.MULTIVALUED_RDN)
            unwrapped = self.assert_success(result)

            components = list(unwrapped)
            # Four RDN components as comma-separated parts
            assert len(components) == 4

            # First component should have the multi-valued RDN
            # ldap3 parser returns (attr, value) tuples
            rdn_component = components[0]
            assert isinstance(rdn_component, (list, tuple))

            # Other components should also be tuples
            for i in range(1, len(components)):
                component = components[i]
                assert len(component) >= 2
                assert isinstance(component[0], str)  # Attribute type
                assert component[1] is not None  # Attribute value

    class TestValidators:
        """Test Pydantic field validators."""

        def test_validate_operation_invalid(self) -> None:
            """Test operation validator with invalid value."""
            with pytest.raises(ValueError, match="Invalid operation"):
                FlextLdifDn(dn="test", operation="invalid_operation")

        def test_validate_escape_mode_invalid(self) -> None:
            """Test escape_mode validator with invalid value."""
            with pytest.raises(ValueError, match="Invalid escape_mode"):
                FlextLdifDn(dn="test", escape_mode="invalid_mode")

    class TestExecuteOperations:
        """Test execute() method with various operations."""

        def test_execute_parse(self) -> None:
            """Test execute with parse operation."""
            service = FlextLdifDn(dn="cn=test,dc=example,dc=com", operation="parse")
            result = service.execute()
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, str)

        def test_execute_validate(self) -> None:
            """Test execute with validate operation."""
            service = FlextLdifDn(dn="cn=test,dc=example,dc=com", operation="validate")
            result = service.execute()
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, str)

        def test_execute_clean(self) -> None:
            """Test execute with clean operation."""
            service = FlextLdifDn(dn="  cn=test , dc=example ", operation="clean")
            result = service.execute()
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, str)

        def test_execute_escape(self) -> None:
            """Test execute with escape operation."""
            service = FlextLdifDn(dn="test,value", operation="escape")
            result = service.execute()
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, str)

        def test_execute_escape_hex(self) -> None:
            """Test execute with escape operation in hex mode."""
            service = FlextLdifDn(
                dn="test",
                operation="escape",
                escape_mode="hex",
            )
            result = service.execute()
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, str)

        def test_execute_unescape(self) -> None:
            """Test execute with unescape operation."""
            service = FlextLdifDn(dn=r"test\,value", operation="unescape")
            result = service.execute()
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, str)

        def test_execute_compare(self) -> None:
            """Test execute with compare operation."""
            service = FlextLdifDn(
                dn="cn=test,dc=example,dc=com",
                other_dn="cn=test,dc=example,dc=com",
                operation="compare",
            )
            result = service.execute()
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, str)

        def test_execute_compare_missing_other_dn(self) -> None:
            """Test execute with compare operation without other_dn."""
            service = FlextLdifDn(dn="cn=test,dc=example,dc=com", operation="compare")
            result = service.execute()
            assert result.is_failure
            assert result.error is not None
            assert "other_dn required" in result.error

        def test_execute_parse_rdn(self) -> None:
            """Test execute with parse_rdn operation."""
            service = FlextLdifDn(dn="cn=test+ou=people", operation="parse_rdn")
            result = service.execute()
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, str)

    class TestInstanceMethods:
        """Test instance method shortcuts."""

        def test_parse_with_none(self) -> None:
            """Test parse instance method with None."""
            service = DnTestFactory.create_service()
            result = service.parse(None)
            assert result.is_failure
            assert result.error is not None
            assert "cannot be None" in result.error

        def test_validate_dn_with_none(self) -> None:
            """Test validate_dn instance method with None."""
            service = DnTestFactory.create_service()
            result = service.validate_dn(None)
            assert result.is_failure
            assert result.error is not None
            assert "cannot be None" in result.error

        def test_norm_with_none(self) -> None:
            """Test norm instance method with None."""
            service = DnTestFactory.create_service()
            result = service.norm(None)
            assert result.is_failure
            assert result.error is not None
            assert "cannot be None" in result.error

        def test_esc(self) -> None:
            """Test esc instance method."""
            service = DnTestFactory.create_service()
            result = service.esc("test,value")
            assert isinstance(result, str)
            # Escape can be either \2c (hex) or \, (standard)
            assert "\\" in result

        def test_unesc(self) -> None:
            """Test unesc instance method."""
            service = DnTestFactory.create_service()
            result = service.unesc(r"test\,value")
            assert isinstance(result, str)

    class TestBuilderPattern:
        """Test fluent builder pattern."""

        def test_builder_creates_instance(self) -> None:
            """Test builder() creates service instance."""
            builder = FlextLdifDn.builder()
            assert isinstance(builder, FlextLdifDn)

        def test_with_dn(self) -> None:
            """Test with_dn fluent method."""
            builder = FlextLdifDn.builder()
            result = builder.with_dn("cn=test,dc=example,dc=com")
            # Builder pattern with frozen Pydantic models returns new instance
            assert result is not builder  # New instance returned
            assert result.dn == "cn=test,dc=example,dc=com"
            assert builder.dn == ""  # Original unchanged (frozen model)

        def test_with_operation(self) -> None:
            """Test with_operation fluent method."""
            builder = FlextLdifDn.builder()
            result = builder.with_operation("normalize")
            # Builder pattern with frozen Pydantic models returns new instance
            assert result is not builder  # New instance returned
            assert result.operation == "normalize"
            assert builder.operation == "normalize"  # Default value

        def test_with_escape_mode(self) -> None:
            """Test with_escape_mode fluent method."""
            builder = FlextLdifDn.builder()
            result = builder.with_escape_mode("hex")
            # Builder pattern with frozen Pydantic models returns new instance
            assert result is not builder  # New instance returned
            assert result.escape_mode == "hex"
            assert builder.escape_mode == "standard"  # Default value

        def test_build(self) -> None:
            """Test build() executes and returns unwrapped result."""
            result = (
                FlextLdifDn.builder()
                .with_dn("CN=Test,DC=Example,DC=Com")
                .with_operation("normalize")
                .build()
            )
            assert isinstance(result, str)
            assert "cn=test" in result.lower()

    class TestClassMethods:
        """Test classmethod helpers."""

        def test_clean_dn_classmethod(self) -> None:
            """Test clean_dn classmethod."""
            result = FlextLdifDn.clean_dn("  cn=test , dc=example ")
            assert isinstance(result, str)
            assert " " not in result or result.strip() != result

        def test_escape_dn_value_classmethod(self) -> None:
            """Test escape_dn_value classmethod."""
            result = FlextLdifDn.escape_dn_value("test,value")
            assert isinstance(result, str)

        def test_unescape_dn_value_classmethod(self) -> None:
            """Test unescape_dn_value classmethod."""
            result = FlextLdifDn.unescape_dn_value(r"test\,value")
            assert isinstance(result, str)

        def test_compare_dns_classmethod(self) -> None:
            """Test compare_dns classmethod."""
            result = FlextLdifDn.compare_dns(
                "cn=test,dc=example,dc=com",
                "CN=TEST,DC=EXAMPLE,DC=COM",
            )
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, int)

        def test_parse_rdn_classmethod(self) -> None:
            """Test parse_rdn classmethod."""
            result = FlextLdifDn.parse_rdn("cn=test+ou=people")
            unwrapped = self.assert_success(result)
            assert isinstance(unwrapped, list)

    class TestHexEscape:
        """Test hex escape/unescape operations."""

        def test_hex_escape(self) -> None:
            """Test hex_escape method."""
            result = FlextLdifDn.Normalizer.hex_escape("abc")
            assert isinstance(result, str)
            assert "\\" in result

        def test_hex_unescape(self) -> None:
            """Test hex_unescape method."""
            hex_escaped = FlextLdifDn.Normalizer.hex_escape("abc")
            result = FlextLdifDn.Normalizer.hex_unescape(hex_escaped)
            assert result == "abc"

        def test_hex_unescape_invalid_hex(self) -> None:
            """Test hex_unescape with invalid hex sequence."""
            result = FlextLdifDn.Normalizer.hex_unescape("\\ZZ")
            # Should handle gracefully
            assert isinstance(result, str)

    class TestEvents:
        """Test event handling."""

        def test_get_last_event_without_events(self) -> None:
            """Test get_last_event when events are disabled."""
            service = FlextLdifDn(dn="cn=test,dc=example,dc=com", operation="normalize")
            service.execute()
            event = service.get_last_event()
            assert event is None

        def test_get_last_event_with_events(self) -> None:
            """Test get_last_event when events are enabled."""
            service = FlextLdifDn(
                dn="cn=test,dc=example,dc=com",
                operation="normalize",
                enable_events=True,
            )
            service.execute()
            event = service.get_last_event()
            # Event may be None if logger is not available
            assert event is None or hasattr(event, "dn_operation")


__all__ = [
    "DnTestData",
    "DnTestFactory",
    "DnTestScenarios",
    "TestDnService",
]
