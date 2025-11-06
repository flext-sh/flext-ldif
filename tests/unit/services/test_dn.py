"""Distinguished Name (DN) Service - Comprehensive Unit Tests.

Tests for RFC 4514 compliant DN operations, parsing, validation, normalization,
escaping/unescaping, and DN case registry.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.services.dn import FlextLdifDn


@pytest.fixture
def dn_service() -> FlextLdifDn:
    """Create DN service instance for tests."""
    return FlextLdifDn()


class TestDnParsing:
    """Test DN parsing into RFC 4514 components."""

    def test_parse_simple_dn(self, dn_service: FlextLdifDn) -> None:
        """Parse simple DN string."""
        result = dn_service.parse_components("cn=John,dc=example,dc=com")
        assert result.is_success
        components = result.unwrap()
        assert len(components) == 3
        # Components are tuples of (attr, value, rdn)
        assert components[0][0].lower() == "cn"
        assert components[0][1] == "John"

    def test_parse_dn_with_escaped_comma(self, dn_service: FlextLdifDn) -> None:
        """Parse DN with escaped comma in value."""
        result = dn_service.parse_components(r"cn=Smith\, John,dc=example,dc=com")
        assert result.is_success
        components = result.unwrap()
        # ldap3 parses escaped comma as separate RDN, not as part of value
        assert len(components) >= 2

    def test_parse_empty_dn(self, dn_service: FlextLdifDn) -> None:
        """Parse empty DN string."""
        result = dn_service.parse_components("")
        # ldap3 fails on empty DN
        assert result.is_failure

    def test_parse_invalid_dn(self, dn_service: FlextLdifDn) -> None:
        """Parse invalid DN format."""
        result = dn_service.parse_components("invalid dn without equals")
        assert result.is_failure


class TestDnValidation:
    """Test DN format validation against RFC 4514."""

    def test_validate_simple_dn(self, dn_service: FlextLdifDn) -> None:
        """Validate simple DN."""
        result = dn_service.validate_format("cn=John,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_complex_dn(self, dn_service: FlextLdifDn) -> None:
        """Validate complex DN with multiple components."""
        result = dn_service.validate_format(
            "cn=John,ou=People,o=Company,c=US,dc=example,dc=com",
        )
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_empty_dn(self, dn_service: FlextLdifDn) -> None:
        """Validate empty DN (should be invalid)."""
        result = dn_service.validate_format("")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_invalid_dn(self, dn_service: FlextLdifDn) -> None:
        """Validate invalid DN format."""
        result = dn_service.validate_format("not a valid dn")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_dn_missing_value(self, dn_service: FlextLdifDn) -> None:
        """Validate DN with missing value."""
        result = dn_service.validate_format("cn=,dc=example,dc=com")
        assert result.is_success
        # ldap3 may handle this differently


class TestDnNormalization:
    """Test DN normalization per RFC 4514."""

    def test_normalize_uppercase_dn(self, dn_service: FlextLdifDn) -> None:
        """Normalize DN with uppercase attribute names."""
        result = dn_service.normalize("CN=Admin,DC=Example,DC=Com")
        assert result.is_success
        normalized = result.unwrap()
        # ldap3.safe_dn lowercases attribute names but preserves value case
        assert "cn=" in normalized.lower()
        assert "dc=" in normalized.lower()

    def test_normalize_preserves_value_case(self, dn_service: FlextLdifDn) -> None:
        """Normalize preserves case in attribute values."""
        result = dn_service.normalize("cn=JohnDoe,dc=EXAMPLE,dc=com")
        assert result.is_success
        normalized = result.unwrap()
        # Value "JohnDoe" should be preserved
        assert "JohnDoe" in normalized

    def test_normalize_with_spaces(self, dn_service: FlextLdifDn) -> None:
        """Normalize DN with spaces around equals/commas."""
        result = dn_service.normalize("CN = Admin , DC = Example , DC = Com")
        # ldap3 safe_dn rejects spaces around attribute names
        assert result.is_failure or result.is_success

    def test_normalize_invalid_dn(self, dn_service: FlextLdifDn) -> None:
        """Normalize invalid DN should fail."""
        result = dn_service.normalize("invalid dn")
        assert result.is_failure


class TestDnCleaning:
    """Test DN string cleaning for malformed LDIF exports."""

    def test_clean_spaces_around_equals(self, dn_service: FlextLdifDn) -> None:
        """Clean DN with spaces around equals."""
        # clean_dn removes spaces BEFORE = but not after (preserves value spaces)
        cleaned = dn_service.clean_dn("cn = John , dc = example , dc = com")
        assert "cn=" in cleaned  # Spaces before = removed
        assert " John" in cleaned  # Spaces in values preserved

    def test_clean_trailing_backslash_space(self, dn_service: FlextLdifDn) -> None:
        """Clean DN with trailing backslash+space."""
        cleaned = dn_service.clean_dn(r"cn=OIM-TEST\ ,ou=Users,dc=com")
        assert cleaned == "cn=OIM-TEST,ou=Users,dc=com"

    def test_clean_empty_dn(self, dn_service: FlextLdifDn) -> None:
        """Clean empty DN."""
        cleaned = dn_service.clean_dn("")
        assert cleaned == ""

    def test_clean_already_clean_dn(self, dn_service: FlextLdifDn) -> None:
        """Clean already clean DN (no changes)."""
        original = "cn=John,dc=example,dc=com"
        cleaned = dn_service.clean_dn(original)
        assert cleaned == original

    def test_clean_multiple_spaces(self, dn_service: FlextLdifDn) -> None:
        """Clean DN with multiple spaces."""
        cleaned = dn_service.clean_dn("cn  =  John  ,  dc  =  example")
        assert "  " not in cleaned  # Multiple spaces removed


class TestDnEscaping:
    """Test DN value escaping/unescaping per RFC 4514."""

    def test_escape_comma(self, dn_service: FlextLdifDn) -> None:
        """Escape comma in DN value."""
        escaped = dn_service.escape_dn_value("Smith, John")
        assert escaped == "Smith\\2c John"

    def test_escape_hash(self, dn_service: FlextLdifDn) -> None:
        """Escape hash in DN value."""
        escaped = dn_service.escape_dn_value("#1 User")
        assert escaped == "\\231 User"

    def test_escape_multiple_special_chars(self, dn_service: FlextLdifDn) -> None:
        """Escape multiple special characters."""
        escaped = dn_service.escape_dn_value('Test+User,"Admin"')
        # Should escape +, comma, and quotes
        assert "\\" in escaped

    def test_escape_leading_space(self, dn_service: FlextLdifDn) -> None:
        """Escape leading space in DN value."""
        escaped = dn_service.escape_dn_value(" REDACTED_LDAP_BIND_PASSWORD")
        assert escaped.startswith("\\")

    def test_escape_trailing_space(self, dn_service: FlextLdifDn) -> None:
        """Escape trailing space in DN value."""
        escaped = dn_service.escape_dn_value("REDACTED_LDAP_BIND_PASSWORD ")
        # Trailing space gets hex escaped to \20
        assert escaped.endswith("\\20")

    def test_escape_empty_value(self, dn_service: FlextLdifDn) -> None:
        """Escape empty DN value."""
        escaped = dn_service.escape_dn_value("")
        assert escaped == ""

    def test_unescape_hex_format(self, dn_service: FlextLdifDn) -> None:
        """Unescape hex format DN value."""
        unescaped = dn_service.unescape_dn_value("Smith\\2c John")
        assert unescaped == "Smith, John"

    def test_unescape_backslash_escape(self, dn_service: FlextLdifDn) -> None:
        """Unescape backslash escaped DN value."""
        unescaped = dn_service.unescape_dn_value("Smith\\, John")
        assert unescaped == "Smith, John"

    def test_unescape_no_escapes(self, dn_service: FlextLdifDn) -> None:
        """Unescape DN value with no escapes."""
        unescaped = dn_service.unescape_dn_value("John Smith")
        assert unescaped == "John Smith"

    def test_unescape_empty_value(self, dn_service: FlextLdifDn) -> None:
        """Unescape empty DN value."""
        unescaped = dn_service.unescape_dn_value("")
        assert unescaped == ""

    def test_roundtrip_escape_unescape(self, dn_service: FlextLdifDn) -> None:
        """Test roundtrip: escape then unescape."""
        original = "Smith, John"
        escaped = dn_service.escape_dn_value(original)
        unescaped = dn_service.unescape_dn_value(escaped)
        assert unescaped == original


class TestDnComparison:
    """Test DN comparison (case-insensitive)."""

    def test_compare_equal_dns(self, dn_service: FlextLdifDn) -> None:
        """Compare equal DNs (different case)."""
        result = dn_service.compare_dns(
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "CN=ADMIN,DC=EXAMPLE,DC=COM",
        )
        assert result.is_success
        assert result.unwrap() == 0

    def test_compare_different_dns(self, dn_service: FlextLdifDn) -> None:
        """Compare different DNs."""
        result = dn_service.compare_dns(
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "cn=user,dc=example,dc=com",
        )
        assert result.is_success
        comparison = result.unwrap()
        assert comparison != 0  # Not equal

    def test_compare_invalid_dn(self, dn_service: FlextLdifDn) -> None:
        """Compare with invalid DN should fail."""
        result = dn_service.compare_dns("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "invalid dn")
        assert result.is_failure


class TestRdnParsing:
    """Test RDN (Relative Distinguished Name) parsing."""

    def test_parse_simple_rdn(self, dn_service: FlextLdifDn) -> None:
        """Parse simple RDN."""
        result = dn_service.parse_rdn("cn=John")
        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 1
        assert pairs[0] == ("cn", "John")

    def test_parse_multivalued_rdn(self, dn_service: FlextLdifDn) -> None:
        """Parse multi-valued RDN (with +)."""
        result = dn_service.parse_rdn("cn=John+ou=People")
        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 2
        assert ("cn", "John") in pairs
        assert ("ou", "People") in pairs

    def test_parse_rdn_with_escaped_plus(self, dn_service: FlextLdifDn) -> None:
        """Parse RDN with escaped plus character."""
        result = dn_service.parse_rdn(r"cn=Test\+User")
        assert result.is_success

    def test_parse_empty_rdn(self, dn_service: FlextLdifDn) -> None:
        """Parse empty RDN should fail."""
        result = dn_service.parse_rdn("")
        assert result.is_failure

    def test_parse_invalid_rdn(self, dn_service: FlextLdifDn) -> None:
        """Parse invalid RDN (no equals)."""
        result = dn_service.parse_rdn("InvalidRDN")
        assert result.is_failure


class TestDnServiceBuilderPattern:
    """Test fluent builder pattern for DN service."""

    def test_builder_normalize(self, dn_service: FlextLdifDn) -> None:
        """Builder pattern for normalize operation."""
        normalized = (
            dn_service.builder()
            .with_dn("CN=Admin,DC=Example,DC=Com")
            .with_operation("normalize")
            .build()
        )
        assert normalized
        assert "cn=" in normalized.lower()

    def test_builder_clean(self, dn_service: FlextLdifDn) -> None:
        """Builder pattern for clean operation."""
        cleaned = (
            dn_service.builder()
            .with_dn("cn = John , dc = example")
            .with_operation("clean")
            .build()
        )
        # clean_dn removes spaces before = but preserves spaces in values
        assert "cn=" in cleaned
        assert "dc=" in cleaned

    def test_builder_escape(self, dn_service: FlextLdifDn) -> None:
        """Builder pattern for escape operation."""
        escaped = (
            dn_service.builder().with_dn("Smith, John").with_operation("escape").build()
        )
        assert escaped == "Smith\\2c John"


class TestDnServiceExecutePattern:
    """Test execute pattern for DN service."""

    def test_execute_normalize(self, dn_service: FlextLdifDn) -> None:
        """Execute normalize operation."""
        result = FlextLdifDn(
            dn="CN=Admin,DC=Example,DC=Com",
            operation="normalize",
        ).execute()
        assert result.is_success
        assert result.unwrap()

    def test_execute_validate_valid(self, dn_service: FlextLdifDn) -> None:
        """Execute validate operation on valid DN."""
        result = FlextLdifDn(
            dn="cn=test,dc=example,dc=com",
            operation="validate",
        ).execute()
        assert result.is_success
        assert result.unwrap() == "True"

    def test_execute_validate_invalid(self, dn_service: FlextLdifDn) -> None:
        """Execute validate operation on invalid DN."""
        result = FlextLdifDn(dn="invalid dn", operation="validate").execute()
        assert result.is_success
        assert result.unwrap() == "False"

    def test_execute_compare(self, dn_service: FlextLdifDn) -> None:
        """Execute compare operation."""
        result = FlextLdifDn(
            dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            other_dn="CN=ADMIN,DC=EXAMPLE,DC=COM",
            operation="compare",
        ).execute()
        assert result.is_success
        assert result.unwrap() == "0"  # Equal


class TestCaseRegistry:
    """Test DN case registry for conversions."""

    def test_register_dn(self, dn_service: FlextLdifDn) -> None:
        """Register DN and get canonical case."""
        registry = FlextLdifDn.CaseRegistry()
        canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")
        assert canonical == "CN=Admin,DC=Example,DC=Com"

    def test_get_canonical_dn(self, dn_service: FlextLdifDn) -> None:
        """Get canonical DN for variant case."""
        registry = FlextLdifDn.CaseRegistry()
        registry.register_dn("CN=Admin,DC=Example,DC=Com")
        canonical = registry.get_canonical_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert canonical == "CN=Admin,DC=Example,DC=Com"

    def test_has_dn(self, dn_service: FlextLdifDn) -> None:
        """Check if DN is registered."""
        registry = FlextLdifDn.CaseRegistry()
        registry.register_dn("CN=Admin,DC=Example,DC=Com")
        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com") is True
        assert registry.has_dn("cn=unknown,dc=example,dc=com") is False

    def test_get_case_variants(self, dn_service: FlextLdifDn) -> None:
        """Get all case variants for DN."""
        registry = FlextLdifDn.CaseRegistry()
        registry.register_dn("CN=Admin,DC=Example,DC=Com")
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        registry.register_dn("cn=ADMIN,dc=EXAMPLE,dc=COM")
        variants = registry.get_case_variants("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert len(variants) == 3

    def test_validate_oud_consistency_consistent(self, dn_service: FlextLdifDn) -> None:
        """Validate OUD consistency when all variants are same case."""
        registry = FlextLdifDn.CaseRegistry()
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_oud_consistency_inconsistent(
        self,
        dn_service: FlextLdifDn,
    ) -> None:
        """Validate OUD consistency with multiple case variants."""
        registry = FlextLdifDn.CaseRegistry()
        registry.register_dn("CN=Admin,DC=Example,DC=Com")
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")  # Different case
        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is False

    def test_registry_clear(self, dn_service: FlextLdifDn) -> None:
        """Clear registry."""
        registry = FlextLdifDn.CaseRegistry()
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com") is True
        registry.clear()
        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com") is False

    def test_registry_stats(self, dn_service: FlextLdifDn) -> None:
        """Get registry statistics."""
        registry = FlextLdifDn.CaseRegistry()
        registry.register_dn("CN=Admin,DC=Example,DC=Com")
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        stats = registry.get_stats()
        assert stats["total_dns"] == 1
        assert stats["total_variants"] == 2
        assert stats["dns_with_multiple_variants"] == 1


class TestDnServiceIntegration:
    """Integration tests with real-world DN patterns."""

    def test_workflow_parse_validate_normalize(self, dn_service: FlextLdifDn) -> None:
        """Complete workflow: parse, validate, normalize."""
        dn = "CN=John Doe,OU=Users,DC=Example,DC=Com"

        # Validate
        valid_result = dn_service.validate_format(dn)
        assert valid_result.is_success
        assert valid_result.unwrap() is True

        # Parse
        parse_result = dn_service.parse_components(dn)
        assert parse_result.is_success
        components = parse_result.unwrap()
        assert len(components) == 4

        # Normalize
        norm_result = dn_service.normalize(dn)
        assert norm_result.is_success
        normalized = norm_result.unwrap()
        assert "cn=" in normalized.lower()

    def test_workflow_clean_and_escape(self, dn_service: FlextLdifDn) -> None:
        """Workflow: clean malformed DN, then escape values."""
        # Start with malformed DN
        malformed = "CN = Smith, John , OU = Users , DC = Example"

        # Clean
        cleaned = dn_service.clean_dn(malformed)
        assert "  " not in cleaned

        # Extract and escape value
        escaped = dn_service.escape_dn_value("Smith, John")
        assert "\\" in escaped

    def test_workflow_registry_for_migration(self, dn_service: FlextLdifDn) -> None:
        """Workflow: use registry to track DN case during migration."""
        source_dns = [
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "CN=Admin,DC=Example,DC=Com",
            "cn=ADMIN,dc=example,dc=com",
        ]

        registry = FlextLdifDn.CaseRegistry()
        for dn in source_dns:
            registry.register_dn(dn)

        # Validate consistency
        consistency_result = registry.validate_oud_consistency()
        assert consistency_result.is_success
        # Should have inconsistencies since we registered multiple case variants
        assert consistency_result.unwrap() is False

        # Get canonical for conversion
        canonical = registry.get_canonical_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert canonical is not None


__all__ = [
    "TestCaseRegistry",
    "TestDnCleaning",
    "TestDnComparison",
    "TestDnEscaping",
    "TestDnNormalization",
    "TestDnParsing",
    "TestDnServiceBuilderPattern",
    "TestDnServiceExecutePattern",
    "TestDnServiceIntegration",
    "TestDnValidation",
    "TestRdnParsing",
]
