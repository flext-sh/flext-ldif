"""Unit tests for Validation Service - RFC 2849/4512 Compliant Validation.

Tests entry, attribute, and object class validation using RFC standards.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.validation_service import FlextLdifValidationService


class TestValidationServiceInitialization:
    """Test validation service initialization."""

    def test_init_creates_service(self) -> None:
        """Test validation service can be instantiated."""
        service = FlextLdifValidationService()
        assert service is not None

    def test_execute_returns_status(self) -> None:
        """Test execute returns service status."""
        service = FlextLdifValidationService()
        result = service.execute()

        assert result.is_success
        status = result.unwrap()
        assert status["service"] == "ValidationService"
        assert status["status"] == "operational"
        rfc_compliance = status.get("rfc_compliance", "")
        assert isinstance(rfc_compliance, str)
        assert "RFC 2849" in rfc_compliance
        assert "RFC 4512" in rfc_compliance
        validation_types = status.get("validation_types", [])
        assert isinstance(validation_types, list)
        assert "attribute_name" in validation_types


class TestValidateAttributeName:
    """Test attribute name validation with RFC 4512 compliance."""

    def test_validate_simple_attribute_name(self) -> None:
        """Test validation of simple attribute name."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("cn")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_attribute_name_with_hyphens(self) -> None:
        """Test validation of attribute name with hyphens (RFC 4512)."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("user-name")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_attribute_name_with_digits(self) -> None:
        """Test validation of attribute name with digits."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("attr123")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_mixed_case_attribute_name(self) -> None:
        """Test validation of mixed case attribute name."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("userName")

        assert result.is_success
        assert result.unwrap() is True

    def test_reject_attribute_name_starting_with_digit(self) -> None:
        """Test rejection of attribute name starting with digit."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("2invalid")

        assert result.is_success
        assert result.unwrap() is False

    def test_reject_attribute_name_with_spaces(self) -> None:
        """Test rejection of attribute name with spaces."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("invalid name")

        assert result.is_success
        assert result.unwrap() is False

    def test_reject_attribute_name_with_special_chars(self) -> None:
        """Test rejection of attribute name with special characters."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("invalid@name")

        assert result.is_success
        assert result.unwrap() is False

    def test_reject_empty_attribute_name(self) -> None:
        """Test rejection of empty attribute name."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("")

        assert result.is_success
        assert result.unwrap() is False

    def test_reject_too_long_attribute_name(self) -> None:
        """Test rejection of attribute name exceeding RFC limit."""
        service = FlextLdifValidationService()
        # RFC 4512 typical limit is 127 characters
        long_name = "a" * 128
        result = service.validate_attribute_name(long_name)

        assert result.is_success
        assert result.unwrap() is False

    def test_accept_max_length_attribute_name(self) -> None:
        """Test acceptance of attribute name at RFC limit."""
        service = FlextLdifValidationService()
        # RFC 4512 typical limit is 127 characters
        max_name = "a" * 127
        result = service.validate_attribute_name(max_name)

        assert result.is_success
        assert result.unwrap() is True

    def test_reject_invalid_attribute_name(self) -> None:
        """Test rejection of invalid attribute name format."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_name("2invalid")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_common_ldap_attributes(self) -> None:
        """Test validation of common LDAP attribute names."""
        service = FlextLdifValidationService()
        common_attrs = [
            "cn",
            "sn",
            "ou",
            "dc",
            "uid",
            "mail",
            "givenName",
            "telephoneNumber",
        ]

        for attr in common_attrs:
            result = service.validate_attribute_name(attr)
            assert result.is_success
            assert result.unwrap() is True, f"Failed for common attribute: {attr}"


class TestValidateObjectClassName:
    """Test object class name validation with RFC 4512 compliance."""

    def test_validate_simple_objectclass_name(self) -> None:
        """Test validation of simple object class name."""
        service = FlextLdifValidationService()
        result = service.validate_objectclass_name("person")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_objectclass_name_with_camel_case(self) -> None:
        """Test validation of camel case object class name."""
        service = FlextLdifValidationService()
        result = service.validate_objectclass_name("inetOrgPerson")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_objectclass_name_with_hyphens(self) -> None:
        """Test validation of object class name with hyphens."""
        service = FlextLdifValidationService()
        result = service.validate_objectclass_name("organization-unit")

        assert result.is_success
        assert result.unwrap() is True

    def test_reject_objectclass_name_with_spaces(self) -> None:
        """Test rejection of object class name with spaces."""
        service = FlextLdifValidationService()
        result = service.validate_objectclass_name("invalid class")

        assert result.is_success
        assert result.unwrap() is False

    def test_reject_objectclass_name_starting_with_digit(self) -> None:
        """Test rejection of object class name starting with digit."""
        service = FlextLdifValidationService()
        result = service.validate_objectclass_name("2person")

        assert result.is_success
        assert result.unwrap() is False

    def test_reject_empty_objectclass_name(self) -> None:
        """Test rejection of empty object class name."""
        service = FlextLdifValidationService()
        result = service.validate_objectclass_name("")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_common_ldap_objectclasses(self) -> None:
        """Test validation of common LDAP object class names."""
        service = FlextLdifValidationService()
        common_classes = [
            "top",
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "groupOfNames",
            "organizationalUnit",
            "domain",
            "country",
        ]

        for oc in common_classes:
            result = service.validate_objectclass_name(oc)
            assert result.is_success
            assert result.unwrap() is True, f"Failed for common objectClass: {oc}"


class TestValidateAttributeValue:
    """Test attribute value validation."""

    def test_validate_simple_attribute_value(self) -> None:
        """Test validation of simple attribute value."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_value("John Smith")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_empty_attribute_value(self) -> None:
        """Test validation of empty attribute value (allowed in LDAP)."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_value("")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_attribute_value_with_special_chars(self) -> None:
        """Test validation of attribute value with special characters."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_value("user@example.com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_attribute_value_with_unicode(self) -> None:
        """Test validation of attribute value with Unicode."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_value("José García")

        assert result.is_success
        assert result.unwrap() is True

    def test_reject_attribute_value_exceeding_max_length(self) -> None:
        """Test rejection of attribute value exceeding max length."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_value("test", max_length=2)

        assert result.is_success
        assert result.unwrap() is False

    def test_accept_attribute_value_at_max_length(self) -> None:
        """Test acceptance of attribute value at max length."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_value("te", max_length=2)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_long_attribute_value(self) -> None:
        """Test validation of long attribute value (default 1MB limit)."""
        service = FlextLdifValidationService()
        # Create a reasonably large value (10KB)
        large_value = "x" * 10240
        result = service.validate_attribute_value(large_value)

        assert result.is_success
        assert result.unwrap() is True

    def test_reject_non_string_attribute_value(self) -> None:
        """Test rejection of non-string attribute value."""
        service = FlextLdifValidationService()
        result = service.validate_attribute_value(123)

        assert result.is_success
        assert result.unwrap() is False


class TestValidateDnComponent:
    """Test DN component validation."""

    def test_validate_simple_dn_component(self) -> None:
        """Test validation of simple DN component."""
        service = FlextLdifValidationService()
        result = service.validate_dn_component("cn", "John Smith")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_component_with_empty_value(self) -> None:
        """Test validation of DN component with empty value."""
        service = FlextLdifValidationService()
        result = service.validate_dn_component("cn", "")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_component_with_special_chars(self) -> None:
        """Test validation of DN component with special characters."""
        service = FlextLdifValidationService()
        result = service.validate_dn_component("mail", "user@example.com")

        assert result.is_success
        assert result.unwrap() is True

    def test_reject_dn_component_with_invalid_attribute(self) -> None:
        """Test rejection of DN component with invalid attribute name."""
        service = FlextLdifValidationService()
        result = service.validate_dn_component("2invalid", "value")

        assert result.is_success
        assert result.unwrap() is False

    def test_reject_dn_component_with_non_string_value(self) -> None:
        """Test rejection of DN component with non-string value."""
        service = FlextLdifValidationService()
        result = service.validate_dn_component("cn", 123)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_common_dn_components(self) -> None:
        """Test validation of common DN components."""
        service = FlextLdifValidationService()
        common_components = [
            ("cn", "John Smith"),
            ("ou", "People"),
            ("dc", "example"),
            ("uid", "jsmith"),
            ("mail", "jsmith@example.com"),
        ]

        for attr, value in common_components:
            result = service.validate_dn_component(attr, value)
            assert result.is_success
            assert result.unwrap() is True, f"Failed for DN component: {attr}={value}"


class TestRFC4512Compliance:
    """Test RFC 4512 compliance scenarios."""

    def test_attribute_names_case_insensitive_validation(self) -> None:
        """Test that attribute name validation is case-insensitive."""
        service = FlextLdifValidationService()

        # All these should be valid (case variations)
        variations = ["cn", "CN", "Cn", "cN"]
        for variant in variations:
            result = service.validate_attribute_name(variant)
            assert result.is_success
            assert result.unwrap() is True

    def test_hyphenated_names_valid(self) -> None:
        """Test that hyphenated names are valid per RFC 4512."""
        service = FlextLdifValidationService()
        hyphenated_names = [
            "user-name",
            "organization-unit",
            "postal-code",
            "street-address",
        ]

        for name in hyphenated_names:
            result = service.validate_attribute_name(name)
            assert result.is_success
            assert result.unwrap() is True

    def test_numeric_suffixes_valid(self) -> None:
        """Test that numeric suffixes in names are valid."""
        service = FlextLdifValidationService()
        numeric_names = ["attr1", "value2", "field99"]

        for name in numeric_names:
            result = service.validate_attribute_name(name)
            assert result.is_success
            assert result.unwrap() is True

    def test_leading_digits_invalid(self) -> None:
        """Test that leading digits in names are invalid per RFC 4512."""
        service = FlextLdifValidationService()
        invalid_names = ["1attr", "2value", "9field"]

        for name in invalid_names:
            result = service.validate_attribute_name(name)
            assert result.is_success
            assert result.unwrap() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
