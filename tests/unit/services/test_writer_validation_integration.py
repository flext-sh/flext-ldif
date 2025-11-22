"""Tests for Writer integrated with ValidationService.

Tests real validation of entries before writing, using actual ValidationService.
ZERO mocks - all real services and data.
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifModels, FlextLdifWriter
from flext_ldif.services.validation import FlextLdifValidation


class TestWriterValidationIntegration:
    """Test Writer integration with ValidationService for entry validation."""

    @pytest.fixture
    def writer(self) -> FlextLdifWriter:
        """Initialize real writer service."""
        return FlextLdifWriter()

    @pytest.fixture
    def validation_service(self) -> FlextLdifValidation:
        """Initialize real validation service."""
        return FlextLdifValidation()

    @pytest.fixture
    def valid_entry(self) -> FlextLdifModels.Entry:
        """Create a valid LDAP entry with RFC-compliant attributes."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=John Doe,ou=people,dc=example,dc=com",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["John Doe"],
                    "sn": ["Doe"],
                    "mail": ["john@example.com"],
                    "objectClass": ["person", "inetOrgPerson"],
                },
            ),
        )

    @pytest.fixture
    def invalid_attribute_entry(self) -> FlextLdifModels.Entry:
        """Create entry with invalid attribute name (contains spaces)."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=Jane Smith,ou=people,dc=example,dc=com",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["Jane Smith"],
                    "invalid attr": ["value"],  # Invalid: contains space
                    "objectClass": ["person"],
                },
            ),
        )

    def test_valid_entry_validates_successfully(
        self,
        writer: FlextLdifWriter,
        validation_service: FlextLdifValidation,
        valid_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test that valid entry attributes pass RFC validation."""
        # Validate all attribute names
        for attr_name in valid_entry.attributes.attributes:
            result = validation_service.validate_attribute_name(attr_name)
            assert result.is_success, f"Validation failed for '{attr_name}'"
            is_valid = result.unwrap()
            assert is_valid, f"Expected '{attr_name}' to be valid RFC attribute name"

    def test_invalid_attribute_name_detected(
        self,
        validation_service: FlextLdifValidation,
    ) -> None:
        """Test that invalid attribute names are rejected."""
        # Space in name is invalid
        result = validation_service.validate_attribute_name("invalid attr")
        assert result.is_success
        assert not result.unwrap(), "Expected 'invalid attr' to be invalid"

        # Valid names
        result = validation_service.validate_attribute_name("cn")
        assert result.is_success
        assert result.unwrap(), "Expected 'cn' to be valid"

        result = validation_service.validate_attribute_name("mail")
        assert result.is_success
        assert result.unwrap(), "Expected 'mail' to be valid"

        result = validation_service.validate_attribute_name("objectClass")
        assert result.is_success
        assert result.unwrap(), "Expected 'objectClass' to be valid"

    def test_validate_dn_components_with_valid_entry(
        self,
        validation_service: FlextLdifValidation,
        valid_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test DN component validation on valid entry."""
        # DN should be valid for writing
        dn_value = (
            valid_entry.dn.value
            if hasattr(valid_entry.dn, "value")
            else str(valid_entry.dn)
        )
        assert dn_value, "DN should exist"
        assert "cn=" in dn_value, "DN should contain cn component"
        assert "ou=" in dn_value, "DN should contain ou component"
        assert "dc=" in dn_value, "DN should contain dc component"

    def test_write_valid_entry_to_string(
        self,
        writer: FlextLdifWriter,
        valid_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test writing valid entry to LDIF string format."""
        result = writer.write(
            entries=[valid_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                include_version_header=True,
                fold_long_lines=False,
            ),
        )

        assert result.is_success
        output = result.unwrap()
        assert isinstance(output, str)
        # Check for DN - always present in plain text
        assert "dn: cn=John Doe,ou=people,dc=example,dc=com" in output
        # Check for base64-encoded or plain text values
        assert "cn: John Doe" in output or "cn::" in output, (
            "Entry should contain cn attribute"
        )
        assert "objectClass: person" in output or "objectClass::" in output, (
            "Entry should contain objectClass"
        )

    def test_write_entry_with_base64_encoding(
        self,
        writer: FlextLdifWriter,
        valid_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test writing entry with base64 encoding for binary values."""
        result = writer.write(
            entries=[valid_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                base64_encode_binary=True,
                fold_long_lines=False,
            ),
        )

        assert result.is_success
        output = result.unwrap()
        assert "dn: cn=John Doe,ou=people,dc=example,dc=com" in output

    def test_validate_multiple_entries_in_batch(
        self,
        writer: FlextLdifWriter,
        validation_service: FlextLdifValidation,
    ) -> None:
        """Test validation of multiple entries before writing."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=User{i},ou=people,dc=example,dc=com",
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": [f"User{i}"],
                        "objectClass": ["person"],
                        "mail": [f"user{i}@example.com"],
                    },
                ),
            )
            for i in range(1, 4)
        ]

        # Validate all attributes
        all_valid = True
        for entry in entries:
            for attr_name in entry.attributes.attributes:
                result = validation_service.validate_attribute_name(attr_name)
                if not result.is_success or not result.unwrap():
                    all_valid = False
                    break

        assert all_valid, "All entries should have valid attribute names"

        # Write them
        result = writer.write(
            entries=entries,
            target_server_type="rfc",
            output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(fold_long_lines=False),
        )

        assert result.is_success
        output = result.unwrap()
        assert "User1" in output
        assert "User2" in output
        assert "User3" in output
