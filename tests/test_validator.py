"""Tests for LDIF validator."""

from __future__ import annotations

from typing import Never

# Use simplified imports from root level
from flext_ldif import LDIFEntry, LDIFValidator


class TestLDIFValidator:
    """Test LDIF validator functionality."""

    def test_validate_entry_valid(self) -> None:
        """Test validating a valid LDIF entry."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person"],
                "mail": ["test@example.com"],
            },
        )

        validator = LDIFValidator()
        result = validator.validate_entry(entry)

        assert result.success
        assert result.data is True

    def test_validate_entry_invalid_dn_format(self) -> None:
        """Test validating entry with invalid DN format."""
        # Test that domain validation catches invalid DN during construction
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            LDIFEntry(
                dn="invalid-dn-format",
                attributes={
                    "cn": ["test"],
                    "objectClass": ["person"],
                },
            )

        # Verify the error message contains DN validation error
        assert "DN must contain at least one attribute=value pair" in str(
            exc_info.value,
        )

    def test_validate_entry_dn_empty(self) -> None:
        """Test validating entry with empty DN."""
        # Test that domain validation catches invalid DN during construction
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            LDIFEntry(
                dn="",
                attributes={
                    "cn": ["test"],
                    "objectClass": ["person"],
                },
            )

        # Verify the error message contains DN validation error
        assert "DN must be a non-empty string" in str(exc_info.value)

    def test_validate_entry_dn_starts_with_equals(self) -> None:
        """Test validating entry with DN starting with equals."""
        # Test that domain validation catches invalid DN during construction
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            LDIFEntry(
                dn="=invalid,dc=example,dc=com",
                attributes={
                    "cn": ["test"],
                    "objectClass": ["person"],
                },
            )

        # Verify the error message contains DN validation error
        assert "Invalid DN component" in str(exc_info.value)

    def test_validate_entry_valid_dn_formats(self) -> None:
        """Test validating entries with various valid DN formats."""
        valid_dns = [
            "cn=test,dc=example,dc=com",
            "uid=user123,ou=people,dc=example,dc=com",
            "mail=test@example.com,dc=example,dc=com",
            "o=organization,c=US",
        ]

        validator = LDIFValidator()

        for dn in valid_dns:
            entry = LDIFEntry(
                dn=dn,
                attributes={"objectClass": ["person"]},
            )

            result = validator.validate_entry(entry)
            assert result.success, f"DN should be valid: {dn}"

    def test_validate_entry_invalid_attribute_name(self) -> None:
        """Test validating entry with invalid attribute name."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "123invalid": ["value"],  # Starts with number
                "objectClass": ["person"],
            },
        )

        validator = LDIFValidator()
        result = validator.validate_entry(entry)

        assert not result.success
        assert result.error is not None
        assert "Invalid attribute name" in result.error
        assert "123invalid" in result.error

    def test_validate_entry_invalid_attribute_name_special_chars(self) -> None:
        """Test validating entry with special characters in attribute name."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "invalid@attr": ["value"],  # Contains @
                "objectClass": ["person"],
            },
        )

        validator = LDIFValidator()
        result = validator.validate_entry(entry)

        assert not result.success
        assert result.error is not None
        assert "Invalid attribute name" in result.error
        assert "invalid@attr" in result.error

    def test_validate_entry_valid_attribute_names(self) -> None:
        """Test validating entries with various valid attribute names."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "mail": ["test@example.com"],
                "objectClass": ["person"],
                "givenName": ["Test"],
                "sn": ["User"],
                "telephoneNumber": ["123-456-7890"],
                "attribute-with-dashes": ["value"],
                "attr123": ["value"],
            },
        )

        validator = LDIFValidator()
        result = validator.validate_entry(entry)

        assert result.success

    def test_validate_entry_missing_objectclass(self) -> None:
        """Test validating entry without objectClass attribute."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "mail": ["test@example.com"],
                # No objectClass
            },
        )

        validator = LDIFValidator()
        result = validator.validate_entry(entry)

        assert not result.success
        assert result.error is not None
        assert "missing required objectClass attribute" in result.error

    def test_validate_entry_empty_objectclass(self) -> None:
        """Test validating entry with empty objectClass attribute."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": [],  # Empty list
            },
        )

        validator = LDIFValidator()
        result = validator.validate_entry(entry)

        # This should pass validation - has_attribute checks for key existence, not values
        assert result.success

    def test_validate_entry_exception_handling(self) -> None:
        """Test validation with entry that causes exception."""
        validator = LDIFValidator()

        # Create a mock entry that will cause an exception
        class BadEntry:
            @property
            def dn(self) -> Never:
                msg = "Simulated error"
                raise ValueError(msg)

            @property
            def attributes(self) -> dict[str, list[str]]:
                return {}

            def has_attribute(self, name: str) -> bool:
                return False

        from typing import Any, cast

        result = validator.validate_entry(cast("Any", BadEntry()))

        assert not result.success
        assert result.error is not None
        assert "Validation error" in result.error

    def test_validate_entries_all_valid(self) -> None:
        """Test validating multiple valid entries."""
        entries = [
            LDIFEntry(
                dn="cn=user1,dc=example,dc=com",
                attributes={
                    "cn": ["user1"],
                    "objectClass": ["person"],
                },
            ),
            LDIFEntry(
                dn="cn=user2,dc=example,dc=com",
                attributes={
                    "cn": ["user2"],
                    "objectClass": ["inetOrgPerson"],
                    "mail": ["user2@example.com"],
                },
            ),
        ]

        validator = LDIFValidator()
        result = validator.validate_entries(entries)

        assert result.success
        assert result.data is True

    def test_validate_entries_first_invalid(self) -> None:
        """Test validating entries where first entry has invalid DN format."""
        # Test that domain validation catches invalid DN during construction
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            LDIFEntry(
                dn="invalid-dn",
                attributes={
                    "cn": ["user1"],
                    "objectClass": ["person"],
                },
            )

        # Verify the error message contains DN validation error
        assert "DN must contain at least one attribute=value pair" in str(
            exc_info.value,
        )

        # Test validator with a valid entry that has invalid attribute name instead
        entries = [
            LDIFEntry(
                dn="cn=user1,dc=example,dc=com",
                attributes={
                    "123invalid": ["user1"],  # Invalid attribute name
                    "objectClass": ["person"],
                },
            ),
            LDIFEntry(
                dn="cn=user2,dc=example,dc=com",
                attributes={
                    "cn": ["user2"],
                    "objectClass": ["person"],
                },
            ),
        ]

        validator = LDIFValidator()
        result = validator.validate_entries(entries)

        assert not result.success
        assert result.error is not None
        assert "Entry 0 validation failed" in result.error
        assert "Invalid attribute name" in result.error

    def test_validate_entries_second_invalid(self) -> None:
        """Test validating entries where second entry is invalid."""
        entries = [
            LDIFEntry(
                dn="cn=user1,dc=example,dc=com",
                attributes={
                    "cn": ["user1"],
                    "objectClass": ["person"],
                },
            ),
            LDIFEntry(
                dn="cn=user2,dc=example,dc=com",
                attributes={
                    "cn": ["user2"],
                    # Missing objectClass
                },
            ),
        ]

        validator = LDIFValidator()
        result = validator.validate_entries(entries)

        assert not result.success
        assert result.error is not None
        assert "Entry 1 validation failed" in result.error
        assert "missing required objectClass attribute" in result.error

    def test_validate_entries_empty_list(self) -> None:
        """Test validating empty list of entries."""
        validator = LDIFValidator()
        result = validator.validate_entries([])

        assert result.success
        assert result.data is True

    def test_validate_entries_exception_handling(self) -> None:
        """Test batch validation with exception."""
        validator = LDIFValidator()

        # Mock an entry that will cause exception during iteration
        class BadEntries:
            def __iter__(self) -> Never:
                msg = "Simulated iteration error"
                raise TypeError(msg)

        from typing import Any, cast

        result = validator.validate_entries(cast("Any", BadEntries()))

        assert not result.success
        assert result.error is not None
        assert "Batch validation error" in result.error

    def test_dn_pattern_regex(self) -> None:
        """Test DN pattern regex directly."""
        validator = LDIFValidator()

        # Valid DNs
        valid_dns = [
            "cn=test,dc=example,dc=com",
            "uid=user123,ou=people,dc=example,dc=com",
            "mail=test@example.com,dc=example,dc=com",
            "o=organization,c=US",
            "a=something",  # Minimal valid DN
        ]

        for dn in valid_dns:
            assert validator.DN_PATTERN.match(dn), f"Should match: {dn}"

        # Invalid DNs
        invalid_dns = [
            "",
            "=invalid",
            "123=invalid",
            "invalid-format",
            " cn=test",  # Leading space
        ]

        for dn in invalid_dns:
            assert not validator.DN_PATTERN.match(dn), f"Should not match: {dn}"

    def test_attr_name_pattern_regex(self) -> None:
        """Test attribute name pattern regex directly."""
        validator = LDIFValidator()

        # Valid attribute names
        valid_attrs = [
            "cn",
            "mail",
            "objectClass",
            "givenName",
            "sn",
            "telephoneNumber",
            "attribute-with-dashes",
            "attr123",
            "a",  # Single character
        ]

        for attr in valid_attrs:
            assert validator.ATTR_NAME_PATTERN.match(attr), f"Should match: {attr}"

        # Invalid attribute names
        invalid_attrs = [
            "",
            "123invalid",  # Starts with number
            "invalid@attr",  # Contains @
            "invalid.attr",  # Contains dot
            "invalid attr",  # Contains space
            "-invalid",  # Starts with dash
            "invalid_attr",  # Contains underscore
        ]

        for attr in invalid_attrs:
            assert not validator.ATTR_NAME_PATTERN.match(attr), (
                f"Should not match: {attr}"
            )
