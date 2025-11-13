"""Tests for FASE 1: LdifAttributes RFC 4512 § 2.5 Validators.

Tests the validate_attribute_names_rfc4512() model_validator implemented in domain.py.
Verifies RFC 4512 § 2.5 (attribute name format: leadkeychar *keychar).

Strategy: Capture RFC violations in metadata WITHOUT rejecting attributes
(preserve problematic attributes for round-trip conversions).
"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels


class TestLdifAttributesRfc4512Validator:
    """Test LdifAttributes RFC 4512 § 2.5 compliance validation with metadata capture."""

    # =========================================================================
    # RFC 4512 § 2.5: Valid Attribute Names
    # =========================================================================

    def test_attribute_starting_with_letter_passes(self) -> None:
        """Attribute name starting with letter is valid."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"cn": ["test"], "mail": ["test@example.com"]}
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is None or "rfc_violations" not in attrs.metadata

    def test_attribute_with_uppercase_passes(self) -> None:
        """Attribute names with uppercase letters are valid."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={
                "CN": ["test"],
                "Mail": ["test@example.com"],
                "OBJECTCLASS": ["person"],
            }
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is None or "rfc_violations" not in attrs.metadata

    def test_attribute_with_digits_passes(self) -> None:
        """Attribute names with digits after first char are valid."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"attr1": ["value1"], "test2attr": ["value2"], "cn3": ["value3"]}
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is None or "rfc_violations" not in attrs.metadata

    def test_attribute_with_hyphens_passes(self) -> None:
        """Attribute names with hyphens are valid (RFC 4512 § 2.5)."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={
                "given-name": ["John"],
                "family-name": ["Doe"],
                "user-id": ["jdoe"],
            }
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is None or "rfc_violations" not in attrs.metadata

    def test_attribute_with_mixed_case_and_hyphens_passes(self) -> None:
        """Complex valid attribute names pass validation."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={
                "givenName": ["John"],
                "sn": ["Doe"],
                "userPassword": ["{SSHA}hash"],
                "jpegPhoto": [b"photo"],
                "x500uniqueIdentifier": ["id"],
            }
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is None or "rfc_violations" not in attrs.metadata

    # =========================================================================
    # RFC 4512 § 2.5: Invalid Attribute Names (Captured in Metadata)
    # =========================================================================

    def test_attribute_starting_with_digit_captures_violation(self) -> None:
        """Attribute name starting with digit should be captured."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"1invalid": ["value"], "cn": ["test"]}
        )

        assert attrs_result.is_success  # NOT rejected
        attrs = attrs_result.unwrap()
        assert attrs.metadata is not None
        assert "rfc_violations" in attrs.metadata
        violations = attrs.metadata["rfc_violations"]
        assert any("1invalid" in v and "RFC 4512 § 2.5" in v for v in violations)

    def test_attribute_with_special_chars_captures_violation(self) -> None:
        """Attribute name with special characters should be captured."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={
                "invalid@attr": ["value"],
                "test_attr": ["value2"],
                "cn": ["test"],
            }
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is not None
        violations = attrs.metadata["rfc_violations"]

        # Both @ and _ are invalid
        assert any("invalid@attr" in v for v in violations)
        assert any("test_attr" in v for v in violations)

    def test_attribute_with_spaces_captures_violation(self) -> None:
        """Attribute name with spaces should be captured."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"invalid attr": ["value"], "cn": ["test"]}
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is not None
        violations = attrs.metadata["rfc_violations"]
        assert any("invalid attr" in v for v in violations)

    def test_attribute_starting_with_hyphen_captures_violation(self) -> None:
        """Attribute name starting with hyphen should be captured."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"-invalid": ["value"], "cn": ["test"]}
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is not None
        violations = attrs.metadata["rfc_violations"]
        assert any("-invalid" in v for v in violations)

    def test_attribute_with_dots_captures_violation(self) -> None:
        """Attribute name with dots should be captured (not allowed in RFC 4512 § 2.5)."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"invalid.attr": ["value"], "cn": ["test"]}
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is not None
        violations = attrs.metadata["rfc_violations"]
        assert any("invalid.attr" in v for v in violations)

    # =========================================================================
    # Multiple Violations Tests
    # =========================================================================

    def test_multiple_invalid_attributes_captures_all(self) -> None:
        """Multiple invalid attribute names should all be captured."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={
                "1invalid": ["value1"],
                "invalid@attr": ["value2"],
                "test_attr": ["value3"],
                "-hyphen": ["value4"],
                "cn": ["valid"],
            }
        )

        assert attrs_result.is_success  # NOT rejected
        attrs = attrs_result.unwrap()
        assert attrs.metadata is not None
        violations = attrs.metadata["rfc_violations"]

        # Should capture all 4 invalid names
        assert len(violations) >= 4
        assert any("1invalid" in v for v in violations)
        assert any("invalid@attr" in v for v in violations)
        assert any("test_attr" in v for v in violations)
        assert any("-hyphen" in v for v in violations)

    def test_all_invalid_attributes_preserves_data(self) -> None:
        """Invalid attributes should preserve data (for round-trip conversions)."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"1invalid": ["value1"], "2invalid": ["value2"]}
        )

        assert attrs_result.is_success  # NOT rejected
        attrs = attrs_result.unwrap()

        # Data preserved
        assert "1invalid" in attrs.attributes
        assert "2invalid" in attrs.attributes
        assert attrs.attributes["1invalid"] == ["value1"]
        assert attrs.attributes["2invalid"] == ["value2"]

        # But violations captured
        assert attrs.metadata is not None
        assert len(attrs.metadata["rfc_violations"]) >= 2

    # =========================================================================
    # Validation Context Tests
    # =========================================================================

    def test_validation_context_includes_metadata(self) -> None:
        """Validation context should include comprehensive metadata."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"1invalid": ["value"], "cn": ["test"]}
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is not None
        assert "validation_context" in attrs.metadata

        context = attrs.metadata["validation_context"]
        assert context["validator"] == "validate_attribute_names_rfc4512"
        assert context["rfc_section"] == "RFC 4512 § 2.5"
        assert "total_violations" in context
        assert "total_attributes" in context
        assert context["total_attributes"] == 2

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_empty_attributes_no_violations(self) -> None:
        """Empty attributes dict should not generate violations."""
        attrs_result = FlextLdifModels.LdifAttributes.create({})

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        # No violations for empty dict
        assert attrs.metadata is None or "rfc_violations" not in attrs.metadata

    def test_single_letter_attribute_passes(self) -> None:
        """Single letter attribute names are valid."""
        attrs_result = FlextLdifModels.LdifAttributes.create(
            attrs_data={"c": ["US"], "l": ["California"], "o": ["Company"]}
        )

        assert attrs_result.is_success
        attrs = attrs_result.unwrap()
        assert attrs.metadata is None or "rfc_violations" not in attrs.metadata

    def test_validator_uses_correct_regex_pattern(self) -> None:
        """Verify regex pattern matches RFC 4512 § 2.5 spec."""
        # Valid patterns: letter followed by letter/digit/hyphen
        valid_names = [
            "a",
            "A",
            "cn",
            "givenName",
            "user-id",
            "attr1",
            "test-attr-2",
            "X500uniqueIdentifier",
        ]
        invalid_names = [
            "1start",
            "_underscore",
            "has space",
            "has@symbol",
            "-hyphen",
            "has.dot",
        ]

        for name in valid_names:
            attrs_result = FlextLdifModels.LdifAttributes.create(
                attrs_data={name: ["value"]}
            )
            assert attrs_result.is_success
            attrs = attrs_result.unwrap()
            assert attrs.metadata is None or "rfc_violations" not in attrs.metadata, (
                f"Valid name '{name}' should not have violations"
            )

        for name in invalid_names:
            attrs_result = FlextLdifModels.LdifAttributes.create(
                attrs_data={name: ["value"]}
            )
            assert attrs_result.is_success
            attrs = attrs_result.unwrap()
            assert attrs.metadata is not None, (
                f"Invalid name '{name}' should have violations"
            )
            assert "rfc_violations" in attrs.metadata
