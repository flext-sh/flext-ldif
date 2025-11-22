"""Tests for FASE 1: Entry RFC Compliance Validators.

Tests the validate_entry_rfc_compliance() model_validator implemented in domain.py.
Verifies RFC 2849 § 2 (DN and attributes required) and RFC 4512 § 2.5 (attribute naming).

Strategy: Capture RFC violations in validation_metadata WITHOUT rejecting entries
(preserve problematic entries for round-trip conversions).
"""

from __future__ import annotations

from typing import cast

from flext_ldif import FlextLdifModels


def get_validation_metadata(entry: object) -> dict[str, object] | None:
    """Helper to get validation_metadata from entry.metadata.validation_results."""
    if not hasattr(entry, "metadata"):
        return None
    metadata = getattr(entry, "metadata", None)
    if not metadata or not hasattr(metadata, "validation_results"):
        return None
    return getattr(metadata, "validation_results", None)


class TestEntryRfcComplianceValidator:
    """Test Entry RFC compliance validation with metadata capture."""

    # =========================================================================
    # RFC 2849 § 2: DN Validation Tests
    # =========================================================================

    def test_entry_with_valid_dn_passes_validation(self) -> None:
        """Valid DN should pass validation without violations."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is None or "rfc_violations" not in metadata

    def test_entry_with_empty_dn_captures_violation(self) -> None:
        """Empty DN should be captured in validation_metadata."""
        entry_result = FlextLdifModels.Entry.create(
            dn="",
            attributes={"cn": ["test"]},
        )

        assert entry_result.is_success  # Entry NOT rejected
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        assert "rfc_violations" in metadata
        violations = cast("list[str]", metadata["rfc_violations"])
        assert any("RFC 2849 § 2" in v and "DN" in v for v in violations)

    def test_entry_with_whitespace_dn_captures_violation(self) -> None:
        """Whitespace-only DN should be captured."""
        entry_result = FlextLdifModels.Entry.create(
            dn="   ",
            attributes={"cn": ["test"]},
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])
        assert any("empty or whitespace DN" in v for v in violations)

    def test_entry_with_none_dn_captured(self) -> None:
        """None DN should be captured (edge case)."""
        # Use model_construct to create entry with None DN for testing validation
        entry = FlextLdifModels.Entry.model_construct(
            dn=None,
            attributes=FlextLdifModels.LdifAttributes.model_construct(
                attributes={"cn": ["test"]},
            ),
        )
        # Trigger validation by accessing validation_metadata
        _ = get_validation_metadata(entry)

        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])
        assert any("RFC 2849 § 2" in v and "DN" in v for v in violations)

    # =========================================================================
    # RFC 2849 § 2: Attributes Validation Tests
    # =========================================================================

    def test_entry_with_no_attributes_captures_violation(self) -> None:
        """Entry without attributes should be captured."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={},
        )

        assert entry_result.is_success  # Entry NOT rejected
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])
        assert any("at least one attribute" in v for v in violations)

    def test_entry_with_none_attributes_captures_violation(self) -> None:
        """Entry with None attributes should be captured."""
        # Use model_construct to create entry with None attributes for testing validation
        entry = FlextLdifModels.Entry.model_construct(
            dn=FlextLdifModels.DistinguishedName.model_construct(
                value="cn=test,dc=example,dc=com",
            ),
            attributes=None,
        )
        # Trigger validation by accessing validation_metadata
        _ = get_validation_metadata(entry)

        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])
        assert any("at least one attribute" in v for v in violations)

    def test_entry_with_valid_attributes_passes(self) -> None:
        """Entry with valid attributes passes validation."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "mail": ["test@example.com"],
                "objectClass": ["person"],  # Required for RFC 4512 § 2.4.1
            },
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is None or "rfc_violations" not in metadata

    # =========================================================================
    # RFC 4512 § 2.5: Attribute Name Format Tests
    # =========================================================================

    def test_attribute_name_starting_with_letter_passes(self) -> None:
        """Attribute names starting with letter are valid."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "mail": ["test@example.com"],
                "userPassword": ["secret"],
                "objectClass": ["person"],  # Required for RFC 4512 § 2.4.1
            },
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is None or "rfc_violations" not in metadata

    def test_attribute_name_with_hyphens_passes(self) -> None:
        """Attribute names with hyphens are valid (RFC 4512 § 2.5)."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],  # RFC 4512 § 2.3: naming attribute from RDN
                "given-name": ["John"],
                "family-name": ["Doe"],
                "objectClass": ["person"],  # Required for RFC 4512 § 2.4.1
            },
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is None or "rfc_violations" not in metadata

    def test_attribute_name_with_digits_passes(self) -> None:
        """Attribute names with digits are valid after first character.

        RFC 4512 § 1.4: Attribute names can contain digits (e.g., test2attr).
        RFC 4512 § 2.3: Entry SHOULD have naming attribute from RDN in attributes.
        """
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],  # RFC 4512 § 2.3: Naming attribute from RDN
                "attr1": ["value1"],
                "test2attr": ["value2"],  # RFC 4512 § 1.4: Digits allowed in attr names
                "objectClass": ["person"],  # Required for RFC 4512 § 2.4.1
            },
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is None or "rfc_violations" not in metadata

    def test_attribute_name_starting_with_digit_captures_violation(self) -> None:
        """Attribute name starting with digit should be captured."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"1invalid": ["value"], "cn": ["test"]},
        )

        assert entry_result.is_success  # Entry NOT rejected
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])
        assert any("RFC 4512 § 2.5" in v and "1invalid" in v for v in violations)

    def test_attribute_name_with_special_chars_captures_violation(self) -> None:
        """Attribute name with special characters should be captured."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"invalid@attr": ["value"], "cn": ["test"]},
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])
        assert any("invalid@attr" in v and "RFC 4512 § 2.5" in v for v in violations)

    def test_attribute_name_with_spaces_captures_violation(self) -> None:
        """Attribute name with spaces should be captured."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"invalid attr": ["value"], "cn": ["test"]},
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])
        assert any("invalid attr" in v for v in violations)

    # =========================================================================
    # Multiple Violations Tests
    # =========================================================================

    def test_entry_with_multiple_violations_captures_all(self) -> None:
        """Entry with multiple RFC violations should capture all."""
        entry_result = FlextLdifModels.Entry.create(
            dn="",  # Invalid DN
            attributes={
                "1invalid": ["value"],
                "invalid@attr": ["value"],
            },  # 2 invalid attrs
        )

        assert entry_result.is_success  # Entry NOT rejected
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])

        # Should have 3 violations: DN + 2 attributes
        assert len(violations) >= 3
        assert any("DN" in v for v in violations)
        assert any("1invalid" in v for v in violations)
        assert any("invalid@attr" in v for v in violations)

    def test_entry_with_all_violations_captures_context(self) -> None:
        """Validation context should include comprehensive metadata."""
        entry_result = FlextLdifModels.Entry.create(
            dn="",
            attributes={},
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        assert "validation_context" in metadata

        context = cast("dict[str, object]", metadata["validation_context"])
        assert context["validator"] == "validate_entry_rfc_compliance"
        assert "dn" in context
        assert "attribute_count" in context
        assert "total_violations" in context
        total_violations = cast("int", context["total_violations"])
        assert total_violations >= 2  # DN + attributes

    # =========================================================================
    # Edge Cases and Boundary Tests
    # =========================================================================

    def test_entry_without_objectclass_is_valid(self) -> None:
        """Schema entries without objectClass should be valid (RFC allows)."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=schema",
            attributes={"cn": ["schema"], "attributeTypes": ["( 1.2.3 NAME 'test' )"]},
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        # No objectClass requirement violation
        validation_results = (
            entry.metadata.validation_results if entry.metadata else None
        )
        assert validation_results is None or "rfc_violations" not in validation_results

    def test_entry_with_complex_valid_attributes_passes(self) -> None:
        """Complex valid entry should pass all validations."""
        entry_result = FlextLdifModels.Entry.create(
            dn="uid=john.doe,ou=users,dc=example,dc=com",
            attributes={
                "uid": ["john.doe"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john.doe@example.com"],
                "userPassword": ["{SSHA}hashedpassword"],
                "objectClass": ["inetOrgPerson", "posixAccount"],
            },
        )

        assert entry_result.is_success
        entry = entry_result.unwrap()
        metadata = get_validation_metadata(entry)
        assert metadata is None or "rfc_violations" not in metadata

    def test_entry_preserves_invalid_data_for_roundtrip(self) -> None:
        """Invalid entries should preserve data (for round-trip conversions)."""
        entry_result = FlextLdifModels.Entry.create(
            dn="invalid dn",  # Spaces in DN (invalid per RFC 4514)
            attributes={"1invalid": ["value"], "cn": ["test"]},
        )

        assert entry_result.is_success  # NOT rejected
        entry = entry_result.unwrap()

        # Data preserved
        assert str(entry.dn) == "invalid dn"
        assert "1invalid" in entry.attributes.attributes
        assert "cn" in entry.attributes.attributes

        # But violations captured
        metadata = get_validation_metadata(entry)
        assert metadata is not None
        violations = cast("list[str]", metadata["rfc_violations"])
        assert len(violations) > 0

    def test_validator_uses_correct_regex_pattern(self) -> None:
        """Verify regex pattern matches RFC 4512 § 2.5 spec."""
        # Valid patterns: letter followed by letter/digit/hyphen
        valid_names = ["a", "A", "cn", "givenName", "user-id", "attr1", "test-attr-2"]
        invalid_names = ["1start", "_underscore", "has space", "has@symbol", "-hyphen"]

        for name in valid_names:
            entry_result = FlextLdifModels.Entry.create(
                dn="cn=test,dc=example,dc=com",
                attributes={
                    "cn": ["test"],  # RFC 4512 § 2.3: naming attribute from RDN
                    name: ["value"],
                    "objectClass": ["person"],  # Required for RFC 4512 § 2.4.1
                },
            )
            assert entry_result.is_success
            entry = entry_result.unwrap()
            metadata = get_validation_metadata(entry)
            assert metadata is None or "rfc_violations" not in metadata, (
                f"Valid name '{name}' should not have violations"
            )

        for name in invalid_names:
            entry_result = FlextLdifModels.Entry.create(
                dn="cn=test,dc=example,dc=com",
                attributes={
                    name: ["value"],
                    "cn": ["required"],
                    "objectClass": ["person"],  # Required for RFC 4512 § 2.4.1
                },  # Add valid attr to avoid empty attrs violation
            )
            assert entry_result.is_success
            entry = entry_result.unwrap()
            metadata = get_validation_metadata(entry)
            assert metadata is not None, f"Invalid name '{name}' should have violations"
            violations = cast("list[str]", metadata["rfc_violations"])
            assert any(name in v and "RFC 4512 § 2.5" in v for v in violations), (
                f"Violation should mention invalid attribute name '{name}'"
            )
