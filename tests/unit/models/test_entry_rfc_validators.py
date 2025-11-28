"""Tests for FASE 1: Entry RFC Compliance Validators.

Tests: FlextLdifModels.Entry RFC compliance validation
Modules: FlextLdifModels.Entry.validate_entry_rfc_compliance() model_validator
Scope: RFC 2849 § 2 (DN/attributes required), RFC 4512 § 2.5 (attribute naming), validation metadata capture

Strategy: Capture RFC violations WITHOUT rejecting entries (preserve for round-trip conversions).
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, cast

import pytest
from tests.fixtures.typing import GenericFieldsDict

from flext_ldif import FlextLdifModels


class TestEntryRfcCompliance:
    """Test Entry RFC compliance validation with metadata capture."""

    # =========================================================================
    # Test Cases - Organized as Nested StrEnum and Mappings
    # =========================================================================

    class RFCTestCase(StrEnum):
        """Test case identifiers for RFC validation scenarios."""

        VALID_DN = "valid_dn"
        EMPTY_DN = "empty_dn"
        WHITESPACE_DN = "whitespace_dn"
        NONE_DN = "none_dn"
        NO_ATTRS = "no_attrs"
        NONE_ATTRS = "none_attrs"
        VALID_ATTRS = "valid_attrs"
        ATTR_LETTER_START = "attr_letter_start"
        ATTR_HYPHEN = "attr_hyphen"
        ATTR_DIGIT = "attr_digit"
        ATTR_DIGIT_START = "attr_digit_start"
        ATTR_SPECIAL_CHAR = "attr_special_char"
        ATTR_SPACE = "attr_space"
        MULTIPLE_VIOLATIONS = "multiple_violations"
        ALL_VIOLATIONS = "all_violations"
        NO_OBJECTCLASS = "no_objectclass"
        COMPLEX_VALID = "complex_valid"
        PRESERVE_INVALID = "preserve_invalid"

    # Test data: Maps scenario to (DN, attributes, should_have_violations, violation_checks)
    RFC_TEST_DATA: ClassVar[
        dict[str, tuple[str | None, dict[str, list[str]] | None, bool, list[str]]]
    ] = {
        RFCTestCase.VALID_DN: (
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
            False,
            [],
        ),
        RFCTestCase.EMPTY_DN: (
            "",
            {"cn": ["test"]},
            True,
            ["RFC 2849 § 2", "DN"],
        ),
        RFCTestCase.WHITESPACE_DN: (
            "   ",
            {"cn": ["test"]},
            True,
            ["empty or whitespace DN"],
        ),
        RFCTestCase.NONE_DN: (
            None,
            {"cn": ["test"]},
            True,
            ["RFC 2849 § 2", "DN"],
        ),
        RFCTestCase.NO_ATTRS: (
            "cn=test,dc=example,dc=com",
            {},
            True,
            ["at least one attribute"],
        ),
        RFCTestCase.NONE_ATTRS: (
            "cn=test,dc=example,dc=com",
            None,
            True,
            ["at least one attribute"],
        ),
        RFCTestCase.VALID_ATTRS: (
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "mail": ["test@example.com"], "objectClass": ["person"]},
            False,
            [],
        ),
        RFCTestCase.ATTR_LETTER_START: (
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "mail": ["test@example.com"],
                "userPassword": ["secret"],
                "objectClass": ["person"],
            },
            False,
            [],
        ),
        RFCTestCase.ATTR_HYPHEN: (
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "given-name": ["John"],
                "family-name": ["Doe"],
                "objectClass": ["person"],
            },
            False,
            [],
        ),
        RFCTestCase.ATTR_DIGIT: (
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "attr1": ["value1"],
                "test2attr": ["value2"],
                "objectClass": ["person"],
            },
            False,
            [],
        ),
        RFCTestCase.ATTR_DIGIT_START: (
            "cn=test,dc=example,dc=com",
            {"1invalid": ["value"], "cn": ["test"]},
            True,
            ["RFC 4512 § 2.5", "1invalid"],
        ),
        RFCTestCase.ATTR_SPECIAL_CHAR: (
            "cn=test,dc=example,dc=com",
            {"invalid@attr": ["value"], "cn": ["test"]},
            True,
            ["invalid@attr", "RFC 4512 § 2.5"],
        ),
        RFCTestCase.ATTR_SPACE: (
            "cn=test,dc=example,dc=com",
            {"invalid attr": ["value"], "cn": ["test"]},
            True,
            ["invalid attr"],
        ),
        RFCTestCase.MULTIPLE_VIOLATIONS: (
            "",
            {"1invalid": ["value"], "invalid@attr": ["value"]},
            True,
            ["DN", "1invalid", "invalid@attr"],
        ),
        RFCTestCase.ALL_VIOLATIONS: (
            "",
            {},
            True,
            ["DN"],
        ),
        RFCTestCase.NO_OBJECTCLASS: (
            "cn=schema",
            {"cn": ["schema"], "attributeTypes": ["( 1.2.3 NAME 'test' )"]},
            False,
            [],
        ),
        RFCTestCase.COMPLEX_VALID: (
            "uid=john.doe,ou=users,dc=example,dc=com",
            {
                "uid": ["john.doe"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john.doe@example.com"],
                "userPassword": ["{SSHA}hashedpassword"],
                "objectClass": ["inetOrgPerson", "posixAccount"],
            },
            False,
            [],
        ),
        RFCTestCase.PRESERVE_INVALID: (
            "invalid dn",
            {"1invalid": ["value"], "cn": ["test"]},
            True,
            ["RFC 4512 § 2.5", "1invalid"],
        ),
    }

    # Valid and invalid attribute names for parametrized test
    VALID_ATTR_NAMES: ClassVar[list[str]] = [
        "a",
        "A",
        "cn",
        "givenName",
        "user-id",
        "attr1",
        "test-attr-2",
    ]
    INVALID_ATTR_NAMES: ClassVar[list[str]] = [
        "1start",
        "_underscore",
        "has space",
        "has@symbol",
        "-hyphen",
    ]

    # =========================================================================
    # Helper Methods
    # =========================================================================

    @staticmethod
    def get_validation_metadata(
        entry: object,
    ) -> GenericFieldsDict | None:
        """Extract validation_metadata from entry.metadata.validation_results."""
        if not hasattr(entry, "metadata"):
            return None
        metadata = getattr(entry, "metadata", None)
        if not metadata or not hasattr(metadata, "validation_results"):
            return None
        return getattr(metadata, "validation_results", None)

    @staticmethod
    def create_entry_with_handling(
        dn: str | None,
        attributes: dict[str, str | list[str]] | None,
    ) -> FlextLdifModels.Entry:
        """Create entry handling None values specially for edge case testing."""
        if dn is None or attributes is None:
            # Use model_construct for None edge cases
            return FlextLdifModels.Entry.model_construct(
                dn=FlextLdifModels.DistinguishedName.model_construct(value=dn)
                if dn is not None
                else None,
                attributes=FlextLdifModels.LdifAttributes.model_construct(
                    attributes=attributes or {},
                )
                if attributes is not None
                else None,
            )
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes)
        return result.unwrap() if result.is_success else result

    # =========================================================================
    # Parametrized Tests Using Mapping-Driven Approach
    # =========================================================================

    @pytest.mark.parametrize(
        (
            "test_case",
            "dn",
            "attributes",
            "should_have_violations",
            "violation_keywords",
        ),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in RFC_TEST_DATA.items()
        ],
    )
    def test_rfc_compliance_validation(
        self,
        test_case: str,
        dn: str | None,
        attributes: dict[str, str | list[str]] | None,
        should_have_violations: bool,
        violation_keywords: list[str],
    ) -> None:
        """Parametrized test covering all RFC compliance scenarios."""
        # Create entry (handling None values)
        if dn is None or attributes is None:
            entry = self.create_entry_with_handling(dn, attributes)
        else:
            result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes)
            assert result.is_success, f"Entry creation failed for {test_case}"
            entry = cast("FlextLdifModels.Entry", result.unwrap())

        # Get validation metadata
        metadata = self.get_validation_metadata(entry)

        # Check violations exist/don't exist
        has_violations = (
            metadata is not None
            and "rfc_violations" in metadata
            and bool(metadata["rfc_violations"])
        )
        assert has_violations == should_have_violations, (
            f"{test_case}: Expected violations={should_have_violations}, got={has_violations}"
        )

        # If should have violations, verify keywords are present
        if should_have_violations and metadata:
            violations: object = metadata.get("rfc_violations", [])
            if isinstance(violations, list):
                violations_str = " ".join(str(v) for v in violations)
                for keyword in violation_keywords:
                    assert keyword in violations_str, (
                        f"{test_case}: Expected '{keyword}' in violations: {violations}"
                    )

    @pytest.mark.parametrize(
        ("attr_name", "should_be_valid"),
        [(name, True) for name in VALID_ATTR_NAMES]
        + [(name, False) for name in INVALID_ATTR_NAMES],
    )
    def test_attribute_name_validation(
        self,
        attr_name: str,
        should_be_valid: bool,
    ) -> None:
        """Parametrized test for RFC 4512 § 2.5 attribute name validation."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                attr_name: ["value"],
                "objectClass": ["person"],
            },
        )

        assert entry_result.is_success, (
            f"Entry creation failed for attr_name={attr_name}"
        )
        entry = entry_result.unwrap()

        metadata = self.get_validation_metadata(entry)
        violations: object = metadata.get("rfc_violations", []) if metadata else []
        has_violations = (
            metadata is not None
            and "rfc_violations" in metadata
            and isinstance(violations, list)
            and any(attr_name in str(v) for v in violations)
        )

        if should_be_valid:
            assert not has_violations, (
                f"Valid attribute name '{attr_name}' should not have violations"
            )
        else:
            assert has_violations, (
                f"Invalid attribute name '{attr_name}' should have violations"
            )

    def test_validation_metadata_structure(self) -> None:
        """Test that validation context metadata is properly structured."""
        result = FlextLdifModels.Entry.create(dn="", attributes={})
        assert result.is_success
        entry = result.unwrap()

        metadata = self.get_validation_metadata(entry)
        assert metadata is not None
        assert "validation_context" in metadata

        context = metadata.get("validation_context", {})
        assert isinstance(context, dict)
        assert context.get("validator") == "validate_entry_rfc_compliance"
        assert "dn" in context
        assert "attribute_count" in context
        assert "total_violations" in context

    def test_entry_data_preservation_with_violations(self) -> None:
        """Test that invalid entries preserve data while capturing violations."""
        result = FlextLdifModels.Entry.create(
            dn="invalid dn",
            attributes={"1invalid": ["value"], "cn": ["test"]},
        )
        assert result.is_success
        entry = result.unwrap()

        # Data preserved
        assert str(entry.dn) == "invalid dn"
        assert "1invalid" in entry.attributes.attributes
        assert "cn" in entry.attributes.attributes

        # Violations captured
        metadata = self.get_validation_metadata(entry)
        assert metadata is not None
        violations: object = metadata.get("rfc_violations", [])
        assert isinstance(violations, list) and len(violations) > 0
