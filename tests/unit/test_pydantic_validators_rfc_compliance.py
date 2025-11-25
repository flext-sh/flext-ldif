"""Expert tests for Pydantic v2 validators - RFC 2849/4512 compliance.

Tests validate that Entry, LdifAttributes, and DistinguishedName models:
1. Capture RFC violations in metadata (not reject entries)
2. Use field_validator and model_validator correctly (Pydantic v2)
3. Preserve non-compliant data for server conversions
4. Follow lenient processing pattern (log violations, don't fail)

Modules tested:
- flext_ldif.models.FlextLdifModels.Entry (RFC 4512 compliance)
- flext_ldif.models.FlextLdifModels.LdifAttributes (RFC 4512 § 2.5)
- flext_ldif.models.FlextLdifModels.DistinguishedName (RFC 4514)
- flext_ldif.models.FlextLdifModels.QuirkMetadata (violation tracking)

Scope:
- RFC violation capture without rejection (lenient processing)
- Metadata preservation for server conversions
- Pydantic v2 validators (field_validator, model_validator)
- Attribute name validation (RFC 4512 § 2.5)
- DN format validation (RFC 4514)
- Extension data preservation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, TypedDict, cast

import pytest
from flext_core import FlextResult

from flext_ldif import FlextLdifModels


class RfcViolationType(StrEnum):
    """RFC violation types for testing."""

    NO_OBJECTCLASS = "no_objectclass"
    ATTRIBUTE_NAME = "attribute_name"
    DN_FORMAT = "dn_format"


class TestEntryType(StrEnum):
    """Entry types for testing."""

    NORMAL = "normal"
    SCHEMA = "schema"
    VIOLATION = "violation"


class EntryTestCase(TypedDict):
    """TypedDict for entry test cases."""

    dn: str
    attributes: dict[str, list[str] | str]
    expect_violations: bool


class TestPydanticValidatorsRfcCompliance:
    """Expert tests for Pydantic v2 validators - RFC 2849/4512 compliance.

    Uses advanced Python 3.13 patterns:
    - Single class organization with nested test methods
    - Enum-based configuration mappings for DRY
    - Dynamic parametrized tests for comprehensive coverage
    - Factory patterns for test data creation
    - Generic helpers for validation metadata extraction
    - Reduced code through mappings and enums
    """

    # Test data constants for DRY
    TEST_DN: ClassVar[str] = "uid=test,dc=example,dc=com"
    SCHEMA_DN: ClassVar[str] = "cn=schema"
    INVALID_DN: ClassVar[str] = "invalid-dn-without-equals"

    # RFC compliant attributes mapping
    RFC_COMPLIANT_ATTRS: ClassVar[dict[str, list[str]]] = {
        "cn": ["Test"],
        "sn": ["User"],
        "mail": ["test@example.com"],
        "objectClass": ["person", "inetOrgPerson"],
        "userPassword": ["{SSHA}hash"],
        "employee-number": ["12345"],
        "cn;lang-en": ["Test"],
    }

    # Server-specific attributes (non-RFC but allowed)
    SERVER_SPECIFIC_ATTRS: ClassVar[dict[str, list[str]]] = {
        "ds-cfg-enabled": ["true"],
        "ds-cfg-java-class": ["org.opends.server.Example"],
        "orclGUID": ["12345678"],
        "orclentrylevelaci": ["access to entry by * (browse)"],
    }

    # Numeric OID attributes
    NUMERIC_OID_ATTRS: ClassVar[dict[str, list[str]]] = {
        "2.5.4.3": ["CommonName"],
        "1.3.6.1.4.1.1466.115.121.1.15": ["DirectoryString"],
        "2.16.840.1.113894.1.1.1": ["orclGUID"],
    }

    # Test cases for entry creation
    ENTRY_TEST_CASES: ClassVar[dict[TestEntryType, EntryTestCase]] = {
        TestEntryType.NORMAL: {
            "dn": TEST_DN,
            "attributes": {
                "uid": ["test"],
                "cn": ["Test User"],
                "objectClass": ["person", "inetOrgPerson"],
            },
            "expect_violations": False,
        },
        TestEntryType.SCHEMA: {
            "dn": SCHEMA_DN,
            "attributes": {
                "cn": ["schema"],
                "attributeTypes": [
                    "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                ],
            },
            "expect_violations": False,
        },
        TestEntryType.VIOLATION: {
            "dn": TEST_DN,
            "attributes": {
                "uid": ["test"],
                "objectClass": ["person"],
                "ds-cfg-enabled": ["true"],
                "orclGUID": ["12345678"],
                "_internal_id": ["999"],
            },
            "expect_violations": True,
        },
    }

    @staticmethod
    def get_validation_metadata(
        entry: FlextLdifModels.Entry,
    ) -> dict[str, object] | None:
        """Helper to get validation_metadata from entry.metadata.validation_results."""
        if not entry.metadata or not entry.metadata.validation_results:
            return None
        return entry.metadata.validation_results

    @classmethod
    def create_test_entry(
        cls,
        entry_type: TestEntryType,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Factory method for creating test entries."""
        case = cls.ENTRY_TEST_CASES[entry_type]
        return cast(
            "FlextResult[FlextLdifModels.Entry]",
            FlextLdifModels.Entry.create(
                dn=case["dn"],
                attributes=case["attributes"],
            ),
        )

    @pytest.mark.parametrize(
        ("entry_type", "expect_violations"),
        [
            (TestEntryType.NORMAL, False),
            (TestEntryType.SCHEMA, False),
            (TestEntryType.VIOLATION, True),
        ],
    )
    def test_entry_rfc_validation(
        self,
        entry_type: TestEntryType,
        expect_violations: bool,
    ) -> None:
        """Parametrized test for Entry RFC 2849/4512 validation using factory patterns."""
        entry_result = self.create_test_entry(entry_type)
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Verify DN
        case = self.ENTRY_TEST_CASES[entry_type]
        assert entry.dn is not None
        assert entry.dn.value == case["dn"]

        # Check RFC violations based on expectation
        validation_metadata = self.get_validation_metadata(entry)
        if expect_violations:
            assert validation_metadata is not None
            assert "rfc_violations" in validation_metadata
            rfc_violations = validation_metadata["rfc_violations"]
            assert isinstance(rfc_violations, list)
            assert len(rfc_violations) > 0

            # For violation case, check specific violation content
            if entry_type == TestEntryType.VIOLATION:
                violation_text = str(rfc_violations[0])
                assert "RFC 4512" in violation_text
                assert "_internal_id" in violation_text
                assert "must start with letter" in violation_text

            # Violations also in metadata.extensions
            assert entry.metadata is not None
            assert "rfc_violations" in entry.metadata.extensions
            assert entry.metadata.extensions["rfc_violations"] == rfc_violations
        # No violations expected
        elif validation_metadata is not None:
            assert "rfc_violations" not in validation_metadata

        # All attributes preserved regardless of violations
        assert entry.attributes is not None
        for attr_name in case["attributes"]:
            assert attr_name in entry.attributes.attributes

    def test_ldif_attributes_rfc_compliance(self) -> None:
        """Test LdifAttributes RFC 4512 § 2.5 compliance using mapping-driven approach."""
        # Test RFC compliant attributes
        rfc_attrs = FlextLdifModels.LdifAttributes(attributes=self.RFC_COMPLIANT_ATTRS)
        for attr_name in self.RFC_COMPLIANT_ATTRS:
            assert attr_name in rfc_attrs.attributes

        # Test server-specific attributes (logged but allowed)
        server_attrs = {**self.RFC_COMPLIANT_ATTRS, **self.SERVER_SPECIFIC_ATTRS}
        server_ldif_attrs = FlextLdifModels.LdifAttributes(attributes=server_attrs)
        for attr_name in server_attrs:
            assert attr_name in server_ldif_attrs.attributes

        # Test numeric OID attributes (allowed for future enhancement)
        oid_attrs = FlextLdifModels.LdifAttributes(attributes=self.NUMERIC_OID_ATTRS)
        for attr_name in self.NUMERIC_OID_ATTRS:
            assert attr_name in oid_attrs.attributes

    @pytest.mark.parametrize(
        ("dn_value", "expected_components"),
        [
            ("uid=test,ou=users,dc=example,dc=com", 4),
            ("uid=test, ou=users, dc=example, dc=com", 4),  # Spaces after comma
        ],
    )
    def test_distinguished_name_rfc_compliance(
        self,
        dn_value: str,
        expected_components: int,
    ) -> None:
        """Parametrized test for DistinguishedName RFC 4514 compliance."""
        dn = FlextLdifModels.DistinguishedName(value=dn_value)

        assert dn.value == dn_value
        components = dn.components
        assert isinstance(components, list)
        assert len(components) == expected_components

    def test_dn_invalid_format_preserved(self) -> None:
        """Validate invalid DN format is preserved for server quirks."""
        dn = FlextLdifModels.DistinguishedName(value=self.INVALID_DN)
        assert dn.value == self.INVALID_DN

    def test_dn_metadata_preservation(self) -> None:
        """Validate DN metadata preservation for server conversions."""
        test_metadata = {
            "original_case": "UID=Test,DC=Example,DC=Com",
            "had_spaces": True,
        }
        dn = FlextLdifModels.DistinguishedName(
            value=self.TEST_DN,
            metadata=test_metadata,
        )

        assert dn.value == self.TEST_DN
        assert dn.metadata is not None
        assert dn.metadata["original_case"] == test_metadata["original_case"]
        assert dn.metadata["had_spaces"] == test_metadata["had_spaces"]

    def test_quirk_metadata_rfc_violations(self) -> None:
        """Validate QuirkMetadata RFC violation tracking using mapping-driven approach."""
        rfc_violations_list: list[str] = [
            "RFC 4512 § 2.4.1: Entry should have objectClass",
            "RFC 2849 § 2: Line length exceeds 76 characters",
        ]
        attr_violations_list: list[str] = [
            "ds-cfg-enabled",
            "_internal_id",
        ]
        test_extensions: dict[str, object] = {
            "rfc_violations": rfc_violations_list,
            "attribute_name_violations": attr_violations_list,
        }

        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="rfc",
            extensions=test_extensions,
        )

        # Verify extensions contain violations
        assert metadata.extensions == test_extensions
        assert "rfc_violations" in metadata.extensions
        assert "attribute_name_violations" in metadata.extensions

        # Verify counts and content
        rfc_viol = metadata.extensions["rfc_violations"]
        attr_viol = metadata.extensions["attribute_name_violations"]
        assert isinstance(rfc_viol, list)
        assert isinstance(attr_viol, list)
        assert len(rfc_viol) == 2
        assert len(attr_viol) == 2
        assert "RFC 4512" in str(rfc_viol[0])

    def test_rfc_violations_consistency_in_entry(self) -> None:
        """Validate RFC violations consistency between validation_metadata and extensions."""
        entry_result = self.create_test_entry(TestEntryType.VIOLATION)
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Get violations from both locations
        validation_metadata = self.get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata

        assert entry.metadata is not None
        assert "rfc_violations" in entry.metadata.extensions

        # Verify they are identical
        assert (
            validation_metadata["rfc_violations"]
            == entry.metadata.extensions["rfc_violations"]
        )


# All tests are now within TestPydanticValidatorsRfcCompliance class
