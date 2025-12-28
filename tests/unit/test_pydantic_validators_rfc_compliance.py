"""Tests for RFC 2849/4512 compliance Pydantic validators.

This module tests Pydantic v2 validators for RFC 2849 (LDIF format) and RFC 4512
(LDAP schema) compliance validation, including entry structure, attribute naming,
DN format validation, and detection of RFC violations in LDIF data.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, TypedDict

import pytest

from flext_ldif.protocols import p
from tests import GenericFieldsDict, OIDs, c, m, s
from tests.helpers.compat import TestAssertions


# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)
# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py
class RfcViolationType(StrEnum):
    """RFC violation types for testing."""

    NO_OBJECTCLASS = "no_objectclass"
    ATTRIBUTE_NAME = "attribute_name"
    DN_FORMAT = "dn_format"


class EntryType(StrEnum):
    """Entry types for testing."""

    NORMAL = "normal"
    SCHEMA = "schema"
    VIOLATION = "violation"


class EntryTestCase(TypedDict):
    """TypedDict for entry test cases."""

    dn: str
    attributes: dict[str, list[str] | str]
    expect_violations: bool


class TestsFlextLdifPydanticValidatorsRfcCompliance(s):
    """Expert tests for Pydantic v2 validators - RFC 2849/4512 compliance.

    Uses advanced Python 3.13 patterns:
    - Single class organization with nested test methods
    - Enum-based configuration mappings for DRY
    - Dynamic parametrized tests for comprehensive coverage
    - Factory patterns for test data creation
    - Generic helpers for validation metadata extraction
    - Reduced code through mappings and enums
    """

    # Test data constants using centralized constants
    TEST_DN: ClassVar[str] = f"uid={c.Values.TEST},{c.DNs.EXAMPLE}"
    SCHEMA_DN: ClassVar[str] = c.DNs.SCHEMA
    INVALID_DN: ClassVar[str] = "invalid-dn-without-equals"

    # RFC compliant attributes mapping using constants
    RFC_COMPLIANT_ATTRS: ClassVar[dict[str, list[str]]] = {
        c.Names.CN: [c.Values.TEST],
        c.Names.SN: [c.Values.USER],
        c.Names.MAIL: ["test@example.com"],
        c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INETORGPERSON],
        "userPassword": ["{SSHA}hash"],
        "employee-number": ["12345"],
        "cn;lang-en": [c.Values.TEST],
    }

    # Server-specific attributes (non-RFC but allowed)
    SERVER_SPECIFIC_ATTRS: ClassVar[dict[str, list[str]]] = {
        "ds-cfg-enabled": ["true"],
        "ds-cfg-java-class": ["org.opends.server.Example"],
        "orclGUID": ["12345678"],
        "orclentrylevelaci": [c.Rfc.ACL_SAMPLE_BROWSE],
    }

    # Numeric OID attributes using constants
    NUMERIC_OID_ATTRS: ClassVar[dict[str, list[str]]] = {
        OIDs.CN: ["CommonName"],
        OIDs.DIRECTORY_STRING: ["DirectoryString"],
        "2.16.840.1.113894.1.1.1": ["orclGUID"],
    }

    # Test cases for entry creation using factories and constants
    ENTRY_TEST_CASES: ClassVar[dict[EntryType, EntryTestCase]] = {
        EntryType.NORMAL: {
            "dn": TEST_DN,
            "attributes": {
                "uid": [c.Values.TEST],
                c.Names.CN: [f"{c.Values.TEST} {c.Values.USER}"],
                c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INETORGPERSON],
            },
            "expect_violations": False,
        },
        EntryType.SCHEMA: {
            "dn": SCHEMA_DN,
            "attributes": {
                c.Names.CN: ["schema"],
                "attributeTypes": [c.RFC.ATTR_DEF_CN],
            },
            "expect_violations": False,
        },
        EntryType.VIOLATION: {
            "dn": TEST_DN,
            "attributes": {
                "uid": [c.Values.TEST],
                c.Names.OBJECTCLASS: [c.Names.PERSON],
                "ds-cfg-enabled": ["true"],
                "orclGUID": ["12345678"],
                "_internal_id": ["999"],
            },
            "expect_violations": True,
        },
    }

    @staticmethod
    def get_validation_metadata(
        entry: p.Entry,
    ) -> m.ValidationMetadata | None:
        """Helper to get validation_metadata from entry.metadata.validation_results."""
        if not entry.metadata or not entry.metadata.validation_results:
            return None
        return entry.metadata.validation_results

    @classmethod
    def create_test_entry(
        cls,
        entry_type: EntryType,
    ) -> p.Entry:
        """Factory method for creating test entries using s."""
        case = cls.ENTRY_TEST_CASES[entry_type]
        return TestAssertions.create_entry(
            dn=case["dn"],
            attributes=case["attributes"],
        )

    @pytest.mark.parametrize(
        ("entry_type", "expect_violations"),
        [
            (EntryType.NORMAL, False),
            (EntryType.SCHEMA, False),
            (EntryType.VIOLATION, True),
        ],
    )
    def test_entry_rfc_validation(
        self,
        entry_type: EntryType,
        expect_violations: bool,
    ) -> None:
        """Parametrized test for Entry RFC 2849/4512 validation using factory patterns."""
        entry = self.create_test_entry(entry_type)
        TestAssertions.assert_entry_valid(entry)

        # Verify DN using constants
        case = self.ENTRY_TEST_CASES[entry_type]
        assert entry.dn is not None
        assert entry.dn.value == case["dn"]

        # Check RFC violations based on expectation
        validation_metadata = self.get_validation_metadata(entry)
        if expect_violations:
            assert validation_metadata is not None
            rfc_violations = validation_metadata.rfc_violations
            assert isinstance(rfc_violations, list)
            assert len(rfc_violations) > 0

            # For violation case, check specific violation content
            if entry_type == EntryType.VIOLATION:
                violation_text = str(rfc_violations[0])
                assert "RFC 4512" in violation_text
                assert "_internal_id" in violation_text
                assert "must start with letter" in violation_text

            # Violations stored in validation_results (not extensions)
            assert entry.metadata is not None
            assert entry.metadata.validation_results is not None
            assert entry.metadata.validation_results.rfc_violations == rfc_violations
        # No violations expected
        elif validation_metadata is not None:
            assert len(validation_metadata.rfc_violations) == 0

        # All attributes preserved regardless of violations
        assert entry.attributes is not None
        for attr_name in case["attributes"]:
            assert attr_name in entry.attributes.attributes

    @pytest.mark.parametrize(
        ("attr_dict", "description"),
        [
            ("RFC_COMPLIANT_ATTRS", "RFC compliant attributes"),
            ("SERVER_SPECIFIC_ATTRS", "Server-specific attributes"),
            ("NUMERIC_OID_ATTRS", "Numeric OID attributes"),
        ],
    )
    def test_ldif_attributes_rfc_compliance(
        self,
        attr_dict: str,
        description: str,
    ) -> None:
        """Test Attributes RFC 4512 § 2.5 compliance using parametrized approach."""
        attrs_dict = getattr(self, attr_dict)
        ldif_attrs = m.Ldif.Attributes(attributes=attrs_dict)
        for attr_name in attrs_dict:
            assert attr_name in ldif_attrs.attributes, (
                f"{description}: {attr_name} not found in attributes"
            )

    def test_ldif_attributes_combined_compliance(self) -> None:
        """Test Attributes with combined RFC and server-specific attributes."""
        combined_attrs = {**self.RFC_COMPLIANT_ATTRS, **self.SERVER_SPECIFIC_ATTRS}
        server_ldif_attrs = m.Ldif.Attributes(attributes=combined_attrs)
        for attr_name in combined_attrs:
            assert attr_name in server_ldif_attrs.attributes

    @pytest.mark.parametrize(
        ("dn_value", "expected_components"),
        [
            (f"uid={c.Values.TEST},ou=users,{c.DNs.EXAMPLE}", 4),
            (
                f"uid={c.Values.TEST}, ou=users, {c.DNs.EXAMPLE}",
                4,
            ),  # Spaces after comma
        ],
    )
    def test_distinguished_name_rfc_compliance(
        self,
        dn_value: str,
        expected_components: int,
    ) -> None:
        """Parametrized test for DN RFC 4514 compliance."""
        dn = m.Ldif.DN(value=dn_value)

        assert dn.value == dn_value
        components = dn.components
        assert isinstance(components, list)
        assert len(components) == expected_components

    def test_dn_invalid_format_preserved(self) -> None:
        """Validate invalid DN format is preserved for server quirks."""
        dn = m.Ldif.DN(value=self.INVALID_DN)
        assert dn.value == self.INVALID_DN

    def test_dn_metadata_preservation(self) -> None:
        """Validate DN metadata preservation for server conversions."""
        test_metadata = {
            "original_case": "UID=Test,DC=Example,DC=Com",
            "had_spaces": True,
        }
        dn = m.Ldif.DN(
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

        metadata = m.Ldif.QuirkMetadata(
            quirk_type="rfc",
            extensions=test_extensions,
        )

        # Verify extensions contain violations using mapping
        assert metadata.extensions == test_extensions
        violation_keys = ("rfc_violations", "attribute_name_violations")
        for key in violation_keys:
            assert key in metadata.extensions
            violations_obj = metadata.extensions[key]
            assert isinstance(violations_obj, list)
            violations = list(violations_obj)
            assert len(violations) == 2

        # Verify specific content
        rfc_viol_obj = metadata.extensions["rfc_violations"]
        assert isinstance(rfc_viol_obj, list)
        rfc_viol = list(rfc_viol_obj)
        assert "RFC 4512" in str(rfc_viol[0])

    def test_rfc_violations_consistency_in_entry(self) -> None:
        """Validate RFC violations consistency in validation_results."""
        entry = self.create_test_entry(EntryType.VIOLATION)

        # Get violations from validation_results
        validation_metadata = self.get_validation_metadata(entry)
        assert validation_metadata is not None
        assert len(validation_metadata.rfc_violations) > 0

        # Verify validation_results is accessible via metadata
        assert entry.metadata is not None
        assert entry.metadata.validation_results is not None

        # Verify consistency - both point to same data
        assert (
            validation_metadata.rfc_violations
            == entry.metadata.validation_results.rfc_violations
        )


# All tests are now within TestPydanticValidatorsRfcCompliance class
