"""Expert tests for Pydantic v2 validators - RFC 2849/4512 compliance.

Tests validate that Entry, LdifAttributes, and DistinguishedName models:
1. Capture RFC violations in metadata (not reject entries)
2. Use field_validator and model_validator correctly (Pydantic v2)
3. Preserve non-compliant data for server conversions
4. Follow lenient processing pattern (log violations, don't fail)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest

from flext_ldif.models import FlextLdifModels


class TestEntryRfcValidation:
    """Entry model RFC 2849/4512 validation tests."""

    def test_entry_without_objectclass_captures_rfc_violation(self) -> None:
        """Validate Entry WITHOUT objectClass captures RFC 4512 § 2.4.1 violation.

        RFC 4512 § 2.4.1: Entry SHOULD have objectClass attribute.
        Violation is captured in validation_metadata['rfc_violations'], not rejected.
        """
        # Create entry without objectClass (RFC violation)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="uid=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "uid": ["test"],
                    "cn": ["Test User"],
                    # NO objectClass - RFC 4512 § 2.4.1 violation
                }
            ),
        )

        # Entry creation SUCCEEDS (lenient processing)
        assert entry.dn.value == "uid=test,dc=example,dc=com"

        # RFC violation CAPTURED in validation_metadata
        assert entry.validation_metadata is not None
        assert "rfc_violations" in entry.validation_metadata
        rfc_violations = entry.validation_metadata["rfc_violations"]
        assert isinstance(rfc_violations, list)
        assert len(rfc_violations) > 0

        # Violation message references RFC 4512 § 2.4.1
        violation_text = rfc_violations[0]
        assert "RFC 4512" in violation_text
        assert "objectClass" in violation_text
        assert "uid=test,dc=example,dc=com" in violation_text

        # Violation ALSO in metadata.extensions for server conversions
        assert entry.metadata is not None
        assert "rfc_violations" in entry.metadata.extensions
        assert entry.metadata.extensions["rfc_violations"] == rfc_violations

    def test_entry_with_objectclass_no_rfc_violation(self) -> None:
        """Validate Entry WITH objectClass has NO RFC violations."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="uid=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "uid": ["test"],
                    "cn": ["Test User"],
                    "objectClass": ["person", "inetOrgPerson"],  # RFC compliant
                }
            ),
        )

        # Entry creation succeeds
        assert entry.dn.value == "uid=test,dc=example,dc=com"

        # NO RFC violations
        if entry.validation_metadata:
            assert "rfc_violations" not in entry.validation_metadata

    def test_schema_entry_exempt_from_objectclass_requirement(self) -> None:
        """Validate schema entry (cn=schema) is exempt from objectClass requirement.

        Schema entries are special - they contain schema definitions, not directory objects.
        RFC 4512 allows schema entries without objectClass.
        """
        # Create schema entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=schema"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["schema"],
                    "attributeTypes": [
                        "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                    ],
                    # NO objectClass - but schema entry is exempt
                }
            ),
        )

        # Entry creation succeeds
        assert entry.dn.value == "cn=schema"

        # NO RFC violations (schema entry exempt)
        if entry.validation_metadata:
            assert "rfc_violations" not in entry.validation_metadata

    def test_entry_preserves_all_attributes_despite_violations(self) -> None:
        """Validate Entry preserves all attributes even with RFC violations.

        Critical for server conversions: non-compliant data MUST be preserved
        in metadata for round-trip OID→OUD→OID conversions.
        """
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="uid=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "uid": ["test"],
                    "ds-cfg-enabled": ["true"],  # OUD-specific (non-RFC)
                    "orclGUID": ["12345678"],  # OID-specific (non-RFC)
                    "_internal_id": ["999"],  # Non-RFC attribute name
                    # NO objectClass
                }
            ),
        )

        # All attributes preserved
        assert "uid" in entry.attributes.attributes
        assert "ds-cfg-enabled" in entry.attributes.attributes
        assert "orclGUID" in entry.attributes.attributes
        assert "_internal_id" in entry.attributes.attributes

        # RFC violation captured
        assert entry.validation_metadata is not None
        assert "rfc_violations" in entry.validation_metadata


class TestLdifAttributesRfcValidation:
    """LdifAttributes RFC 4512 § 2.5 attribute name validation tests."""

    def test_rfc_compliant_attribute_names_pass_validation(self) -> None:
        """Validate RFC 4512 § 2.5 compliant attribute names pass."""
        # RFC 4512 § 2.5: attributetype = letter followed by letter/digit/hyphen
        attributes = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["Test"],
                "sn": ["User"],
                "mail": ["test@example.com"],
                "objectClass": ["person", "inetOrgPerson"],
                "userPassword": ["{SSHA}hash"],
                "employee-number": ["12345"],  # Hyphen allowed
                "cn;lang-en": ["Test"],  # Options allowed (RFC 4512 § 2.5)
            }
        )

        # All RFC-compliant names accepted
        assert "cn" in attributes.attributes
        assert "employee-number" in attributes.attributes
        assert "cn;lang-en" in attributes.attributes

    def test_server_specific_attribute_names_logged_but_allowed(self) -> None:
        """Validate server-specific attributes (ds-cfg-*, orcl*) are logged but allowed.

        These are non-RFC-compliant but required for OUD, OID server-specific functionality.
        Validation logs warning but allows attributes for lenient processing.
        """
        # Server-specific attributes (non-RFC but valid for specific servers)
        attributes = FlextLdifModels.LdifAttributes(
            attributes={
                "ds-cfg-enabled": ["true"],  # OUD-specific
                "ds-cfg-java-class": ["org.opends.server.Example"],  # OUD-specific
                "orclGUID": ["12345678"],  # OID-specific
                "orclentrylevelaci": ["access to entry by * (browse)"],  # OID-specific
                "cn": ["Test"],  # RFC-compliant
            }
        )

        # All attributes accepted (lenient processing)
        assert "ds-cfg-enabled" in attributes.attributes
        assert "orclGUID" in attributes.attributes
        assert "orclentrylevelaci" in attributes.attributes

        # Note: Non-compliant names are logged via logger.debug
        # (Validation doesn't reject, only logs for tracking)

    def test_numeric_oid_attribute_names_allowed(self) -> None:
        """Validate numeric OID attribute names are allowed (RFC 4512 § 2.5).

        RFC 4512 § 2.5: attributetype = numericoid | descr
        NumericOID format: digit (dot digit)+
        """
        attributes = FlextLdifModels.LdifAttributes(
            attributes={
                "2.5.4.3": ["CommonName"],  # cn OID
                "1.3.6.1.4.1.1466.115.121.1.15": ["DirectoryString"],  # SYNTAX OID
                "2.16.840.1.113894.1.1.1": ["orclGUID"],  # Oracle OID
            }
        )

        # Numeric OIDs accepted
        # Note: Current pattern starts with letter, so these would be logged
        # This documents expected behavior for future enhancement
        assert "2.5.4.3" in attributes.attributes


class TestDistinguishedNameRfcValidation:
    """DistinguishedName RFC 4514 validation tests."""

    def test_rfc4514_compliant_dn_passes_validation(self) -> None:
        """Validate RFC 4514 compliant DN passes field_validator."""
        dn = FlextLdifModels.DistinguishedName(
            value="uid=test,ou=users,dc=example,dc=com"
        )

        assert dn.value == "uid=test,ou=users,dc=example,dc=com"
        assert len(dn.components) == 4

    def test_dn_with_spaces_after_comma_passes(self) -> None:
        """Validate DN with spaces after comma passes (RFC 4514 allows).

        RFC 4514 allows spaces after comma in DN components.
        """
        dn = FlextLdifModels.DistinguishedName(
            value="uid=test, ou=users, dc=example, dc=com"
        )

        assert dn.value == "uid=test, ou=users, dc=example, dc=com"
        assert len(dn.components) == 4

    def test_dn_invalid_format_raises_validation_error(self) -> None:
        """Validate invalid DN format raises ValidationError from field_validator."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            FlextLdifModels.DistinguishedName(value="invalid-dn-without-equals")

    def test_dn_metadata_preserved_for_server_conversions(self) -> None:
        """Validate DN metadata is preserved for server conversions."""
        dn = FlextLdifModels.DistinguishedName(
            value="uid=test,dc=example,dc=com",
            metadata={
                "original_case": "UID=Test,DC=Example,DC=Com",  # OID format
                "had_spaces": True,  # Original had spaces after commas
            },
        )

        assert dn.value == "uid=test,dc=example,dc=com"
        assert dn.metadata is not None
        assert dn.metadata["original_case"] == "UID=Test,DC=Example,DC=Com"
        assert dn.metadata["had_spaces"] is True


class TestQuirkMetadataRfcViolations:
    """QuirkMetadata RFC violation tracking tests."""

    def test_quirk_metadata_rfc_violations_field_exists(self) -> None:
        """Validate QuirkMetadata has rfc_violations field."""
        metadata = FlextLdifModels.QuirkMetadata(
            rfc_violations=[
                "RFC 4512 § 2.4.1: Entry should have objectClass",
                "RFC 2849 § 2: Line length exceeds 76 characters",
            ],
            attribute_name_violations=[
                "ds-cfg-enabled",
                "_internal_id",
            ],
        )

        assert len(metadata.rfc_violations) == 2
        assert len(metadata.attribute_name_violations) == 2
        assert "RFC 4512" in metadata.rfc_violations[0]
        assert "ds-cfg-enabled" in metadata.attribute_name_violations

    def test_rfc_violations_preserved_in_entry_metadata(self) -> None:
        """Validate RFC violations are preserved in Entry.metadata for conversions."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="uid=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "uid": ["test"],
                    # NO objectClass - RFC violation
                }
            ),
        )

        # RFC violations captured in both locations
        assert entry.validation_metadata is not None
        assert "rfc_violations" in entry.validation_metadata

        assert entry.metadata is not None
        assert "rfc_violations" in entry.metadata.extensions

        # Both should have same violations
        assert (
            entry.validation_metadata["rfc_violations"]
            == entry.metadata.extensions["rfc_violations"]
        )


__all__ = [
    "TestDistinguishedNameRfcValidation",
    "TestEntryRfcValidation",
    "TestLdifAttributesRfcValidation",
    "TestQuirkMetadataRfcViolations",
]
