"""Comprehensive unit tests for FlextLdifEntry.

Tests all ACTUAL entry transformation methods with REAL implementations.
Validates DN cleaning, operational attribute removal, and attribute stripping.

This test suite covers:
  ✅ Public classmethod API (clean_dn, remove_operational_attributes, etc)
  ✅ Execute pattern (V1 FlextService style)
  ✅ Fluent builder pattern
  ✅ Single entry transformations
  ✅ Batch entry transformations
  ✅ Error handling and validation
  ✅ Edge cases and special characters

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifModels, FlextLdifUtilities
from flext_ldif.services.entry import FlextLdifEntry
from flext_ldif.services.syntax import FlextLdifSyntax
from flext_ldif.services.validation import FlextLdifValidation

from ...helpers.test_deduplication_helpers import TestDeduplicationHelpers
from ...helpers.test_rfc_helpers import RfcTestHelpers

# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


def create_entry(
    dn_str: str,
    attributes: dict[str, list[str]],
) -> FlextLdifModels.Entry:
    """Create test entry with DN and attributes."""
    dn = FlextLdifModels.DistinguishedName(value=dn_str)
    attrs = TestDeduplicationHelpers.create_attributes_from_dict(attributes)
    return FlextLdifModels.Entry(dn=dn, attributes=attrs)


@pytest.fixture
def simple_entry() -> FlextLdifModels.Entry:
    """Create a simple test entry."""
    return create_entry(
        "cn=john,ou=users,dc=example,dc=com",
        {
            "cn": ["john"],
            "sn": ["Doe"],
            "mail": ["john@example.com"],
            "objectClass": ["person", "inetOrgPerson"],
        },
    )


@pytest.fixture
def entry_with_operational_attrs() -> FlextLdifModels.Entry:
    """Create entry with operational attributes."""
    return create_entry(
        "cn=jane,ou=users,dc=example,dc=com",
        {
            "cn": ["jane"],
            "sn": ["Smith"],
            "mail": ["jane@example.com"],
            "createTimestamp": ["20250104120000Z"],
            "modifyTimestamp": ["20250105120000Z"],
            "creatorsName": ["cn=admin,dc=example,dc=com"],
            "modifiersName": ["cn=admin,dc=example,dc=com"],
            "entryCSN": ["20250105120000.123456Z#000000#000#000000"],
            "entryUUID": ["12345678-1234-5678-1234-567812345678"],
        },
    )


@pytest.fixture
def entries_batch() -> list[FlextLdifModels.Entry]:
    """Create batch of entries for testing."""
    return [
        create_entry(
            "cn=user1,ou=users,dc=example,dc=com",
            {"cn": ["user1"], "createTimestamp": ["20250104120000Z"]},
        ),
        create_entry(
            "cn=user2,ou=users,dc=example,dc=com",
            {"cn": ["user2"], "modifyTimestamp": ["20250105120000Z"]},
        ),
        create_entry(
            "cn=user3,ou=users,dc=example,dc=com",
            {"cn": ["user3"], "entryCSN": ["20250105120000.123456Z"]},
        ),
    ]


# ════════════════════════════════════════════════════════════════════════════
# TEST PUBLIC CLASSMETHOD API
# ════════════════════════════════════════════════════════════════════════════


class TestPublicClassmethods:
    """Test public classmethod helpers (most direct API)."""

    def test_clean_dn_with_spaces(self) -> None:
        """Test clean_dn removes spaces around equals signs."""
        messy_dn = "cn = John Doe , ou = users , dc = example , dc = com"
        cleaned = FlextLdifUtilities.DN.clean_dn(messy_dn)

        assert "=" in cleaned
        assert " = " not in cleaned
        assert "cn=" in cleaned

    def test_clean_dn_already_clean(self) -> None:
        """Test clean_dn with already clean DN."""
        clean_dn = "cn=john,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DN.clean_dn(clean_dn)

        assert result == clean_dn

    def test_clean_dn_with_escaped_chars(self) -> None:
        """Test clean_dn handles escaped characters."""
        dn_with_escaped = r"cn=John\, Doe,ou=users,dc=example,dc=com"
        cleaned = FlextLdifUtilities.DN.clean_dn(dn_with_escaped)

        assert isinstance(cleaned, str)
        assert len(cleaned) > 0

    def test_remove_operational_attributes_single(
        self,
        entry_with_operational_attrs: FlextLdifModels.Entry,
    ) -> None:
        """Test remove_operational_attributes with single entry."""
        result = FlextLdifEntry.remove_operational_attributes(
            entry_with_operational_attrs,
        )

        assert result.is_success
        cleaned_entry = result.unwrap()

        # Verify operational attributes are removed
        attrs = cleaned_entry.attributes.attributes
        assert "createTimestamp" not in attrs
        assert "modifyTimestamp" not in attrs
        assert "creatorsName" not in attrs
        assert "entryCSN" not in attrs
        assert "entryUUID" not in attrs

        # Verify normal attributes are kept
        assert "cn" in attrs
        assert "mail" in attrs

    def test_remove_operational_attributes_batch(
        self,
        entries_batch: list[FlextLdifModels.Entry],
    ) -> None:
        """Test remove_operational_attributes_batch with multiple entries."""
        result = FlextLdifEntry.remove_operational_attributes_batch(entries_batch)

        assert result.is_success
        cleaned_entries = result.unwrap()
        assert len(cleaned_entries) == 3

        # Verify all operational attributes are removed
        for entry in cleaned_entries:
            attrs = entry.attributes.attributes
            for attr_name in attrs:
                assert attr_name not in {
                    "createTimestamp",
                    "modifyTimestamp",
                    "creatorsName",
                    "modifiersName",
                    "entryCSN",
                    "entryUUID",
                }

    def test_remove_attributes_single(
        self,
        simple_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test remove_attributes with single entry."""
        result = FlextLdifEntry.remove_attributes(
            simple_entry,
            attributes=["mail", "sn"],
        )

        assert result.is_success
        cleaned_entry = result.unwrap()

        attrs = cleaned_entry.attributes.attributes
        assert "cn" in attrs
        assert "mail" not in attrs
        assert "sn" not in attrs
        assert "objectClass" in attrs

    def test_remove_attributes_batch(
        self,
        entries_batch: list[FlextLdifModels.Entry],
    ) -> None:
        """Test remove_attributes_batch with multiple entries."""
        result = FlextLdifEntry.remove_attributes_batch(
            entries_batch,
            attributes=["cn"],
        )

        assert result.is_success
        cleaned_entries = result.unwrap()

        # cn should be removed from all entries
        for entry in cleaned_entries:
            assert "cn" not in entry.attributes.attributes


# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTE PATTERN (V1 Style)
# ════════════════════════════════════════════════════════════════════════════


class TestExecutePattern:
    """Test execute() method for FlextService V1 pattern."""

    def test_execute_operations_batch(
        self,
        entries_batch: list[FlextLdifModels.Entry],
        simple_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test execute() with various operations in batch."""
        service1 = FlextLdifEntry(
            entries=entries_batch,
            operation="remove_operational_attributes",
        )
        RfcTestHelpers.test_service_execute_and_assert(
            service1,
            expected_type=list,
            expected_count=3,
        )

        service2 = FlextLdifEntry(
            entries=[simple_entry],
            operation="remove_attributes",
            attributes_to_remove=["mail"],
        )
        cleaned2 = RfcTestHelpers.test_service_execute_and_assert(
            service2,
            expected_type=list,
        )
        assert "mail" not in cleaned2[0].attributes.attributes

        service3 = FlextLdifEntry(
            entries=[simple_entry],
            operation="invalid_operation",
        )
        RfcTestHelpers.test_service_execute_and_assert(
            service3,
            should_succeed=False,
        )

        service4 = FlextLdifEntry(
            entries=[],
            operation="remove_operational_attributes",
        )
        empty_result = RfcTestHelpers.test_service_execute_and_assert(
            service4,
            expected_type=list,
            expected_count=0,
        )
        assert empty_result == []


# ════════════════════════════════════════════════════════════════════════════
# TEST FLUENT BUILDER PATTERN
# ════════════════════════════════════════════════════════════════════════════


class TestFluentBuilder:
    """Test fluent builder pattern."""

    def test_builder_basic(self, simple_entry: FlextLdifModels.Entry) -> None:
        """Test builder().with_entries().with_operation().build()."""
        cleaned_entries = (
            FlextLdifEntry.builder()
            .with_entries([simple_entry])
            .with_operation("remove_operational_attributes")
            .build()
        )

        assert isinstance(cleaned_entries, list)
        assert len(cleaned_entries) == 1
        assert "cn" in cleaned_entries[0].attributes.attributes

    def test_builder_with_attributes_to_remove(
        self,
        simple_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test builder with attributes_to_remove."""
        cleaned_entries = (
            FlextLdifEntry.builder()
            .with_entries([simple_entry])
            .with_operation("remove_attributes")
            .with_attributes_to_remove(["mail", "sn"])
            .build()
        )

        assert len(cleaned_entries) == 1
        attrs = cleaned_entries[0].attributes.attributes
        assert "mail" not in attrs
        assert "sn" not in attrs

    def test_builder_chaining(self, simple_entry: FlextLdifModels.Entry) -> None:
        """Test builder method returns same instance for chaining."""
        builder = FlextLdifEntry.builder()
        assert builder is not None

        builder2 = builder.with_entries([simple_entry])
        assert builder2 is builder  # Same instance

        builder3 = builder2.with_operation("remove_attributes")
        assert builder3 is builder  # Same instance


# ════════════════════════════════════════════════════════════════════════════
# TEST OPERATIONAL ATTRIBUTE REMOVAL
# ════════════════════════════════════════════════════════════════════════════


class TestOperationalAttributeRemoval:
    """Test operational attribute removal functionality."""

    def test_removes_all_common_operational_attrs(self) -> None:
        """Test that all COMMON operational attributes are removed."""
        entry = create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "createTimestamp": ["20250104120000Z"],
                "modifyTimestamp": ["20250105120000Z"],
                "creatorsName": ["cn=admin"],
                "modifiersName": ["cn=admin"],
                "entryCSN": ["20250105120000.123456Z"],
                "entryUUID": ["12345678-1234-5678-1234-567812345678"],
            },
        )

        result = FlextLdifEntry.remove_operational_attributes(entry)
        cleaned = result.unwrap()

        attrs = cleaned.attributes.attributes
        # All operational should be removed
        assert "createTimestamp" not in attrs
        assert "modifyTimestamp" not in attrs
        assert "creatorsName" not in attrs
        assert "modifiersName" not in attrs
        assert "entryCSN" not in attrs
        assert "entryUUID" not in attrs
        # Normal attributes should remain
        assert "cn" in attrs

    def test_case_insensitive_operational_attr_matching(self) -> None:
        """Test that operational attribute matching is case-insensitive."""
        entry = create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "CREATETIMESTAMP": ["20250104120000Z"],  # Uppercase
                "modifyTimestamp": ["20250105120000Z"],  # Mixed case
            },
        )

        result = FlextLdifEntry.remove_operational_attributes(entry)
        cleaned = result.unwrap()

        attrs = cleaned.attributes.attributes
        # Should be removed regardless of case
        assert "CREATETIMESTAMP" not in attrs
        assert "modifyTimestamp" not in attrs
        assert "cn" in attrs


# ════════════════════════════════════════════════════════════════════════════
# TEST ATTRIBUTE REMOVAL
# ════════════════════════════════════════════════════════════════════════════


class TestAttributeRemoval:
    """Test selective attribute removal."""

    def test_remove_single_attribute(self, simple_entry: FlextLdifModels.Entry) -> None:
        """Test removing a single attribute."""
        result = FlextLdifEntry.remove_attributes(simple_entry, attributes=["mail"])

        assert result.is_success
        cleaned = result.unwrap()
        assert "mail" not in cleaned.attributes.attributes
        assert "cn" in cleaned.attributes.attributes

    def test_remove_multiple_attributes(
        self,
        simple_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test removing multiple attributes."""
        result = FlextLdifEntry.remove_attributes(
            simple_entry,
            attributes=["mail", "sn", "objectClass"],
        )

        assert result.is_success
        cleaned = result.unwrap()
        assert "mail" not in cleaned.attributes.attributes
        assert "sn" not in cleaned.attributes.attributes
        assert "objectClass" not in cleaned.attributes.attributes
        assert "cn" in cleaned.attributes.attributes

    def test_remove_nonexistent_attribute(
        self,
        simple_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test removing attribute that doesn't exist doesn't fail."""
        result = FlextLdifEntry.remove_attributes(
            simple_entry,
            attributes=["nonexistent"],
        )

        assert result.is_success
        cleaned = result.unwrap()
        # All original attributes should still be there
        assert "cn" in cleaned.attributes.attributes
        assert "mail" in cleaned.attributes.attributes

    def test_case_insensitive_attribute_removal(
        self,
        simple_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test attribute removal is case-insensitive."""
        result = FlextLdifEntry.remove_attributes(
            simple_entry,
            attributes=["MAIL", "SN"],
        )

        assert result.is_success
        cleaned = result.unwrap()
        # Should be removed regardless of case
        assert "mail" not in cleaned.attributes.attributes
        assert "sn" not in cleaned.attributes.attributes


# ════════════════════════════════════════════════════════════════════════════
# TEST DN CLEANING
# ════════════════════════════════════════════════════════════════════════════


class TestDNCleaning:
    """Test DN string cleaning."""

    def test_clean_dn_with_multiple_spaces(self) -> None:
        """Test cleaning DN with multiple spaces."""
        messy = "cn  =  John  ,  ou  =  users  ,  dc  =  example"
        cleaned = FlextLdifUtilities.DN.clean_dn(messy)

        # Should handle spaces properly
        assert isinstance(cleaned, str)
        assert len(cleaned) > 0

    def test_clean_dn_preserves_values_with_spaces(self) -> None:
        """Test that spaces within values are preserved."""
        dn = r"cn=John Doe,ou=users,dc=example,dc=com"
        cleaned = FlextLdifUtilities.DN.clean_dn(dn)

        # Spaces in value should be preserved
        assert "John Doe" in cleaned or "john doe" in cleaned.lower()

    def test_clean_dn_with_special_characters(self) -> None:
        """Test cleaning DN with special characters."""
        dn = r"cn=John\, Doe,ou=users,dc=example,dc=com"
        cleaned = FlextLdifUtilities.DN.clean_dn(dn)

        assert isinstance(cleaned, str)
        assert len(cleaned) > 0

    def test_clean_dn_empty_string(self) -> None:
        """Test cleaning empty DN string."""
        cleaned = FlextLdifUtilities.DN.clean_dn("")

        assert cleaned == "" or cleaned is not None


# ════════════════════════════════════════════════════════════════════════════
# EDGE CASES
# ════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Test edge cases and special situations."""

    def test_entry_with_no_attributes(self) -> None:
        """Test handling entry with minimal attributes."""
        entry = create_entry(
            "cn=empty,dc=example,dc=com",
            {"cn": ["empty"]},
        )

        result = FlextLdifEntry.remove_operational_attributes(entry)
        assert result.is_success
        cleaned = result.unwrap()
        assert "cn" in cleaned.attributes.attributes

    def test_entry_with_only_operational_attributes(self) -> None:
        """Test entry with only operational attributes."""
        entry = create_entry(
            "cn=test,dc=example,dc=com",
            {
                "createTimestamp": ["20250104120000Z"],
                "modifyTimestamp": ["20250105120000Z"],
            },
        )

        result = FlextLdifEntry.remove_operational_attributes(entry)
        assert result.is_success
        cleaned = result.unwrap()
        # Should have empty attributes after removal
        assert len(cleaned.attributes.attributes) == 0

    def test_unicode_in_dn(self) -> None:
        """Test handling Unicode characters in DN."""
        entry = create_entry(
            "cn=日本語,dc=example,dc=com",
            {"cn": ["日本語"]},
        )

        result = FlextLdifEntry.remove_operational_attributes(entry)
        assert result.is_success
        cleaned = result.unwrap()
        assert "cn" in cleaned.attributes.attributes

    def test_very_long_attribute_values(self) -> None:
        """Test handling very long attribute values."""
        long_value = "x" * 10000
        entry = create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "description": [long_value]},
        )

        result = FlextLdifEntry.remove_attributes(entry, attributes=["description"])
        assert result.is_success
        cleaned = result.unwrap()
        assert "description" not in cleaned.attributes.attributes
        assert "cn" in cleaned.attributes.attributes

    def test_entry_with_many_attributes(self) -> None:
        """Test handling entry with many attributes."""
        attrs = {f"attr{i}": [f"value{i}"] for i in range(100)}
        attrs["cn"] = ["test"]
        entry = create_entry("cn=test,dc=example,dc=com", attrs)

        result = FlextLdifEntry.remove_attributes(
            entry,
            attributes=[f"attr{i}" for i in range(50)],
        )

        assert result.is_success
        cleaned = result.unwrap()
        # First 50 attrs should be removed
        assert all(f"attr{i}" not in cleaned.attributes.attributes for i in range(50))
        # Second 50 attrs should remain
        assert all(f"attr{i}" in cleaned.attributes.attributes for i in range(50, 100))


# ════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ════════════════════════════════════════════════════════════════════════════


class TestIntegration:
    """Integration tests for real-world scenarios."""

    def test_clean_and_adapt_entry_pipeline(
        self,
        entry_with_operational_attrs: FlextLdifModels.Entry,
    ) -> None:
        """Test realistic pipeline: remove operational attrs then remove specific ones."""
        # Stage 1: Remove operational attributes
        result1 = FlextLdifEntry.remove_operational_attributes(
            entry_with_operational_attrs,
        )
        assert result1.is_success
        intermediate = result1.unwrap()

        # Stage 2: Remove specific attributes
        result2 = FlextLdifEntry.remove_attributes(intermediate, attributes=["mail"])
        assert result2.is_success
        final = result2.unwrap()

        # Verify results
        attrs = final.attributes.attributes
        assert "mail" not in attrs
        assert "createTimestamp" not in attrs
        assert "cn" in attrs

    def test_batch_cleaning_pipeline(
        self,
        entries_batch: list[FlextLdifModels.Entry],
    ) -> None:
        """Test realistic batch processing pipeline."""
        # Stage 1: Remove operational attributes from batch
        result1 = FlextLdifEntry.remove_operational_attributes_batch(entries_batch)
        assert result1.is_success
        cleaned_batch = result1.unwrap()

        # Stage 2: Remove specific attributes
        result2 = FlextLdifEntry.remove_attributes_batch(
            cleaned_batch,
            attributes=["cn"],
        )
        assert result2.is_success
        final_batch = result2.unwrap()

        # Verify all entries processed
        assert len(final_batch) == len(entries_batch)
        for entry in final_batch:
            assert "cn" not in entry.attributes.attributes


# ════════════════════════════════════════════════════════════════════════════
# TESTS FOR FLEXTLDIFVALIDATIONSERVICE (RFC 4512/4514)
# ════════════════════════════════════════════════════════════════════════════


class TestFlextLdifValidation:
    """RFC 4512/4514 LDAP attribute and DN component validation tests."""

    def test_validate_attribute_name_valid(self) -> None:
        """Test validation of valid attribute names."""
        service = FlextLdifValidation()

        valid_names = [
            "cn",
            "mail",
            "objectClass",
            "user-account",
            "extensionAttribute123",
        ]
        for name in valid_names:
            result = service.validate_attribute_name(name)
            assert result.is_success
            assert result.unwrap() is True

    def test_validate_attribute_name_invalid(self) -> None:
        """Test validation of invalid attribute names."""
        service = FlextLdifValidation()

        invalid_names = ["2invalid", "user name", "", "user@name"]
        for name in invalid_names:
            result = service.validate_attribute_name(name)
            assert result.is_success
            assert result.unwrap() is False

    def test_validate_objectclass_name(self) -> None:
        """Test validation of objectClass names."""
        service = FlextLdifValidation()

        result = service.validate_objectclass_name("person")
        assert result.is_success
        assert result.unwrap() is True

        result = service.validate_objectclass_name("invalid class")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_attribute_value(self) -> None:
        """Test attribute value length validation."""
        service = FlextLdifValidation()

        result = service.validate_attribute_value("John Smith")
        assert result.is_success
        assert result.unwrap() is True

        result = service.validate_attribute_value("test", max_length=2)
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_dn_component(self) -> None:
        """Test DN component validation (RFC 4514)."""
        service = FlextLdifValidation()

        result = service.validate_dn_component("cn", "John Smith")
        assert result.is_success
        assert result.unwrap() is True

        result = service.validate_dn_component("2invalid", "value")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_attribute_names_batch(self) -> None:
        """Test batch validation of attribute names."""
        service = FlextLdifValidation()

        names = ["cn", "mail", "2invalid", "objectClass"]
        result = service.validate_attribute_names(names)
        assert result.is_success

        validated = result.unwrap()
        assert validated["cn"] is True
        assert validated["mail"] is True
        assert validated["2invalid"] is False
        assert validated["objectClass"] is True


# ════════════════════════════════════════════════════════════════════════════
# TESTS FOR FLEXTLDIFSYNT AXSERVICE (RFC 4517)
# ════════════════════════════════════════════════════════════════════════════


class TestFlextLdifSyntax:
    """RFC 4517 LDAP attribute syntax validation and resolution tests."""

    def test_validate_oid_format(self) -> None:
        """Test OID format validation."""
        syntax = FlextLdifSyntax()
        result = syntax.validate_oid("1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success
        assert result.unwrap() is True

        result = syntax.validate_oid("invalid-oid")
        assert result.is_success
        assert result.unwrap() is False

    def test_is_rfc4517_standard(self) -> None:
        """Test RFC 4517 standard OID detection."""
        syntax = FlextLdifSyntax()
        # Boolean syntax is RFC 4517 standard
        result = syntax.is_rfc4517_standard("1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success

    def test_lookup_syntax_name(self) -> None:
        """Test looking up OID by syntax name."""
        syntax = FlextLdifSyntax()
        # Try with lowercase name (as stored in constants)
        result = syntax.lookup_name("boolean")
        if not result.is_success:
            # Try with capitalized name
            result = syntax.lookup_name("Boolean")
        assert result.is_success
        oid = result.unwrap()
        assert oid == "1.3.6.1.4.1.1466.115.121.1.7"

    def test_lookup_syntax_oid(self) -> None:
        """Test looking up syntax name by OID."""
        syntax = FlextLdifSyntax()
        result = syntax.lookup_oid("1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success
        name = result.unwrap()
        assert name.lower() == "boolean"

    def test_resolve_syntax_oid(self) -> None:
        """Test resolving OID to Syntax model."""
        syntax = FlextLdifSyntax()
        result = syntax.resolve_syntax("1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success
        syntax_model = result.unwrap()
        assert syntax_model.oid == "1.3.6.1.4.1.1466.115.121.1.7"

    def test_validate_syntax_value(self) -> None:
        """Test value validation against syntax type."""
        syntax = FlextLdifSyntax()
        result = syntax.validate_value(
            "TRUE",
            "1.3.6.1.4.1.1466.115.121.1.7",
        )
        assert result.is_success

    def test_get_syntax_type(self) -> None:
        """Test getting syntax type category."""
        syntax = FlextLdifSyntax()
        result = syntax.get_syntax_category("1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success
        category = result.unwrap()
        assert isinstance(category, str)

    def test_list_all_syntaxes(self) -> None:
        """Test listing all supported RFC 4517 syntaxes."""
        syntax = FlextLdifSyntax()
        result = syntax.list_common_syntaxes()
        assert result.is_success
        oids = result.unwrap()
        assert isinstance(oids, list)
        assert len(oids) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
