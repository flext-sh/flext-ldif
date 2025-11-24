"""Unit tests for Syntax Pydantic model - RFC 4517 Attribute Syntax Definitions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifModels


class TestSyntaxModelCreation:
    """Test Syntax model instantiation and validation."""

    def test_create_boolean_syntax(self) -> None:
        """Test creating Boolean syntax model."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="Boolean",
            type_category="boolean",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax.oid == "1.3.6.1.4.1.1466.115.121.1.7"
        assert syntax.name == "Boolean"
        assert syntax.type_category == "boolean"

    def test_create_with_all_fields(self) -> None:
        """Test creating Syntax with all optional fields."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            name="Directory String",
            desc="UTF-8 string for directory entries",
            type_category="string",
            is_binary=False,
            max_length=65535,
            case_insensitive=True,
            allows_multivalued=True,
            encoding="utf-8",
            validation_pattern=r"^[\x00-\x7F]+$",
        )
        assert syntax.name == "Directory String"
        assert syntax.case_insensitive is True
        assert syntax.max_length == 65535

    def test_syntax_defaults(self) -> None:
        """Test default field values."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.39",
            name="Octet String",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax.type_category == "string"
        assert syntax.is_binary is False
        assert syntax.case_insensitive is False
        assert syntax.allows_multivalued is True
        assert syntax.encoding == "utf-8"

    def test_syntax_oid_required(self) -> None:
        """Test that OID is required field."""
        with pytest.raises(ValueError):
            FlextLdifModels.Syntax(name="Invalid")

    def test_syntax_with_desc_only(self) -> None:
        """Test creating syntax with just OID and description."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.27",
            desc="Integer syntax for numeric values",
        )
        assert syntax.oid == "1.3.6.1.4.1.1466.115.121.1.27"
        assert syntax.desc == "Integer syntax for numeric values"
        assert syntax.name is None

    def test_syntax_with_metadata(self) -> None:
        """Test creating syntax with quirk metadata."""
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="oid",
            extensions={
                "priority": 50,
                "description": "OID-specific syntax handling",
            },
        )
        syntax = FlextLdifModels.Syntax(
            oid="2.16.840.1.113894.1.1.1",
            name="Oracle GUID",
            metadata=metadata,
        )
        assert syntax.metadata is not None
        assert syntax.metadata.quirk_type == "oid"


class TestSyntaxComputedFields:
    """Test Syntax computed_field properties."""

    def test_is_rfc4517_standard_true(self) -> None:
        """Test detection of RFC 4517 standard syntax OID."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="Boolean",
        )
        assert syntax.is_rfc4517_standard is True

    def test_is_rfc4517_standard_false(self) -> None:
        """Test detection of non-RFC 4517 syntax OID."""
        syntax = FlextLdifModels.Syntax(
            oid="2.16.840.1.113894.1.1.1",
            name="Oracle GUID",
        )
        assert syntax.is_rfc4517_standard is False

    def test_syntax_oid_suffix_rfc4517(self) -> None:
        """Test extraction of OID suffix from RFC 4517 OID."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="Boolean",
        )
        assert syntax.syntax_oid_suffix == "7"

    def test_syntax_oid_suffix_directory_string(self) -> None:
        """Test OID suffix extraction for Directory String."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            name="Directory String",
        )
        assert syntax.syntax_oid_suffix == "15"

    def test_syntax_oid_suffix_non_rfc4517(self) -> None:
        """Test OID suffix is None for non-RFC 4517 OID."""
        syntax = FlextLdifModels.Syntax(
            oid="2.16.840.1.113894.1.1.1",
            name="Oracle GUID",
        )
        assert syntax.syntax_oid_suffix is None


class TestSyntaxTypeCategories:
    """Test different syntax type categories."""

    def test_boolean_type(self) -> None:
        """Test Boolean type syntax."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="Boolean",
            type_category="boolean",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax.type_category == "boolean"

    def test_integer_type(self) -> None:
        """Test Integer type syntax."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.27",
            name="Integer",
            type_category="integer",
            max_length=10,
        )
        assert syntax.type_category == "integer"

    def test_binary_type(self) -> None:
        """Test Binary type syntax."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.5",
            name="Binary",
            type_category="binary",
            is_binary=True,
        )
        assert syntax.is_binary is True

    def test_dn_type(self) -> None:
        """Test DN type syntax."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.12",
            name="Distinguished Name",
            type_category="dn",
        )
        assert syntax.type_category == "dn"

    def test_time_type(self) -> None:
        """Test Time type syntax."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.24",
            name="Generalized Time",
            type_category="time",
        )
        assert syntax.type_category == "time"


class TestSyntaxEncoding:
    """Test syntax encoding handling."""

    def test_utf8_encoding(self) -> None:
        """Test UTF-8 encoding."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.55",
            name="UTF-8 String",
            encoding="utf-8",
        )
        assert syntax.encoding == "utf-8"

    def test_ascii_encoding(self) -> None:
        """Test ASCII encoding."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.26",
            name="IA5 String",
            encoding="ascii",
        )
        assert syntax.encoding == "ascii"

    def test_custom_encoding(self) -> None:
        """Test custom character encoding."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.44",
            name="Printable String",
            encoding="iso-8859-1",
        )
        assert syntax.encoding == "iso-8859-1"


class TestSyntaxValidation:
    """Test syntax validation patterns."""

    def test_validation_pattern_numeric(self) -> None:
        """Test numeric validation pattern."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.36",
            name="Numeric String",
            validation_pattern=r"^[0-9]+$",
        )
        assert syntax.validation_pattern == r"^[0-9]+$"

    def test_validation_pattern_phone(self) -> None:
        """Test telephone number validation pattern."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.50",
            name="Telephone Number",
            validation_pattern=r"^[0-9\s\-\(\)\+]+$",
        )
        assert syntax.validation_pattern is not None

    def test_no_validation_pattern(self) -> None:
        """Test syntax with no validation pattern."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            name="Directory String",
        )
        assert syntax.validation_pattern is None


class TestSyntaxSerialization:
    """Test Syntax model serialization."""

    def test_model_dump(self) -> None:
        """Test model_dump method."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="Boolean",
            type_category="boolean",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        dumped = syntax.model_dump()
        assert dumped["oid"] == "1.3.6.1.4.1.1466.115.121.1.7"
        assert dumped["name"] == "Boolean"
        assert dumped["is_rfc4517_standard"] is True

    def test_model_dump_json(self) -> None:
        """Test model_dump_json method."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="Boolean",
        )
        json_str = syntax.model_dump_json()
        assert "Boolean" in json_str
        assert "1.3.6.1.4.1.1466.115.121.1.7" in json_str

    def test_model_validate(self) -> None:
        """Test model_validate class method."""
        data = {
            "oid": "1.3.6.1.4.1.1466.115.121.1.15",
            "name": "Directory String",
            "type_category": "string",
        }
        syntax = FlextLdifModels.Syntax.model_validate(data)
        assert syntax.name == "Directory String"
        assert syntax.is_rfc4517_standard is True


class TestSyntaxEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_oid_fails(self) -> None:
        """Test validation with empty OID."""
        with pytest.raises(ValueError):
            FlextLdifModels.Syntax(
                oid="",
                name="Invalid",
                desc=None,
                max_length=None,
                validation_pattern=None,
            )

    def test_negative_max_length(self) -> None:
        """Test negative max_length is accepted."""
        # Pydantic allows negative int - semantically invalid but accepted
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            name="Directory String",
            max_length=-1,
            desc=None,
            validation_pattern=None,
        )
        assert syntax.max_length == -1

    def test_very_long_oid(self) -> None:
        """Test handling of very long OID."""
        long_oid = "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15"
        syntax = FlextLdifModels.Syntax(
            oid=long_oid,
            name="Custom OID",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax.oid == long_oid

    def test_syntax_with_empty_name(self) -> None:
        """Test creating syntax with empty name."""
        syntax = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert not syntax.name

    def test_multiple_syntaxes_independence(self) -> None:
        """Test that multiple syntax instances are independent."""
        syntax1 = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="Boolean",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        syntax2 = FlextLdifModels.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            name="Directory String",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax1.oid != syntax2.oid
        assert syntax1.name != syntax2.name


class TestSyntaxComputedFieldsAdvanced:
    """Test advanced computed field scenarios."""

    def test_multiple_rfc4517_oids(self) -> None:
        """Test multiple RFC 4517 OID suffix extraction."""
        test_oids = [
            ("1.3.6.1.4.1.1466.115.121.1.1", "1"),
            ("1.3.6.1.4.1.1466.115.121.1.7", "7"),
            ("1.3.6.1.4.1.1466.115.121.1.15", "15"),
            ("1.3.6.1.4.1.1466.115.121.1.27", "27"),
        ]
        for oid, expected_suffix in test_oids:
            syntax = FlextLdifModels.Syntax(
                oid=oid,
                name="Test",
                desc=None,
                max_length=None,
                validation_pattern=None,
            )
            assert syntax.is_rfc4517_standard is True
            assert syntax.syntax_oid_suffix == expected_suffix

    def test_non_standard_oids(self) -> None:
        """Test non-standard OID detection."""
        non_standard_oids = [
            "2.5.4.3",  # cn - not RFC 4517 syntax
            "2.16.840.1.113894.1.1.1",  # Oracle
            "1.2.840.113556.1.2.1",  # Active Directory
        ]
        for oid in non_standard_oids:
            syntax = FlextLdifModels.Syntax(
                oid=oid,
                name="Test",
                desc=None,
                max_length=None,
                validation_pattern=None,
            )
            assert syntax.is_rfc4517_standard is False
            assert syntax.syntax_oid_suffix is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
