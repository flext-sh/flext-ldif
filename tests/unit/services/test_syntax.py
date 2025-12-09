"""Tests for RFC 4517 Syntax model.

This module tests the RFC 4517 Syntax Pydantic model including instantiation,
validation, computed fields, serialization, and edge cases with parametrized
tests and DRY helper patterns.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from tests import m, s


class TestsFlextLdifSyntaxModel(s):
    """Unified test suite for RFC 4517 Syntax Pydantic model.

    Covers instantiation, validation, computed fields, serialization,
    and edge cases using parametrized tests and DRY helper patterns.
    """

    class SyntaxTestCase(StrEnum):
        """Enumeration of RFC 4517 syntax test cases."""

        BOOLEAN = "boolean"
        DIRECTORY_STRING = "directory_string"
        INTEGER = "integer"
        BINARY = "binary"
        DN = "dn"
        GENERALIZED_TIME = "generalized_time"
        OCTET_STRING = "octet_string"
        IA5_STRING = "ia5_string"
        NUMERIC_STRING = "numeric_string"
        TELEPHONE_NUMBER = "telephone_number"
        ORACLE_GUID = "oracle_guid"

    class EncodingTestCase(StrEnum):
        """Enumeration of encoding test cases."""

        UTF8 = "utf-8"
        ASCII = "ascii"
        ISO_8859_1 = "iso-8859-1"

    # ========================================================================
    # TEST DATA MAPPINGS
    # ========================================================================

    SYNTAX_DATA: ClassVar[
        dict[SyntaxTestCase, tuple[str, str | None, str | None, str]]
    ] = {
        SyntaxTestCase.BOOLEAN: (
            "1.3.6.1.4.1.1466.115.121.1.7",
            "Boolean",
            "RFC 4517 boolean syntax",
            "boolean",
        ),
        SyntaxTestCase.DIRECTORY_STRING: (
            "1.3.6.1.4.1.1466.115.121.1.15",
            "Directory String",
            "UTF-8 string for directory entries",
            "string",
        ),
        SyntaxTestCase.INTEGER: (
            "1.3.6.1.4.1.1466.115.121.1.27",
            "Integer",
            "Integer syntax for numeric values",
            "integer",
        ),
        SyntaxTestCase.BINARY: (
            "1.3.6.1.4.1.1466.115.121.1.5",
            "Binary",
            "Binary data syntax",
            "binary",
        ),
        SyntaxTestCase.DN: (
            "1.3.6.1.4.1.1466.115.121.1.12",
            "Distinguished Name",
            "DN syntax",
            "dn",
        ),
        SyntaxTestCase.GENERALIZED_TIME: (
            "1.3.6.1.4.1.1466.115.121.1.24",
            "Generalized Time",
            "Generalized time format",
            "time",
        ),
        SyntaxTestCase.OCTET_STRING: (
            "1.3.6.1.4.1.1466.115.121.1.39",
            "Octet String",
            "Raw octets",
            "string",
        ),
        SyntaxTestCase.IA5_STRING: (
            "1.3.6.1.4.1.1466.115.121.1.26",
            "IA5 String",
            "IA5 (ASCII) string syntax",
            "string",
        ),
        SyntaxTestCase.NUMERIC_STRING: (
            "1.3.6.1.4.1.1466.115.121.1.36",
            "Numeric String",
            "Numeric-only string",
            "string",
        ),
        SyntaxTestCase.TELEPHONE_NUMBER: (
            "1.3.6.1.4.1.1466.115.121.1.50",
            "Telephone Number",
            "Phone number format",
            "string",
        ),
        SyntaxTestCase.ORACLE_GUID: (
            "2.16.840.1.113894.1.1.1",
            "Oracle GUID",
            "Oracle-specific GUID syntax",
            "string",
        ),
    }

    ENCODING_DATA: ClassVar[dict[EncodingTestCase, tuple[str, str]]] = {
        EncodingTestCase.UTF8: (
            "1.3.6.1.4.1.1466.115.121.1.55",
            "UTF-8 String",
        ),
        EncodingTestCase.ASCII: (
            "1.3.6.1.4.1.1466.115.121.1.26",
            "IA5 String",
        ),
        EncodingTestCase.ISO_8859_1: (
            "1.3.6.1.4.1.1466.115.121.1.44",
            "Printable String",
        ),
    }

    RFC4517_OIDS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("1.3.6.1.4.1.1466.115.121.1.1", "1"),
        ("1.3.6.1.4.1.1466.115.121.1.7", "7"),
        ("1.3.6.1.4.1.1466.115.121.1.15", "15"),
        ("1.3.6.1.4.1.1466.115.121.1.27", "27"),
    )

    NON_RFC4517_OIDS: ClassVar[tuple[str, ...]] = (
        "2.5.4.3",  # cn - attribute OID, not syntax
        "2.16.840.1.113894.1.1.1",  # Oracle
        "1.2.840.113556.1.2.1",  # Active Directory
    )

    # ========================================================================
    # PARAMETRIZED TESTS - MODEL INSTANTIATION
    # ========================================================================

    @pytest.mark.parametrize("test_case", list(SyntaxTestCase))
    def test_create_syntax_basic_cases(self, test_case: SyntaxTestCase) -> None:
        """Test creating Syntax models with various type categories.

        Parametrized test covering:
        - Boolean, Directory String, Integer, Binary syntaxes
        - DN, Generalized Time, Octet String syntaxes
        - IA5 String, Numeric String, Telephone Number syntaxes
        - Oracle GUID (non-RFC 4517) syntax
        """
        oid, name, desc, type_category = self.SYNTAX_DATA[test_case]

        syntax = m.Syntax(
            oid=oid,
            name=name,
            desc=desc,
            type_category=type_category,
            max_length=None,
            validation_pattern=None,
        )

        assert syntax.oid == oid
        assert syntax.name == name
        assert syntax.type_category == type_category

    def test_create_syntax_with_all_optional_fields(self) -> None:
        """Test creating Syntax with complete field specification."""
        syntax = m.Syntax(
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
        """Test default field values for Syntax model."""
        syntax = m.Syntax(
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
            m.Syntax(
                oid="",
                name="Invalid",
                desc=None,
                max_length=None,
                validation_pattern=None,
                type_category="string",
                is_binary=False,
                case_insensitive=False,
                allows_multivalued=True,
                encoding="utf-8",
                metadata=None,
            )

    def test_syntax_with_metadata(self) -> None:
        """Test creating Syntax with quirk metadata."""
        metadata = m.Ldif.QuirkMetadata(
            quirk_type="oid",
            extensions=m.Ldif.DynamicMetadata(
                priority=50,
                description="OID-specific syntax handling",
            ),
        )
        syntax = m.Syntax(
            oid="2.16.840.1.113894.1.1.1",
            name="Oracle GUID",
            metadata=metadata,
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax.metadata is not None
        assert syntax.metadata.quirk_type == "oid"

    # ========================================================================
    # PARAMETRIZED TESTS - COMPUTED FIELDS
    # ========================================================================

    @pytest.mark.parametrize(("oid", "expected_suffix"), RFC4517_OIDS)
    def test_is_rfc4517_standard_and_suffix(
        self,
        oid: str,
        expected_suffix: str,
    ) -> None:
        """Test RFC 4517 detection and OID suffix extraction.

        Parametrized test covering OID suffix extraction for:
        - Boolean (1), DN (7), Directory String (15), Integer (27)
        """
        syntax = m.Syntax(
            oid=oid,
            name="Test",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax.is_rfc4517_standard is True
        assert syntax.syntax_oid_suffix == expected_suffix

    @pytest.mark.parametrize("oid", NON_RFC4517_OIDS)
    def test_non_rfc4517_detection(self, oid: str) -> None:
        """Test non-RFC 4517 OID detection.

        Parametrized test covering:
        - Attribute OID (cn = 2.5.4.3)
        - Oracle-specific OID
        - Active Directory OID
        """
        syntax = m.Syntax(
            oid=oid,
            name="Test",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax.is_rfc4517_standard is False
        assert syntax.syntax_oid_suffix is None

    # ========================================================================
    # PARAMETRIZED TESTS - ENCODING SUPPORT
    # ========================================================================

    @pytest.mark.parametrize("encoding_case", list(EncodingTestCase))
    def test_syntax_encoding_support(self, encoding_case: EncodingTestCase) -> None:
        """Test different character encoding support.

        Parametrized test covering UTF-8, ASCII, ISO-8859-1 encodings.
        """
        oid, name = self.ENCODING_DATA[encoding_case]

        syntax = m.Syntax(
            oid=oid,
            name=name,
            desc=f"{encoding_case.value} encoded string syntax",
            max_length=None,
            validation_pattern=None,
            encoding=encoding_case.value,
        )
        assert syntax.encoding == encoding_case.value

    # ========================================================================
    # PARAMETRIZED TESTS - VALIDATION PATTERNS
    # ========================================================================

    VALIDATION_PATTERNS: ClassVar[tuple[tuple[str | None, str], ...]] = (
        (r"^[0-9]+$", "numeric"),
        (r"^[0-9\s\-\(\)\+]+$", "phone"),
        (None, "none"),
    )

    @pytest.mark.parametrize(("pattern", "description"), VALIDATION_PATTERNS)
    def test_syntax_validation_patterns(
        self,
        pattern: str | None,
        description: str,
    ) -> None:
        """Test validation pattern support.

        Parametrized test covering:
        - Numeric validation (digits only)
        - Phone number validation (with spaces, dashes, parens, plus)
        - No validation pattern
        """
        syntax = m.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.36",
            name=f"Test {description}",
            desc=None,
            max_length=None,
            validation_pattern=pattern,
        )
        assert syntax.validation_pattern == pattern

    # ========================================================================
    # PARAMETRIZED TESTS - SERIALIZATION
    # ========================================================================

    @pytest.mark.parametrize(
        "test_case",
        [SyntaxTestCase.BOOLEAN, SyntaxTestCase.DIRECTORY_STRING],
    )
    def test_model_serialization(self, test_case: SyntaxTestCase) -> None:
        """Test Pydantic serialization methods.

        Parametrized test covering:
        - model_dump()
        - model_dump_json()
        - model_validate()
        """
        oid, name, _, _ = self.SYNTAX_DATA[test_case]

        syntax = m.Syntax(
            oid=oid,
            name=name,
            desc=None,
            max_length=None,
            validation_pattern=None,
        )

        # Test model_dump
        dumped = syntax.model_dump()
        assert dumped["oid"] == oid
        assert dumped["name"] == name

        # Test model_dump_json
        json_str = syntax.model_dump_json()
        assert json_str is not None
        assert name in json_str
        assert oid in json_str

        # Test model_validate
        data = {"oid": oid, "name": name, "type_category": "string"}
        validated = m.Syntax.model_validate(data)
        assert validated.name == name

    # ========================================================================
    # EDGE CASES AND ERROR CONDITIONS
    # ========================================================================

    EDGE_CASE_MAX_LENGTHS: ClassVar[tuple[int, ...]] = (0, -1, 65535, 999999)

    @pytest.mark.parametrize("max_length", EDGE_CASE_MAX_LENGTHS)
    def test_syntax_edge_case_max_lengths(self, max_length: int) -> None:
        """Test edge case max_length values.

        Parametrized test covering:
        - Zero length
        - Negative length (Pydantic allows, semantically invalid)
        - Large lengths
        """
        syntax = m.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            name="Directory String",
            max_length=max_length,
            desc=None,
            validation_pattern=None,
        )
        assert syntax.max_length == max_length

    def test_empty_name_allowed(self) -> None:
        """Test creating syntax with empty name is allowed."""
        syntax = m.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert not syntax.name

    def test_very_long_oid(self) -> None:
        """Test handling of very long OID."""
        long_oid = "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15"
        syntax = m.Syntax(
            oid=long_oid,
            name="Custom OID",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax.oid == long_oid

    def test_multiple_syntaxes_independence(self) -> None:
        """Test that multiple syntax instances are independent."""
        syntax1 = m.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.7",
            name="Boolean",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        syntax2 = m.Syntax(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            name="Directory String",
            desc=None,
            max_length=None,
            validation_pattern=None,
        )
        assert syntax1.oid != syntax2.oid
        assert syntax1.name != syntax2.name
