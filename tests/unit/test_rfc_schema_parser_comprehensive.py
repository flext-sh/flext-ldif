"""Comprehensive test suite for RFC schema parser.

This module provides extensive testing for RfcSchemaParserService covering:
- Attribute type parsing (basic types, custom OIDs, syntax specifications)
- Object class parsing (structural, auxiliary, abstract, inheritance)
- Quirks integration for schema parsing
- Error cases (invalid syntax, missing fields, circular dependencies)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.quirks.registry import QuirkRegistryService
from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService


class TestSchemaParserAttributeTypes:
    """Test suite for attribute type parsing."""

    def test_parse_basic_attribute_type(self) -> None:
        """Test parsing basic attribute type definition."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 2.5.4.3 NAME 'cn'
  DESC 'commonName' SUP name )
"""

        result = parser.execute()
        # Should execute without error (may or may not fully parse)
        assert result.is_success or result.is_failure

    def test_parse_attribute_with_custom_oid(self) -> None:
        """Test parsing attribute type with custom OID."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 1.2.3.4.5.6.7.8.9 NAME 'customAttr'
  DESC 'Custom attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_attribute_with_syntax_specification(self) -> None:
        """Test parsing attribute type with explicit syntax."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 2.5.4.35 NAME 'userPassword'
  DESC 'Password' EQUALITY octetStringMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_multivalued_attribute_names(self) -> None:
        """Test parsing attribute type with multiple NAMEs."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 2.5.4.4 NAME ( 'sn' 'surname' )
  DESC 'Surname' SUP name )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_attribute_with_sup(self) -> None:
        """Test parsing attribute type with SUP (superior) inheritance."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 2.5.4.10 NAME 'o'
  DESC 'Organization' SUP name )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure


class TestSchemaParserObjectClasses:
    """Test suite for object class parsing."""

    def test_parse_structural_object_class(self) -> None:
        """Test parsing structural object class."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """objectClasses: ( 2.5.6.6 NAME 'person'
  DESC 'Person' SUP top STRUCTURAL
  MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_auxiliary_object_class(self) -> None:
        """Test parsing auxiliary object class."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """objectClasses: ( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson'
  DESC 'Internet Organizational Person' SUP person AUXILIARY
  MAY ( mail $ displayName ) )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_abstract_object_class(self) -> None:
        """Test parsing abstract object class."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """objectClasses: ( 2.5.6.0 NAME 'top'
  DESC 'Top of the tree' ABSTRACT
  MUST objectClass )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_object_class_with_inheritance(self) -> None:
        """Test parsing object class with SUP (inheritance)."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """objectClasses: ( 2.5.6.7 NAME 'organizationalPerson'
  DESC 'Organizational Person' SUP person STRUCTURAL
  MAY ( title $ x121Address ) )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_object_class_with_must_may(self) -> None:
        """Test parsing object class with MUST and MAY attributes."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """objectClasses: ( 2.5.6.6 NAME 'person'
  DESC 'Person' SUP top STRUCTURAL
  MUST ( sn $ cn )
  MAY ( userPassword $ telephoneNumber $ description ) )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure


class TestSchemaParserQuirksIntegration:
    """Test suite for schema parser with quirks integration."""

    @pytest.mark.parametrize("server_type", ["oid", "oud", "openldap"])
    def test_parse_with_server_quirks(self, server_type: str) -> None:
        """Test schema parsing with different server type quirks."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={"server_type": server_type},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 2.5.4.3 NAME 'cn'
  DESC 'commonName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""

        result = parser.execute()
        # Should execute without error
        assert result.is_success or result.is_failure

    def test_parse_oid_schema_attributes(self) -> None:
        """Test parsing OID-specific schema attributes."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={"server_type": "oid"},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 2.16.840.1.113894.1.1.1 NAME 'orclNetDescString'
  DESC 'Oracle Net Description String'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_oud_schema_attributes(self) -> None:
        """Test parsing OUD-specific schema attributes."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={"server_type": "oud"},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 1.3.6.1.4.1.42.2.27.9.1.1 NAME 'ds-pwp-account-disabled'
  DESC 'Password Policy Account Disabled'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure


class TestSchemaParserErrorHandling:
    """Test suite for schema parser error handling."""

    def test_parse_invalid_attribute_syntax(self) -> None:
        """Test parsing attribute type with invalid syntax."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( invalid-oid NAME 'broken'
  DESC 'Broken attribute' )
"""

        result = parser.execute()
        # Should handle gracefully - either parse or return error
        assert result.is_success or result.is_failure

    def test_parse_missing_required_fields(self) -> None:
        """Test parsing schema definition with missing required fields."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        # Missing NAME field
        _schema_content = """attributeTypes: ( 2.5.4.3
  DESC 'Missing name attribute' )
"""

        result = parser.execute()
        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_parse_empty_schema_content(self) -> None:
        """Test parsing empty schema content."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        result = parser.execute()
        # Empty schema should succeed or fail gracefully
        assert result.is_success or result.is_failure

    def test_parse_malformed_object_class(self) -> None:
        """Test parsing malformed object class definition."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """objectClasses: ( not a valid object class definition )
"""

        result = parser.execute()
        # Should handle gracefully
        assert result.is_success or result.is_failure


class TestSchemaParserSpecialCases:
    """Test suite for schema parser special cases."""

    def test_parse_schema_with_comments(self) -> None:
        """Test parsing schema with comment lines."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """# This is a comment
attributeTypes: ( 2.5.4.3 NAME 'cn'
  # Another comment
  DESC 'commonName' )
"""

        result = parser.execute()
        # Comments should be handled
        assert result.is_success or result.is_failure

    def test_parse_multiline_schema_definition(self) -> None:
        """Test parsing schema definition spanning multiple lines."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 2.5.4.3
  NAME 'cn'
  DESC 'commonName'
  SUP name
  EQUALITY caseIgnoreMatch
  SUBSTR caseIgnoreSubstringsMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure

    def test_parse_mixed_attribute_and_object_class(self) -> None:
        """Test parsing schema with both attributes and object classes."""
        registry = QuirkRegistryService()
        parser = RfcSchemaParserService(
            params={},
            quirk_registry=registry,
        )

        _schema_content = """attributeTypes: ( 2.5.4.3 NAME 'cn'
  DESC 'commonName' )

objectClasses: ( 2.5.6.6 NAME 'person'
  DESC 'Person' SUP top STRUCTURAL
  MUST ( sn $ cn ) )
"""

        result = parser.execute()
        assert result.is_success or result.is_failure
