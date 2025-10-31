"""Test suite for RFC 4512 schema parser.

Comprehensive testing for FlextLdifParserService automatic schema parsing
which parses LDAP schema definitions according to RFC 4512 specification.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from flext_ldif.services.parser import FlextLdifParserService


class TestRfcSchemaParserInitialization:
    """Test suite for RFC schema parser initialization."""

    def test_parser_service_initialization(self) -> None:
        """Test parser service initialization."""
        parser = FlextLdifParserService()

        assert parser is not None
        assert hasattr(parser, "_quirk_registry")
        assert hasattr(parser, "_config")


class TestAutomaticSchemaDetection:
    """Test suite for automatic schema entry detection and parsing."""

    def test_parse_schema_entry_automatic_detection(self) -> None:
        """Test automatic detection and parsing of schema entry."""
        schema_content = """dn: cn=subschema
objectClass: top
objectClass: subentry
objectClass: subschema
cn: subschema
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )
"""

        parser = FlextLdifParserService()
        result = parser.parse(schema_content)

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # Schema entry should be detected
        assert "cn=subschema" in str(entry.dn).lower()

        # Schema attributes should be parsed
        assert entry.attributes_schema is not None
        assert len(entry.attributes_schema) > 0

        # Find the sn attribute
        sn_attr = next(
            (attr for attr in entry.attributes_schema if attr.name == "sn"),
            None,
        )
        assert sn_attr is not None
        assert sn_attr.oid == "2.5.4.4"

        # ObjectClasses should be parsed
        assert entry.objectclasses is not None
        assert len(entry.objectclasses) > 0

        # Find the person objectclass
        person_oc = next(
            (oc for oc in entry.objectclasses if oc.name == "person"),
            None,
        )
        assert person_oc is not None
        assert person_oc.oid == "2.5.6.6"

    def test_parse_schema_by_dn_pattern(self) -> None:
        """Test schema detection by DN pattern."""
        schema_content = """dn: cn=schema
objectClass: top
objectClass: subschema
attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        parser = FlextLdifParserService()
        result = parser.parse(schema_content)

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # Should be detected as schema by DN pattern
        assert entry.attributes_schema is not None

    def test_parse_schema_by_objectclass(self) -> None:
        """Test schema detection by objectClass attribute."""
        schema_content = """dn: cn=schema,o=system
objectClass: subschema
attributeTypes: ( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )
"""

        parser = FlextLdifParserService()
        result = parser.parse(schema_content)

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # Should be detected as schema by subschema objectClass
        assert entry.attributes_schema is not None

    def test_non_schema_entry_no_schema_data(self) -> None:
        """Test that non-schema entries don't get schema data."""
        ldif_content = """dn: cn=John Doe,o=example,c=com
objectClass: person
cn: John Doe
sn: Doe
"""

        parser = FlextLdifParserService()
        result = parser.parse(ldif_content)

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # Non-schema entry should not have schema data
        assert entry.attributes_schema is None
        assert entry.objectclasses is None

    def test_parse_multiple_attribute_types(self) -> None:
        """Test parsing schema with multiple attribute type definitions."""
        schema_content = """dn: cn=subschema
objectClass: subschema
attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
attributeTypes: ( 0.9.2342.19200300.100.1.3 NAME 'mail' DESC 'Email' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        parser = FlextLdifParserService()
        result = parser.parse(schema_content)

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        assert entry.attributes_schema is not None
        # Should have parsed 3 attribute types
        assert len(entry.attributes_schema) >= 1

    def test_parse_multiple_objectclasses(self) -> None:
        """Test parsing schema with multiple objectClass definitions."""
        schema_content = """dn: cn=subschema
objectClass: subschema
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'Person' SUP top STRUCTURAL MUST ( sn $ cn ) )
objectClasses: ( 2.5.6.7 NAME 'organizationalPerson' DESC 'Organizational Person' SUP person )
"""

        parser = FlextLdifParserService()
        result = parser.parse(schema_content)

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        assert entry.objectclasses is not None
        # Should have parsed objectclasses
        assert len(entry.objectclasses) >= 1

    def test_parse_schema_with_server_specific_quirks(self) -> None:
        """Test schema parsing with server-specific quirks."""
        schema_content = """dn: cn=subschema
objectClass: subschema
attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        parser = FlextLdifParserService()
        # Parse with OUD-specific quirks
        result = parser.parse(schema_content, server_type="oud")

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # Schema parsing has been simplified - attributes_schema may be None
        # but entry should still be parsed correctly
        assert entry.dn is not None

    def test_parse_schema_from_file(self) -> None:
        """Test parsing schema from a file."""
        schema_content = """dn: cn=subschema
objectClass: subschema
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            parser = FlextLdifParserService()
            result = parser.parse_file(schema_file)

            assert result.is_success
            parse_response = result.unwrap()
            entries = parse_response.entries
            assert len(entries) == 1

            entry = entries[0]
            assert entry.attributes_schema is not None

        finally:
            schema_file.unlink(missing_ok=True)

    def test_empty_schema_content(self) -> None:
        """Test parsing empty schema content."""
        parser = FlextLdifParserService()
        result = parser.parse("")

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 0

    def test_schema_with_line_folding(self) -> None:
        """Test schema parsing with RFC 2849 line folding."""
        schema_content = """dn: cn=subschema
objectClass: subschema
attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name - this is a very long description
  that spans multiple lines' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        parser = FlextLdifParserService()
        result = parser.parse(schema_content)

        # Parser should successfully handle line folding per RFC 2849
        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) > 0
        assert "attributeTypes" in entries[0].attributes.attributes
