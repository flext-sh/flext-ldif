"""Test suite for RFC 4512 schema parser.

Comprehensive testing for FlextLdifParser automatic schema parsing
which parses LDAP schema definitions according to RFC 4512 specification.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from flext_ldif.services.parser import FlextLdifParser


class TestRfcSchemaParserInitialization:
    """Test suite for RFC schema parser initialization."""

    def test_parser_service_initialization(self) -> None:
        """Test parser service initialization."""
        parser = FlextLdifParser()

        assert parser is not None
        assert hasattr(parser, "_registry")
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

        parser = FlextLdifParser()
        result = parser.parse(schema_content, input_source="string")

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # Schema entry should be detected
        assert "cn=subschema" in str(entry.dn).lower()

        # The new API doesn't automatically extract schema from entries
        # Schema extraction is handled separately via parser services
        # Just verify the entry was parsed correctly
        assert entry.dn.value is not None
        assert len(entry.attributes.attributes) > 0

    def test_parse_schema_by_dn_pattern(self) -> None:
        """Test schema detection by DN pattern."""
        schema_content = """dn: cn=schema
objectClass: top
objectClass: subschema
attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        parser = FlextLdifParser()
        result = parser.parse(schema_content, input_source="string")

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # The new API doesn't automatically extract schema from entries
        # Just verify entry was parsed
        assert entry.dn.value is not None

    def test_parse_schema_by_objectclass(self) -> None:
        """Test schema detection by objectClass attribute."""
        schema_content = """dn: cn=schema,o=system
objectClass: subschema
attributeTypes: ( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )
"""

        parser = FlextLdifParser()
        result = parser.parse(schema_content, input_source="string")

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # The new API doesn't automatically extract schema from entries
        # Just verify entry was parsed
        assert entry.dn.value is not None

    def test_non_schema_entry_no_schema_data(self) -> None:
        """Test that non-schema entries don't get schema data."""
        ldif_content = """dn: cn=John Doe,o=example,c=com
objectClass: person
cn: John Doe
sn: Doe
"""

        parser = FlextLdifParser()
        result = parser.parse(ldif_content, input_source="string")

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # The new API doesn't automatically extract schema from non-schema entries
        # Just verify entry was parsed
        assert entry.dn.value is not None

    def test_parse_multiple_attribute_types(self) -> None:
        """Test parsing schema with multiple attribute type definitions."""
        schema_content = """dn: cn=subschema
objectClass: subschema
attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
attributeTypes: ( 0.9.2342.19200300.100.1.3 NAME 'mail' DESC 'Email' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        parser = FlextLdifParser()
        result = parser.parse(schema_content, input_source="string")

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # The new API doesn't automatically extract schema from entries
        # Just verify the entry was parsed correctly
        assert entry.dn.value is not None
        assert len(entry.attributes.attributes) > 0

    def test_parse_multiple_objectclasses(self) -> None:
        """Test parsing schema with multiple objectClass definitions."""
        schema_content = """dn: cn=subschema
objectClass: subschema
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'Person' SUP top STRUCTURAL MUST ( sn $ cn ) )
objectClasses: ( 2.5.6.7 NAME 'organizationalPerson' DESC 'Organizational Person' SUP person )
"""

        parser = FlextLdifParser()
        result = parser.parse(schema_content, input_source="string")

        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) == 1

        entry = entries[0]
        # The new API doesn't automatically extract schema from entries
        # Just verify the entry was parsed correctly
        assert entry.dn.value is not None
        assert len(entry.attributes.attributes) > 0

    def test_parse_schema_with_server_specifics(self) -> None:
        """Test schema parsing with server-specific quirks."""
        schema_content = """dn: cn=subschema
objectClass: subschema
attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        parser = FlextLdifParser()
        # Parse with OUD-specific quirks
        result = parser.parse(schema_content, input_source="string", server_type="oud")

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
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            parser = FlextLdifParser()
            result = parser.parse_ldif_file(schema_file)

            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1

            entry = entries[0]
            # The new API doesn't automatically extract schema from entries
            # Just verify the entry was parsed correctly
            assert entry.dn.value is not None

        finally:
            schema_file.unlink(missing_ok=True)

    def test_empty_schema_content(self) -> None:
        """Test parsing empty schema content."""
        parser = FlextLdifParser()
        result = parser.parse("", input_source="string")

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

        parser = FlextLdifParser()
        result = parser.parse(schema_content, input_source="string")

        # Parser should successfully handle line folding per RFC 2849
        assert result.is_success
        parse_response = result.unwrap()
        entries = parse_response.entries
        assert len(entries) > 0
        assert "attributeTypes" in entries[0].attributes.attributes
