"""Test suite for RFC 4512 schema parser.

Comprehensive testing for FlextLdifRfcSchemaParser which parses LDAP schema
definitions according to RFC 4512 specification.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc_schema_parser import FlextLdifRfcSchemaParser


class TestRfcSchemaParserInitialization:
    """Test suite for RFC schema parser initialization."""

    def test_initialization_with_registry(self) -> None:
        """Test parser initialization with quirks registry."""
        registry = FlextLdifQuirksRegistry()
        params: dict[str, object] = {"file_path": "/tmp/test.ldif"}

        parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)

        assert parser is not None
        assert parser._quirk_registry is registry
        assert parser._params == params

    def test_initialization_with_server_type(self) -> None:
        """Test parser initialization with specific server type."""
        registry = FlextLdifQuirksRegistry()
        params: dict[str, object] = {"file_path": "/tmp/test.ldif"}

        parser = FlextLdifRfcSchemaParser(
            params=params, quirk_registry=registry, server_type="openldap"
        )

        assert parser._server_type == "openldap"


class TestSchemaFileParsingBasic:
    """Test suite for basic schema file parsing."""

    def test_parse_schema_file_success(self) -> None:
        """Test successful parsing of valid schema file."""
        schema_content = """dn: cn=subschemasubentry
objectClass: top
objectClass: subentry
objectClass: subschema
cn: subschema
attributetypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
objectclasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword ) )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            # Check structure
            assert FlextLdifConstants.DictKeys.ATTRIBUTES in data
            assert "objectclasses" in data
            assert "source_dn" in data
            assert "stats" in data

            # Check parsed data
            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            assert "cn" in attributes

            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            assert "person" in objectclasses

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_schema_file_missing_file(self) -> None:
        """Test parsing with non-existent file."""
        registry = FlextLdifQuirksRegistry()
        params: dict[str, object] = {"file_path": "/tmp/nonexistent_schema.ldif"}

        parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
        result = parser.execute()

        assert result.is_failure
        assert "not found" in str(result.error)

    def test_parse_schema_file_no_file_path(self) -> None:
        """Test parsing with missing file_path parameter."""
        registry = FlextLdifQuirksRegistry()
        params: dict[str, object] = {}

        parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
        result = parser.execute()

        assert result.is_failure
        assert "required" in str(result.error)


class TestAttributeTypeParsing:
    """Test suite for AttributeType parsing."""

    def test_parse_simple_attribute_type(self) -> None:
        """Test parsing simple attributeType definition."""
        schema_content = """dn: cn=subschema
attributetypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {
                "file_path": str(schema_file),
                "parse_attributes": True,
            }

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            assert "sn" in attributes

            attr = attributes["sn"]
            assert isinstance(attr, dict)
            assert attr["oid"] == "2.5.4.4"
            assert attr["name"] == "sn"
            assert attr["desc"] == "Surname"
            assert attr["syntax"] == "1.3.6.1.4.1.1466.115.121.1.15"

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_attribute_type_with_matching(self) -> None:
        """Test parsing attributeType with matching rules."""
        schema_content = """dn: cn=subschema
attributetypes: ( 2.5.4.35 NAME 'userPassword' DESC 'User Password' EQUALITY octetStringMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            attr = attributes["userPassword"]
            assert isinstance(attr, dict)

            assert attr["equality"] == "octetStringMatch"

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_attribute_type_with_sup(self) -> None:
        """Test parsing attributeType with SUP (superior) attribute."""
        schema_content = """dn: cn=subschema
attributetypes: ( 2.5.4.42 NAME 'givenName' DESC 'Given Name' SUP name SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            attr = attributes["givenName"]
            assert isinstance(attr, dict)

            assert attr["sup"] == "name"

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_attribute_type_with_length(self) -> None:
        """Test parsing attributeType with syntax length constraint."""
        schema_content = """dn: cn=subschema
attributetypes: ( 1.2.3.4.5 NAME 'shortString' DESC 'Short String' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'{64} )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            attr = attributes["shortString"]
            assert isinstance(attr, dict)

            assert attr["length"] == 64

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_attributes_disabled(self) -> None:
        """Test parsing with attribute parsing disabled."""
        schema_content = """dn: cn=subschema
attributetypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {
                "file_path": str(schema_file),
                "parse_attributes": False,
            }

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            assert len(attributes) == 0

        finally:
            schema_file.unlink(missing_ok=True)


class TestObjectClassParsing:
    """Test suite for ObjectClass parsing."""

    def test_parse_simple_object_class(self) -> None:
        """Test parsing simple objectClass definition."""
        schema_content = """dn: cn=subschema
objectclasses: ( 2.5.6.6 NAME 'person' DESC 'Person class' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( telephoneNumber ) )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            assert "person" in objectclasses

            oc = objectclasses["person"]
            assert isinstance(oc, dict)
            assert oc["oid"] == "2.5.6.6"
            assert oc["name"] == "person"
            assert oc["desc"] == "Person class"
            assert oc["sup"] == "top"
            assert oc["kind"] == "STRUCTURAL"

            # Check MUST attributes
            must = oc["must"]
            assert isinstance(must, list)
            assert "sn" in must
            assert "cn" in must

            # Check MAY attributes
            may = oc["may"]
            assert isinstance(may, list)
            assert "telephoneNumber" in may

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_object_class_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        schema_content = """dn: cn=subschema
objectclasses: ( 2.5.6.0 NAME 'top' DESC 'Top class' ABSTRACT MUST objectClass )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            oc = objectclasses["top"]
            assert isinstance(oc, dict)

            assert oc["kind"] == "ABSTRACT"

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_object_class_no_kind(self) -> None:
        """Test parsing objectClass with no explicit kind (defaults to STRUCTURAL)."""
        schema_content = """dn: cn=subschema
objectclasses: ( 2.5.6.20 NAME 'simpleClass' DESC 'Simple' MUST cn )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            oc = objectclasses["simpleClass"]
            assert isinstance(oc, dict)

            # Should default to STRUCTURAL
            assert oc["kind"] == "STRUCTURAL"

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_objectclasses_disabled(self) -> None:
        """Test parsing with objectClass parsing disabled."""
        schema_content = """dn: cn=subschema
objectclasses: ( 2.5.6.6 NAME 'person' DESC 'Person' SUP top STRUCTURAL MUST cn )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {
                "file_path": str(schema_file),
                "parse_objectclasses": False,
            }

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            assert len(objectclasses) == 0

        finally:
            schema_file.unlink(missing_ok=True)


class TestLineFoldingHandling:
    """Test suite for LDIF line folding handling."""

    def test_parse_folded_attribute_definition(self) -> None:
        """Test parsing attributeType definition with LDIF line folding."""
        schema_content = """dn: cn=subschema
attributetypes: ( 2.5.4.3 NAME 'cn'
 DESC 'Common Name'
 EQUALITY caseIgnoreMatch
 SUBSTR caseIgnoreSubstringsMatch
 SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            assert "cn" in attributes

            attr = attributes["cn"]
            assert isinstance(attr, dict)
            assert attr["desc"] == "Common Name"
            assert attr["equality"] == "caseIgnoreMatch"
            assert attr["substr"] == "caseIgnoreSubstringsMatch"

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_folded_objectclass_definition(self) -> None:
        """Test parsing objectClass definition with LDIF line folding."""
        schema_content = """dn: cn=subschema
objectclasses: ( 2.5.6.6 NAME 'person'
 DESC 'Person class'
 SUP top
 STRUCTURAL
 MUST ( sn $ cn )
 MAY ( telephoneNumber $ description ) )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            assert "person" in objectclasses

            oc = objectclasses["person"]
            assert isinstance(oc, dict)
            assert oc["desc"] == "Person class"
            assert "sn" in oc["must"]
            assert "cn" in oc["must"]
            assert "telephoneNumber" in oc["may"]
            assert "description" in oc["may"]

        finally:
            schema_file.unlink(missing_ok=True)


class TestSchemaDN:
    """Test suite for schema DN parsing."""

    def test_parse_schema_dn(self) -> None:
        """Test parsing schema subentry DN."""
        schema_content = """dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema
attributetypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            assert data["source_dn"] == "cn=schema,cn=config"

        finally:
            schema_file.unlink(missing_ok=True)


class TestMultipleDefinitions:
    """Test suite for parsing multiple schema definitions."""

    def test_parse_multiple_attributes(self) -> None:
        """Test parsing multiple attributeType definitions."""
        schema_content = """dn: cn=subschema
attributetypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
attributetypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
attributetypes: ( 2.5.4.41 NAME 'name' DESC 'Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            assert len(attributes) >= 3
            assert "cn" in attributes
            assert "sn" in attributes
            assert "name" in attributes

        finally:
            schema_file.unlink(missing_ok=True)

    def test_parse_multiple_objectclasses(self) -> None:
        """Test parsing multiple objectClass definitions."""
        schema_content = """dn: cn=subschema
objectclasses: ( 2.5.6.0 NAME 'top' DESC 'Top' ABSTRACT MUST objectClass )
objectclasses: ( 2.5.6.6 NAME 'person' DESC 'Person' SUP top STRUCTURAL MUST ( sn $ cn ) )
objectclasses: ( 2.5.6.7 NAME 'organizationalPerson' DESC 'Organizational Person' SUP person STRUCTURAL )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            assert len(objectclasses) >= 3
            assert "top" in objectclasses
            assert "person" in objectclasses
            assert "organizationalPerson" in objectclasses

        finally:
            schema_file.unlink(missing_ok=True)


class TestStatistics:
    """Test suite for parsing statistics."""

    def test_statistics_generation(self) -> None:
        """Test that statistics are correctly generated."""
        schema_content = """dn: cn=subschema
attributetypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
attributetypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
objectclasses: ( 2.5.6.6 NAME 'person' DESC 'Person' SUP top STRUCTURAL MUST ( sn $ cn ) )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            stats = data["stats"]
            assert isinstance(stats, dict)
            stats_total_attrs = stats["total_attributes"]
            assert isinstance(stats_total_attrs, int)
            stats_total_ocs = stats["total_objectclasses"]
            assert isinstance(stats_total_ocs, int)
            assert stats_total_attrs >= 2
            assert stats_total_ocs >= 1

        finally:
            schema_file.unlink(missing_ok=True)


class TestErrorHandling:
    """Test suite for error handling."""

    def test_invalid_schema_syntax(self) -> None:
        """Test handling of invalid schema syntax."""
        schema_content = """dn: cn=subschema
attributetypes: invalid syntax here
objectclasses: also invalid
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            # Should succeed but skip invalid definitions
            assert result.is_success

        finally:
            schema_file.unlink(missing_ok=True)

    def test_empty_schema_file(self) -> None:
        """Test handling of empty schema file."""
        schema_content = ""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            # Should succeed with no definitions
            assert result.is_success
            data = result.unwrap()
            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            assert len(attributes) == 0
            assert len(objectclasses) == 0

        finally:
            schema_file.unlink(missing_ok=True)


class TestCompleteSchemaWorkflow:
    """Test suite for complete schema parsing workflows."""

    def test_complete_schema_parsing(self) -> None:
        """Test parsing a complete realistic schema."""
        schema_content = """dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema
attributetypes: ( 2.5.4.3 NAME 'cn' DESC 'RFC4519: common name(s) for which the entity is known by' SUP name )
attributetypes: ( 2.5.4.4 NAME 'sn' DESC 'RFC2256: last (family) name(s) for which the entity is known by' SUP name )
attributetypes: ( 2.5.4.20 NAME 'telephoneNumber' DESC 'RFC2256: Telephone Number' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.50' )
objectclasses: ( 2.5.6.0 NAME 'top' DESC 'RFC4512: top of the superclass chain' ABSTRACT MUST objectClass )
objectclasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )
objectclasses: ( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC2256: an organizational person' SUP person STRUCTURAL MAY ( title $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l ) )
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(schema_content)
            schema_file = Path(f.name)

        try:
            registry = FlextLdifQuirksRegistry()
            params: dict[str, object] = {"file_path": str(schema_file)}

            parser = FlextLdifRfcSchemaParser(params=params, quirk_registry=registry)
            result = parser.execute()

            assert result.is_success
            data = result.unwrap()

            # Verify attributes
            attributes = data[FlextLdifConstants.DictKeys.ATTRIBUTES]
            assert isinstance(attributes, dict)
            assert "cn" in attributes
            assert "sn" in attributes
            assert "telephoneNumber" in attributes

            # Verify telephone number has matching rules
            tel_attr = attributes["telephoneNumber"]
            assert isinstance(tel_attr, dict)
            assert tel_attr["equality"] == "telephoneNumberMatch"
            assert tel_attr["substr"] == "telephoneNumberSubstringsMatch"

            # Verify objectclasses
            objectclasses = data["objectclasses"]
            assert isinstance(objectclasses, dict)
            assert "top" in objectclasses
            assert "person" in objectclasses
            assert "organizationalPerson" in objectclasses

            # Verify inheritance
            org_person = objectclasses["organizationalPerson"]
            assert isinstance(org_person, dict)
            assert org_person["sup"] == "person"

            # Verify MAY attributes
            may_attrs = org_person["may"]
            assert isinstance(may_attrs, list)
            assert "title" in may_attrs
            assert "ou" in may_attrs

        finally:
            schema_file.unlink(missing_ok=True)
