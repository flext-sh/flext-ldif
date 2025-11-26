"""Test suite for RFC 4512 schema parser.

Comprehensive testing for FlextLdifParser automatic schema parsing
which parses LDAP schema definitions according to RFC 4512 specification.

All tests use real implementations with real data, no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from flext_ldif import FlextLdifModels, FlextLdifParser
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests.helpers.test_quirk_helpers import QuirkTestHelpers
from tests.helpers.test_rfc_helpers import RfcTestHelpers
from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

# Test constants - always at top of module, no type checking
# Use classes directly, no instantiation needed


class TestRfcSchemaParserInitialization:
    """Test suite for RFC schema parser initialization."""

    @pytest.mark.timeout(5)
    def test_parser_service_initialization(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parser service initialization with real functionality."""
        parser = real_parser_service

        # Test real functionality - parser should be able to parse valid LDIF
        test_ldif = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""

        result = parser.parse(
            content=test_ldif, input_source="string", server_type="rfc",
        )
        assert result.is_success
        entries = result.unwrap().entries
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"


class TestAutomaticSchemaDetection:
    """Test suite for automatic schema entry detection and parsing."""

    @pytest.mark.timeout(5)
    def test_parse_schema_entry_automatic_detection(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test automatic detection and parsing of schema entry."""
        entries = RfcTestHelpers.test_parse_ldif_content(
            real_parser_service,
            TestsRfcConstants.SAMPLE_SCHEMA_CONTENT,
            expected_count=1,
            server_type="rfc",
        )
        assert (
            "cn=subschema" in str(entries[0].dn.value).lower() if entries[0].dn else ""
        )

    @pytest.mark.timeout(10)
    def test_parse_schema_variations(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing various schema configurations."""
        test_cases = [
            (
                f"""dn: {TestsRfcConstants.SCHEMA_DN_SCHEMA}
objectClass: top
objectClass: subschema
attributeTypes: {TestsRfcConstants.ATTR_DEF_CN_COMPLETE}
""",
                1,
                None,
            ),
            (
                f"""dn: {TestsRfcConstants.SCHEMA_DN_SCHEMA_SYSTEM}
objectClass: subschema
attributeTypes: {TestsRfcConstants.ATTR_DEF_OBJECTCLASS}
""",
                1,
                None,
            ),
            (
                """dn: cn=John Doe,o=example,c=com
objectClass: person
cn: John Doe
sn: Doe
""",
                1,
                None,
            ),
            (
                f"""dn: {TestsRfcConstants.SCHEMA_DN_SUBSCHEMA}
objectClass: subschema
attributeTypes: {TestsRfcConstants.ATTR_DEF_CN_COMPLETE}
attributeTypes: {TestsRfcConstants.ATTR_DEF_SN}
attributeTypes: ( 0.9.2342.19200300.100.1.3 NAME 'mail' \
DESC 'Email' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
""",
                1,
                ["attributeTypes"],
            ),
            (
                f"""dn: {TestsRfcConstants.SCHEMA_DN_SUBSCHEMA}
objectClass: subschema
objectClasses: {TestsRfcConstants.OC_DEF_PERSON_FULL}
objectClasses: ( 2.5.6.7 NAME 'organizationalPerson' \
DESC 'Organizational Person' SUP person )
""",
                1,
                ["objectClasses"],
            ),
            (
                f"""dn: {TestsRfcConstants.SCHEMA_DN_SUBSCHEMA}
objectClass: subschema
attributeTypes: {TestsRfcConstants.ATTR_DEF_CN_COMPLETE}
""",
                1,
                None,
            ),
        ]
        for schema_content, expected_count, expected_attrs in test_cases:
            entries = RfcTestHelpers.test_parse_ldif_content(
                real_parser_service,
                schema_content,
                expected_count=expected_count,
            )
            entry = entries[0]
            assert entry.dn is not None
            assert entry.dn.value is not None
            if expected_attrs:
                assert entry.attributes is not None
                for attr_name in expected_attrs:
                    assert attr_name in entry.attributes.attributes

    @pytest.mark.timeout(5)
    def test_parse_schema_with_server_specifics(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test schema parsing with server-specific quirks."""
        schema_content = f"""dn: {TestsRfcConstants.SCHEMA_DN_SUBSCHEMA}
objectClass: subschema
attributeTypes: {TestsRfcConstants.ATTR_DEF_CN_COMPLETE}
"""
        entries = RfcTestHelpers.test_parse_ldif_content(
            real_parser_service,
            schema_content,
            expected_count=1,
            server_type="oud",
        )
        assert entries[0].dn is not None
        assert entries[0].dn.value is not None

    @pytest.mark.timeout(5)
    def test_parse_schema_from_file(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing schema from a file."""
        schema_content = f"""dn: {TestsRfcConstants.SCHEMA_DN_SUBSCHEMA}
objectClass: subschema
attributeTypes: {TestsRfcConstants.ATTR_DEF_SN}
"""

        with NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            _ = f.write(schema_content)
            schema_file = Path(f.name)

        try:
            entries = RfcTestHelpers.test_parse_ldif_file(
                real_parser_service,
                schema_file,
                expected_count=1,
            )
            assert entries[0].dn is not None
            assert entries[0].dn.value is not None
        finally:
            if schema_file.exists():
                schema_file.unlink()

    @pytest.mark.timeout(5)
    def test_empty_and_line_folding_schema(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing empty schema and schema with line folding."""
        entries = RfcTestHelpers.test_parse_ldif_content(
            real_parser_service,
            "",
            expected_count=0,
            server_type="rfc",
        )
        assert len(entries) == 0

        schema_content = f"""dn: {TestsRfcConstants.SCHEMA_DN_SUBSCHEMA}
objectClass: subschema
attributeTypes: ( {TestsRfcConstants.ATTR_OID_CN} \
NAME '{TestsRfcConstants.ATTR_NAME_CN}' \
DESC 'Common Name - this is a very long description
  that spans multiple lines' \
SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
"""
        entries = RfcTestHelpers.test_parse_ldif_content(
            real_parser_service,
            schema_content,
        )
        assert len(entries) > 0
        assert entries[0].attributes is not None
        assert "attributeTypes" in entries[0].attributes.attributes


class TestRfcSchemaQuirkDirectUsage:
    """Test direct usage of RFC Schema quirk methods."""

    @pytest.mark.timeout(5)
    def test_schema_parse_attribute_direct(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.parse with attribute definition."""
        _ = QuirkTestHelpers.test_schema_parse_and_validate_complete(
            rfc_schema_quirk,
            TestsRfcConstants.ATTR_DEF_CN_COMPLETE,
            expected_oid=TestsRfcConstants.ATTR_OID_CN,
            expected_name=TestsRfcConstants.ATTR_NAME_CN,
        )

    @pytest.mark.timeout(5)
    def test_schema_parse_objectclass_direct(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.parse with objectClass definition."""
        oc = RfcTestHelpers.test_schema_parse_objectclass(
            rfc_schema_quirk,
            TestsRfcConstants.OC_DEF_PERSON_BASIC,
            TestsRfcConstants.OC_OID_PERSON,
            TestsRfcConstants.OC_NAME_PERSON,
        )
        assert oc.oid == TestsRfcConstants.OC_OID_PERSON
        assert oc.name == TestsRfcConstants.OC_NAME_PERSON

    @pytest.mark.timeout(5)
    def test_schema_quirk_methods(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
        sample_schema_attribute: FlextLdifModels.SchemaAttribute,
        sample_schema_objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> None:
        """Test Schema quirk can_handle and should_filter methods."""
        assert rfc_schema_quirk.can_handle_attribute("any attribute definition") is True
        assert (
            rfc_schema_quirk.can_handle_attribute(TestsRfcConstants.ATTR_DEF_CN) is True
        )
        assert (
            rfc_schema_quirk.can_handle_objectclass("any objectclass definition")
            is True
        )
        assert (
            rfc_schema_quirk.can_handle_objectclass(TestsRfcConstants.OC_DEF_PERSON)
            is True
        )
        assert (
            rfc_schema_quirk.should_filter_out_attribute(sample_schema_attribute)
            is False
        )
        assert (
            rfc_schema_quirk.should_filter_out_objectclass(sample_schema_objectclass)
            is False
        )
