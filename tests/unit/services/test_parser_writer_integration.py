"""Integration tests for FlextLdifParser and FlextLdifWriter.

Tests the interaction between parsing and writing with various options combinations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.writer import FlextLdifWriter


class TestParserWriterIntegration:
    """Test integration between parser and writer services."""

    @pytest.fixture
    def parser_service(self) -> FlextLdifParser:
        """Create parser service instance."""
        return FlextLdifParser(config=FlextLdifConfig())

    @pytest.fixture
    def writer_service(self) -> FlextLdifWriter:
        """Create writer service instance."""
        return FlextLdifWriter()

    @pytest.fixture
    def complex_ldif_content(self) -> str:
        """Complex LDIF content for roundtrip testing."""
        return """version: 1

dn: cn=schema
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectClasses: ( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people
aci: (targetattr="*")(version 3.0; acl "Admin Access"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)
createTimestamp: 20250130120000Z
modifyTimestamp: 20250130130000Z

dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
telephoneNumber: +1-555-123-4567
description: A very long description that should test line folding behavior according to RFC 2849 specifications
userPassword: {SSHA}abcdefghijklmnopqrstuvwxyz==
createTimestamp: 20250130120000Z
entryUUID: 12345678-1234-1234-1234-123456789abc

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: person
cn: Jane Smith
sn: Smith
emptyAttribute:
mail: jane.smith@example.com
"""

    def test_roundtrip_basic(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
        complex_ldif_content: str,
    ) -> None:
        """Test basic parse -> write roundtrip."""
        from tests.helpers.test_rfc_helpers import RfcTestHelpers

        write_options = FlextLdifModels.WriteFormatOptions(
            base64_encode_binary=False,
            include_version_header=True,
        )
        _, output_ldif = RfcTestHelpers.test_parse_write_roundtrip_with_options(
            parser_service,
            writer_service,
            complex_ldif_content,
            write_options=write_options,
            must_contain=[
                "dn: cn=John Doe,ou=people,dc=example,dc=com",
                "dn: cn=Jane Smith,ou=people,dc=example,dc=com",
                "objectClass",
            ],
        )
        assert "cn: John Doe" in output_ldif or "cn::" in output_ldif

    def test_roundtrip_with_attribute_order_preservation(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test roundtrip with attribute order preservation."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
objectClass: person
sn: Test
cn: Test User
givenName: Test
mail: test@example.com
telephoneNumber: 123-456-7890
"""

        from tests.helpers.test_rfc_helpers import RfcTestHelpers

        parse_options = FlextLdifModels.ParseFormatOptions(
            preserve_attribute_order=True,
        )
        write_options = FlextLdifModels.WriteFormatOptions(respect_attribute_order=True)
        _, output = RfcTestHelpers.test_parse_write_roundtrip_with_options(
            parser_service,
            writer_service,
            ldif_content,
            parse_options=parse_options,
            write_options=write_options,
        )

        # Extract attribute order from output
        lines = [
            line.strip()
            for line in output.split("\n")
            if ":" in line
            and not line.startswith("dn:")
            and not line.startswith("version:")
        ]
        attribute_lines = [line for line in lines if not line.startswith("#")]

        # Should maintain some semblance of original order
        assert len(attribute_lines) > 0

    def test_roundtrip_with_operational_attributes_filtering(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
        complex_ldif_content: str,
    ) -> None:
        """Test roundtrip with operational attributes filtering."""
        # Parse excluding operational attributes
        parse_options = FlextLdifModels.ParseFormatOptions(
            include_operational_attrs=False,
        )
        parse_result = parser_service.parse(
            content=complex_ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=parse_options,
        )

        assert parse_result.is_success
        entries = parse_result.unwrap().entries

        # Verify operational attributes were filtered out
        for entry in entries:
            attr_names = [name.lower() for name in entry.attributes]
            operational_attrs = ["createtimestamp", "modifytimestamp", "entryuuid"]
            for op_attr in operational_attrs:
                assert op_attr not in attr_names, (
                    f"Found operational attribute {op_attr} in {entry.dn}"
                )

        # Write the filtered entries
        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="string",
        )

        assert write_result.is_success
        output = write_result.unwrap()

        # Output should not contain operational attributes
        assert "createTimestamp:" not in output
        assert "entryUUID:" not in output

    def test_roundtrip_with_schema_processing(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
        complex_ldif_content: str,
    ) -> None:
        """Test roundtrip with schema processing."""
        # Parse with schema processing enabled
        parse_options = FlextLdifModels.ParseFormatOptions(auto_parse_schema=True)
        parse_result = parser_service.parse(
            content=complex_ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=parse_options,
        )

        assert parse_result.is_success
        response = parse_result.unwrap()

        # Should have identified schema entries
        assert response.statistics.schema_entries > 0
        assert response.statistics.data_entries > 0

        # Write all entries back
        write_result = writer_service.write(
            entries=response.entries,
            target_server_type="rfc",
            output_target="string",
        )

        assert write_result.is_success
        output = write_result.unwrap()

        # Should contain both schema and data entries
        assert "dn: cn=schema" in output
        assert "attributeTypes:" in output
        assert "dn: cn=John Doe" in output

    def test_roundtrip_with_acl_processing(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
        complex_ldif_content: str,
    ) -> None:
        """Test roundtrip with ACL processing."""
        # Parse with ACL extraction enabled
        parse_options = FlextLdifModels.ParseFormatOptions(auto_extract_acls=True)
        parse_result = parser_service.parse(
            content=complex_ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=parse_options,
        )

        assert parse_result.is_success
        entries = parse_result.unwrap().entries

        # Write back with metadata comments to see ACL processing results
        write_options = FlextLdifModels.WriteFormatOptions(
            write_metadata_as_comments=True,
        )
        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="string",
            format_options=write_options,
        )

        assert write_result.is_success
        output = write_result.unwrap()

        # Should contain original ACI attributes
        assert "aci:" in output

    def test_roundtrip_with_validation_and_error_handling(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test roundtrip with validation and error handling."""
        # LDIF with some validation issues
        problematic_ldif = """version: 1

dn: cn=valid,dc=example,dc=com
objectClass: person
cn: Valid User
sn: User

dn: cn=missing-objectclass,dc=example,dc=com
cn: Missing ObjectClass
sn: User

dn: cn=empty-values,dc=example,dc=com
objectClass: person
cn:
sn: Empty Values
"""

        # Parse with validation but non-strict mode
        parse_options = FlextLdifModels.ParseFormatOptions(
            validate_entries=True,
            strict_schema_validation=False,
            max_parse_errors=5,
        )
        parse_result = parser_service.parse(
            content=problematic_ldif,
            input_source="string",
            server_type="rfc",
            format_options=parse_options,
        )

        assert parse_result.is_success
        response = parse_result.unwrap()

        # Some entries should have been processed despite issues
        assert len(response.entries) > 0

        # Write with empty value filtering
        write_options = FlextLdifModels.WriteFormatOptions(write_empty_values=False)
        write_result = writer_service.write(
            entries=response.entries,
            target_server_type="rfc",
            output_target="string",
            format_options=write_options,
        )

        assert write_result.is_success
        output = write_result.unwrap()

        # Empty attributes should be filtered out
        assert "cn: \n" not in output and "cn:\n" not in output

    def test_roundtrip_file_operations(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
        complex_ldif_content: str,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip with file operations."""
        # Create input file
        input_file = tmp_path / "input.ldif"
        input_file.write_text(complex_ldif_content, encoding="utf-8")

        # Parse from file
        parse_result = parser_service.parse(
            content=input_file,
            input_source="file",
            server_type="rfc",
        )

        assert parse_result.is_success
        entries = parse_result.unwrap().entries

        # Write to file
        output_file = tmp_path / "output.ldif"
        write_options = FlextLdifModels.WriteFormatOptions(
            include_version_header=True,
            include_timestamps=True,
        )
        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
            format_options=write_options,
        )

        assert write_result.is_success
        assert output_file.exists()

        # Verify file content
        output_content = output_file.read_text(encoding="utf-8")
        assert "version: 1" in output_content
        assert "# Generated on:" in output_content
        assert "dn: cn=John Doe" in output_content

    def test_roundtrip_ldap3_format(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test roundtrip using ldap3 format."""
        # Real ldap3 data format for testing
        ldap3_data = [
            (
                "cn=test1,dc=example,dc=com",
                {
                    "objectClass": ["person"],
                    "cn": ["Test User 1"],
                    "sn": ["User1"],
                    "mail": ["test1@example.com"],
                },
            ),
            (
                "cn=test2,dc=example,dc=com",
                {
                    "objectClass": ["person"],
                    "cn": ["Test User 2"],
                    "sn": ["User2"],
                    "mail": ["test2@example.com"],
                },
            ),
        ]

        # Parse from ldap3 format
        parse_result = parser_service.parse(
            content=ldap3_data,
            input_source="ldap3",
            server_type="rfc",
        )

        assert parse_result.is_success
        entries = parse_result.unwrap().entries
        assert len(entries) == 2

        # Write back to ldap3 format
        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="ldap3",
        )

        assert write_result.is_success
        output_ldap3 = write_result.unwrap()

        assert isinstance(output_ldap3, list)
        assert len(output_ldap3) == 2

        # Verify structure
        for dn, attrs in output_ldap3:
            assert isinstance(dn, str)
            assert isinstance(attrs, dict)
            assert "objectClass" in attrs
            assert "cn" in attrs

    def test_format_options_compatibility(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test that parse and write options work well together."""
        ldif_content = """version: 1

dn: cn=compatibility-test,dc=example,dc=com
objectClass: person
sn: Test
cn: Compatibility Test
givenName: Compatibility
mail: compat@example.com
createTimestamp: 20250130120000Z
entryUUID: 12345678-1234-1234-1234-123456789abc
"""

        # Parse with comprehensive options
        parse_options = FlextLdifModels.ParseFormatOptions(
            preserve_attribute_order=True,
            include_operational_attrs=False,
            validate_entries=True,
            normalize_dns=True,
        )

        parse_result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=parse_options,
        )

        assert parse_result.is_success
        entries = parse_result.unwrap().entries

        # Write with comprehensive options
        write_options = FlextLdifModels.WriteFormatOptions(
            respect_attribute_order=True,
            include_version_header=True,
            include_timestamps=True,
            write_metadata_as_comments=True,
            line_width=60,
            fold_long_lines=True,
            base64_encode_binary=True,
            normalize_attribute_names=False,
        )

        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="string",
            format_options=write_options,
        )

        assert write_result.is_success
        output = write_result.unwrap()

        # Verify various options worked
        assert "version: 1" in output  # include_version_header
        assert "# Generated on:" in output  # include_timestamps
        assert "createTimestamp:" not in output  # operational attrs filtered
        assert "entryUUID:" not in output  # operational attrs filtered

        # Check line width compliance
        lines = output.split("\n")
        long_lines = [
            line for line in lines if len(line) > 60 and not line.startswith(" ")
        ]
        assert len(long_lines) == 0

    def test_error_propagation(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test that errors are properly propagated through the pipeline."""
        # Test invalid server type in parser
        parse_result = parser_service.parse(
            content="dn: cn=test\nobjectClass: person\ncn: test",
            input_source="string",
            server_type="invalid_server_type",
        )

        assert parse_result.is_failure
        error_msg = parse_result.error or ""
        assert "server type" in error_msg.lower()

        # Test invalid server type in writer
        valid_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"objectClass": ["person"], "cn": ["test"]},
            ),
        )

        write_result = writer_service.write(
            entries=[valid_entry],
            target_server_type="invalid_server_type",
            output_target="string",
        )

        assert write_result.is_failure
        error_msg = write_result.error or ""
        assert "server type" in error_msg.lower()

    def test_performance_with_large_dataset(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test performance with larger dataset."""
        # Generate a larger LDIF dataset
        large_ldif_parts = ["version: 1\n"]

        for i in range(100):  # 100 entries
            entry_ldif = f"""
dn: cn=user{i:03d},ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
cn: User {i:03d}
sn: User{i:03d}
givenName: Test
mail: user{i:03d}@example.com
telephoneNumber: +1-555-{i:03d}-{i:04d}
description: Test user number {i} for performance testing
"""
            large_ldif_parts.append(entry_ldif)

        large_ldif = "\n".join(large_ldif_parts)

        # Parse the large dataset
        parse_result = parser_service.parse(
            content=large_ldif,
            input_source="string",
            server_type="rfc",
        )

        assert parse_result.is_success
        entries = parse_result.unwrap().entries
        assert len(entries) == 100

        # Write the large dataset
        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="string",
        )

        assert write_result.is_success
        output = write_result.unwrap()

        # Verify all entries are present
        assert output.count("dn: cn=user") == 100
        assert "cn=user099" in output  # Last entry

    def test_edge_case_empty_and_special_values(
        self,
        parser_service: FlextLdifParser,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test handling of empty and special values."""
        edge_case_ldif = """version: 1

dn: cn=edge-case,dc=example,dc=com
objectClass: person
cn: edge-case
sn: Test
emptyValue:
spaceStart:  starts with space
spaceEnd: ends with space
colonStart: : starts with colon
multiLine: This is a very
 long multi-line
 value that spans
 multiple lines
"""

        # Parse edge cases
        parse_result = parser_service.parse(
            content=edge_case_ldif,
            input_source="string",
            server_type="rfc",
        )

        assert parse_result.is_success
        entries = parse_result.unwrap().entries

        # Write with special handling
        write_options = FlextLdifModels.WriteFormatOptions(
            write_empty_values=True,
            base64_encode_binary=True,
            fold_long_lines=True,
        )

        write_result = writer_service.write(
            entries=entries,
            target_server_type="rfc",
            output_target="string",
            format_options=write_options,
        )

        assert write_result.is_success
        output = write_result.unwrap()

        # Values with special characteristics should be handled properly
        # (base64 encoded or preserved as-is depending on content)
        assert "emptyValue:" in output
        assert (
            "spaceStart::" in output or "spaceStart: " in output
        )  # May be base64 encoded
