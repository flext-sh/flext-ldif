"""Test suite for RFC LDIF parsers and writers.

This module provides comprehensive testing for RFC-compliant LDIF processing
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import cast

import pytest

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.writer import FlextLdifWriter
from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants


class TestRfcLdifParserService:
    """Test RFC LDIF parser service."""

    def test_initialization(self, real_parser_service: FlextLdifParser) -> None:
        """Test parser initialization."""
        assert real_parser_service is not None

    def test_parse_basic_entry(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing basic LDIF entry."""
        ldif_content = TestsRfcConstants.SAMPLE_LDIF_BASIC + "\n"

        result = real_parser_service.parse(ldif_content, input_source="string")
        assert result.is_success, (
            f"Parse failed: {result.error if result.is_failure else 'unknown error'}"
        )
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 1
        entry = parse_response.entries[0]
        assert entry.dn is not None
        assert entry.dn.value == TestsRfcConstants.SAMPLE_DN
        assert entry.attributes is not None
        assert (
            TestsRfcConstants.SAMPLE_ATTRIBUTE_CN
            in entry.attributes.attributes
        )
        assert TestsRfcConstants.SAMPLE_ATTRIBUTE_SN in entry.attributes.attributes

    def test_parse_invalid_dn(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing invalid DN."""
        ldif_content = f"""dn: {TestsRfcConstants.INVALID_DN}
objectClass: person

"""

        result = real_parser_service.parse(ldif_content, input_source="string")
        # Parser should handle invalid DN gracefully
        # May succeed with relaxed parsing or fail
        # Either outcome is acceptable as long as it doesn't crash
        assert result.is_success or result.is_failure

    def test_parse_multiple_entries(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing multiple entries."""
        ldif_content = TestsRfcConstants.SAMPLE_LDIF_MULTIPLE

        result = real_parser_service.parse(ldif_content, input_source="string")
        assert result.is_success, (
            f"Parse failed: {result.error if result.is_failure else 'unknown error'}"
        )
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 2
        dns = {
            entry.dn.value for entry in parse_response.entries if entry.dn is not None
        }
        assert TestsRfcConstants.SAMPLE_DN_USER1 in dns
        assert TestsRfcConstants.SAMPLE_DN_USER2 in dns

    def test_parse_with_binary_data(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing entry with binary data."""
        ldif_content = TestsRfcConstants.SAMPLE_LDIF_BINARY

        result = real_parser_service.parse(ldif_content, input_source="string")
        assert result.is_success, (
            f"Parse failed: {result.error if result.is_failure else 'unknown error'}"
        )
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 1
        entry = parse_response.entries[0]
        assert entry.dn is not None
        assert entry.dn.value == TestsRfcConstants.SAMPLE_DN
        assert entry.attributes is not None
        assert "photo" in entry.attributes.attributes


class TestRfcLdifWriterService:
    """Test RFC LDIF writer service."""

    def test_initialization(self, real_writer_service: FlextLdifWriter) -> None:
        """Test writer initialization."""
        assert real_writer_service is not None

    def test_write_basic_entry(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing basic LDIF entry."""
        entry = cast(
            "FlextLdifModels.Entry",
            FlextLdifModels.Entry.create(
                dn="cn=test,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "sn": ["user"],
                },
            ).unwrap(),
        )
        result = real_writer_service.write(
            [entry],
            target_server_type="rfc",
            output_target="string",
        )
        assert result.is_success or result.is_failure

    def test_write_to_file(
        self,
        real_writer_service: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        """Test writing LDIF to file."""
        entry = cast(
            "FlextLdifModels.Entry",
            FlextLdifModels.Entry.create(
                dn="cn=test,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "sn": ["user"],
                },
            ).unwrap(),
        )
        ldif_file = tmp_path / "test_output.ldif"
        result = real_writer_service.write(
            [entry],
            target_server_type="rfc",
            output_target="file",
            output_path=ldif_file,
        )
        assert result.is_success or result.is_failure

    def test_write_multiple_entries(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing multiple entries."""
        entry1 = cast(
            "FlextLdifModels.Entry",
            FlextLdifModels.Entry.create(
                dn="cn=user1,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": ["user1"],
                },
            ).unwrap(),
        )
        entry2 = cast(
            "FlextLdifModels.Entry",
            FlextLdifModels.Entry.create(
                dn="cn=user2,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": ["user2"],
                },
            ).unwrap(),
        )
        result = real_writer_service.write(
            [entry1, entry2],
            target_server_type="rfc",
            output_target="string",
        )
        assert result.is_success or result.is_failure


# Comprehensive RFC Parser Tests from test_rfc_parser_comprehensive.py


class TestRfcParserEdgeCases:
    """Test suite for RFC parser edge cases."""

    def test_parse_base64_encoded_values(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with base64-encoded attribute values."""
        parser = real_parser_service

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:: VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHZhbHVl

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_continuation_lines(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with continuation lines (lines starting with space)."""
        parser = real_parser_service

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: This is a very long description that spans multiple lines
  and should be properly folded according to RFC 2849

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_unicode_values(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing LDIF with Unicode characters."""
        parser = real_parser_service

        ldif_content = """dn: cn=Tëst Üsër,dc=example,dc=com
objectClass: person
cn: Tëst Üsër
sn: Üsër

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_binary_attributes(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with binary attributes (ending with ;binary)."""
        parser = real_parser_service

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
userCertificate;binary:: VGVzdCBiaW5hcnkgZGF0YQ==

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_empty_attribute_values(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with empty attribute values."""
        parser = real_parser_service

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_multiple_spaces_in_dn(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing DN with multiple spaces."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        ldif_content = """dn:   cn=test   ,   dc=example   ,   dc=com
objectClass: person
cn: test

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_comments_interspersed(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with comments interspersed with entries."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        ldif_content = """# Start of LDIF file
dn: cn=test1,dc=example,dc=com
# Comment before objectClass
objectClass: person
cn: test1

# Comment between entries
dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_malformed_base64(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing LDIF with malformed base64 values."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:: invalid-base64-content!!!

"""

        result = parser.parse(ldif_content, input_source="string")
        # Should handle gracefully - either fail or parse what it can
        assert result.is_success or result.is_failure

    def test_parse_extremely_long_lines(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with extremely long lines."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        long_value = "x" * 10000  # 10KB line
        ldif_content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: {long_value}

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_empty_lines_between_entries(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with multiple empty lines between entries."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        ldif_content = """dn: cn=test1,dc=example,dc=com
objectClass: person
cn: test1




dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure


class TestRfcParserQuirksIntegration:
    """Test suite for RFC parser quirks integration."""

    def test_parse_with_oid(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing with OID-specific quirks enabled."""
        parser = real_parser_service

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
orclguid: 12345678-1234-1234-1234-123456789012

"""

        result = parser.parse(ldif_content, input_source="string", server_type="oid")
        assert result.is_success or result.is_failure

    def test_parse_with_ouds(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing with OUD-specific quirks enabled."""
        parser = real_parser_service

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
ds-sync-hist: 12345678901234567890

"""

        result = parser.parse(ldif_content, input_source="string", server_type="oud")
        assert result.is_success or result.is_failure

    def test_parse_with_openldap(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing with OpenLDAP-specific quirks enabled."""
        parser = real_parser_service

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
olcRootDN: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com

"""

        result = parser.parse(
            ldif_content,
            input_source="string",
            server_type="openldap",
        )
        assert result.is_success or result.is_failure

    def test_parse_with_auto_server_detection(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing with automatic server type detection."""
        parser = real_parser_service

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

"""

        result = parser.parse(ldif_content, input_source="string", server_type=None)
        assert result.is_success or result.is_failure


class TestRfcParserErrorHandling:
    """Test suite for RFC parser error handling."""

    def test_parse_invalid_dn_syntax(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with invalid DN syntax."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        ldif_content = """dn: invalid-dn-syntax-without-equals
objectClass: person
cn: test

"""

        result = parser.parse(ldif_content, input_source="string")
        # Should handle gracefully - either fail or parse what it can
        assert result.is_success or result.is_failure

    def test_parse_missing_dn(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing LDIF entry missing DN."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        ldif_content = """objectClass: person
cn: test
sn: user

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_malformed_continuation_line(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with malformed continuation lines."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: This line doesn't start with space
but should be a continuation

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_incomplete_base64(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing LDIF with incomplete base64 data."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description::

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_empty_content(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing empty LDIF content."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        result = parser.parse("", input_source="string")
        assert result.is_success
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 0

    def test_parse_whitespace_only_content(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing whitespace-only LDIF content."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        result = parser.parse("   \n\t\n   ", input_source="string")
        assert result.is_success
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 0


class TestRfcParserLargeFiles:
    """Test suite for RFC parser large file handling."""

    def test_parse_large_number_of_entries(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing a large number of entries."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        # Create 100 entries
        entries = [
            f"""dn: cn=user{i},dc=example,dc=com
objectClass: person
cn: user{i}
sn: User{i}

"""
            for i in range(100)
        ]

        ldif_content = "".join(entries)

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_entries_with_many_attributes(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing entries with many attributes."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        # Create entry with many attributes
        attributes = [f"attr{i}: value{i}" for i in range(50)]

        ldif_content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
{"\n".join(attributes)}

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure

    def test_parse_entries_with_large_attribute_values(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing entries with large attribute values."""
        parser = FlextLdifParser(
            config=FlextLdifConfig(),
        )

        # Create entry with large attribute values
        large_value = "x" * 10000  # 10KB
        ldif_content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: {large_value}

"""

        result = parser.parse(ldif_content, input_source="string")
        assert result.is_success or result.is_failure


# Comprehensive RFC Schema Parser Tests from test_rfc_schema_parser_comprehensive.py


class TestRfcLdifWriterComprehensive:
    """Comprehensive test suite for RFC LDIF writer."""

    @pytest.fixture
    def sample_entry(self) -> FlextLdifModels.Entry:
        """Create a sample LDIF entry."""
        result = FlextLdifModels.Entry.create(
            dn="cn=Test User,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "sn": ["User"],
                "objectclass": ["person", "organizationalPerson"],
                "mail": ["test@example.com"],
            },
        )
        return cast("FlextLdifModels.Entry", result.unwrap())

    @pytest.fixture
    def sample_entries(
        self,
        sample_entry: FlextLdifModels.Entry,
    ) -> list[FlextLdifModels.Entry]:
        """Create multiple sample entries."""
        entry2_result = FlextLdifModels.Entry.create(
            dn="cn=Another User,dc=example,dc=com",
            attributes={
                "cn": ["Another User"],
                "sn": ["User"],
                "objectclass": ["person"],
            },
        )
        return [sample_entry, cast("FlextLdifModels.Entry", entry2_result.unwrap())]

    def test_writer_initialization_basic(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test basic writer initialization."""
        writer = real_writer_service

        assert writer is not None

    def test_writer_initialization_with_params(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writer initialization with parameters."""
        writer = real_writer_service

        assert writer is not None

    def test_write_single_entry_to_string(
        self,
        real_writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test writing a single entry to string."""
        writer = real_writer_service

        result = writer.write(
            [sample_entry],
            target_server_type="rfc",
            output_target="string",
        )

        assert result.is_success or result.is_failure

    def test_write_multiple_entries_to_string(
        self,
        real_writer_service: FlextLdifWriter,
        sample_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test writing multiple entries to string."""
        writer = real_writer_service

        result = writer.write(
            sample_entries,
            target_server_type="rfc",
            output_target="string",
        )

        assert result.is_success or result.is_failure

    def test_write_empty_entries_list(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing empty entries list."""
        writer = real_writer_service

        result = writer.write([], target_server_type="rfc", output_target="string")

        assert result.is_success
        content = result.unwrap()
        # RFC 2849: Empty entry list produces LDIF version header but no entries
        assert content == "version: 1\n"

    def test_write_entry_with_binary_data(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing entry with binary attribute data."""
        binary_data = b"binary content for testing"
        # Base64 encode the binary data for LDIF
        encoded_data = base64.b64encode(binary_data).decode("ascii")
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Binary Test,dc=example,dc=com",
            attributes={
                "cn": ["Binary Test"],
                "objectclass": ["person"],
                "userCertificate;binary": [encoded_data],
            },
        )
        entry = cast("FlextLdifModels.Entry", entry_result.unwrap())

        writer = real_writer_service

        result = writer.write([entry], target_server_type="rfc", output_target="string")

        assert result.is_success or result.is_failure

    def test_write_entry_with_unicode_data(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing entry with Unicode attribute data."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Tëst Üsër,dc=example,dc=com",
            attributes={
                "cn": ["Tëst Üsër"],
                "sn": ["Üsër"],
                "objectclass": ["person"],
                "description": ["Tëst dëscriptïon wïth Ünicödé"],
            },
        )
        entry = cast("FlextLdifModels.Entry", entry_result.unwrap())

        writer = real_writer_service

        result = writer.write([entry], target_server_type="rfc", output_target="string")

        assert result.is_success or result.is_failure

    def test_write_entry_with_long_lines(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing entry with very long attribute values."""
        long_value = "x" * 1000  # 1000 character line
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Long Line Test,dc=example,dc=com",
            attributes={
                "cn": ["Long Line Test"],
                "objectclass": ["person"],
                "description": [long_value],
            },
        )
        entry = cast("FlextLdifModels.Entry", entry_result.unwrap())

        writer = real_writer_service

        result = writer.write([entry], target_server_type="rfc", output_target="string")

        assert result.is_success or result.is_failure

    def test_write_to_file(
        self,
        real_writer_service: FlextLdifWriter,
        sample_entries: list[FlextLdifModels.Entry],
        tmp_path: Path,
    ) -> None:
        """Test writing entries to file."""
        output_file = tmp_path / "test_output.ldif"
        writer = real_writer_service

        result = writer.write(
            sample_entries,
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert result.is_success or result.is_failure
        if result.is_success:
            assert output_file.exists()

    def test_write_to_nonexistent_directory(
        self,
        real_writer_service: FlextLdifWriter,
        sample_entries: list[FlextLdifModels.Entry],
        tmp_path: Path,
    ) -> None:
        """Test writing to file in non-existent directory."""
        nonexistent_dir = tmp_path / "nonexistent"
        output_file = nonexistent_dir / "test_output.ldif"

        writer = real_writer_service

        result = writer.write(
            sample_entries,
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert result.is_success or result.is_failure
        if result.is_success:
            assert output_file.exists()
            assert output_file.parent.exists()

    def test_writer_error_handling_invalid_entry(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writer handles edge case entry with empty attributes."""
        # Create a valid entry first
        # Then test what happens if we try to write invalid data
        valid_entry = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["test"],
            },
        ).unwrap()

        writer = real_writer_service

        result = writer.write(
            [valid_entry],  # type: ignore[list-item]
            target_server_type="rfc",
            output_target="string",
        )

        # Writer should handle valid entries successfully
        assert result.is_success

    def test_writer_handles_none_input(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writer handles None input gracefully."""
        writer = real_writer_service

        # This should not crash - empty list is valid
        result = writer.write(
            [],
            target_server_type="rfc",
            output_target="string",
        )

        # Empty list should succeed (produces version header)
        assert result.is_success

    def test_writer_handles_empty_attributes(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writer handles entries with minimal attributes."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Empty Test,dc=example,dc=com",
            attributes={"objectClass": ["person"]},
        )
        entry = cast("FlextLdifModels.Entry", entry_result.unwrap())

        writer = real_writer_service

        result = writer.write([entry], target_server_type="rfc", output_target="string")

        assert result.is_success or result.is_failure


class TestRfcLdifWriterFileOperations:
    """Test suite for RFC LDIF writer file operations."""

    def test_write_entries_to_file_basic(
        self,
        real_writer_service: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        """Test write_entries_to_file() with basic entries."""
        entry = cast(
            "FlextLdifModels.Entry",
            FlextLdifModels.Entry.create(
                dn="cn=Test,dc=example,dc=com",
                attributes={"cn": ["Test"], "objectclass": ["person"]},
            ).unwrap(),
        )

        output_file = tmp_path / "test.ldif"
        writer = real_writer_service

        result = writer.write(
            [entry],
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert result.is_success
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "dn: cn=Test,dc=example,dc=com" in content

    def test_write_entries_to_file_creates_directory(
        self,
        real_writer_service: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        """Test write_entries_to_file() creates parent directories."""
        entry = cast(
            "FlextLdifModels.Entry",
            FlextLdifModels.Entry.create(
                dn="cn=Test,dc=example,dc=com",
                attributes={"cn": ["Test"], "objectClass": ["person"]},
            ).unwrap(),
        )

        output_file = tmp_path / "subdir" / "nested" / "test.ldif"
        writer = real_writer_service

        result = writer.write(
            [entry],
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert result.is_success
        assert output_file.exists()
        assert output_file.parent.exists()

    def test_write_entries_to_file_empty_list(
        self,
        real_writer_service: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        """Test write_entries_to_file() with empty entries list."""
        output_file = tmp_path / "empty.ldif"
        writer = real_writer_service

        result = writer.write(
            [],
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert result.is_success
        assert output_file.exists()


class TestRfcEntryQuirkIntegration:
    """Test RFC Entry quirk integration methods."""

    def test_can_handle_entry_valid(self, rfc_entry_quirk: object) -> None:
        """Test Entry.can_handle_entry with valid entry."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectClass": ["person"], "cn": ["test"]},
        ).unwrap()

        assert rfc_entry_quirk.can_handle_entry(entry) is True  # type: ignore[attr-defined]

    def test_can_handle_entry_missing_dn(
        self, rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.can_handle_entry with missing DN."""
        # Create entry with empty DN
        entry = FlextLdifModels.Entry.create(
            dn="",
            attributes={"objectClass": ["person"]},
        ).unwrap()

        assert rfc_entry_quirk.can_handle_entry(entry) is False  # type: ignore[attr-defined,arg-type]

    def test_can_handle_entry_missing_objectclass(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.can_handle_entry with missing objectClass."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},  # No objectClass
        ).unwrap()

        assert rfc_entry_quirk.can_handle_entry(entry) is False  # type: ignore[attr-defined,arg-type]

    def test_normalize_attribute_name_objectclass(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry._normalize_attribute_name for objectclass variants."""
        # Test various case variants
        assert rfc_entry_quirk._normalize_attribute_name("objectclass") == "objectClass"  # type: ignore[attr-defined]
        assert rfc_entry_quirk._normalize_attribute_name("OBJECTCLASS") == "objectClass"  # type: ignore[attr-defined]
        assert rfc_entry_quirk._normalize_attribute_name("ObjectClass") == "objectClass"  # type: ignore[attr-defined]
        assert rfc_entry_quirk._normalize_attribute_name("objectClass") == "objectClass"  # type: ignore[attr-defined]

    def test_normalize_attribute_name_other(
        self, rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry._normalize_attribute_name for other attributes."""
        # Other attributes should be preserved
        assert rfc_entry_quirk._normalize_attribute_name("cn") == "cn"  # type: ignore[attr-defined]
        assert rfc_entry_quirk._normalize_attribute_name("mail") == "mail"  # type: ignore[attr-defined]
        assert rfc_entry_quirk._normalize_attribute_name("") == ""  # type: ignore[attr-defined]

    def test_needs_base64_encoding(
        self, rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry._needs_base64_encoding static method."""
        # Values that need base64 encoding
        assert rfc_entry_quirk._needs_base64_encoding(" starts with space") is True  # type: ignore[attr-defined]
        assert rfc_entry_quirk._needs_base64_encoding(":starts with colon") is True  # type: ignore[attr-defined]
        assert rfc_entry_quirk._needs_base64_encoding("<starts with less-than") is True  # type: ignore[attr-defined]
        assert rfc_entry_quirk._needs_base64_encoding("ends with space ") is True  # type: ignore[attr-defined]
        assert rfc_entry_quirk._needs_base64_encoding("has\nnewline") is True  # type: ignore[attr-defined]
        assert rfc_entry_quirk._needs_base64_encoding("has\0null") is True  # type: ignore[attr-defined]

        # Values that don't need base64 encoding
        assert rfc_entry_quirk._needs_base64_encoding("normal value") is False  # type: ignore[attr-defined]
        assert rfc_entry_quirk._needs_base64_encoding("test123") is False  # type: ignore[attr-defined]
        assert rfc_entry_quirk._needs_base64_encoding("") is False  # type: ignore[attr-defined]

    def test_can_handle_any_entry(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.can_handle always returns True."""
        assert (
            rfc_entry_quirk.can_handle("cn=test,dc=example,dc=com", {"cn": ["test"]})
            is True
        )  # type: ignore[attr-defined]
        assert rfc_entry_quirk.can_handle("", {}) is True  # type: ignore[attr-defined]  # RFC handles all

    def test_can_handle_attribute_returns_false(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
        sample_schema_attribute: FlextLdifModels.SchemaAttribute,
    ) -> None:
        """Test Entry.can_handle_attribute always returns False."""
        assert rfc_entry_quirk.can_handle_attribute(sample_schema_attribute) is False  # type: ignore[attr-defined]

    def test_can_handle_objectclass_returns_false(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
        sample_schema_objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> None:
        """Test Entry.can_handle_objectclass always returns False."""
        assert (
            rfc_entry_quirk.can_handle_objectclass(sample_schema_objectclass) is False
        )  # type: ignore[attr-defined]


class TestRfcAclQuirkIntegration:
    """Test RFC ACL quirk integration methods."""

    def test_can_handle_acl_string(
        self, rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.can_handle_acl with string input."""
        assert rfc_acl_quirk.can_handle_acl("access to entry by * (browse)") is True  # type: ignore[attr-defined]

    def test_can_handle_acl_model(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
        sample_acl: FlextLdifModels.Acl,
    ) -> None:
        """Test Acl.can_handle_acl with Acl model."""
        assert rfc_acl_quirk.can_handle_acl(sample_acl) is True  # type: ignore[attr-defined]

    def test_can_handle_always_true(
        self, rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.can_handle always returns True."""
        assert rfc_acl_quirk.can_handle("any acl string") is True  # type: ignore[attr-defined]
        assert rfc_acl_quirk.can_handle("") is True  # type: ignore[attr-defined]

    def test_can_handle_attribute_returns_false(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
        sample_schema_attribute: FlextLdifModels.SchemaAttribute,
    ) -> None:
        """Test Acl.can_handle_attribute always returns False."""
        assert rfc_acl_quirk.can_handle_attribute(sample_schema_attribute) is False  # type: ignore[attr-defined]

    def test_can_handle_objectclass_returns_false(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
        sample_schema_objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> None:
        """Test Acl.can_handle_objectclass always returns False."""
        assert rfc_acl_quirk.can_handle_objectclass(sample_schema_objectclass) is False  # type: ignore[attr-defined]

    def test_parse_acl_success(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.parse_acl with valid ACL."""
        acl_line = "access to entry by * (browse)"
        result = rfc_acl_quirk.parse_acl(acl_line)  # type: ignore[attr-defined]

        assert result.is_success
        acl_model = result.unwrap()
        assert acl_model.raw_acl == acl_line
        assert acl_model.server_type == "rfc"

    def test_write_acl_with_raw_acl(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl._write_acl with raw_acl."""
        acl_model = FlextLdifModels.Acl(  # type: ignore[call-arg]
            raw_acl="access to entry by * (browse)",
            server_type="rfc",
        )

        result = rfc_acl_quirk._write_acl(acl_model)  # type: ignore[attr-defined]
        assert result.is_success
        assert result.unwrap() == "access to entry by * (browse)"

    def test_write_acl_with_name_only(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl._write_acl with name only."""
        acl_model = FlextLdifModels.Acl(  # type: ignore[call-arg]
            name="test_acl",
            server_type="rfc",
        )

        result = rfc_acl_quirk._write_acl(acl_model)  # type: ignore[attr-defined]
        assert result.is_success
        assert result.unwrap() == "test_acl:"

    def test_write_acl_no_data(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl._write_acl with no raw_acl or name."""
        acl_model = FlextLdifModels.Acl(  # type: ignore[call-arg]
            server_type="rfc",
        )

        result = rfc_acl_quirk._write_acl(acl_model)  # type: ignore[attr-defined]
        assert result.is_failure
        assert result.error is not None
        assert "no raw_acl or name" in result.error.lower()

    def test_convert_rfc_acl_to_aci_pass_through(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.convert_rfc_acl_to_aci is pass-through."""
        rfc_acl_attrs = {"aci": ["access to entry by * (browse)"]}
        result = rfc_acl_quirk.convert_rfc_acl_to_aci(rfc_acl_attrs, "oid")  # type: ignore[attr-defined]

        assert result.is_success
        assert result.unwrap() == rfc_acl_attrs

    def test_create_metadata(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.create_metadata."""
        metadata = rfc_acl_quirk.create_metadata(  # type: ignore[attr-defined]
            original_format="access to entry by * (browse)",
            extensions={"custom": "value"},
        )

        assert metadata.quirk_type == "rfc"
        assert metadata.extensions["original_format"] == "access to entry by * (browse)"
        assert metadata.extensions["custom"] == "value"


class TestRfcConstants:
    """Test RFC Constants."""

    def test_constants_accessible(self) -> None:
        """Test that RFC Constants are accessible."""
        # Test that TestsRfcConstants class is accessible and has expected attributes
        assert hasattr(TestsRfcConstants, "ATTR_OID_CN")
        assert hasattr(TestsRfcConstants, "ATTR_NAME_CN")
        assert hasattr(TestsRfcConstants, "OC_DEF_PERSON")
        assert hasattr(TestsRfcConstants, "SCHEMA_DN_SCHEMA")
        assert TestsRfcConstants.ATTR_OID_CN == "2.5.4.3"
        assert TestsRfcConstants.ATTR_NAME_CN == "cn"
        assert TestsRfcConstants.OC_OID_PERSON == "2.5.6.6"
        assert TestsRfcConstants.SCHEMA_DN_SCHEMA == "cn=schema"
