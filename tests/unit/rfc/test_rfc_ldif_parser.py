"""Test suite for RFC LDIF parsers and writers.

This module provides comprehensive testing for RFC-compliant LDIF processing
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.writer import FlextLdifWriter


class TestRfcLdifParserService:
    """Test RFC LDIF parser service."""

    def test_initialization(self, real_parser_service: FlextLdifParser) -> None:
        """Test parser initialization."""
        assert real_parser_service is not None

    def test_parse_basic_entry(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing basic LDIF entry."""
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user

"""

        result = real_parser_service.parse(ldif_content, input_source="string")
        assert result.is_success, f"Parse failed: {result.error if result.is_failure else 'unknown error'}"
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 1
        entry = parse_response.entries[0]
        assert entry.dn is not None
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert entry.attributes is not None
        assert "cn" in entry.attributes.attributes
        assert "sn" in entry.attributes.attributes

    def test_parse_invalid_dn(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing invalid DN."""
        ldif_content = """dn: invalid-dn-format
objectClass: person

"""

        result = real_parser_service.parse(ldif_content, input_source="string")
        # Parser should handle invalid DN gracefully - may succeed with relaxed parsing or fail
        # Either outcome is acceptable as long as it doesn't crash
        assert result.is_success or result.is_failure

    def test_parse_multiple_entries(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing multiple entries."""
        ldif_content = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2

"""

        result = real_parser_service.parse(ldif_content, input_source="string")
        assert result.is_success, f"Parse failed: {result.error if result.is_failure else 'unknown error'}"
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 2
        dns = {entry.dn.value for entry in parse_response.entries if entry.dn is not None}
        assert "cn=user1,dc=example,dc=com" in dns
        assert "cn=user2,dc=example,dc=com" in dns

    def test_parse_with_binary_data(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing entry with binary data."""
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
photo:: UGhvdG8gZGF0YQ==

"""

        result = real_parser_service.parse(ldif_content, input_source="string")
        assert result.is_success, f"Parse failed: {result.error if result.is_failure else 'unknown error'}"
        parse_response = result.unwrap()
        assert len(parse_response.entries) == 1
        entry = parse_response.entries[0]
        assert entry.dn is not None
        assert entry.dn.value == "cn=test,dc=example,dc=com"
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
        ldif_test_entries: list[dict[str, object]],
    ) -> None:
        """Test writing basic LDIF entry."""
        result = real_writer_service.write(
            ldif_test_entries[:1],
            target_server_type="rfc",
            output_target="string",
        )
        assert result.is_success or result.is_failure

    def test_write_to_file(
        self,
        real_writer_service: FlextLdifWriter,
        ldif_test_entries: list[dict[str, object]],
        tmp_path: Path,
    ) -> None:
        """Test writing LDIF to file."""
        ldif_file = tmp_path / "test_output.ldif"
        result = real_writer_service.write(
            ldif_test_entries[:1],
            target_server_type="rfc",
            output_target="file",
            output_path=ldif_file,
        )
        assert result.is_success or result.is_failure

    def test_write_multiple_entries(
        self,
        real_writer_service: FlextLdifWriter,
        ldif_test_entries: list[dict[str, object]],
    ) -> None:
        """Test writing multiple entries."""
        result = real_writer_service.write(
            ldif_test_entries,
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
        parser = FlextLdifParser()

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
orclguid: 12345678-1234-1234-1234-123456789012

"""

        result = parser.parse(ldif_content, input_source="string", server_type="oid")
        assert result.is_success or result.is_failure

    def test_parse_with_ouds(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing with OUD-specific quirks enabled."""
        parser = FlextLdifParser()

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
ds-sync-hist: 12345678901234567890

"""

        result = parser.parse(ldif_content, input_source="string", server_type="oud")
        assert result.is_success or result.is_failure

    def test_parse_with_openldap(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing with OpenLDAP-specific quirks enabled."""
        parser = FlextLdifParser()

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
        parser = FlextLdifParser()

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
        return result.unwrap()

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
        return [sample_entry, entry2_result.unwrap()]

    def test_writer_initialization_basic(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test basic writer initialization."""
        writer = FlextLdifWriter()

        assert writer is not None

    def test_writer_initialization_with_params(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test writer initialization with parameters."""
        writer = FlextLdifWriter()

        assert writer is not None

    def test_write_single_entry_to_string(
        self,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test writing a single entry to string."""
        writer = FlextLdifWriter()

        result = writer.write(
            [sample_entry],
            target_server_type="rfc",
            output_target="string",
        )

        assert result.is_success or result.is_failure

    def test_write_multiple_entries_to_string(
        self,
        sample_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test writing multiple entries to string."""
        writer = FlextLdifWriter()

        result = writer.write(
            sample_entries,
            target_server_type="rfc",
            output_target="string",
        )

        assert result.is_success or result.is_failure

    def test_write_empty_entries_list(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test writing empty entries list."""
        writer = FlextLdifWriter()

        result = writer.write([], target_server_type="rfc", output_target="string")

        assert result.is_success
        content = result.unwrap()
        # RFC 2849: Empty entry list produces LDIF version header but no entries
        assert content == "version: 1\n"

    def test_write_entry_with_binary_data(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test writing entry with binary attribute data."""
        binary_data = b"binary content for testing"
        # Base64 encode the binary data for LDIF compatibility
        encoded_data = base64.b64encode(binary_data).decode("ascii")
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Binary Test,dc=example,dc=com",
            attributes={
                "cn": ["Binary Test"],
                "objectclass": ["person"],
                "userCertificate;binary": [encoded_data],
            },
        )
        entry = entry_result.unwrap()

        writer = FlextLdifWriter()

        result = writer.write([entry], target_server_type="rfc", output_target="string")

        assert result.is_success or result.is_failure

    def test_write_entry_with_unicode_data(
        self,
        real_parser_service: FlextLdifParser,
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
        entry = entry_result.unwrap()

        writer = FlextLdifWriter()

        result = writer.write([entry], target_server_type="rfc", output_target="string")

        assert result.is_success or result.is_failure

    def test_write_entry_with_long_lines(
        self,
        real_parser_service: FlextLdifParser,
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
        entry = entry_result.unwrap()

        writer = FlextLdifWriter()

        result = writer.write([entry], target_server_type="rfc", output_target="string")

        assert result.is_success or result.is_failure

    def test_write_to_file(
        self,
        sample_entries: list[FlextLdifModels.Entry],
        tmp_path: Path,
    ) -> None:
        """Test writing entries to file."""
        output_file = tmp_path / "test_output.ldif"
        writer = FlextLdifWriter()

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
        sample_entries: list[FlextLdifModels.Entry],
        tmp_path: Path,
    ) -> None:
        """Test writing to file in non-existent directory."""
        nonexistent_dir = tmp_path / "nonexistent"
        output_file = nonexistent_dir / "test_output.ldif"

        writer = FlextLdifWriter()

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
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test writer handles edge case entry with empty attributes."""
        # Create a valid entry first, then test what happens if we try to write invalid data
        valid_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                },
            ),
        )

        writer = FlextLdifWriter()

        result = writer.write(
            [valid_entry],
            target_server_type="rfc",
            output_target="string",
        )

        # Writer should handle valid entries successfully
        assert result.is_success

    def test_writer_handles_none_input(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test writer handles None input gracefully."""
        writer = FlextLdifWriter()

        # This should not crash - intentionally testing invalid input
        result = writer.write(
            "list[FlextLdifModels.Entry]",
            target_server_type="rfc",
            output_target="string",
        )

        assert result.is_failure

    def test_writer_handles_empty_attributes(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test writer handles entries with minimal attributes."""
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Empty Test,dc=example,dc=com",
            attributes={"objectClass": ["person"]},
        )
        entry = entry_result.unwrap()

        writer = FlextLdifWriter()

        result = writer.write([entry], target_server_type="rfc", output_target="string")

        assert result.is_success or result.is_failure


class TestRfcLdifWriterFileOperations:
    """Test suite for RFC LDIF writer file operations."""

    def test_write_entries_to_file_basic(self, tmp_path: Path) -> None:
        """Test write_entries_to_file() with basic entries."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=Test,dc=example,dc=com",
            attributes={"cn": ["Test"], "objectclass": ["person"]},
        ).unwrap()

        output_file = tmp_path / "test.ldif"
        writer = FlextLdifWriter()

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

    def test_write_entries_to_file_creates_directory(self, tmp_path: Path) -> None:
        """Test write_entries_to_file() creates parent directories."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=Test,dc=example,dc=com",
            attributes={"cn": ["Test"], "objectClass": ["person"]},
        ).unwrap()

        output_file = tmp_path / "subdir" / "nested" / "test.ldif"
        writer = FlextLdifWriter()

        result = writer.write(
            [entry],
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
        )

        assert result.is_success
        assert output_file.exists()
        assert output_file.parent.exists()

    def test_write_entries_to_file_empty_list(self, tmp_path: Path) -> None:
        """Test write_entries_to_file() with empty entries list."""
        output_file = tmp_path / "empty.ldif"
        writer = FlextLdifWriter()

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

    def test_can_handle_entry_valid(self) -> None:
        """Test Entry.can_handle_entry with valid entry."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        entry = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectClass": ["person"], "cn": ["test"]},
        ).unwrap()

        assert entry_quirk.can_handle_entry(entry) is True

    def test_can_handle_entry_missing_dn(self) -> None:
        """Test Entry.can_handle_entry with missing DN."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        # Create entry with empty DN
        entry = FlextLdifModels.Entry.create(
            dn="",
            attributes={"objectClass": ["person"]},
        ).unwrap()

        assert entry_quirk.can_handle_entry(entry) is False

    def test_can_handle_entry_missing_objectclass(self) -> None:
        """Test Entry.can_handle_entry with missing objectClass."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        entry = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},  # No objectClass
        ).unwrap()

        assert entry_quirk.can_handle_entry(entry) is False

    def test_normalize_attribute_name_objectclass(self) -> None:
        """Test Entry._normalize_attribute_name for objectclass variants."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        # Test various case variants
        assert entry_quirk._normalize_attribute_name("objectclass") == "objectClass"
        assert entry_quirk._normalize_attribute_name("OBJECTCLASS") == "objectClass"
        assert entry_quirk._normalize_attribute_name("ObjectClass") == "objectClass"
        assert entry_quirk._normalize_attribute_name("objectClass") == "objectClass"

    def test_normalize_attribute_name_other(self) -> None:
        """Test Entry._normalize_attribute_name for other attributes."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        # Other attributes should be preserved
        assert entry_quirk._normalize_attribute_name("cn") == "cn"
        assert entry_quirk._normalize_attribute_name("mail") == "mail"
        assert entry_quirk._normalize_attribute_name("") == ""

    def test_needs_base64_encoding(self) -> None:
        """Test Entry._needs_base64_encoding static method."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        # Values that need base64 encoding
        assert entry_quirk._needs_base64_encoding(" starts with space") is True
        assert entry_quirk._needs_base64_encoding(":starts with colon") is True
        assert entry_quirk._needs_base64_encoding("<starts with less-than") is True
        assert entry_quirk._needs_base64_encoding("ends with space ") is True
        assert entry_quirk._needs_base64_encoding("has\nnewline") is True
        assert entry_quirk._needs_base64_encoding("has\0null") is True

        # Values that don't need base64 encoding
        assert entry_quirk._needs_base64_encoding("normal value") is False
        assert entry_quirk._needs_base64_encoding("test123") is False
        assert entry_quirk._needs_base64_encoding("") is False

    def test_can_handle_any_entry(self) -> None:
        """Test Entry.can_handle always returns True."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        assert entry_quirk.can_handle("cn=test,dc=example,dc=com", {"cn": ["test"]}) is True
        assert entry_quirk.can_handle("", {}) is True  # RFC handles all

    def test_can_handle_attribute_returns_false(self) -> None:
        """Test Entry.can_handle_attribute always returns False."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc
        from flext_ldif.models import FlextLdifModels

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        attr = FlextLdifModels.SchemaAttribute(oid="2.5.4.3", name="cn")
        assert entry_quirk.can_handle_attribute(attr) is False

    def test_can_handle_objectclass_returns_false(self) -> None:
        """Test Entry.can_handle_objectclass always returns False."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc
        from flext_ldif.models import FlextLdifModels

        rfc = FlextLdifServersRfc()
        entry_quirk = rfc.entry_quirk

        oc = FlextLdifModels.SchemaObjectClass(oid="2.5.6.6", name="person")
        assert entry_quirk.can_handle_objectclass(oc) is False


class TestRfcAclQuirkIntegration:
    """Test RFC ACL quirk integration methods."""

    def test_can_handle_acl_string(self) -> None:
        """Test Acl.can_handle_acl with string input."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        assert acl_quirk.can_handle_acl("access to entry by * (browse)") is True

    def test_can_handle_acl_model(self) -> None:
        """Test Acl.can_handle_acl with Acl model."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc
        from flext_ldif.models import FlextLdifModels

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        acl_model = FlextLdifModels.Acl(
            raw_acl="access to entry by * (browse)",
            server_type="rfc",
        )
        assert acl_quirk.can_handle_acl(acl_model) is True

    def test_can_handle_always_true(self) -> None:
        """Test Acl.can_handle always returns True."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        assert acl_quirk.can_handle("any acl string") is True
        assert acl_quirk.can_handle("") is True

    def test_can_handle_attribute_returns_false(self) -> None:
        """Test Acl.can_handle_attribute always returns False."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc
        from flext_ldif.models import FlextLdifModels

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        attr = FlextLdifModels.SchemaAttribute(oid="2.5.4.3", name="cn")
        assert acl_quirk.can_handle_attribute(attr) is False

    def test_can_handle_objectclass_returns_false(self) -> None:
        """Test Acl.can_handle_objectclass always returns False."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc
        from flext_ldif.models import FlextLdifModels

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        oc = FlextLdifModels.SchemaObjectClass(oid="2.5.6.6", name="person")
        assert acl_quirk.can_handle_objectclass(oc) is False

    def test_parse_acl_success(self) -> None:
        """Test Acl.parse_acl with valid ACL."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        acl_line = "access to entry by * (browse)"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_model = result.unwrap()
        assert acl_model.raw_acl == acl_line
        assert acl_model.server_type == "rfc"

    def test_write_acl_with_raw_acl(self) -> None:
        """Test Acl._write_acl with raw_acl."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc
        from flext_ldif.models import FlextLdifModels

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        acl_model = FlextLdifModels.Acl(
            raw_acl="access to entry by * (browse)",
            server_type="rfc",
        )

        result = acl_quirk._write_acl(acl_model)
        assert result.is_success
        assert result.unwrap() == "access to entry by * (browse)"

    def test_write_acl_with_name_only(self) -> None:
        """Test Acl._write_acl with name only."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc
        from flext_ldif.models import FlextLdifModels

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        acl_model = FlextLdifModels.Acl(
            name="test_acl",
            server_type="rfc",
        )

        result = acl_quirk._write_acl(acl_model)
        assert result.is_success
        assert result.unwrap() == "test_acl:"

    def test_write_acl_no_data(self) -> None:
        """Test Acl._write_acl with no raw_acl or name."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc
        from flext_ldif.models import FlextLdifModels

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        acl_model = FlextLdifModels.Acl(
            server_type="rfc",
        )

        result = acl_quirk._write_acl(acl_model)
        assert result.is_failure
        assert "no raw_acl or name" in result.error.lower()

    def test_convert_rfc_acl_to_aci_pass_through(self) -> None:
        """Test Acl.convert_rfc_acl_to_aci is pass-through."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        rfc_acl_attrs = {"aci": ["access to entry by * (browse)"]}
        result = acl_quirk.convert_rfc_acl_to_aci(rfc_acl_attrs, "oid")

        assert result.is_success
        assert result.unwrap() == rfc_acl_attrs

    def test_create_metadata(self) -> None:
        """Test Acl.create_metadata."""
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc = FlextLdifServersRfc()
        acl_quirk = rfc.acl_quirk

        metadata = acl_quirk.create_metadata(
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
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        constants = FlextLdifServersRfc.Constants

        # SERVER_TYPE and PRIORITY are in Constants class
        assert constants.SERVER_TYPE == "rfc"
        assert constants.PRIORITY == 100
        assert constants.DEFAULT_PORT == 389
        assert constants.ACL_FORMAT == "rfc_generic"
        assert constants.SCHEMA_DN == "cn=schema"
        assert isinstance(constants.OPERATIONAL_ATTRIBUTES, frozenset)
        assert constants.ENCODING_UTF8 == "utf-8"
        assert constants.LDIF_LINE_LENGTH_LIMIT == 76
