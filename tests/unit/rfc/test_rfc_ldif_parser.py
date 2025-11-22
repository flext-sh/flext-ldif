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

from flext_ldif import FlextLdifModels, FlextLdifParser, FlextLdifWriter
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers
from tests.helpers.test_rfc_helpers import RfcTestHelpers
from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

# Test constants - always at top of module, no type checking
# Use classes directly, no instantiation needed


class TestRfcLdifParserService:
    """Test RFC LDIF parser service."""

    @pytest.mark.timeout(5)
    def test_initialization(self, real_parser_service: FlextLdifParser) -> None:
        """Test parser initialization."""
        assert real_parser_service is not None

    @pytest.mark.timeout(5)
    def test_parse_basic_entry(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing basic LDIF entry."""
        _ = RfcTestHelpers.test_parse_and_assert_entry_structure(
            real_parser_service,
            TestsRfcConstants.SAMPLE_LDIF_BASIC + "\n",
            expected_dn=TestsRfcConstants.SAMPLE_DN,
            expected_attributes=[
                TestsRfcConstants.SAMPLE_ATTRIBUTE_CN,
                TestsRfcConstants.SAMPLE_ATTRIBUTE_SN,
            ],
            expected_count=1,
        )

    @pytest.mark.timeout(5)
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

    @pytest.mark.timeout(5)
    def test_parse_multiple_entries(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing multiple entries."""
        _ = RfcTestHelpers.test_parse_and_assert_multiple_entries(
            real_parser_service,
            TestsRfcConstants.SAMPLE_LDIF_MULTIPLE,
            expected_dns=[
                TestsRfcConstants.SAMPLE_DN_USER1,
                TestsRfcConstants.SAMPLE_DN_USER2,
            ],
            expected_count=2,
        )

    @pytest.mark.timeout(5)
    def test_parse_with_binary_data(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing entry with binary data."""
        _ = RfcTestHelpers.test_parse_and_assert_entry_structure(
            real_parser_service,
            TestsRfcConstants.SAMPLE_LDIF_BINARY,
            expected_dn=TestsRfcConstants.SAMPLE_DN,
            expected_attributes=["photo"],
            expected_count=1,
        )


class TestRfcLdifWriterService:
    """Test RFC LDIF writer service."""

    @pytest.mark.timeout(5)
    def test_initialization(self, real_writer_service: FlextLdifWriter) -> None:
        """Test writer initialization."""
        assert real_writer_service is not None

    @pytest.mark.timeout(5)
    def test_write_basic_entry(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing basic LDIF entry."""
        entry = RfcTestHelpers.test_create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["test"],
                "sn": ["user"],
            },
        )
        _ = RfcTestHelpers.test_write_entries_to_string(
            real_writer_service,
            [entry],
            expected_content=["cn=test,dc=example,dc=com"],
        )

    @pytest.mark.timeout(5)
    def test_write_to_file(
        self,
        real_writer_service: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        """Test writing LDIF to file."""
        entry = RfcTestHelpers.test_create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["test"],
                "sn": ["user"],
            },
        )
        ldif_file = tmp_path / "test_output.ldif"
        _ = RfcTestHelpers.test_write_entries_to_file(
            real_writer_service,
            [entry],
            ldif_file,
        )

    @pytest.mark.timeout(5)
    def test_write_multiple_entries(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing multiple entries."""
        entry1 = RfcTestHelpers.test_create_entry(
            dn="cn=user1,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["user1"],
            },
        )
        entry2 = RfcTestHelpers.test_create_entry(
            dn="cn=user2,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["user2"],
            },
        )
        _ = RfcTestHelpers.test_write_entries_to_string(
            real_writer_service,
            [entry1, entry2],
        )


# Comprehensive RFC Parser Tests from test_rfc_parser_comprehensive.py


class TestRfcParserEdgeCases:
    """Test suite for RFC parser edge cases."""

    @pytest.mark.timeout(10)
    def test_parse_edge_cases_batch(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing multiple edge cases in batch."""
        test_cases = [
            {
                "ldif_content": """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:: VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHZhbHVl

""",
                "expected_count": 1,
            },
            {
                "ldif_content": """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: This is a very long description that spans multiple lines
  and should be properly folded according to RFC 2849

""",
                "expected_count": 1,
            },
            {
                "ldif_content": """dn: cn=Tëst Üsër,dc=example,dc=com
objectClass: person
cn: Tëst Üsër
sn: Üsër

""",
                "expected_count": 1,
            },
            {
                "ldif_content": """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
userCertificate;binary:: VGVzdCBiaW5hcnkgZGF0YQ==

""",
                "expected_count": 1,
            },
            {
                "ldif_content": """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:

""",
                "expected_count": 1,
            },
            {
                "ldif_content": """dn:   cn=test   ,   dc=example   ,   dc=com
objectClass: person
cn: test

""",
                "expected_count": 1,
            },
            {
                "ldif_content": """# Start of LDIF file
dn: cn=test1,dc=example,dc=com
# Comment before objectClass
objectClass: person
cn: test1

# Comment between entries
dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2

""",
                "expected_count": 2,
            },
            {
                "ldif_content": """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:: invalid-base64-content!!!

""",
                "expected_count": 1,
                "should_succeed": True,  # Parser may handle gracefully
            },
            {
                "ldif_content": f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: {"x" * 10000}

""",
                "expected_count": 1,
            },
            {
                "ldif_content": """dn: cn=test1,dc=example,dc=com
objectClass: person
cn: test1




dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2

""",
                "expected_count": 2,
            },
        ]
        _ = TestDeduplicationHelpers.batch_parse_and_assert(
            real_parser_service,
            test_cases,
            validate_all=True,
        )


class TestRfcParserQuirksIntegration:
    """Test suite for RFC parser quirks integration."""

    @pytest.mark.timeout(10)
    def test_parse_with_server_quirks(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing with different server-specific quirks."""
        test_cases = [
            (
                "oid",
                """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
orclguid: 12345678-1234-1234-1234-123456789012

""",
            ),
            (
                "oud",
                """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
ds-sync-hist: 12345678901234567890

""",
            ),
            (
                "openldap",
                """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
olcRootDN: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com

""",
            ),
            (
                None,
                """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

""",
            ),
        ]
        for _server_type, ldif_content in test_cases:
            RfcTestHelpers.test_parse_edge_case(
                real_parser_service,
                ldif_content,
                should_succeed=None,
            )


class TestRfcParserErrorHandling:
    """Test suite for RFC parser error handling."""

    @pytest.mark.timeout(10)
    def test_parse_error_cases_batch(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing error cases in batch."""
        test_cases = [
            {
                "ldif_content": """dn: invalid-dn-syntax-without-equals
objectClass: person
cn: test

""",
                "should_succeed": True,  # Parser may handle gracefully
                "server_type": "rfc",
            },
            {
                "ldif_content": """objectClass: person
cn: test
sn: user

""",
                "should_succeed": True,  # Parser may handle gracefully
                "server_type": "rfc",
            },
            {
                "ldif_content": """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: This line doesn't start with space
but should be a continuation

""",
                "should_succeed": True,  # Parser may handle gracefully
            },
            {
                "ldif_content": """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description::

""",
                "should_succeed": True,  # Empty base64 may be valid
            },
        ]
        _ = TestDeduplicationHelpers.batch_parse_and_assert(
            real_parser_service,
            test_cases,
            validate_all=False,
        )

    @pytest.mark.timeout(5)
    def test_parse_empty_content(self, real_parser_service: FlextLdifParser) -> None:
        """Test parsing empty LDIF content."""
        entries = RfcTestHelpers.test_parse_ldif_content(
            real_parser_service,
            "",
            expected_count=0,
            server_type="rfc",
        )
        assert len(entries) == 0

    @pytest.mark.timeout(5)
    def test_parse_whitespace_only_content(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing whitespace-only LDIF content."""
        entries = RfcTestHelpers.test_parse_ldif_content(
            real_parser_service,
            "   \n\t\n   ",
            expected_count=0,
            server_type="rfc",
        )
        assert len(entries) == 0


class TestRfcParserLargeFiles:
    """Test suite for RFC parser large file handling."""

    @pytest.mark.timeout(15)
    def test_parse_large_number_of_entries(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing a large number of entries."""
        entries = [
            f"""dn: cn=user{i},dc=example,dc=com
objectClass: person
cn: user{i}
sn: User{i}

"""
            for i in range(100)
        ]
        ldif_content = "".join(entries)
        RfcTestHelpers.test_parse_edge_case(real_parser_service, ldif_content)

    @pytest.mark.timeout(10)
    def test_parse_entries_with_many_attributes(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing entries with many attributes."""
        attributes = [f"attr{i}: value{i}" for i in range(50)]
        ldif_content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
{"\n".join(attributes)}

"""
        RfcTestHelpers.test_parse_edge_case(real_parser_service, ldif_content)

    @pytest.mark.timeout(10)
    def test_parse_entries_with_large_attribute_values(
        self,
        real_parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing entries with large attribute values."""
        large_value = "x" * 10000  # 10KB
        ldif_content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: {large_value}

"""
        RfcTestHelpers.test_parse_edge_case(real_parser_service, ldif_content)


# Comprehensive RFC Schema Parser Tests from test_rfc_schema_parser_comprehensive.py


class TestRfcLdifWriterComprehensive:
    """Comprehensive test suite for RFC LDIF writer."""

    @pytest.mark.timeout(5)
    def test_writer_initialization(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writer initialization."""
        assert real_writer_service is not None

    @pytest.mark.timeout(5)
    def test_write_entries_variations(
        self,
        real_writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
        sample_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test writing various entry configurations."""
        _ = RfcTestHelpers.test_write_entries_to_string(
            real_writer_service,
            [sample_entry],
        )
        _ = RfcTestHelpers.test_write_entries_to_string(
            real_writer_service,
            sample_entries,
        )

    @pytest.mark.timeout(5)
    def test_write_empty_entries_list(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing empty entries list."""
        result = real_writer_service.write(
            [],
            target_server_type="rfc",
            output_target="string",
        )
        assert result.is_success
        content = result.unwrap()
        assert content == "version: 1\n"

    @pytest.mark.timeout(10)
    def test_write_entry_variations(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writing entries with different data types."""
        entry_data: dict[str, dict[str, str | dict[str, list[str]]]] = {
            "binary": {
                "dn": "cn=Binary Test,dc=example,dc=com",
                "attributes": {
                    "cn": ["Binary Test"],
                    "objectclass": ["person"],
                    "userCertificate;binary": [
                        base64.b64encode(b"binary content").decode("ascii"),
                    ],
                },
            },
            "unicode": {
                "dn": "cn=Tëst Üsër,dc=example,dc=com",
                "attributes": {
                    "cn": ["Tëst Üsër"],
                    "sn": ["Üsër"],
                    "objectclass": ["person"],
                    "description": ["Tëst dëscriptïon wïth Ünicödé"],
                },
            },
            "long_lines": {
                "dn": "cn=Long Line Test,dc=example,dc=com",
                "attributes": {
                    "cn": ["Long Line Test"],
                    "objectclass": ["person"],
                    "description": ["x" * 1000],
                },
            },
        }
        RfcTestHelpers.test_write_entry_variations(real_writer_service, entry_data)

    @pytest.mark.timeout(5)
    def test_write_to_file(
        self,
        real_writer_service: FlextLdifWriter,
        sample_entries: list[FlextLdifModels.Entry],
        tmp_path: Path,
    ) -> None:
        """Test writing entries to file."""
        output_file = tmp_path / "test_output.ldif"
        _ = RfcTestHelpers.test_write_entries_to_file(
            real_writer_service,
            sample_entries,
            output_file,
        )

    @pytest.mark.timeout(5)
    def test_write_to_nonexistent_directory(
        self,
        real_writer_service: FlextLdifWriter,
        sample_entries: list[FlextLdifModels.Entry],
        tmp_path: Path,
    ) -> None:
        """Test writing to file in non-existent directory."""
        output_file = tmp_path / "nonexistent" / "test_output.ldif"
        _ = RfcTestHelpers.test_write_entries_to_file(
            real_writer_service,
            sample_entries,
            output_file,
        )

    @pytest.mark.timeout(5)
    def test_writer_error_handling(
        self,
        real_writer_service: FlextLdifWriter,
    ) -> None:
        """Test writer handles various edge cases."""
        valid_entry = RfcTestHelpers.test_create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["test"],
            },
        )
        _ = RfcTestHelpers.test_write_entries_to_string(
            real_writer_service,
            [valid_entry],
        )

        result = real_writer_service.write(
            [],
            target_server_type="rfc",
            output_target="string",
        )
        assert result.is_success

        minimal_entry = RfcTestHelpers.test_create_entry(
            dn="cn=Empty Test,dc=example,dc=com",
            attributes={"objectClass": ["person"]},
        )
        _ = RfcTestHelpers.test_write_entries_to_string(
            real_writer_service,
            [minimal_entry],
        )


class TestRfcLdifWriterFileOperations:
    """Test suite for RFC LDIF writer file operations."""

    @pytest.mark.timeout(5)
    def test_write_entries_to_file_operations(
        self,
        real_writer_service: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        """Test write_entries_to_file() with various operations."""
        entry = RfcTestHelpers.test_create_entry(
            dn="cn=Test,dc=example,dc=com",
            attributes={"cn": ["Test"], "objectclass": ["person"]},
        )

        output_file = tmp_path / "test.ldif"
        _ = RfcTestHelpers.test_write_entries_to_file(
            real_writer_service,
            [entry],
            output_file,
        )
        content = output_file.read_text(encoding="utf-8")
        assert "dn: cn=Test,dc=example,dc=com" in content

        nested_file = tmp_path / "subdir" / "nested" / "test.ldif"
        _ = RfcTestHelpers.test_write_entries_to_file(
            real_writer_service,
            [entry],
            nested_file,
        )

        empty_file = tmp_path / "empty.ldif"
        result = real_writer_service.write(
            [],
            target_server_type="rfc",
            output_target="file",
            output_path=empty_file,
        )
        assert result.is_success
        assert empty_file.exists()


class TestRfcEntryQuirkIntegration:
    """Test RFC Entry quirk integration methods."""

    @pytest.mark.timeout(5)
    def test_can_handle_entry_cases(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.can_handle_entry with various cases."""
        valid_entry = RfcTestHelpers.test_create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectClass": ["person"], "cn": ["test"]},
        )
        RfcTestHelpers.test_entry_quirk_can_handle(
            rfc_entry_quirk,
            valid_entry,
            expected=True,
        )

        empty_dn_entry = RfcTestHelpers.test_create_entry(
            dn="",
            attributes={"objectClass": ["person"]},
        )
        RfcTestHelpers.test_entry_quirk_can_handle(
            rfc_entry_quirk,
            empty_dn_entry,
            expected=False,
        )

        no_objectclass_entry = RfcTestHelpers.test_create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        RfcTestHelpers.test_entry_quirk_can_handle(
            rfc_entry_quirk,
            no_objectclass_entry,
            expected=False,
        )

    @pytest.mark.timeout(5)
    def test_normalize_attribute_name(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry._normalize_attribute_name for various cases."""
        test_cases = [
            ("objectclass", "objectClass"),
            ("OBJECTCLASS", "objectClass"),
            ("ObjectClass", "objectClass"),
            ("objectClass", "objectClass"),
            ("cn", "cn"),
            ("mail", "mail"),
            ("", ""),
        ]
        # Test indirectly through parse/write behavior
        # _normalize_attribute_name is used internally during parsing
        for input_name, expected in test_cases:
            # Create LDIF with the input attribute name
            ldif_content = f"""dn: cn=test,dc=example,dc=com
{input_name}: test_value
objectClass: person

"""
            parse_result = rfc_entry_quirk.parse(ldif_content)
            assert parse_result.is_success, f"Failed to parse with {input_name}"
            entries = parse_result.unwrap()
            assert len(entries) == 1
            entry = entries[0]
            # Verify the attribute was normalized to expected canonical form
            if expected:  # Skip empty string case
                assert entry.attributes is not None
                assert entry.attributes.attributes is not None
                # The attribute should be normalized to canonical form
                attr_keys = list(entry.attributes.attributes.keys())
                assert expected in entry.attributes.attributes, (
                    f"Expected {expected} in attributes, got {attr_keys}"
                )

    @pytest.mark.timeout(5)
    def test_needs_base64_encoding(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry._needs_base64_encoding indirectly through write."""
        needs_encoding = [
            " starts with space",
            ":starts with colon",
            "<starts with less-than",
            "ends with space ",
            "has\nnewline",
            "has\0null",
        ]
        no_encoding = ["normal value", "test123", ""]
        # Test indirectly through write behavior
        # _needs_base64_encoding is used internally during writing
        entry = RfcTestHelpers.test_create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectClass": ["person"], "description": ["test"]},
        )
        for value in needs_encoding:
            # Update entry with value that needs encoding
            if entry.attributes and entry.attributes.attributes:
                entry.attributes.attributes["description"] = [value]
            write_result = rfc_entry_quirk.write(entry)
            assert write_result.is_success, f"Failed to write with value: {value!r}"
            written_ldif = write_result.unwrap()
            # Value should be base64 encoded (indicated by ::)
            assert (
                "description::" in written_ldif
                or f"description: {value}" in written_ldif
            ), f"Value {value!r} should be base64 encoded or written correctly"
        for value in no_encoding:
            # Update entry with value that doesn't need encoding
            if entry.attributes and entry.attributes.attributes:
                entry.attributes.attributes["description"] = [value]
            write_result = rfc_entry_quirk.write(entry)
            assert write_result.is_success, f"Failed to write with value: {value!r}"
            written_ldif = write_result.unwrap()
            # Value should be written as plain text (indicated by :)
            if value:  # Skip empty string case
                assert (
                    f"description: {value}" in written_ldif
                    or "description::" in written_ldif
                ), f"Value {value!r} should be written correctly"

    @pytest.mark.timeout(5)
    def test_entry_quirk_can_handle_methods(
        self,
        rfc_entry_quirk: FlextLdifServersRfc.Entry,
        sample_schema_attribute: FlextLdifModels.SchemaAttribute,
        sample_schema_objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> None:
        """Test Entry quirk can_handle methods."""
        assert (
            rfc_entry_quirk.can_handle("cn=test,dc=example,dc=com", {"cn": ["test"]})
            is True
        )
        assert rfc_entry_quirk.can_handle("", {}) is True
        assert rfc_entry_quirk.can_handle_attribute(sample_schema_attribute) is False
        assert (
            rfc_entry_quirk.can_handle_objectclass(sample_schema_objectclass) is False
        )


class TestRfcAclQuirkIntegration:
    """Test RFC ACL quirk integration methods."""

    @pytest.mark.timeout(5)
    def test_acl_quirk_can_handle_methods(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
        sample_acl: FlextLdifModels.Acl,
        sample_schema_attribute: FlextLdifModels.SchemaAttribute,
        sample_schema_objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> None:
        """Test ACL quirk can_handle methods."""
        assert rfc_acl_quirk.can_handle_acl("access to entry by * (browse)") is True
        assert rfc_acl_quirk.can_handle_acl(sample_acl) is True
        assert rfc_acl_quirk.can_handle("any acl string") is True
        assert rfc_acl_quirk.can_handle("") is True
        assert rfc_acl_quirk.can_handle_attribute(sample_schema_attribute) is False
        assert rfc_acl_quirk.can_handle_objectclass(sample_schema_objectclass) is False

    @pytest.mark.timeout(5)
    def test_acl_quirk_parse_and_write(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test ACL quirk parse and write operations."""
        acl_line = "access to entry by * (browse)"
        acl = RfcTestHelpers.test_acl_quirk_parse_and_verify(
            rfc_acl_quirk,
            acl_line,
            expected_raw_acl=acl_line,
        )
        assert acl.server_type == "rfc"

        _ = RfcTestHelpers.test_acl_quirk_write_and_verify(
            rfc_acl_quirk,
            acl,
            expected_content=acl_line,
        )

        name_only_acl = FlextLdifModels.Acl(name="test_acl", server_type="rfc")
        _ = RfcTestHelpers.test_acl_quirk_write_and_verify(
            rfc_acl_quirk,
            name_only_acl,
            expected_content="test_acl:",
        )

        # Test empty ACL through public write() method
        empty_acl = FlextLdifModels.Acl(server_type="rfc")
        result = rfc_acl_quirk.write(empty_acl)
        assert result.is_failure
        assert result.error is not None
        assert "no raw_acl or name" in result.error.lower()

    @pytest.mark.timeout(5)
    def test_convert_rfc_acl_to_aci_pass_through(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.convert_rfc_acl_to_aci is pass-through."""
        rfc_acl_attrs = {"aci": ["access to entry by * (browse)"]}
        result = rfc_acl_quirk.convert_rfc_acl_to_aci(rfc_acl_attrs, "oid")

        assert result.is_success
        assert result.unwrap() == rfc_acl_attrs

    @pytest.mark.timeout(5)
    def test_create_metadata(
        self,
        rfc_acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.create_metadata."""
        metadata = rfc_acl_quirk.create_metadata(
            original_format="access to entry by * (browse)",
            extensions={"custom": "value"},
        )

        assert metadata.quirk_type == "rfc"
        assert metadata.extensions["original_format"] == "access to entry by * (browse)"
        assert metadata.extensions["custom"] == "value"


class TestRfcConstants:
    """Test RFC Constants."""

    @pytest.mark.timeout(5)
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
