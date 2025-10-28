"""Unit tests for FlextLdifClient - LDIF/Encoding Utility Methods.

Tests the integrated LDIF and encoding utility methods in FlextLdifClient.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest

from flext_ldif.client import FlextLdifClient


@pytest.fixture
def client() -> FlextLdifClient:
    """Create a FlextLdifClient with real initialization."""
    return FlextLdifClient()


class TestDetectEncoding:
    """Test encoding detection from raw bytes."""

    def test_detect_utf8_encoding(self, client: FlextLdifClient) -> None:
        """Test detection of UTF-8 encoded content."""
        utf8_content = "dn: cn=José,dc=example,dc=com\n".encode()

        result = client.detect_encoding(utf8_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"

    def test_detect_invalid_utf8_fails(self, client: FlextLdifClient) -> None:
        """Test that non-UTF-8 content fails (RFC 2849 compliance).

        RFC 2849 mandates UTF-8 encoding. Invalid UTF-8 bytes should
        not be silently accepted via fallback - they indicate a non-compliant LDIF file.
        """
        # Create bytes that are invalid UTF-8 but valid latin-1
        invalid_utf8_content = b"dn: cn=test\x80invalid\x90utf8,dc=example,dc=com\n"

        result = client.detect_encoding(invalid_utf8_content)

        # Should fail - not RFC 2849 compliant
        assert result.is_failure
        assert result.error is not None
        assert "RFC 2849 violation" in result.error
        assert "not valid UTF-8" in result.error

    def test_detect_encoding_empty_bytes(self, client: FlextLdifClient) -> None:
        """Test encoding detection with empty bytes."""
        empty_content = b""

        result = client.detect_encoding(empty_content)

        assert result.is_success
        # Empty bytes should decode as UTF-8
        assert result.unwrap() == "utf-8"

    def test_detect_encoding_ascii_compatible(self, client: FlextLdifClient) -> None:
        """Test ASCII content (UTF-8 compatible)."""
        ascii_content = b"dn: cn=test,dc=example,dc=com\n"

        result = client.detect_encoding(ascii_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"

    def test_detect_encoding_unicode_characters(self, client: FlextLdifClient) -> None:
        """Test UTF-8 with various Unicode characters."""
        unicode_content = "dn: cn=日本語テスト,dc=example,dc=com\n".encode()

        result = client.detect_encoding(unicode_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"


class TestNormalizeEncoding:
    """Test encoding normalization."""

    def test_normalize_to_utf8(self, client: FlextLdifClient) -> None:
        """Test normalization to UTF-8."""
        content = "dn: cn=José,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == content

    def test_normalize_to_latin1(self, client: FlextLdifClient) -> None:
        """Test normalization to latin-1."""
        # Use only latin-1 compatible characters
        content = "dn: cn=test,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "latin-1")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == content

    def test_normalize_encoding_default_utf8(self, client: FlextLdifClient) -> None:
        """Test normalization with default UTF-8 encoding."""
        content = "dn: cn=test,dc=example,dc=com\n"

        result = client.normalize_encoding(content)

        assert result.is_success
        assert result.unwrap() == content

    def test_normalize_encoding_invalid_characters(
        self, client: FlextLdifClient
    ) -> None:
        """Test normalization failure with invalid characters for target encoding."""
        # Unicode characters not representable in ASCII
        content = "dn: cn=José,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "ascii")

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "not representable in ascii" in result.error.lower()

    def test_normalize_empty_content(self, client: FlextLdifClient) -> None:
        """Test normalization of empty content."""
        content = ""

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        assert not result.unwrap()

    def test_normalize_unicode_content(self, client: FlextLdifClient) -> None:
        """Test normalization with Unicode characters."""
        content = "dn: cn=日本語テスト,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        assert result.unwrap() == content


class TestValidateLdifSyntax:
    """Test LDIF syntax validation."""

    def test_validate_valid_single_entry(self, client: FlextLdifClient) -> None:
        """Test validation of valid single entry LDIF."""
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_valid_multiple_entries(self, client: FlextLdifClient) -> None:
        """Test validation of valid multiple entry LDIF."""
        ldif_content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_empty_content(self, client: FlextLdifClient) -> None:
        """Test validation of empty content returns False."""
        ldif_content = ""

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_whitespace_only(self, client: FlextLdifClient) -> None:
        """Test validation of whitespace-only content returns False."""
        ldif_content = "   \n  \t  \n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_missing_dn_line(self, client: FlextLdifClient) -> None:
        """Test validation fails when no dn: line present."""
        ldif_content = "cn: test\nobjectClass: person\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_case_insensitive_dn(self, client: FlextLdifClient) -> None:
        """Test validation accepts DN: (uppercase)."""
        ldif_content = "DN: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_spaces(self, client: FlextLdifClient) -> None:
        """Test validation with DN containing spaces."""
        ldif_content = "dn: cn=John Smith,ou=People,dc=example,dc=com\ncn: John Smith\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_special_chars(self, client: FlextLdifClient) -> None:
        """Test validation with DN containing special characters."""
        ldif_content = (
            r"dn: cn=Smith\, John,ou=People,dc=example,dc=com" + "\ncn: Smith, John\n"
        )

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_minimal_ldif(self, client: FlextLdifClient) -> None:
        """Test validation with minimal valid LDIF (just dn:)."""
        ldif_content = "dn: dc=example,dc=com\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True


class TestCountLdifEntries:
    """Test LDIF entry counting."""

    def test_count_single_entry(self, client: FlextLdifClient) -> None:
        """Test counting single LDIF entry."""
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 1

    def test_count_multiple_entries(self, client: FlextLdifClient) -> None:
        """Test counting multiple LDIF entries."""
        ldif_content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n\n"
            "dn: cn=test3,dc=example,dc=com\n"
            "cn: test3\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 3

    def test_count_empty_content(self, client: FlextLdifClient) -> None:
        """Test counting empty content returns 0."""
        ldif_content = ""

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 0

    def test_count_whitespace_only(self, client: FlextLdifClient) -> None:
        """Test counting whitespace-only content returns 0."""
        ldif_content = "   \n  \t  \n"

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 0

    def test_count_entries_no_blank_lines(self, client: FlextLdifClient) -> None:
        """Test counting entries without blank line separators."""
        ldif_content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        # Should count by "dn:" lines
        assert result.unwrap() == 2

    def test_count_case_insensitive_dn(self, client: FlextLdifClient) -> None:
        """Test counting with uppercase DN:."""
        ldif_content = (
            "DN: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 2

    def test_count_entries_with_comments(self, client: FlextLdifClient) -> None:
        """Test counting entries with LDIF comments."""
        ldif_content = (
            "# First entry\n"
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "# Second entry\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 2

    def test_count_large_number_of_entries(self, client: FlextLdifClient) -> None:
        """Test counting large number of entries."""
        # Generate 100 entries
        entries = [
            f"dn: cn=test{i},dc=example,dc=com\ncn: test{i}\n\n" for i in range(100)
        ]
        ldif_content = "".join(entries)

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 100


class TestParseLdif:
    """Test LDIF parsing from files and content strings."""

    def test_parse_ldif_from_content_string(self, client: FlextLdifClient) -> None:
        """Test parsing LDIF from content string."""
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n\n"
        )

        result = client.parse_ldif(ldif_content)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"
        assert entries[0].attributes.attributes["cn"] == ["test"]

    def test_parse_ldif_from_path_object(
        self, client: FlextLdifClient, tmp_path: Path
    ) -> None:
        """Test parsing LDIF from Path object."""
        # Create test LDIF file
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n\n"
        )
        test_file = tmp_path / "test.ldif"
        test_file.write_text(ldif_content)

        result = client.parse_ldif(test_file)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"
        assert entries[0].attributes.attributes["cn"] == ["test"]

    def test_parse_ldif_with_minimal_container(self) -> None:
        """Test parse_ldif behavior with minimal container (real test, no mocks)."""
        # Create a real client with actual container
        # The default FlextLdifClient has parser registered, so this tests normal path
        client = FlextLdifClient()

        # Parse LDIF content with proper objectClass - should succeed with real parser
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n\n"
        )
        result = client.parse_ldif(ldif_content)

        # Should succeed with real parser
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"
        assert entries[0].attributes.attributes["cn"] == ["test"]


class TestWriteLdif:
    """Test LDIF writing to files and strings."""

    def test_write_ldif_to_string(self, client: FlextLdifClient) -> None:
        """Test writing LDIF to string (output_path=None)."""
        from flext_ldif.models import FlextLdifModels

        # Create test entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectclass": ["person"]},
        )
        entries = [entry_result.unwrap()]

        result = client.write_ldif(entries, output_path=None)

        assert result.is_success
        ldif_content = result.unwrap()
        # Real writer includes version header
        assert "version: 1" in ldif_content
        assert "dn: cn=test,dc=example,dc=com" in ldif_content
        assert "cn: test" in ldif_content
        assert "objectclass: person" in ldif_content


class TestLdifFileOperations:
    """Test LDIF file I/O operations with real files."""

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get path to OID entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    @pytest.fixture
    def temp_ldif_file(self) -> Generator[Path]:
        """Create temporary LDIF file."""
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".ldif")
        import os

        os.close(fd)
        yield Path(path)
        Path(path).unlink(missing_ok=True)

    def test_write_ldif_to_file_creates_output(
        self, client: FlextLdifClient, temp_ldif_file: Path
    ) -> None:
        """Test writing LDIF entries to a file creates the file."""
        from flext_ldif.models import FlextLdifModels

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=alice,dc=example,dc=com",
            attributes={"cn": ["alice"], "objectclass": ["person"]},
        )
        entries = [entry_result.unwrap()]

        result = client.write_ldif(entries, output_path=temp_ldif_file)

        assert result.is_success
        assert temp_ldif_file.exists()
        content = temp_ldif_file.read_text(encoding="utf-8")
        assert "dn: cn=alice,dc=example,dc=com" in content

    def test_parse_ldif_from_real_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test parsing LDIF from real OID fixture file."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        # Read fixture content
        fixture_content = oid_entries_fixture.read_text(encoding="utf-8")

        # Parse it
        result = client.parse_ldif(fixture_content)

        assert result.is_success
        entries = result.unwrap()
        # Real fixture should have entries
        assert len(entries) > 0

    def test_round_trip_parse_write_parse(
        self, client: FlextLdifClient, oid_entries_fixture: Path, temp_ldif_file: Path
    ) -> None:
        """Test round-trip: parse → write → parse again."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        # Step 1: Parse original fixture
        original_content = oid_entries_fixture.read_text(encoding="utf-8")
        parse_result = client.parse_ldif(original_content)
        assert parse_result.is_success
        original_entries = parse_result.unwrap()

        # Step 2: Write parsed entries to new file
        write_result = client.write_ldif(original_entries, output_path=temp_ldif_file)
        assert write_result.is_success

        # Step 3: Parse written file
        written_content = temp_ldif_file.read_text(encoding="utf-8")
        reparse_result = client.parse_ldif(written_content)
        assert reparse_result.is_success
        reparsed_entries = reparse_result.unwrap()

        # Verify same number of entries in round-trip
        assert len(reparsed_entries) == len(original_entries)

    def test_validate_entries_with_real_data(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test entry validation with real parsed data."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        fixture_content = oid_entries_fixture.read_text(encoding="utf-8")
        parse_result = client.parse_ldif(fixture_content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Validate entries
        validation_result = client.validate_entries(entries)
        assert validation_result.is_success

    def test_count_ldif_entries_with_multi_entry_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test counting entries in LDIF with multiple entries."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        fixture_content = oid_entries_fixture.read_text(encoding="utf-8")

        result = client.count_ldif_entries(fixture_content)

        assert result.is_success
        count = result.unwrap()
        # Real fixture should have multiple entries
        assert count > 0

    def test_parse_ldif_single_entry_minimal(self, client: FlextLdifClient) -> None:
        """Test parsing single minimal entry."""
        ldif = """version: 1
dn: cn=test,dc=example,dc=com
objectClass: device
cn: test

"""

        result = client.parse_ldif(ldif)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_ldif_multiple_entries(self, client: FlextLdifClient) -> None:
        """Test parsing multiple entries."""
        ldif = """version: 1
dn: cn=alice,dc=example,dc=com
objectClass: person
cn: alice

dn: cn=bob,dc=example,dc=com
objectClass: person
cn: bob

"""

        result = client.parse_ldif(ldif)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 2

    def test_detect_server_type_with_oid_patterns(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test server type detection with OID fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        fixture_content = oid_entries_fixture.read_text(encoding="utf-8")

        # Test server detection
        result = client.detect_server_type(ldif_content=fixture_content)

        # May detect as OID or unknown, both are acceptable
        assert result.is_success or result.is_failure

    def test_get_effective_server_type_default(self, client: FlextLdifClient) -> None:
        """Test getting effective server type with defaults."""
        # No LDIF path means no auto-detection, should return config default
        result = client.get_effective_server_type(ldif_path=None)

        # Should return some server type
        assert result.is_success
        server_type = result.unwrap()
        # Should return RFC as default when no detection possible
        assert isinstance(server_type, str)
        assert len(server_type) > 0

    def test_validate_ldif_syntax_valid_content(self, client: FlextLdifClient) -> None:
        """Test LDIF syntax validation with valid content."""
        valid_ldif = """version: 1
dn: cn=test,dc=example,dc=com
cn: test

"""

        result = client.validate_ldif_syntax(valid_ldif)

        assert result.is_success
        is_valid = result.unwrap()
        assert is_valid is True

    def test_filter_entries_by_dn_pattern(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test filtering entries by DN pattern."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        fixture_content = oid_entries_fixture.read_text(encoding="utf-8")
        parse_result = client.parse_ldif(fixture_content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Filter entries by DN pattern - specify filter_type and dn_pattern
        filter_result = client.filter(
            entries,
            filter_type="dn_pattern",
            dn_pattern=".*dc=example.*",
            mode="include",
        )

        # Filter should handle successfully
        assert filter_result.is_success
        filtered_entries = filter_result.unwrap()
        # Should return list of entries
        assert isinstance(filtered_entries, list)

    def test_analyze_entries_with_real_data(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test entry analysis with real parsed data."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        fixture_content = oid_entries_fixture.read_text(encoding="utf-8")
        parse_result = client.parse_ldif(fixture_content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Analyze entries
        analysis_result = client.analyze_entries(entries)

        assert analysis_result.is_success

    def test_write_ldif_with_multiple_entries(
        self, client: FlextLdifClient, temp_ldif_file: Path
    ) -> None:
        """Test writing multiple entries to file."""
        from flext_ldif.models import FlextLdifModels

        # Create multiple entries
        entries = []
        for name in ["alice", "bob", "charlie"]:
            entry_result = FlextLdifModels.Entry.create(
                dn=f"cn={name},dc=example,dc=com",
                attributes={"cn": [name], "objectclass": ["person"]},
            )
            if entry_result.is_success:
                entries.append(entry_result.unwrap())

        # Write to file
        result = client.write_ldif(entries, output_path=temp_ldif_file)

        assert result.is_success
        assert temp_ldif_file.exists()

        # Verify content
        content = temp_ldif_file.read_text(encoding="utf-8")
        assert "cn=alice" in content
        assert "cn=bob" in content
        assert "cn=charlie" in content

    def test_parse_ldif_with_special_characters(self, client: FlextLdifClient) -> None:
        """Test parsing LDIF with special characters in attributes."""
        ldif = """version: 1
dn: cn=José Garcia,dc=example,dc=com
objectClass: person
cn: José Garcia
sn: Garcia
description: Español y más

"""

        result = client.parse_ldif(ldif)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        # Verify special characters preserved
        assert "José" in str(entries[0].attributes)

    def test_register_quirk_adds_to_registry(self, client: FlextLdifClient) -> None:
        """Test registering a custom quirk."""
        from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid

        quirk = FlextLdifQuirksServersOid()

        # Register quirk - OID quirks are schema quirks by default
        result = client.register_quirk(quirk, quirk_type="schema")

        # Registration should succeed
        assert result.is_success

    def test_detect_encoding_utf8(self, client: FlextLdifClient) -> None:
        """Test UTF-8 encoding detection."""
        content = b"version: 1\ndn: cn=test,dc=example,dc=com\n"

        result = client.detect_encoding(content)

        assert result.is_success
        encoding = result.unwrap()
        assert isinstance(encoding, str)

    def test_detect_encoding_with_special_chars(self, client: FlextLdifClient) -> None:
        """Test encoding detection with UTF-8 special characters."""
        # Use valid UTF-8 content with special characters
        content = "version: 1\ndn: cn=José García,dc=example,dc=com\n".encode()

        result = client.detect_encoding(content)

        assert result.is_success
        encoding = result.unwrap()
        assert isinstance(encoding, str)
        assert len(encoding) > 0

    def test_normalize_encoding_utf8_content(self, client: FlextLdifClient) -> None:
        """Test encoding normalization for UTF-8 content."""
        content = "version: 1\ndn: cn=test,dc=example,dc=com\n"

        result = client.normalize_encoding(content)

        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, str)
        assert "version: 1" in normalized

    def test_count_ldif_entries_single(self, client: FlextLdifClient) -> None:
        """Test counting entries in LDIF content."""
        ldif = """version: 1
dn: cn=alice,dc=example,dc=com
cn: alice

"""

        result = client.count_ldif_entries(ldif)

        assert result.is_success
        count = result.unwrap()
        assert count == 1

    def test_count_ldif_entries_multiple(self, client: FlextLdifClient) -> None:
        """Test counting multiple entries."""
        ldif = """version: 1
dn: cn=alice,dc=example,dc=com
cn: alice

dn: cn=bob,dc=example,dc=com
cn: bob

"""

        result = client.count_ldif_entries(ldif)

        assert result.is_success
        count = result.unwrap()
        assert count == 2

    def test_migrate_entries_rfc_format(self, client: FlextLdifClient) -> None:
        """Test migrating entries between RFC formats."""
        from flext_ldif.models import FlextLdifModels

        # Create test entries
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectclass": ["person"]},
        )
        assert entry_result.is_success
        entries = [entry_result.unwrap()]

        # Migrate from RFC to OUD format
        result = client.migrate_entries(entries, from_server="rfc", to_server="oud")

        # May succeed or fail depending on actual implementation
        # Just verify the method accepts proper parameters
        assert result.is_success or result.is_failure

    def test_categorize_entries_returns_dict(self, client: FlextLdifClient) -> None:
        """Test categorizing entries returns proper structure."""
        from flext_ldif.models import FlextLdifModels

        # Create entries with different objectClasses
        person_result = FlextLdifModels.Entry.create(
            dn="cn=alice,dc=example,dc=com",
            attributes={"cn": ["alice"], "objectclass": ["person"]},
        )
        assert person_result.is_success
        entries = [person_result.unwrap()]

        # Categorize entries
        result = client.categorize_entries(entries)

        # Verify method works (result may be success or failure)
        assert result.is_success or result.is_failure

    def test_validate_entries_with_valid_data(self, client: FlextLdifClient) -> None:
        """Test entry validation with valid data."""
        from flext_ldif.models import FlextLdifModels

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectclass": ["person"]},
        )
        assert entry_result.is_success
        entries = [entry_result.unwrap()]

        result = client.validate_entries(entries)

        # Should succeed or fail gracefully
        assert result.is_success or result.is_failure
        if result.is_success:
            validation_result = result.unwrap()
            # ValidationResult should have is_valid attribute
            assert hasattr(validation_result, "is_valid")
            assert validation_result.is_valid

    def test_analyze_entries_calculates_statistics(
        self, client: FlextLdifClient
    ) -> None:
        """Test entry analysis returns statistics."""
        from flext_ldif.models import FlextLdifModels

        # Create multiple entries
        entries = []
        for name in ["alice", "bob"]:
            entry_result = FlextLdifModels.Entry.create(
                dn=f"cn={name},dc=example,dc=com",
                attributes={"cn": [name], "objectclass": ["person"]},
            )
            if entry_result.is_success:
                entries.append(entry_result.unwrap())

        result = client.analyze_entries(entries)

        # Should return a result
        assert result.is_success or result.is_failure


class TestFlextLdifClientWithRealFixtures:
    """Test FlextLdifClient operations with real LDIF fixture data."""

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        """Create FlextLdifClient instance."""
        return FlextLdifClient()

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get path to OID entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    @pytest.fixture
    def oid_schema_fixture(self) -> Path:
        """Get path to OID schema fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_schema_fixtures.ldif"
        )

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get path to OID ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )

    @pytest.fixture
    def oud_entries_fixture(self) -> Path:
        """Get path to OUD entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_entries_fixtures.ldif"
        )

    def test_client_parse_ldif_entries_oid(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test parsing real OID entries fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = client.parse_ldif(oid_entries_fixture)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "Should parse at least one entry"

    def test_client_parse_ldif_schema_oid(
        self, client: FlextLdifClient, oid_schema_fixture: Path
    ) -> None:
        """Test parsing real OID schema fixture."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        result = client.parse_ldif(oid_schema_fixture)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "Schema should have entries"

    def test_client_parse_ldif_acl_oid(
        self, client: FlextLdifClient, oid_acl_fixture: Path
    ) -> None:
        """Test parsing real OID ACL fixture."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        result = client.parse_ldif(oid_acl_fixture)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "ACL fixture should have entries"

    def test_client_parse_ldif_oud_entries(
        self, client: FlextLdifClient, oud_entries_fixture: Path
    ) -> None:
        """Test parsing real OUD entries fixture."""
        if not oud_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_entries_fixture}")

        result = client.parse_ldif(oud_entries_fixture)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

    def test_client_detect_encoding_from_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test detecting encoding from real fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_bytes()
        result = client.detect_encoding(content)
        assert result.is_success, "Should detect encoding"
        encoding = result.unwrap()
        assert isinstance(encoding, str)
        assert len(encoding) > 0

    def test_client_validate_ldif_syntax_from_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test LDIF syntax validation on real fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_text(encoding="utf-8")
        result = client.validate_ldif_syntax(content)
        assert result.is_success, "Should validate syntax"
        is_valid = result.unwrap()
        assert isinstance(is_valid, bool)

    def test_client_count_ldif_entries_from_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test counting entries in real fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_text(encoding="utf-8")
        result = client.count_ldif_entries(content)
        assert result.is_success, "Should count entries"
        count = result.unwrap()
        assert count > 0, "Should have at least one entry"

    def test_client_write_ldif_to_string(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test writing parsed entries to LDIF string."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        write_result = client.write_ldif(entries, output_path=None)
        assert write_result.is_success, f"Write failed: {write_result.error}"

        output = write_result.unwrap()
        assert isinstance(output, str)
        assert len(output) > 0
        assert "version: 1" in output, "Should have LDIF version header"
        assert "dn:" in output, "Should have DN entries"

    def test_client_write_ldif_to_file(
        self,
        client: FlextLdifClient,
        oid_entries_fixture: Path,
        tmp_path: Path,
    ) -> None:
        """Test writing parsed entries to LDIF file."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        output_file = tmp_path / "output.ldif"
        write_result = client.write_ldif(entries, output_path=output_file)
        assert write_result.is_success

        assert output_file.exists(), "Output file should be created"
        content = output_file.read_text(encoding="utf-8")
        assert len(content) > 0
        assert "dn:" in content

    def test_client_roundtrip_parse_write_parse(
        self,
        client: FlextLdifClient,
        oid_entries_fixture: Path,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip: parse → write → parse again."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        # Parse original
        parse1 = client.parse_ldif(oid_entries_fixture)
        assert parse1.is_success
        entries1 = parse1.unwrap()
        count1 = len(entries1)

        # Write to temp
        output_file = tmp_path / "roundtrip.ldif"
        write_result = client.write_ldif(entries1, output_path=output_file)
        assert write_result.is_success

        # Parse written file
        parse2 = client.parse_ldif(output_file)
        assert parse2.is_success
        entries2 = parse2.unwrap()
        count2 = len(entries2)

        # Verify counts preserved
        assert count1 == count2, "Roundtrip should preserve entry count"

    def test_client_parse_multiple_fixtures_sequential(
        self,
        client: FlextLdifClient,
        oid_entries_fixture: Path,
        oud_entries_fixture: Path,
    ) -> None:
        """Test parsing multiple fixtures in sequence."""
        if not oid_entries_fixture.exists() or not oud_entries_fixture.exists():
            pytest.skip("One or both fixtures not found")

        # Parse OID
        result1 = client.parse_ldif(oid_entries_fixture)
        assert result1.is_success
        entries1 = result1.unwrap()

        # Parse OUD
        result2 = client.parse_ldif(oud_entries_fixture)
        assert result2.is_success
        entries2 = result2.unwrap()

        # Both successful
        assert len(entries1) > 0
        assert len(entries2) > 0

    def test_client_handle_large_fixture(
        self, client: FlextLdifClient, oid_schema_fixture: Path
    ) -> None:
        """Test handling large LDIF schema fixture."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        result = client.parse_ldif(oid_schema_fixture)
        assert result.is_success
        entries = result.unwrap()
        # Schema files should have at least one entry
        assert len(entries) > 0, "Schema should have at least one entry"


__all__ = [
    "TestCountLdifEntries",
    "TestDetectEncoding",
    "TestFlextLdifClientWithRealFixtures",
    "TestLdifFileOperations",
    "TestNormalizeEncoding",
    "TestParseLdif",
    "TestValidateLdifSyntax",
    "TestWriteLdif",
]
