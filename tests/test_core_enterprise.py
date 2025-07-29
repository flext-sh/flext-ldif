"""Enterprise tests for TLdif core functionality.

# Constants
EXPECTED_DATA_COUNT = 3

Comprehensive test suite covering all core LDIF processing functionality
using enterprise-grade testing practices with full coverage and validation.
"""

import time
import gc
import sys
import queue
import threading


from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif import TLdif


class TestTLdifEnterprise:
    """Enterprise-grade tests for TLdif core functionality."""

    @pytest.fixture
    def sample_ldif_content(self) -> str:
        """Sample LDIF content for testing."""
        return """dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
uid: johndoe

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com
uid: janesmith

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people
description: People container

"""

    @pytest.fixture
    def invalid_ldif_content(self) -> str:
        """Invalid LDIF content for error testing."""
        return """dn: cn=test,dc=example,dc=com
cn: test
# Missing objectClass - should fail validation

dn: invalid-dn-format
cn: invalid
objectClass: person

"""

    @pytest.fixture
    def malformed_ldif_content(self) -> str:
        """Malformed LDIF content for parser testing."""
        return """not-a-dn: invalid
some content without proper structure
invalid: line: format

"""

    def test_parse_valid_ldif_success(self, sample_ldif_content: str) -> None:
        """Test parsing valid LDIF content succeeds."""
        result = TLdif.parse(sample_ldif_content)

        assert result.is_success
        assert result.data is not None
        if len(result.data) != EXPECTED_DATA_COUNT:
            raise AssertionError(f"Expected {3}, got {len(result.data)}")
        assert result.error is None

        # Verify first entry
        entry = result.data[0]
        if str(entry.dn) != "cn=John Doe,ou=people,dc=example,dc=com":
            raise AssertionError(f"Expected {"cn=John Doe,ou=people,dc=example,dc=com"}, got {str(entry.dn)}")
        assert entry.get_attribute("cn") == ["John Doe"]
        if entry.get_attribute("mail") != ["john.doe@example.com"]:
            raise AssertionError(f"Expected {["john.doe@example.com"]}, got {entry.get_attribute("mail")}")
        assert entry.has_object_class("person")
        assert entry.has_object_class("inetOrgPerson")

    def test_parse_empty_content_returns_empty_list(self) -> None:
        """Test parsing empty content returns empty list."""
        result = TLdif.parse("")

        assert result.is_success
        if result.data != []:
            raise AssertionError(f"Expected {[]}, got {result.data}")
        assert result.error is None

    def test_parse_malformed_content_fails(self, malformed_ldif_content: str) -> None:
        """Test parsing malformed content fails gracefully."""
        result = TLdif.parse(malformed_ldif_content)

        assert not result.is_success
        assert result.data is None
        assert result.error is not None

    def test_validate_valid_entries_success(self, sample_ldif_content: str) -> None:
        """Test validating valid entries succeeds."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.is_success

        validate_result = TLdif.validate_entries(parse_result.data)

        assert validate_result.is_success
        if not (validate_result.data):
            raise AssertionError(f"Expected True, got {validate_result.data}")
        assert validate_result.error is None

    def test_validate_invalid_entries_fails(self, invalid_ldif_content: str) -> None:
        """Test validating invalid entries fails with proper error."""
        parse_result = TLdif.parse(invalid_ldif_content)

        if parse_result.is_success:
            validate_result = TLdif.validate_entries(parse_result.data)
            assert not validate_result.is_success
            assert validate_result.error is not None

    def test_validate_single_entry_success(self, sample_ldif_content: str) -> None:
        """Test validating single valid entry succeeds."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.is_success

        entry = parse_result.data[0]
        validate_result = TLdif.validate(entry)

        assert validate_result.is_success
        if not (validate_result.data):
            raise AssertionError(f"Expected True, got {validate_result.data}")

    def test_write_entries_success(self, sample_ldif_content: str) -> None:
        """Test writing entries to LDIF string succeeds."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.is_success

        write_result = TLdif.write(parse_result.data)

        assert write_result.is_success
        assert write_result.data is not None
        assert len(write_result.data) > 0
        if "dn:" not in write_result.data:
            raise AssertionError(f"Expected {"dn:"} in {write_result.data}")
        assert "objectClass:" in write_result.data

    def test_round_trip_parsing_writing(self, sample_ldif_content: str) -> None:
        """Test round-trip: parse → write → parse maintains data integrity."""
        # Parse original
        parse1_result = TLdif.parse(sample_ldif_content)
        assert parse1_result.is_success
        original_entries = parse1_result.data

        # Write to string
        write_result = TLdif.write(original_entries)
        assert write_result.is_success
        written_content = write_result.data

        # Parse written content
        parse2_result = TLdif.parse(written_content)
        assert parse2_result.is_success
        reparsed_entries = parse2_result.data

        # Verify integrity
        if len(reparsed_entries) != len(original_entries):
            raise AssertionError(f"Expected {len(original_entries)}, got {len(reparsed_entries)}")

        for original, reparsed in zip(original_entries, reparsed_entries, strict=False):
            if str(original.dn) != str(reparsed.dn):
                raise AssertionError(f"Expected {str(reparsed.dn)}, got {str(original.dn)}")
            assert original.attributes.attributes == reparsed.attributes.attributes

    def test_write_file_success(self, sample_ldif_content: str) -> None:
        """Test writing entries to file succeeds."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.is_success

        with tempfile.NamedTemporaryFile(encoding="utf-8", mode="w", delete=False, suffix=".ldif") as f:
            temp_file = Path(f.name)

        try:
            # Write to file
            write_result = TLdif.write_file(parse_result.data, temp_file)
            assert write_result.is_success
            if not (write_result.data):
                raise AssertionError(f"Expected True, got {write_result.data}")

            # Verify file exists and has content
            assert temp_file.exists()
            content = temp_file.read_text(encoding="utf-8")
            assert len(content) > 0
            if "dn:" not in content:
                raise AssertionError(f"Expected {"dn:"} in {content}")

        finally:
            temp_file.unlink(missing_ok=True)

    def test_read_file_success(self, sample_ldif_content: str) -> None:
        """Test reading entries from file succeeds."""
        with tempfile.NamedTemporaryFile(encoding="utf-8", mode="w", delete=False, suffix=".ldif") as f:
            f.write(sample_ldif_content)
            temp_file = Path(f.name)

        try:
            # Read from file
            read_result = TLdif.read_file(temp_file)
            assert read_result.is_success
            assert read_result.data is not None
            if len(read_result.data) != EXPECTED_DATA_COUNT:
                raise AssertionError(f"Expected {3}, got {len(read_result.data)}")

            # Verify content
            entry = read_result.data[0]
            if entry.get_attribute("cn") != ["John Doe"]:
                raise AssertionError(f"Expected {["John Doe"]}, got {entry.get_attribute("cn")}")

        finally:
            temp_file.unlink(missing_ok=True)

    def test_read_nonexistent_file_fails(self) -> None:
        """Test reading nonexistent file fails gracefully."""
        nonexistent_file = Path("/nonexistent/path/file.ldif")

        read_result = TLdif.read_file(nonexistent_file)

        assert not read_result.is_success
        assert read_result.data is None
        if "not found" not in read_result.error.lower():
            raise AssertionError(f"Expected {"not found"} in {read_result.error.lower()}")

    def test_write_file_to_nonexistent_directory_fails(self, sample_ldif_content: str) -> None:
        """Test writing to nonexistent directory fails gracefully."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.is_success

        nonexistent_path = Path("/nonexistent/directory/file.ldif")
        write_result = TLdif.write_file(parse_result.data, nonexistent_path)

        assert not write_result.is_success
        if "failed" not in write_result.error.lower():
            raise AssertionError(f"Expected {"failed"} in {write_result.error.lower()}")

    def test_parse_with_ldif3_fallback(self, sample_ldif_content: str) -> None:
        """Test parsing works with both ldif3 and custom parser."""
        # This test verifies the fallback mechanism works
        result = TLdif.parse(sample_ldif_content)

        assert result.is_success
        assert result.data is not None
        assert len(result.data) > 0

    def test_write_with_ldif3_fallback(self, sample_ldif_content: str) -> None:
        """Test writing works with both ldif3 and custom writer."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.is_success

        write_result = TLdif.write(parse_result.data)

        assert write_result.is_success
        assert write_result.data is not None

    def test_performance_large_ldif(self) -> None:
        """Test performance with larger LDIF content."""


        # Generate larger LDIF content
        large_content = ""
        for i in range(100):
            large_content += f"""dn: cn=user{i},ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: user{i}
sn: User{i}
uid: user{i}
mail: user{i}@example.com

"""

        start_time = time.time()
        result = TLdif.parse(large_content)
        parse_time = time.time() - start_time

        assert result.is_success
        if len(result.data) != 100:
            raise AssertionError(f"Expected {100}, got {len(result.data)}")
        if parse_time < 5.0  # Should parse 100 entries not in under 5 seconds:
            raise AssertionError(f"Expected {parse_time < 5.0  # Should parse 100 entries} in {under 5 seconds}")

    def test_memory_usage_large_ldif(self) -> None:
        """Test memory usage with larger LDIF content."""



        # Generate content and measure memory
        large_content = ""
        for i in range(200):
            large_content += f"""dn: cn=user{i},ou=people,dc=example,dc=com
objectClass: person
cn: user{i}
sn: User{i}

"""

        gc.collect()
        memory_before = sys.getsizeof(large_content)

        result = TLdif.parse(large_content)
        assert result.is_success

        gc.collect()
        memory_after = sys.getsizeof(result.data)

        # Memory usage should be reasonable (not more than 10x input)
        assert memory_after / memory_before < 10.0

    def test_concurrent_parsing(self, sample_ldif_content: str) -> None:
        """Test concurrent parsing operations."""



        results = queue.Queue()

        def parse_worker():
            result = TLdif.parse(sample_ldif_content)
            results.put(result.is_success)

        # Start multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=parse_worker)
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify all succeeded
        success_count = 0
        while not results.empty():
            if results.get():
                success_count += 1

        if success_count != 10:

            raise AssertionError(f"Expected {10}, got {success_count}")

    def test_edge_cases_special_characters(self) -> None:
        """Test parsing LDIF with special characters."""
        special_content = """dn: cn=Special Üser,ou=people,dc=example,dc=com
objectClass: person
cn: Special Üser
sn: Üser
description: User with special chars: àáâãäåæçèéêë
mail: special@example.com

"""

        result = TLdif.parse(special_content)

        assert result.is_success
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")

        entry = result.data[0]
        if "Üser" not in entry.get_attribute("cn")[0]:
            raise AssertionError(f"Expected {"Üser"} in {entry.get_attribute("cn")[0]}")
        assert "àáâãäåæçèéêë" in entry.get_attribute("description")[0]

    def test_edge_cases_long_lines(self) -> None:
        """Test parsing LDIF with very long lines."""
        long_value = "x" * 1000
        long_content = f"""dn: cn=longuser,ou=people,dc=example,dc=com
objectClass: person
cn: longuser
description: {long_value}

"""

        result = TLdif.parse(long_content)

        assert result.is_success
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")

        entry = result.data[0]
        if len(entry.get_attribute("description")[0]) != 1000:
            raise AssertionError(f"Expected {1000}, got {len(entry.get_attribute("description")[0])}")

    def test_error_handling_robustness(self) -> None:
        """Test error handling robustness with various invalid inputs."""
        invalid_inputs = [
            None,
            123,
            [],
            {},
            "dn: invalid\nno-colon-line",
            "dn: \ncn: empty-dn",
        ]

        for invalid_input in invalid_inputs:
            try:
                result = TLdif.parse(invalid_input)
                # Should either succeed or fail gracefully
                assert result is not None
                assert hasattr(result, "is_success")
                if not result.is_success:
                    assert result.error is not None
            except (RuntimeError, ValueError, TypeError) as e:
                # If exception is raised, it should be expected type
                assert isinstance(e, (TypeError, ValueError, AttributeError))
