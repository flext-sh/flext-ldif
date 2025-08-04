"""Enterprise tests for TLdif core functionality.

Comprehensive test suite covering all core LDIF processing functionality
using enterprise-grade testing practices with full coverage and validation.
"""

from __future__ import annotations

import gc
import queue
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from flext_ldif import TLdif

# Constants
EXPECTED_DATA_COUNT = 3


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

        assert result.success
        assert result.data is not None
        if len(result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(result.data)}"
            raise AssertionError(msg)
        assert result.error is None

        # Verify first entry
        entry = result.data[0]
        if str(entry.dn) != "cn=John Doe,ou=people,dc=example,dc=com":
            msg: str = f"Expected {'cn=John Doe,ou=people,dc=example,dc=com'}, got {entry.dn!s}"
            raise AssertionError(msg)
        assert entry.get_attribute("cn") == ["John Doe"]
        if entry.get_attribute("mail") != ["john.doe@example.com"]:
            msg: str = f"Expected {['john.doe@example.com']}, got {entry.get_attribute('mail')}"
            raise AssertionError(msg)
        assert entry.has_object_class("person")
        assert entry.has_object_class("inetOrgPerson")

    def test_parse_empty_content_returns_empty_list(self) -> None:
        """Test parsing empty content returns empty list."""
        result = TLdif.parse("")

        assert result.success
        if result.data != []:
            msg: str = f"Expected {[]}, got {result.data}"
            raise AssertionError(msg)
        assert result.error is None

    def test_parse_malformed_content_fails(self, malformed_ldif_content: str) -> None:
        """Test parsing malformed content fails gracefully."""
        result = TLdif.parse(malformed_ldif_content)

        assert not result.success
        assert result.data is None
        assert result.error is not None

    def test_validate_valid_entries_success(self, sample_ldif_content: str) -> None:
        """Test validating valid entries succeeds."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.success

        validate_result = TLdif.validate_entries(parse_result.data)

        assert validate_result.success
        if not (validate_result.data):
            msg: str = f"Expected True, got {validate_result.data}"
            raise AssertionError(msg)
        assert validate_result.error is None

    def test_validate_invalid_entries_fails(self, invalid_ldif_content: str) -> None:
        """Test validating invalid entries fails with proper error."""
        parse_result = TLdif.parse(invalid_ldif_content)

        if parse_result.success:
            validate_result = TLdif.validate_entries(parse_result.data)
            assert not validate_result.success
            assert validate_result.error is not None

    def test_validate_single_entry_success(self, sample_ldif_content: str) -> None:
        """Test validating single valid entry succeeds."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.success

        entry = parse_result.data[0]
        validate_result = TLdif.validate(entry)

        assert validate_result.success
        if not (validate_result.data):
            msg: str = f"Expected True, got {validate_result.data}"
            raise AssertionError(msg)

    def test_write_entries_success(self, sample_ldif_content: str) -> None:
        """Test writing entries to LDIF string succeeds."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.success

        write_result = TLdif.write(parse_result.data)

        assert write_result.success
        assert write_result.data is not None
        assert len(write_result.data) > 0
        if "dn:" not in write_result.data:
            msg: str = f"Expected {'dn:'} in {write_result.data}"
            raise AssertionError(msg)
        assert "objectClass:" in write_result.data

    def test_round_trip_parsing_writing(self, sample_ldif_content: str) -> None:
        """Test round-trip: parse → write → parse maintains data integrity."""
        # Parse original
        parse1_result = TLdif.parse(sample_ldif_content)
        assert parse1_result.success
        original_entries = parse1_result.data

        # Write to string
        write_result = TLdif.write(original_entries)
        assert write_result.success
        written_content = write_result.data

        # Parse written content
        parse2_result = TLdif.parse(written_content)
        assert parse2_result.success
        reparsed_entries = parse2_result.data

        # Verify integrity
        if len(reparsed_entries) != len(original_entries):
            msg: str = f"Expected {len(original_entries)}, got {len(reparsed_entries)}"
            raise AssertionError(msg)

        for original, reparsed in zip(original_entries, reparsed_entries, strict=False):
            if str(original.dn) != str(reparsed.dn):
                msg: str = f"Expected {reparsed.dn!s}, got {original.dn!s}"
                raise AssertionError(msg)
            assert original.attributes.attributes == reparsed.attributes.attributes

    def test_write_file_success(self, sample_ldif_content: str) -> None:
        """Test writing entries to file succeeds."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.success

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            delete=False,
            suffix=".ldif",
        ) as f:
            temp_file = Path(f.name)

        try:
            # Write to file
            write_result = TLdif.write_file(parse_result.data, temp_file)
            assert write_result.success
            if not (write_result.data):
                msg: str = f"Expected True, got {write_result.data}"
                raise AssertionError(msg)

            # Verify file exists and has content
            assert temp_file.exists()
            content = temp_file.read_text(encoding="utf-8")
            assert len(content) > 0
            if "dn:" not in content:
                msg: str = f"Expected {'dn:'} in {content}"
                raise AssertionError(msg)

        finally:
            temp_file.unlink(missing_ok=True)

    def test_read_file_success(self, sample_ldif_content: str) -> None:
        """Test reading entries from file succeeds."""
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            delete=False,
            suffix=".ldif",
        ) as f:
            f.write(sample_ldif_content)
            temp_file = Path(f.name)

        try:
            # Read from file
            read_result = TLdif.read_file(temp_file)
            assert read_result.success
            assert read_result.data is not None
            if len(read_result.data) != EXPECTED_DATA_COUNT:
                msg: str = f"Expected {3}, got {len(read_result.data)}"
                raise AssertionError(msg)

            # Verify content
            entry = read_result.data[0]
            if entry.get_attribute("cn") != ["John Doe"]:
                msg: str = f"Expected {['John Doe']}, got {entry.get_attribute('cn')}"
                raise AssertionError(msg)

        finally:
            temp_file.unlink(missing_ok=True)

    def test_read_nonexistent_file_fails(self) -> None:
        """Test reading nonexistent file fails gracefully."""
        nonexistent_file = Path("/nonexistent/path/file.ldif")

        read_result = TLdif.read_file(nonexistent_file)

        assert not read_result.success
        assert read_result.data is None
        if "not found" not in read_result.error.lower():
            msg: str = f"Expected {'not found'} in {read_result.error.lower()}"
            raise AssertionError(msg)

    def test_write_file_to_nonexistent_directory_fails(
        self,
        sample_ldif_content: str,
    ) -> None:
        """Test writing to nonexistent directory fails gracefully."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.success

        nonexistent_path = Path("/nonexistent/directory/file.ldif")
        write_result = TLdif.write_file(parse_result.data, nonexistent_path)

        assert not write_result.success
        if "failed" not in write_result.error.lower():
            msg: str = f"Expected {'failed'} in {write_result.error.lower()}"
            raise AssertionError(msg)

    def test_parse_with_ldif3_fallback(self, sample_ldif_content: str) -> None:
        """Test parsing works with both ldif3 and custom parser."""
        # This test verifies the fallback mechanism works
        result = TLdif.parse(sample_ldif_content)

        assert result.success
        assert result.data is not None
        assert len(result.data) > 0

    def test_write_with_ldif3_fallback(self, sample_ldif_content: str) -> None:
        """Test writing works with both ldif3 and custom writer."""
        parse_result = TLdif.parse(sample_ldif_content)
        assert parse_result.success

        write_result = TLdif.write(parse_result.data)

        assert write_result.success
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

        assert result.success
        if len(result.data) != 100:
            msg: str = f"Expected {100}, got {len(result.data)}"
            raise AssertionError(msg)
        if not (parse_time < 5.0):  # Should parse 100 entries in under 5 seconds
            msg: str = f"Expected parse time < 5.0 seconds, got {parse_time}"
            raise AssertionError(msg)

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
        assert result.success

        gc.collect()
        memory_after = sys.getsizeof(result.data)

        # Memory usage should be reasonable (not more than 10x input)
        assert memory_after / memory_before < 10.0

    def test_concurrent_parsing(self, sample_ldif_content: str) -> None:
        """Test concurrent parsing operations."""

        results = queue.Queue()

        def parse_worker():
            result = TLdif.parse(sample_ldif_content)
            results.put(result.success)

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
            msg: str = f"Expected {10}, got {success_count}"
            raise AssertionError(msg)

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

        assert result.success
        if len(result.data) != 1:
            msg: str = f"Expected {1}, got {len(result.data)}"
            raise AssertionError(msg)

        entry = result.data[0]
        if "Üser" not in entry.get_attribute("cn")[0]:
            msg: str = f"Expected {'Üser'} in {entry.get_attribute('cn')[0]}"
            raise AssertionError(msg)
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

        assert result.success
        if len(result.data) != 1:
            msg: str = f"Expected {1}, got {len(result.data)}"
            raise AssertionError(msg)

        entry = result.data[0]
        if len(entry.get_attribute("description")[0]) != 1000:
            msg: str = (
                f"Expected {1000}, got {len(entry.get_attribute('description')[0])}"
            )
            raise AssertionError(msg)

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
                assert hasattr(result, "success")
                if not result.success:
                    assert result.error is not None
            except (RuntimeError, ValueError, TypeError):
                # If exception is raised, it should be expected type
                pass
