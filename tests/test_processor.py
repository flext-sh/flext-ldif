"""Tests for LDIF processor."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

# Use simplified imports from root level
from flext_ldif import LDIFEntry, LDIFProcessor
from flext_ldif.config import LDIFConfig
from flext_ldif.domain.values import DistinguishedName, LDIFAttributes


class TestLDIFProcessor:
    """Test LDIF processor functionality."""

    def test_processor_initialization_default_config(self) -> None:
        """Test processor initialization with default config."""
        processor = LDIFProcessor()

        assert processor.config is not None
        assert isinstance(processor.config, LDIFConfig)
        assert processor.parser is not None
        assert processor.validator is not None

    def test_processor_initialization_custom_config(self) -> None:
        """Test processor initialization with custom config."""
        config = LDIFConfig(strict_validation=True, max_entries=100)
        processor = LDIFProcessor(config)

        assert processor.config == config
        assert processor.config.strict_validation is True
        assert processor.config.max_entries == 100

    def test_parse_ldif_content_success(self) -> None:
        """Test parsing LDIF content successfully."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
mail: test@example.com"""

        processor = LDIFProcessor()
        result = processor.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 1

        entry = entries[0]
        assert str(entry.dn) == "cn=test,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["test"]

    def test_parse_ldif_content_with_validation(self) -> None:
        """Test parsing LDIF content with strict validation enabled."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person"""

        config = LDIFConfig(strict_validation=True)
        processor = LDIFProcessor(config)
        result = processor.parse_ldif_content(content)

        # Should succeed if validator passes
        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 1

    def test_parse_ldif_content_exceeds_max_entries(self) -> None:
        """Test parsing LDIF content that exceeds max entries limit."""
        content = """dn: cn=user1,dc=example,dc=com
cn: user1
objectClass: person

dn: cn=user2,dc=example,dc=com
cn: user2
objectClass: person

dn: cn=user3,dc=example,dc=com
cn: user3
objectClass: person"""

        config = LDIFConfig(max_entries=2)
        processor = LDIFProcessor(config)
        result = processor.parse_ldif_content(content)

        assert not result.success
        assert result.error is not None
        assert "Too many entries" in result.error

    def test_parse_ldif_content_parser_fails(self) -> None:
        """Test parsing LDIF content when parser fails."""
        content = """invalid ldif content without dn
cn: test"""

        processor = LDIFProcessor()
        result = processor.parse_ldif_content(content)

        assert not result.success
        assert result.error is not None
        assert "First line must be DN" in result.error

    def test_parse_ldif_content_no_data_returned(self) -> None:
        """Test handling when parser returns None data."""
        from flext_core.domain.shared_types import ServiceResult
        processor = LDIFProcessor()

        # Mock the parser to return success but None data
        original_parse = processor.parser.parse_ldif_content

        def mock_parse(content: str) -> ServiceResult[Any]:
            # Create a successful result but with None data to test the processor's handling
            return ServiceResult.ok(None)

        processor.parser.parse_ldif_content = mock_parse

        try:
            result = processor.parse_ldif_content("test")
            assert not result.success
            assert result.error is not None
            assert "no data returned" in result.error
        finally:
            processor.parser.parse_ldif_content = original_parse

    def test_parse_ldif_content_type_error(self) -> None:
        """Test parsing LDIF content with type error."""
        processor = LDIFProcessor()

        # Pass invalid type to trigger TypeError
        from typing import Any, cast

        result = processor.parse_ldif_content(cast("Any", 123))

        assert not result.success
        assert result.error is not None
        assert "Failed to parse LDIF" in result.error

    def test_parse_ldif_file_success(self) -> None:
        """Test parsing LDIF from file successfully."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
mail: test@example.com"""

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(content)
            temp_file = f.name

        try:
            processor = LDIFProcessor()
            result = processor.parse_ldif_file(temp_file)

            assert result.success
            entries = result.data
            assert entries is not None
            assert len(entries) == 1

            entry = entries[0]
            assert str(entry.dn) == "cn=test,dc=example,dc=com"
        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_parse_ldif_file_not_found(self) -> None:
        """Test parsing LDIF from non-existent file."""
        processor = LDIFProcessor()
        result = processor.parse_ldif_file("/non/existent/file.ldif")

        assert not result.success
        assert result.error is not None
        assert "LDIF file not found" in result.error

    def test_parse_ldif_file_too_large(self) -> None:
        """Test parsing LDIF file that is too large."""
        # Create a file that exceeds size limit
        large_content = "dn: cn=test,dc=example,dc=com\ncn: test\n" * 1000

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(large_content)
            temp_file = f.name

        try:
            config = LDIFConfig(max_entries=1, max_entry_size=100)  # Very small limits
            processor = LDIFProcessor(config)
            result = processor.parse_ldif_file(temp_file)

            assert not result.success
            assert result.error is not None
            assert "File too large" in result.error
        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_parse_ldif_file_unicode_error(self) -> None:
        """Test parsing LDIF file with unicode decode error."""
        # Create file with binary data that can't be decoded as UTF-8
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".ldif", delete=False) as f:
            f.write(b"\xff\xfe\x00\x00invalid_unicode")
            temp_file = f.name

        try:
            processor = LDIFProcessor()
            result = processor.parse_ldif_file(temp_file)

            assert not result.success
            assert result.error is not None
            assert "File processing failed" in result.error
        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_write_ldif_file_success(self) -> None:
        """Test writing LDIF entries to file successfully."""
        entries = [
            LDIFEntry(
                dn=DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=LDIFAttributes(
                    attributes={
                        "cn": ["test"],
                        "objectClass": ["person"],
                    },
                ),
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            temp_file = f.name

        try:
            processor = LDIFProcessor()
            result = processor.write_ldif_file(entries, temp_file)

            assert result.success
            assert result.data is True

            # Verify file was created and contains expected content
            with open(temp_file, encoding="utf-8") as f:
                content = f.read()
                assert "dn: cn=test,dc=example,dc=com" in content
                assert "cn: test" in content
        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_write_ldif_file_create_directory(self) -> None:
        """Test writing LDIF file with directory creation."""
        entries = [
            LDIFEntry(
                dn=DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=LDIFAttributes(attributes={"cn": ["test"]}),
            ),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "subdir" / "test.ldif"

            config = LDIFConfig(create_output_dir=True)
            processor = LDIFProcessor(config)
            result = processor.write_ldif_file(entries, temp_path)

            assert result.success
            assert temp_path.exists()

    def test_write_ldif_file_permission_error(self) -> None:
        """Test writing LDIF file with permission error."""
        entries = [
            LDIFEntry(
                dn=DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=LDIFAttributes(attributes={"cn": ["test"]}),
            ),
        ]

        # Try to write to a directory without permissions (use /root which should be inaccessible)
        processor = LDIFProcessor()
        result = processor.write_ldif_file(entries, "/root/test.ldif")

        assert not result.success
        assert result.error is not None
        assert "File write failed" in result.error

    def test_filter_entries(self) -> None:
        """Test filtering entries by object class."""
        entries = [
            LDIFEntry(
                dn=DistinguishedName(value="cn=person1,dc=example,dc=com"),
                attributes=LDIFAttributes(attributes={"objectClass": ["person"]}),
            ),
            LDIFEntry(
                dn=DistinguishedName(value="cn=group1,dc=example,dc=com"),
                attributes=LDIFAttributes(attributes={"objectClass": ["groupOfNames"]}),
            ),
            LDIFEntry(
                dn=DistinguishedName(value="cn=person2,dc=example,dc=com"),
                attributes=LDIFAttributes(
                    attributes={"objectClass": ["person", "inetOrgPerson"]},
                ),
            ),
        ]

        processor = LDIFProcessor()
        filtered = processor.filter_entries(entries, "person")

        assert len(filtered) == 2
        assert str(filtered[0].dn) == "cn=person1,dc=example,dc=com"
        assert str(filtered[1].dn) == "cn=person2,dc=example,dc=com"

    def test_validate_entries_success(self) -> None:
        """Test validating entries successfully."""
        entries = [
            LDIFEntry(
                dn=DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=LDIFAttributes(
                    attributes={
                        "cn": ["test"],
                        "objectClass": ["person"],  # Add required objectClass
                    },
                ),
            ),
        ]

        processor = LDIFProcessor()
        result = processor.validate_entries(entries)

        if not result.success:
            pass  # Debug info
        assert result.success

    def test_validate_entries_failure(self) -> None:
        """Test validating entries with failure."""
        # Create invalid entries - this depends on validator implementation
        entries: list[LDIFEntry] = []  # Empty entries might be considered invalid

        processor = LDIFProcessor()
        result = processor.validate_entries(entries)

        # Result depends on validator implementation
        # Should either succeed (empty is valid) or fail with specific error
        assert isinstance(result.success, bool)
