"""Tests for FlextLdif processor.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_ldif import FlextLdifConfig, FlextLdifEntry, FlextLdifProcessor


class TestFlextLdifProcessor:
    """Test FlextLdif processor functionality."""

    def test_processor_initialization_default_config(self) -> None:
        """Test processor initialization with default config."""
        processor = FlextLdifProcessor()

        assert processor.config is not None
        assert isinstance(processor.config, FlextLdifConfig)
        assert processor.parser is not None
        assert processor.validator is not None

    def test_processor_initialization_custom_config(self) -> None:
        """Test processor initialization with custom config."""
        # Create config with desired values directly
        config = FlextLdifConfig.model_validate(
            {"strict_validation": True, "max_entries": 100},
        )

        processor = FlextLdifProcessor(config)

        assert processor.config == config
        assert processor.config.strict_validation is True
        assert processor.config.max_entries == 100

    def test_parse_ldif_content_success(self) -> None:
        """Test parsing LDIF content successfully."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
mail: test@example.com"""

        processor = FlextLdifProcessor()
        result = processor.parse_ldif_content(content)

        assert result.success
        entries = result.data
        assert entries is not None
        assert len(entries) == 1

        entry = entries[0]
        assert str(entry.dn) == "cn=test,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["test"]

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

        config = FlextLdifConfig.model_validate({"max_entries": 2})
        processor = FlextLdifProcessor(config)
        result = processor.parse_ldif_content(content)

        assert not result.success
        assert result.error is not None
        assert "Too many entries" in result.error

    def test_parse_ldif_content_parser_fails(self) -> None:
        """Test parsing LDIF content when parser fails."""
        content = """invalid ldif content without dn
cn: test"""

        processor = FlextLdifProcessor()
        result = processor.parse_ldif_content(content)

        assert not result.success
        assert result.error is not None
        assert "First line must be DN" in result.error

    def test_parse_ldif_file_success(self) -> None:
        """Test parsing LDIF from file successfully."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
mail: test@example.com"""

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".ldif", delete=False,
        ) as f:
            f.write(content)
            temp_file = f.name

        try:
            processor = FlextLdifProcessor()
            result = processor.parse_ldif_file(temp_file)

            assert result.success
            entries = result.data
            assert entries is not None
            assert len(entries) == 1

            entry = entries[0]
            assert str(entry.dn) == "cn=test,dc=example,dc=com"
            assert entry.get_attribute("cn") == ["test"]

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_parse_ldif_file_not_found(self) -> None:
        """Test parsing LDIF from non-existent file."""
        processor = FlextLdifProcessor()
        result = processor.parse_ldif_file("/non/existent/file.ldif")

        assert not result.success
        assert result.error is not None
        assert "LDIF file not found" in result.error

    def test_filter_entries(self) -> None:
        """Test filtering entries by object class."""
        entries = [
            FlextLdifEntry.from_ldif_block(
                """dn: cn=person1,dc=example,dc=com
cn: person1
objectClass: person""",
            ),
            FlextLdifEntry.from_ldif_block(
                """dn: cn=group1,dc=example,dc=com
cn: group1
objectClass: group""",
            ),
        ]

        processor = FlextLdifProcessor()
        filtered = processor.filter_entries(entries, "person")

        assert len(filtered) == 1
        assert str(filtered[0].dn) == "cn=person1,dc=example,dc=com"

    def test_validate_entries_success(self) -> None:
        """Test validating entries successfully."""
        entries = [
            FlextLdifEntry.from_ldif_block(
                """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person""",
            ),
        ]

        processor = FlextLdifProcessor()
        result = processor.validate_entries(entries)

        assert result.success
