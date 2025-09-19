"""Complete tests for FlextLdifParserService - 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif.format_handlers import FlextLdifFormatHandler
from flext_ldif.parser_service import FlextLdifParserService


class FormatHandlerError(Exception):
    """Custom exception for format handler errors in tests."""


class TestFlextLdifParserServiceComplete:
    """Complete tests for FlextLdifParserService to achieve 100% coverage."""

    def test_parser_service_initialization_default(self) -> None:
        """Test parser service initialization with default format handler."""
        service = FlextLdifParserService()
        assert service is not None
        assert service._format_handler is not None

    def test_parser_service_initialization_custom(self) -> None:
        """Test parser service initialization with custom format handler."""
        custom_handler = FlextLdifFormatHandler()
        service = FlextLdifParserService(format_handler=custom_handler)
        assert service is not None
        assert service._format_handler is custom_handler

    def test_get_config_info(self) -> None:
        """Test get_config_info method."""
        service = FlextLdifParserService()

        config_info = service.get_config_info()
        assert isinstance(config_info, dict)
        assert config_info["service"] == "FlextLdifParserService"
        assert "config" in config_info
        assert isinstance(config_info["config"], dict)
        assert config_info["config"]["service_type"] == "parser"
        assert config_info["config"]["status"] == "ready"
        assert "capabilities" in config_info["config"]

    def test_get_service_info(self) -> None:
        """Test get_service_info method."""
        service = FlextLdifParserService()

        service_info = service.get_service_info()
        assert isinstance(service_info, dict)
        assert service_info["service_name"] == "FlextLdifParserService"
        assert service_info["service_type"] == "parser"
        assert service_info["status"] == "ready"
        assert "capabilities" in service_info

    def test_parse_ldif_file_success(self) -> None:
        """Test parse_ldif_file with successful parsing."""
        service = FlextLdifParserService()

        # Create temporary LDIF file using secure tempfile
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as temp_f:
            ldif_content = """dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John

dn: uid=jane,ou=people,dc=example,dc=com
objectClass: person
cn: Jane
"""
            temp_f.write(ldif_content)
            temp_file = Path(temp_f.name)

        try:
            result = service.parse_ldif_file(temp_file)
            assert result.is_success is True
            assert isinstance(result.value, list)
        finally:
            # Clean up
            if temp_file.exists():
                temp_file.unlink()

    def test_parse_ldif_file_exception(self) -> None:
        """Test parse_ldif_file when file reading raises exception."""
        service = FlextLdifParserService()

        # Try to parse non-existent file
        result = service.parse_ldif_file("/nonexistent/file.ldif")
        assert result.is_success is False
        assert result.error is not None and (
            "File read failed" in result.error or "File not found" in result.error
        )

    def test_parse_content_success(self) -> None:
        """Test parse_content with successful parsing."""
        service = FlextLdifParserService()

        ldif_content = """dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John
"""
        result = service.parse_content(ldif_content)
        assert result.is_success is True
        assert isinstance(result.value, list)

    def test_parse_content_empty(self) -> None:
        """Test parse_content with empty content."""
        service = FlextLdifParserService()

        result = service.parse_content("")
        assert result.is_success is True
        assert result.value == []

        result = service.parse_content("   ")
        assert result.is_success is True
        assert result.value == []

    def test_parse_content_exception(self) -> None:
        """Test parse_content with malformed content that raises exception."""
        service = FlextLdifParserService()

        # Create content that will trigger an exception in the format handler
        malformed_content = "dn: test\ninvalid_line_without_colon"

        result = service.parse_content(malformed_content)

        assert result.is_failure
        assert result.error is not None and "LDIF parse failed" in result.error

    def test_validate_ldif_syntax_success(self) -> None:
        """Test validate_ldif_syntax with valid LDIF."""
        service = FlextLdifParserService()

        ldif_content = """dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John
"""
        result = service.validate_ldif_syntax(ldif_content)
        assert result.is_success is True
        assert result.value is True

    def test_validate_ldif_syntax_empty(self) -> None:
        """Test validate_ldif_syntax with empty content."""
        service = FlextLdifParserService()

        result = service.validate_ldif_syntax("")
        assert result.is_success is False
        assert result.error is not None and "Empty LDIF content" in result.error

        result = service.validate_ldif_syntax("   ")
        assert result.is_success is False
        assert result.error is not None and "Empty LDIF content" in result.error

    def test_validate_ldif_syntax_invalid_start(self) -> None:
        """Test validate_ldif_syntax with invalid start."""
        service = FlextLdifParserService()

        ldif_content = """objectClass: person
cn: John
dn: uid=john,ou=people,dc=example,dc=com
"""
        result = service.validate_ldif_syntax(ldif_content)
        assert result.is_success is False
        assert result.error is not None and "LDIF must start with dn:" in result.error

    def test_validate_ldif_syntax_whitespace_only_lines(self) -> None:
        """Test validate_ldif_syntax with whitespace-only lines before dn."""
        service = FlextLdifParserService()

        ldif_content = """

dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John
"""
        result = service.validate_ldif_syntax(ldif_content)
        assert result.is_success is True
        assert result.value is True

    def test_parse_entry_block_success(self) -> None:
        """Test _parse_entry_block with successful parsing."""
        service = FlextLdifParserService()

        block = """dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John
"""
        result = service._parse_entry_block(block)
        assert result.is_success is True
        assert isinstance(result.value, list)

    def test_parse_entry_block_empty(self) -> None:
        """Test _parse_entry_block with empty block."""
        service = FlextLdifParserService()

        result = service._parse_entry_block("")
        assert result.is_failure is True
        assert result.error is not None and "Empty entry block" in result.error

    def test_parse_content_exception_malformed(self) -> None:
        """Test parse_content with malformed content that raises exception."""
        service = FlextLdifParserService()

        # Create content that will trigger an exception in the format handler
        malformed_content = "dn: test\ninvalid_line_without_colon"

        result = service.parse_content(malformed_content)

        assert result.is_failure
        assert result.error is not None and "LDIF parse failed" in result.error

    def test_execute_method(self) -> None:
        """Test execute method."""
        service = FlextLdifParserService()

        result = service.execute()
        assert result.is_success is True
        assert result.value == []
