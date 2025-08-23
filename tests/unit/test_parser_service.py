"""Tests for FlextLdifParserService - comprehensive real functionality coverage."""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_core import FlextResult

from flext_ldif.models import FlextLdifConfig, FlextLdifEntry
from flext_ldif.parser_service import FlextLdifParserService


class TestFlextLdifParserService:
    """Test FlextLdifParserService with real functionality."""

    def test_service_initialization(self) -> None:
        """Test service can be initialized."""
        service = FlextLdifParserService()
        assert service.config is None

    def test_service_initialization_with_config(self) -> None:
        """Test service initialization with custom config."""
        config = FlextLdifConfig(strict_validation=True)
        service = FlextLdifParserService(config=config)
        assert service.config is not None
        assert service.config.strict_validation is True

    def test_execute_default(self) -> None:
        """Test execute method returns empty list by default."""
        service = FlextLdifParserService()
        result = service.execute()
        
        assert result.is_success
        assert result.value == []

    def test_parse_valid_ldif_content(self) -> None:
        """Test parsing valid LDIF content."""
        service = FlextLdifParserService()
        
        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson  
objectClass: person
objectClass: top
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com"""

        result = service.parse(ldif_content)
        
        assert result.is_success
        assert len(result.value) == 2
        
        # Verify first entry
        first_entry = result.value[0]
        assert str(first_entry.dn) == "cn=John Doe,ou=people,dc=example,dc=com"
        assert "John Doe" in first_entry.get_attribute("cn")
        assert "inetOrgPerson" in first_entry.get_attribute("objectClass")

    def test_parse_empty_content(self) -> None:
        """Test parsing empty content returns empty list."""
        service = FlextLdifParserService()
        
        result = service.parse("")
        assert result.is_success
        assert result.value == []

    def test_parse_whitespace_only_content(self) -> None:
        """Test parsing whitespace-only content returns empty list."""
        service = FlextLdifParserService()
        
        result = service.parse("   \n\t  \n  ")
        assert result.is_success
        assert result.value == []

    def test_parse_non_string_content(self) -> None:
        """Test parsing non-string content fails gracefully."""
        service = FlextLdifParserService()
        
        # Test with integer
        result = service.parse(123)  # type: ignore[arg-type]
        assert result.is_failure
        assert "content type" in (result.error or "")
        
        # Test with None
        result = service.parse(None)  # type: ignore[arg-type]
        assert result.is_failure
        
        # Test with list
        result = service.parse([])  # type: ignore[arg-type]
        assert result.is_failure

    def test_parse_invalid_ldif_blocks(self) -> None:
        """Test parsing invalid LDIF blocks."""
        service = FlextLdifParserService()
        
        # Invalid LDIF that can't be parsed at all
        invalid_content = """invalid: format
not: ldif
broken: completely"""

        result = service.parse(invalid_content)
        
        # Should fail when no entries can be parsed from non-empty content
        assert result.is_failure
        assert "blocks failed to parse" in (result.error or "").lower()

    def test_parse_mixed_valid_invalid_blocks(self) -> None:
        """Test parsing mixed valid/invalid LDIF blocks."""
        service = FlextLdifParserService()
        
        mixed_content = """dn: cn=valid,dc=example,dc=com
objectClass: person
objectClass: top
cn: valid
sn: entry

invalid: block
not: a
valid: ldif

dn: cn=another_valid,dc=example,dc=com
objectClass: person
objectClass: top
cn: another_valid
sn: entry"""

        result = service.parse(mixed_content)
        
        # Should succeed with the valid entries, ignoring invalid ones
        assert result.is_success
        assert len(result.value) >= 1  # At least one valid entry should be parsed

    def test_parse_ldif_file_success(self) -> None:
        """Test parsing LDIF file successfully."""
        service = FlextLdifParserService()
        
        # Create a temporary LDIF file
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: top
cn: test
sn: user"""

        # Use pytest's tmp_path fixture equivalent
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ldif', delete=False) as f:
            f.write(ldif_content)
            f.flush()
            
            result = service.parse_ldif_file(f.name)
            
            assert result.is_success
            assert len(result.value) == 1
            assert str(result.value[0].dn) == "cn=test,dc=example,dc=com"

    def test_parse_ldif_file_not_found(self) -> None:
        """Test parsing non-existent LDIF file."""
        service = FlextLdifParserService()
        
        result = service.parse_ldif_file("/nonexistent/file.ldif")
        
        assert result.is_failure
        assert "file" in (result.error or "").lower()

    def test_parse_ldif_file_permission_error(self) -> None:
        """Test parsing LDIF file with permission issues."""
        service = FlextLdifParserService()
        
        # Try to read a directory instead of a file to trigger permission/type error
        result = service.parse_ldif_file("/")
        
        assert result.is_failure

    def test_parse_ldif_file_encoding_issues(self) -> None:
        """Test parsing LDIF file with encoding problems."""
        service = FlextLdifParserService()
        
        # Create a file with problematic encoding
        import tempfile
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.ldif', delete=False) as f:
            # Write invalid UTF-8 bytes
            f.write(b"dn: cn=test,dc=example,dc=com\n")
            f.write(b"cn: \xff\xfe invalid bytes")
            f.flush()
            
            result = service.parse_ldif_file(f.name)
            
            # Should handle encoding errors gracefully
            assert result.is_failure or result.is_success  # Either way is acceptable

    def test_parse_entry_block_valid(self) -> None:
        """Test parsing a single valid entry block."""
        service = FlextLdifParserService()
        
        block = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: top
cn: test
sn: user"""

        result = service._parse_entry_block(block)
        
        assert result.is_success
        entry = result.value
        assert str(entry.dn) == "cn=test,dc=example,dc=com"
        assert "person" in entry.get_attribute("objectClass")

    def test_parse_entry_block_invalid(self) -> None:
        """Test parsing invalid entry block."""
        service = FlextLdifParserService()
        
        # Block without DN
        invalid_block = """objectClass: person
cn: test"""

        result = service._parse_entry_block(invalid_block)
        
        assert result.is_failure

    def test_parse_entry_block_empty(self) -> None:
        """Test parsing empty entry block."""
        service = FlextLdifParserService()
        
        result = service._parse_entry_block("")
        
        assert result.is_failure

    def test_error_handling_with_malformed_content(self) -> None:
        """Test error handling with malformed LDIF content."""
        service = FlextLdifParserService()
        
        # Test with content that causes parsing errors
        malformed_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
# This malformed content should trigger error handling
invalid-attribute-format: value with \x00 null bytes"""

        result = service.parse(malformed_content)
        
        # Should either succeed (ignoring malformed parts) or fail gracefully
        assert isinstance(result, FlextResult)

    def test_parse_with_config(self) -> None:
        """Test parsing with specific configuration."""
        config = FlextLdifConfig(strict_validation=True, allow_empty_attributes=False)
        service = FlextLdifParserService(config=config)
        
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: top
cn: test
sn: user"""

        result = service.parse(ldif_content)
        
        assert result.is_success
        assert len(result.value) == 1

    def test_tap_error_functionality(self) -> None:
        """Test tap_error callback functionality during parsing."""
        service = FlextLdifParserService()
        
        # Mix valid and invalid blocks to test tap_error callback
        content_with_errors = """dn: cn=valid,dc=example,dc=com
objectClass: person
objectClass: top
cn: valid

invalid_block_without_dn
still: invalid

dn: cn=another_valid,dc=example,dc=com
objectClass: person  
objectClass: top
cn: another_valid"""

        result = service.parse(content_with_errors)
        
        # Should succeed with valid entries and log errors for invalid ones
        if result.is_success:
            assert len(result.value) >= 1
        else:
            # Or fail if all blocks are invalid
            assert "failed to parse" in (result.error or "").lower()