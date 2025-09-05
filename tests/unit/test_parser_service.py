"""Tests for FlextLDIFServices.ParserService - Real functionality testing without mocks.

Comprehensive tests using actual LDIF data and real service functionality.
No mocks, bypasses, or fake implementations - only real LDIF processing.
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif import FlextLDIFModels, FlextLDIFServices
from tests.support import LdifTestData, TestValidators
from tests.support.test_files import TestFileManager


class TestFlextLDIFServicesParserServiceReal:
    """Test FlextLDIFServices.ParserService with real functionality - no mocks."""

    def test_service_initialization_real_config(self) -> None:
        """Test service initializes with real configuration."""
        config = FlextLDIFModels.Config(
            encoding="utf-8",
            strict_parsing=True,
            validate_dn=True,
            max_entries=1000,
        )
        service = FlextLDIFServices.ParserService(config=config)

        # Validate service has real configuration
        assert service.config is not None
        assert service.config.encoding == "utf-8"
        assert service.config.strict_parsing is True
        assert service.config.validate_dn is True
        assert service.config.max_entries == 1000

    def test_service_initialization_default_config(self) -> None:
        """Test service works with default configuration."""
        service = FlextLDIFServices.ParserService()

        # Even without explicit config, service should work
        result = service.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_parse_real_basic_ldif_entries(self) -> None:
        """Test parsing real LDIF entries with actual data."""
        service = FlextLDIFServices.ParserService()
        ldif_sample = LdifTestData.basic_entries()

        # Parse real LDIF content
        result = service.parse_ldif_content(ldif_sample.content)

        # Validate real parsing results
        TestValidators.assert_successful_result(result)
        entries = result.value
        assert len(entries) == ldif_sample.expected_entries

        # Validate each entry is real and complete
        for entry in entries:
            TestValidators.assert_valid_ldif_entry(entry)
            assert isinstance(entry, FlextLDIFModels.Entry)
            assert entry.dn is not None
            assert len(entry.attributes) > 0

    def test_parse_real_multi_valued_attributes(self) -> None:
        """Test parsing LDIF with multi-valued attributes."""
        service = FlextLDIFServices.ParserService()
        ldif_sample = LdifTestData.multi_valued_attributes()

        # Parse LDIF with multi-valued attributes
        result = service.parse_ldif_content(ldif_sample.content)

        TestValidators.assert_successful_result(result)
        entries = result.value
        assert len(entries) == 1

        entry = entries[0]
        # Verify multi-valued attributes are properly parsed
        mail_values = entry.get_attribute("mail")
        assert mail_values is not None
        assert len(mail_values) == 2
        assert "multi.user@example.com" in mail_values
        assert "multi.user.alt@example.com" in mail_values

        phone_values = entry.get_attribute("telephoneNumber")
        assert phone_values is not None
        assert len(phone_values) == 2

    def test_parse_real_binary_data(self) -> None:
        """Test parsing LDIF with binary (base64) data."""
        service = FlextLDIFServices.ParserService()
        ldif_sample = LdifTestData.with_binary_data()

        # Parse LDIF with binary data
        result = service.parse_ldif_content(ldif_sample.content)

        TestValidators.assert_successful_result(result)
        entries = result.value
        assert len(entries) == 1

        entry = entries[0]
        # Verify binary attribute exists
        jpeg_photo = entry.get_attribute("jpegPhoto")
        assert jpeg_photo is not None
        assert len(jpeg_photo) == 1
        # Should contain base64 data
        assert len(jpeg_photo[0]) > 20  # Base64 encoded data should be substantial

    def test_parse_real_change_records(self) -> None:
        """Test parsing LDIF with change records - should fail gracefully for unsupported format."""
        service = FlextLDIFServices.ParserService()
        ldif_sample = LdifTestData.with_changes()

        # Parse LDIF with change records - expect failure for change records
        result = service.parse_ldif_content(ldif_sample.content)

        # Change records should fail parsing in basic LDIF parser
        assert not result.is_success, "Parser should fail on change records"
        assert result.error is not None
        assert "syntax" in result.error.lower() or "invalid" in result.error.lower()

        # This tests real LDIF parser behavior - change records are not supported
        # by basic LDIF entry parsers, which is correct behavior
        # Change records should still be parsed as entries

    def test_parse_real_special_characters(self) -> None:
        """Test parsing LDIF with UTF-8 special characters."""
        service = FlextLDIFServices.ParserService()
        ldif_sample = LdifTestData.special_characters()

        # Parse LDIF with special characters
        result = service.parse_ldif_content(ldif_sample.content)

        TestValidators.assert_successful_result(result)
        entries = result.value
        assert len(entries) == 1

        entry = entries[0]
        cn_values = entry.get_attribute("cn")
        assert cn_values is not None
        assert "José María Ñuñez" in cn_values[0]

        description = entry.get_attribute("description")
        assert description is not None
        assert "áéíóú ÁÉÍÓÚ ñÑ" in description[0]

    def test_parse_real_long_lines(self) -> None:
        """Test parsing LDIF with long lines requiring continuation."""
        service = FlextLDIFServices.ParserService()
        ldif_sample = LdifTestData.long_lines()

        # Parse LDIF with long lines
        result = service.parse_ldif_content(ldif_sample.content)

        TestValidators.assert_successful_result(result)
        entries = result.value
        assert len(entries) == 1

        entry = entries[0]
        description = entry.get_attribute("description")
        assert description is not None
        # Long description should be properly reconstructed
        assert len(description[0]) > 100  # Should be substantial text

    def test_parse_real_error_invalid_ldif(self) -> None:
        """Test parser handles invalid LDIF data correctly."""
        service = FlextLDIFServices.ParserService()
        ldif_sample = LdifTestData.invalid_data()

        # Parse invalid LDIF - should handle gracefully
        result = service.parse_ldif_content(ldif_sample.content)

        # Parser should either succeed with partial results or fail gracefully
        assert isinstance(result, FlextResult)
        if result.is_success:
            # If successful, should have limited entries due to validation
            entries = result.value
            assert len(entries) <= 3  # Should filter out invalid entries
        else:
            # If failed, should have meaningful error message
            assert result.error is not None
            assert len(str(result.error)) > 0

    def test_parse_real_empty_content(self) -> None:
        """Test parser handles empty content correctly."""
        service = FlextLDIFServices.ParserService()

        # Parse empty content
        result = service.parse_ldif_content("")

        TestValidators.assert_successful_result(result)
        entries = result.value
        assert len(entries) == 0

    def test_parse_real_from_file_path(
        self, test_file_manager: TestFileManager
    ) -> None:
        """Test parsing from actual file path."""
        service = FlextLDIFServices.ParserService()
        ldif_sample = LdifTestData.basic_entries()

        # Create real file with LDIF content
        ldif_file = test_file_manager.create_sample_file(ldif_sample)

        # Parse from file path
        result = service.parse_ldif_file(ldif_file)

        TestValidators.assert_successful_result(result)
        entries = result.value
        assert len(entries) == ldif_sample.expected_entries

        # Verify file parsing produces same results as content parsing
        content_result = service.parse_ldif_content(ldif_sample.content)
        assert len(entries) == len(content_result.value)

    def test_parse_real_large_dataset(self, test_file_manager: TestFileManager) -> None:
        """Test parsing performance with larger dataset."""
        service = FlextLDIFServices.ParserService()

        # Create larger dataset for performance testing
        ldif_sample = LdifTestData.large_dataset(50)  # 50 entries
        ldif_file = test_file_manager.create_sample_file(ldif_sample)

        # Parse large dataset
        result = service.parse_ldif_file(ldif_file)

        TestValidators.assert_successful_result(result)
        entries = result.value
        assert len(entries) == 50

        # Verify all entries are properly formed
        for i, entry in enumerate(entries):
            TestValidators.assert_valid_ldif_entry(entry)
            # Verify unique DN for each entry
            assert f"user{i:04d}" in str(entry.dn)


# Integration tests using real parser with other services
class TestParserIntegrationReal:
    """Integration tests with real parser and other services."""

    def test_parser_with_real_validator_integration(
        self, integration_services: dict[str, object]
    ) -> None:
        """Test parser integrated with real validator service."""
        parser = integration_services["parser"]
        validator = integration_services["validator"]

        # Parse real data
        ldif_sample = LdifTestData.basic_entries()
        parse_result = parser.parse_ldif_content(ldif_sample.content)

        TestValidators.assert_successful_result(parse_result)
        entries = parse_result.value

        # Validate each parsed entry with real validator
        for entry in entries:
            validation_result = validator.validate_entry_structure(entry)
            TestValidators.assert_successful_result(validation_result)

    def test_parser_with_real_writer_roundtrip(
        self, integration_services: dict[str, object]
    ) -> None:
        """Test parser → writer → parser roundtrip with real services."""
        parser = integration_services["parser"]
        writer = integration_services["writer"]

        # Parse original data
        ldif_sample = LdifTestData.basic_entries()
        original_result = parser.parse_ldif_content(ldif_sample.content)
        TestValidators.assert_successful_result(original_result)
        original_entries = original_result.value

        # Write entries back to LDIF
        write_result = writer.write_entries_to_string(original_entries)
        TestValidators.assert_successful_result(write_result)
        written_content = write_result.value

        # Parse the written content again
        reparse_result = parser.parse_ldif_content(written_content)
        TestValidators.assert_successful_result(reparse_result)
        reparsed_entries = reparse_result.value

        # Verify roundtrip consistency
        assert len(original_entries) == len(reparsed_entries)
        for original, reparsed in zip(original_entries, reparsed_entries, strict=False):
            assert str(original.dn) == str(reparsed.dn)
            assert len(original.attributes) == len(reparsed.attributes)
