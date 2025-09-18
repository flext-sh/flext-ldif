"""Additional tests for FlextLdifUtilities to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class TestFlextLdifUtilitiesAdditional:
    """Additional test cases for FlextLdifUtilities to achieve 100% coverage."""

    def test_validate_ldif_file_path_file_not_exists(self) -> None:
        """Test validate_ldif_file_path with non-existent file."""
        utilities = FlextLdifUtilities()

        result = utilities.validate_ldif_file_path("/nonexistent/file.ldif")

        assert result.is_failure
        assert "File does not exist" in result.error

    def test_validate_ldif_file_path_not_file(self) -> None:
        """Test validate_ldif_file_path with directory instead of file."""
        utilities = FlextLdifUtilities()

        # Use a directory that exists
        result = utilities.validate_ldif_file_path("/usr")

        assert result.is_failure
        assert "Path is not a file" in result.error

    def test_validate_ldif_file_extension_exception_handling(self) -> None:
        """Test validate_ldif_file_extension with exception during path conversion."""
        utilities = FlextLdifUtilities()

        # Create a mock path object that raises exception on str() conversion
        class FailingPath:
            def __str__(self) -> str:
                msg = "Path conversion failed"
                raise RuntimeError(msg)

        failing_path = FailingPath()

        result = utilities.validate_ldif_file_extension(failing_path)

        assert result.is_failure
        assert "Extension validation failed" in result.error

    def test_validate_ldif_content_empty_content(self) -> None:
        """Test validate_ldif_content with empty content."""
        utilities = FlextLdifUtilities()

        result = utilities.validate_ldif_content("")

        assert result.is_failure
        assert "Content cannot be empty" in result.error

    def test_validate_ldif_content_whitespace_only(self) -> None:
        """Test validate_ldif_content with whitespace-only content."""
        utilities = FlextLdifUtilities()

        result = utilities.validate_ldif_content("   \n\t  ")

        assert result.is_failure
        assert "Content cannot be empty" in result.error

    def test_validate_ldif_content_validation_exception(self) -> None:
        """Test validate_ldif_content with validation exception."""
        utilities = FlextLdifUtilities()

        # Mock FlextUtilities.Validation.is_non_empty_string to raise exception
        with patch(
            "flext_ldif.utilities.FlextUtilities.Validation.is_non_empty_string"
        ) as mock_validation:
            mock_validation.side_effect = RuntimeError("Validation failed")

            result = utilities.validate_ldif_content("test content")

            assert result.is_failure
            assert "Content validation failed" in result.error

    def test_validate_dn_format_validation_exception(self) -> None:
        """Test validate_dn_format with validation exception."""
        utilities = FlextLdifUtilities()

        # Mock FlextLdifModels.DistinguishedName to raise exception
        with patch("flext_ldif.utilities.FlextLdifModels.DistinguishedName") as mock_dn:
            mock_dn.side_effect = RuntimeError("DN validation failed")

            result = utilities.validate_dn_format("cn=test,dc=example,dc=com")

            assert result.is_failure
            assert "DN validation failed" in result.error

    def test_normalize_dn_format_no_equals_in_component(self) -> None:
        """Test normalize_dn_format with component without equals sign."""
        utilities = FlextLdifUtilities()

        result = utilities.normalize_dn_format("cn=test,invalidcomponent,dc=com")

        assert result.is_failure
        assert "DN normalization failed" in result.error

    def test_normalize_dn_format_validation_failure(self) -> None:
        """Test normalize_dn_format with validation failure."""
        utilities = FlextLdifUtilities()

        # Mock the DN validation to fail
        with patch(
            "flext_ldif.utilities.FlextLdifModels.DistinguishedName"
        ) as mock_dn_class:
            mock_dn_instance = Mock()
            mock_dn_instance.validate_business_rules.return_value = FlextResult[
                None
            ].fail("Validation failed")
            mock_dn_class.return_value = mock_dn_instance

            result = utilities.normalize_dn_format("cn=test,dc=example,dc=com")

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_validate_attribute_name_validation_exception(self) -> None:
        """Test validate_attribute_name with validation exception."""
        utilities = FlextLdifUtilities()

        # Mock FlextLdifModels.LdifAttributeName to raise exception
        with patch(
            "flext_ldif.utilities.FlextLdifModels.LdifAttributeName"
        ) as mock_attr:
            mock_attr.side_effect = RuntimeError("Attribute validation failed")

            result = utilities.validate_attribute_name("cn")

            assert result.is_failure
            assert "Attribute name validation failed" in result.error

    def test_normalize_ldif_content_exception_handling(self) -> None:
        """Test normalize_ldif_content with exception handling."""
        utilities = FlextLdifUtilities()

        # Mock the normalize_ldif_content method to simulate exception
        original_normalize = utilities.normalize_ldif_content

        def mock_normalize(_content: str) -> FlextResult[str]:
            return FlextResult[str].fail("Content normalization failed")

        # Temporarily replace the method
        utilities.normalize_ldif_content = mock_normalize

        try:
            result = utilities.normalize_ldif_content("test content")

            assert result.is_failure
            assert "Content normalization failed" in result.error
        finally:
            # Restore original method
            utilities.normalize_ldif_content = original_normalize

    def test_extract_dn_from_content_validation_failure(self) -> None:
        """Test extract_dn_from_content with validation failure."""
        utilities = FlextLdifUtilities()

        # Mock validate_ldif_content to fail
        with patch.object(utilities, "validate_ldif_content") as mock_validate:
            mock_validate.return_value = FlextResult[str].fail(
                "Content validation failed"
            )

            result = utilities.extract_dn_from_content("invalid content")

            assert result.is_failure
            assert "Content validation failed" in result.error

    def test_extract_dn_from_content_no_dn_found(self) -> None:
        """Test extract_dn_from_content with no DN found."""
        utilities = FlextLdifUtilities()

        # Mock validate_ldif_content to succeed but return content without DN
        with patch.object(utilities, "validate_ldif_content") as mock_validate:
            mock_validate.return_value = FlextResult[str].ok("cn: test\nsn: user")

            result = utilities.extract_dn_from_content("cn: test\nsn: user")

            assert result.is_failure
            assert "No DN found in content" in result.error

    def test_extract_dn_from_content_empty_dn_value(self) -> None:
        """Test extract_dn_from_content with empty DN value."""
        utilities = FlextLdifUtilities()

        result = utilities.extract_dn_from_content("dn: \ncn: test")

        assert result.is_failure
        assert "No DN found in content" in result.error

    def test_count_entries_in_content_validation_failure(self) -> None:
        """Test count_entries_in_content with validation failure."""
        utilities = FlextLdifUtilities()

        # Mock validate_ldif_content to fail
        with patch.object(utilities, "validate_ldif_content") as mock_validate:
            mock_validate.return_value = FlextResult[str].fail(
                "Content validation failed"
            )

            result = utilities.count_entries_in_content("invalid content")

            assert result.is_failure
            assert "Content validation failed" in result.error

    def test_get_file_size_mb_file_not_exists(self) -> None:
        """Test get_file_size_mb with non-existent file."""
        utilities = FlextLdifUtilities()

        result = utilities.get_file_size_mb("/nonexistent/file.ldif")

        assert result.is_failure
        assert "File does not exist" in result.error

    def test_get_file_size_mb_exception_handling(self) -> None:
        """Test get_file_size_mb with exception during stat."""
        utilities = FlextLdifUtilities()

        # Mock Path.stat() to raise exception
        with patch("flext_ldif.utilities.Path") as mock_path_class:
            mock_path_instance = Mock()
            mock_path_instance.exists.return_value = True
            mock_path_instance.stat.side_effect = OSError("Stat failed")
            mock_path_class.return_value = mock_path_instance

            result = utilities.get_file_size_mb("/test/file.ldif")

            assert result.is_failure
            assert "File size calculation failed" in result.error

    def test_is_file_too_large_size_calculation_failure(self) -> None:
        """Test is_file_too_large with size calculation failure."""
        utilities = FlextLdifUtilities()

        # Mock get_file_size_mb to fail
        with patch.object(utilities, "get_file_size_mb") as mock_size:
            mock_size.return_value = FlextResult[float].fail("Size calculation failed")

            result = utilities.is_file_too_large("/test/file.ldif", 100)

            assert result.is_failure
            assert "Size calculation failed" in result.error

    def test_create_entry_summary_exception_handling(self) -> None:
        """Test create_entry_summary with exception handling."""
        utilities = FlextLdifUtilities()

        # Create a mock entry that raises exception
        mock_entry = Mock()
        mock_entry.dn.value = "cn=test,dc=example,dc=com"
        mock_entry.get_rdn.side_effect = RuntimeError("Summary creation failed")

        result = utilities.create_entry_summary(mock_entry)

        assert result.is_failure
        assert "Entry summary creation failed" in result.error

    def test_convert_entry_to_dict_exception_handling(self) -> None:
        """Test convert_entry_to_dict with exception handling."""
        utilities = FlextLdifUtilities()

        # Create a mock entry that raises exception
        mock_entry = Mock()
        mock_entry.dn.value = "cn=test,dc=example,dc=com"
        mock_entry.attributes.data.side_effect = RuntimeError("Conversion failed")

        result = utilities.convert_entry_to_dict(mock_entry)

        assert result.is_failure
        assert "Entry conversion failed" in result.error

    def test_calculate_entry_size_exception_handling(self) -> None:
        """Test calculate_entry_size with exception handling."""
        utilities = FlextLdifUtilities()

        # Create a mock entry that raises exception
        mock_entry = Mock()
        mock_dn = Mock()
        mock_dn.value.encode.side_effect = UnicodeError("Encoding failed")
        mock_entry.dn = mock_dn

        result = utilities.calculate_entry_size(mock_entry)

        assert result.is_failure
        assert "Entry size calculation failed" in result.error

    def test_extract_base_dn_validation_failure(self) -> None:
        """Test extract_base_dn with validation failure."""
        utilities = FlextLdifUtilities()

        # Mock DN validation to fail
        with patch(
            "flext_ldif.utilities.FlextLdifModels.DistinguishedName"
        ) as mock_dn_class:
            mock_dn_instance = Mock()
            mock_dn_instance.validate_business_rules.return_value = FlextResult[
                None
            ].fail("Validation failed")
            mock_dn_class.return_value = mock_dn_instance

            result = utilities.extract_base_dn("cn=test,dc=example,dc=com")

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_validate_ldif_entry_completeness_validation_failure(self) -> None:
        """Test validate_ldif_entry_completeness with validation failure."""
        utilities = FlextLdifUtilities()

        # Create a mock entry with validation failure
        mock_entry = Mock()
        mock_entry.validate_business_rules.return_value = FlextResult[None].fail(
            "Entry validation failed"
        )

        result = utilities.validate_ldif_entry_completeness(mock_entry)

        assert result.is_failure
        assert "Entry validation failed" in result.error

    def test_merge_ldif_entries_different_dn(self) -> None:
        """Test merge_ldif_entries with different DNs."""
        utilities = FlextLdifUtilities()

        entry1 = FlextLdifModels.create_entry(
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": ["test1"]}}
        )

        entry2 = FlextLdifModels.create_entry(
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": ["test2"]}}
        )

        result = utilities.merge_ldif_entries(entry1, entry2)

        assert result.is_failure
        assert "Cannot merge entries with different DNs" in result.error

    def test_merge_ldif_entries_exception_handling(self) -> None:
        """Test merge_ldif_entries with exception handling."""
        utilities = FlextLdifUtilities()

        # Create mock entries that raise exception
        mock_entry1 = Mock()
        mock_entry1.dn.value = "cn=test,dc=example,dc=com"
        mock_entry1.attributes.data = {"cn": ["test"]}

        mock_entry2 = Mock()
        mock_entry2.dn.value = "cn=test,dc=example,dc=com"
        mock_entry2.attributes.data.side_effect = RuntimeError("Merge failed")

        result = utilities.merge_ldif_entries(mock_entry1, mock_entry2)

        assert result.is_failure
        assert "Entry merge failed" in result.error
