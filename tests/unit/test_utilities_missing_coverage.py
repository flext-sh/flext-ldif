"""Additional tests for FlextLdifUtilities to cover missing lines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class TestFlextLdifUtilitiesMissingCoverage:
    """Additional tests to achieve 100% coverage for utilities."""

    def test_validate_ldif_file_extension_with_invalid_extension(self) -> None:
        """Test validate_ldif_file_extension with invalid file extension."""
        utilities = FlextLdifUtilities()

        # Test with file that has invalid extension
        result = utilities.validate_ldif_file_extension("test_file.txt")
        assert result.is_success is True
        assert (
            result.value is False
        )  # Invalid extension but successful validation operation

    def test_normalize_dn_format_with_empty_string(self) -> None:
        """Test normalize_dn_format with empty string input."""
        utilities = FlextLdifUtilities()

        # Test with empty string
        result = utilities.normalize_dn_format("")
        assert result.is_success is False
        assert result.error is not None and "DN normalization failed" in result.error

    def test_extract_base_dn_with_malformed_dn(self) -> None:
        """Test extract_base_dn with malformed DN input."""
        utilities = FlextLdifUtilities()

        # Test with malformed DN (missing parts)
        result = utilities.extract_base_dn("invaliddn")
        assert result.is_success is False
        assert result.error is not None and "Base DN extraction failed" in result.error

    def test_merge_ldif_entries_entry2_attributes_none(self) -> None:
        """Test merge_ldif_entries when entry2.attributes is None."""
        utilities = FlextLdifUtilities()

        # Create entry1 with attributes
        entry1_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        # Create entry2 with None attributes using model_construct
        entry2 = FlextLdifModels.Entry.model_construct(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=john,ou=people,dc=example,dc=com"
            ),
            attributes=None,  # None attributes
        )

        result = utilities.merge_ldif_entries(entry1, entry2)
        assert result.is_success is True
        merged_entry = result.value
        assert merged_entry.dn.value == "uid=john,ou=people,dc=example,dc=com"
        # Should only have entry1's attributes since entry2 has None attributes
        assert "cn" in merged_entry.attributes.data
        assert "objectClass" in merged_entry.attributes.data

    def test_merge_ldif_entries_entry1_attributes_none(self) -> None:
        """Test merge_ldif_entries when entry1.attributes is None."""
        utilities = FlextLdifUtilities()

        # Create entry1 with None attributes using model_construct
        entry1 = FlextLdifModels.Entry.model_construct(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=john,ou=people,dc=example,dc=com"
            ),
            attributes=None,  # None attributes
        )

        # Create entry2 with attributes
        entry2_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        result = utilities.merge_ldif_entries(entry1, entry2)
        assert result.is_success is True
        merged_entry = result.value
        assert merged_entry.dn.value == "uid=john,ou=people,dc=example,dc=com"
        # Should have entry2's attributes since entry1 has None attributes
        assert "cn" in merged_entry.attributes.data
        assert "objectClass" in merged_entry.attributes.data

    def test_merge_ldif_entries_entry2_attributes_no_data_attr(self) -> None:
        """Test merge_ldif_entries when entry2.attributes doesn't have data attr."""
        utilities = FlextLdifUtilities()

        # Create entry1 with attributes
        entry1_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry1 = FlextLdifModels.create_entry(entry1_data)

        # Create entry2 with attributes but no data attribute
        entry2 = FlextLdifModels.Entry.model_construct(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=john,ou=people,dc=example,dc=com"
            ),
            attributes=object(),  # Object without data attribute
        )

        result = utilities.merge_ldif_entries(entry1, entry2)
        assert result.is_success is True
        merged_entry = result.value
        assert merged_entry.dn.value == "uid=john,ou=people,dc=example,dc=com"
        # Should only have entry1's attributes since entry2 doesn't have data attr
        assert "cn" in merged_entry.attributes.data
        assert "objectClass" in merged_entry.attributes.data

    def test_merge_ldif_entries_entry1_attributes_no_data_attr(self) -> None:
        """Test merge_ldif_entries when entry1.attributes doesn't have data attr."""
        utilities = FlextLdifUtilities()

        # Create entry1 with attributes but no data attribute
        entry1 = FlextLdifModels.Entry.model_construct(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=john,ou=people,dc=example,dc=com"
            ),
            attributes=object(),  # Object without data attribute
        )

        # Create entry2 with attributes
        entry2_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry2 = FlextLdifModels.create_entry(entry2_data)

        result = utilities.merge_ldif_entries(entry1, entry2)
        assert result.is_success is True
        merged_entry = result.value
        assert merged_entry.dn.value == "uid=john,ou=people,dc=example,dc=com"
        # Should have entry2's attributes since entry1 doesn't have data attr
        assert "cn" in merged_entry.attributes.data
        assert "objectClass" in merged_entry.attributes.data

    def test_validate_ldif_file_extension_with_conversion_exception(self) -> None:
        """Test validate_ldif_file_extension when str() conversion fails."""
        utilities = FlextLdifUtilities()

        # Create an object that raises exception when converted to string
        class BadPath:
            def __str__(self) -> str:
                error_msg = "String conversion failed"
                raise ValueError(error_msg)

        # This should trigger exception handling on lines 68-69
        result = utilities.validate_ldif_file_extension(BadPath())
        assert result.is_failure
        assert result.error and "Extension validation failed" in result.error

    def test_validate_ldif_content_with_validation_exception(self) -> None:
        """Test validate_ldif_content when LdifContent validation fails."""
        utilities = FlextLdifUtilities()

        # Mock the LdifContent validation to fail by using None
        result = utilities.validate_ldif_content(None)
        assert result.is_failure
        # The validation fails at the initial content check
        assert (result.error and "Content cannot be empty" in result.error) or (
            result.error and "Content validation failed" in result.error
        )

    def test_validate_dn_format_with_validation_exception(self) -> None:
        """Test validate_dn_format when DistinguishedName validation fails."""
        utilities = FlextLdifUtilities()

        # Use None to trigger validation exception
        result = utilities.validate_dn_format(None)
        assert result.is_failure
        assert result.error and "DN validation failed" in result.error

    def test_extract_dn_from_content_success(self) -> None:
        """Test extract_dn_from_content with valid LDIF content."""
        utilities = FlextLdifUtilities()

        content = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person"
        result = utilities.extract_dn_from_content(content)
        assert result.is_success
        assert result.value == "cn=test,dc=example,dc=com"

    def test_extract_dn_from_content_no_dn(self) -> None:
        """Test extract_dn_from_content when no DN is found."""
        utilities = FlextLdifUtilities()

        # Valid LDIF format but without a dn: line to trigger the "No DN found" path
        content = "# This is a comment\ncn: test\nobjectClass: person"
        result = utilities.extract_dn_from_content(content)
        assert result.is_failure
        # The validation may fail at the model level, so we check for various error messages
        assert (
            (result.error and "No DN found in content" in result.error)
            or (result.error and "Content validation failed" in result.error)
            or (result.error and "LDIF must start with" in result.error)
        )

    def test_extract_dn_from_content_with_exception(self) -> None:
        """Test extract_dn_from_content when validation fails."""
        utilities = FlextLdifUtilities()

        # Use None to trigger validation exception
        result = utilities.extract_dn_from_content(None)
        assert result.is_failure
        # The validation fails at the content check level
        assert (result.error and "Content cannot be empty" in result.error) or (
            result.error and "DN extraction failed" in result.error
        )

    def test_count_entries_in_content_success(self) -> None:
        """Test count_entries_in_content with valid LDIF content."""
        utilities = FlextLdifUtilities()

        content = """dn: cn=test1,dc=example,dc=com
cn: test1
objectClass: person

dn: cn=test2,dc=example,dc=com
cn: test2
objectClass: person"""

        result = utilities.count_entries_in_content(content)
        assert result.is_success
        assert result.value == 2

    def test_count_entries_in_content_with_exception(self) -> None:
        """Test count_entries_in_content when validation fails."""
        utilities = FlextLdifUtilities()

        # Use None to trigger validation exception
        result = utilities.count_entries_in_content(None)
        assert result.is_failure
        # The validation fails before reaching the exception handler
        assert (result.error and "Content cannot be empty" in result.error) or (
            result.error and "Entry count failed" in result.error
        )

    def test_get_file_size_mb_success(self) -> None:
        """Test get_file_size_mb with valid file."""
        utilities = FlextLdifUtilities()

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".ldif", delete=False
        ) as temp_file:
            temp_file.write("dn: cn=test,dc=example,dc=com\ncn: test")
            temp_path = Path(temp_file.name)

        try:
            result = utilities.get_file_size_mb(temp_path)
            assert result.is_success
            assert isinstance(result.value, float)
            assert result.value >= 0
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink()

    def test_get_file_size_mb_with_exception(self) -> None:
        """Test get_file_size_mb when file doesn't exist."""
        utilities = FlextLdifUtilities()

        # Use non-existent file
        result = utilities.get_file_size_mb("/nonexistent/file.ldif")
        assert result.is_failure
        # The method first validates file path, which fails before size calculation
        assert (result.error and "File does not exist" in result.error) or (
            result.error and "File size calculation failed" in result.error
        )

    def test_is_file_too_large_success(self) -> None:
        """Test is_file_too_large with valid file."""
        utilities = FlextLdifUtilities()

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".ldif", delete=False
        ) as temp_file:
            temp_file.write("dn: cn=test,dc=example,dc=com\ncn: test")
            temp_path = Path(temp_file.name)

        try:
            result = utilities.is_file_too_large(temp_path, max_size_mb=1)
            assert result.is_success
            assert isinstance(result.value, bool)
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink()

    def test_is_file_too_large_with_exception(self) -> None:
        """Test is_file_too_large when file doesn't exist."""
        utilities = FlextLdifUtilities()

        # Use non-existent file
        result = utilities.is_file_too_large("/nonexistent/file.ldif", max_size_mb=1)
        assert result.is_failure
        # The method uses get_file_size_mb which validates file path first
        assert (result.error and "File does not exist" in result.error) or (
            result.error and "File size check failed" in result.error
        )

    def test_create_entry_summary_success(self) -> None:
        """Test create_entry_summary with valid entry."""
        utilities = FlextLdifUtilities()

        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = utilities.create_entry_summary(entry)
        assert result.is_success
        summary = result.value
        assert isinstance(summary, dict)
        assert "dn" in summary
        assert "attribute_count" in summary

    def test_create_entry_summary_with_exception(self) -> None:
        """Test create_entry_summary when entry is None."""
        utilities = FlextLdifUtilities()

        # Use None to trigger exception
        result = utilities.create_entry_summary(None)
        assert result.is_failure
        assert result.error and "Entry summary creation failed" in result.error

    def test_calculate_entry_size_with_exception(self) -> None:
        """Test calculate_entry_size when entry is None."""
        utilities = FlextLdifUtilities()

        # Use None to trigger exception
        result = utilities.calculate_entry_size(None)
        assert result.is_failure
        assert result.error and "Entry size calculation failed" in result.error

    def test_validate_ldif_entry_completeness_success(self) -> None:
        """Test validate_ldif_entry_completeness with valid entry."""
        utilities = FlextLdifUtilities()

        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = utilities.validate_ldif_entry_completeness(entry)
        assert result.is_success
        assert isinstance(result.value, bool)

    def test_validate_ldif_entry_completeness_with_exception(self) -> None:
        """Test validate_ldif_entry_completeness when entry is None."""
        utilities = FlextLdifUtilities()

        # Use None to trigger exception
        result = utilities.validate_ldif_entry_completeness(None)
        assert result.is_failure
        assert result.error and "Entry completeness validation failed" in result.error

    def test_get_utility_info_success(self) -> None:
        """Test get_utility_info method."""
        utilities = FlextLdifUtilities()

        result = utilities.get_utility_info()
        assert isinstance(result, dict)
        assert "service" in result
        assert "capabilities" in result
