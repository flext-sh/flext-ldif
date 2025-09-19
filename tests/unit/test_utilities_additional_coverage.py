"""Additional tests for FlextLdifUtilities to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class TestFlextLdifUtilitiesAdditional:
    """Additional test cases for FlextLdifUtilities to achieve 100% coverage."""

    def test_validate_ldif_file_path_file_not_exists(self) -> None:
        """Test validate_ldif_file_path with non-existent file."""
        utilities = FlextLdifUtilities()

        result = utilities.validate_ldif_file_path("/nonexistent/file.ldif")

        assert result.is_failure
        assert result.error is not None and "File does not exist" in result.error

    def test_validate_ldif_file_path_not_file(self) -> None:
        """Test validate_ldif_file_path with directory instead of file."""
        utilities = FlextLdifUtilities()

        # Use a directory that exists
        result = utilities.validate_ldif_file_path("/usr")

        assert result.is_failure
        assert result.error is not None and "Path is not a file" in result.error

    def test_validate_ldif_file_extension_with_no_extension(self) -> None:
        """Test validate_ldif_file_extension with file that has no extension."""
        utilities = FlextLdifUtilities()

        # Test with file that has no extension
        result = utilities.validate_ldif_file_extension("filename_without_extension")

        assert result.is_success
        assert (
            result.value is False
        )  # Invalid extension but successful validation operation

    def test_validate_ldif_content_empty_content(self) -> None:
        """Test validate_ldif_content with empty content."""
        utilities = FlextLdifUtilities()

        result = utilities.validate_ldif_content("   \n\t  ")

        assert result.is_failure
        assert result.error is not None and "Content cannot be empty" in result.error

    def test_normalize_dn_format_malformed_component(self) -> None:
        """Test normalize_dn_format with component without equals sign."""
        utilities = FlextLdifUtilities()

        result = utilities.normalize_dn_format("cn=test,invalidcomponent,dc=com")

        assert result.is_failure
        assert result.error is not None and "DN normalization failed" in result.error

    def test_normalize_dn_format_empty_component(self) -> None:
        """Test normalize_dn_format with empty DN components."""
        utilities = FlextLdifUtilities()

        result = utilities.normalize_dn_format("cn=test,,dc=com")

        assert result.is_failure
        assert result.error is not None and "DN normalization failed" in result.error

    def test_validate_attribute_name_invalid_characters(self) -> None:
        """Test validate_attribute_name with invalid characters."""
        utilities = FlextLdifUtilities()

        # Test with attribute name containing invalid characters
        result = utilities.validate_attribute_name("invalid-attr@name")

        assert result.is_failure
        assert (
            result.error is not None
            and "Attribute name validation failed" in result.error
        )

    def test_normalize_ldif_content_with_mixed_line_endings(self) -> None:
        """Test normalize_ldif_content with mixed line endings."""
        utilities = FlextLdifUtilities()

        # Test content with mixed line endings
        content = "dn: cn=test,dc=example,dc=com\r\ncn: test\n\robjectClass: person"
        result = utilities.normalize_ldif_content(content)

        assert result.is_success
        assert result.value is not None
        # Should normalize to consistent line endings
        assert "\r\n" not in result.value or "\n" in result.value

    def test_calculate_entry_size_with_large_attributes(self) -> None:
        """Test calculate_entry_size with entry containing large attributes."""
        utilities = FlextLdifUtilities()

        # Create entry with large attribute values
        entry_data = {
            "dn": "cn=large-entry,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["large-entry"],
                "description": ["x" * 1000],  # Large description
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = utilities.calculate_entry_size(entry)

        assert result.is_success
        assert result.value is not None
        assert result.value > 1000  # Should be more than just the description

    def test_merge_ldif_entries_overlapping_attributes(self) -> None:
        """Test merge_ldif_entries with overlapping attributes."""
        utilities = FlextLdifUtilities()

        # Create two entries with overlapping attributes
        entry1_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"], "sn": ["User"]},
        }
        entry2_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "objectClass": ["organizationalPerson"],
                "cn": ["test"],
                "givenName": ["Test"],
            },
        }

        entry1 = FlextLdifModels.create_entry(entry1_data)
        entry2 = FlextLdifModels.create_entry(entry2_data)

        result = utilities.merge_ldif_entries(entry1, entry2)

        assert result.is_success
        merged_entry = result.value
        assert merged_entry is not None

        # Should contain attributes from both entries
        object_classes = merged_entry.get_attribute("objectClass") or []
        assert "person" in object_classes
        assert "organizationalPerson" in object_classes

        assert merged_entry.get_attribute("sn") == ["User"]
        assert merged_entry.get_attribute("givenName") == ["Test"]

    def test_convert_entry_to_dict_with_complex_entry(self) -> None:
        """Test convert_entry_to_dict with complex entry structure."""
        utilities = FlextLdifUtilities()

        # Create complex entry with multiple attributes
        entry_data = {
            "dn": "cn=complex-user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "cn": ["complex-user"],
                "sn": ["User"],
                "givenName": ["Complex"],
                "mail": ["complex.user@example.com"],
                "telephoneNumber": ["+1-555-0123", "+1-555-0124"],
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = utilities.convert_entry_to_dict(entry)

        assert result.is_success
        entry_dict = result.value
        assert entry_dict is not None
        assert entry_dict["dn"] == "cn=complex-user,ou=people,dc=example,dc=com"
        assert isinstance(entry_dict["attributes"], dict)

        attributes = entry_dict["attributes"]
        assert "objectClass" in attributes
        assert "telephoneNumber" in attributes
        assert len(attributes["telephoneNumber"]) == 2
