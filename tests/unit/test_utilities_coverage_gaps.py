"""Tests for FlextLDIFUtilities coverage gaps.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.models import FlextLDIFModels
from flext_ldif.utilities import FlextLDIFUtilities


class TestFlextLDIFUtilitiesCoverageGaps:
    """Test coverage gaps in FlextLDIFUtilities."""

    def test_ldif_domain_processors_property(self) -> None:
        """Test ldif_domain_processors property access."""
        utilities = FlextLDIFUtilities()
        processors = utilities.ldif_domain_processors
        assert processors is not None
        assert isinstance(processors, FlextLDIFUtilities.Processors)

    def test_get_default_instance_class_method(self) -> None:
        """Test _get_default_instance class method."""
        # Reset default instance
        FlextLDIFUtilities._default_instance = None

        # Test getting default instance
        instance1 = FlextLDIFUtilities._get_default_instance()
        assert instance1 is not None
        assert isinstance(instance1, FlextLDIFUtilities)

        # Test that subsequent calls return the same instance
        instance2 = FlextLDIFUtilities._get_default_instance()
        assert instance1 is instance2

    def test_class_level_access(self) -> None:
        """Test class-level access to utilities."""
        # Test that class-level access works
        utilities = FlextLDIFUtilities()
        assert utilities is not None

        # Test processors access
        processors = utilities._processors
        assert processors is not None

        # Test converters access
        converters = utilities._converters
        assert converters is not None

    def test_find_entries_missing_required_attributes_empty_required(self) -> None:
        """Test find_entries_missing_required_attributes with empty required attributes."""
        utilities = FlextLDIFUtilities()
        processors = utilities.ldif_domain_processors
        
        # Create a test entry
        entry = FlextLDIFModels.Factory.create_entry({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]}
        })
        
        # Test with empty required attributes list
        result = processors.find_entries_with_missing_required_attributes([entry], [])
        assert result.is_failure
        assert "Required attributes list cannot be empty" in result.error

    def test_entry_to_dict_success(self) -> None:
        """Test entry_to_dict successful conversion."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Create a test entry
        entry = FlextLDIFModels.Factory.create_entry({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]}
        })
        
        result = converters.entry_to_dict(entry)
        assert result.is_success
        data = result.unwrap()
        assert data["dn"] == "cn=test,dc=example,dc=com"
        assert "attributes" in data

    def test_attributes_to_ldif_format_empty_key_skip_empty(self) -> None:
        """Test attributes_to_ldif_format with empty key and skip_empty=True."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Test with empty key and skip_empty=True (should continue)
        attributes = {"": "value", "cn": "test"}
        result = converters.attributes_to_ldif_format(attributes, skip_empty=True)
        assert result.is_success
        data = result.unwrap()
        assert "cn" in data
        assert "" not in data  # Empty key should be skipped

    def test_attributes_to_ldif_format_empty_key_no_skip_empty(self) -> None:
        """Test attributes_to_ldif_format with empty key and skip_empty=False."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Test with empty key and skip_empty=False (should fail)
        attributes = {"": "value"}
        result = converters.attributes_to_ldif_format(attributes, skip_empty=False)
        assert result.is_failure
        assert "Empty attribute name found" in result.error

    def test_attributes_to_ldif_format_empty_string_value_skip_empty(self) -> None:
        """Test attributes_to_ldif_format with empty string value and skip_empty=True."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Test with empty string value and skip_empty=True
        attributes = {"cn": "", "sn": "test"}
        result = converters.attributes_to_ldif_format(attributes, skip_empty=True)
        assert result.is_success
        data = result.unwrap()
        assert "cn" not in data  # Empty string should be skipped
        assert "sn" in data

    def test_attributes_to_ldif_format_empty_string_value_no_skip_empty(self) -> None:
        """Test attributes_to_ldif_format with empty string value and skip_empty=False."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Test with empty string value and skip_empty=False
        attributes = {"cn": "", "sn": "test"}
        result = converters.attributes_to_ldif_format(attributes, skip_empty=False)
        assert result.is_success
        data = result.unwrap()
        assert "cn" in data  # Empty string should be included
        assert "sn" in data

    def test_attributes_to_ldif_format_normalize_names_false(self) -> None:
        """Test attributes_to_ldif_format with normalize_names=False."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Test with normalize_names=False
        attributes = {"CN": "test", "sn": "test"}
        result = converters.attributes_to_ldif_format(attributes, normalize_names=False)
        assert result.is_success
        data = result.unwrap()
        assert "CN" in data  # Should preserve case
        assert "sn" in data

    def test_attributes_to_ldif_format_list_with_none_values(self) -> None:
        """Test attributes_to_ldif_format with list containing None values."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Test with list containing None values
        attributes = {"cn": ["test", None, "another"], "sn": "test"}
        result = converters.attributes_to_ldif_format(attributes)
        assert result.is_success
        data = result.unwrap()
        assert "cn" in data
        assert len(data["cn"]) == 2  # None values should be filtered out
        assert "test" in data["cn"]
        assert "another" in data["cn"]

    def test_attributes_to_ldif_format_list_with_empty_strings_skip_empty(self) -> None:
        """Test attributes_to_ldif_format with list containing empty strings and skip_empty=True."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Test with list containing empty strings and skip_empty=True
        attributes = {"cn": ["test", "", "another"], "sn": "test"}
        result = converters.attributes_to_ldif_format(attributes, skip_empty=True)
        assert result.is_success
        data = result.unwrap()
        assert "cn" in data
        assert len(data["cn"]) == 2  # Empty strings should be filtered out
        assert "test" in data["cn"]
        assert "another" in data["cn"]

    def test_entry_to_dict_exception_handling(self) -> None:
        """Test entry_to_dict exception handling."""
        utilities = FlextLDIFUtilities()
        converters = utilities._converters
        
        # Create a mock entry that will cause an exception
        class MockEntry:
            def __init__(self):
                self.dn = None  # This will cause an AttributeError
                self.attributes = None
        
        mock_entry = MockEntry()
        result = converters.entry_to_dict(mock_entry)
        assert result.is_failure
        assert "Entry conversion failed" in result.error
