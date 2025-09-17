"""Additional tests for FlextLdifUtilities to cover missing lines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections import UserString
from typing import Never

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class PathConversionError(Exception):
    """Custom exception for path conversion errors in tests."""


class SplitError(Exception):
    """Custom exception for string split errors in tests."""


class TestFlextLdifUtilitiesMissingCoverage:
    """Additional tests to achieve 100% coverage for utilities."""

    def test_validate_ldif_file_extension_exception_path(self) -> None:
        """Test validate_ldif_file_extension exception handling with Path object."""
        utilities = FlextLdifUtilities()

        # Create a mock object that raises exception when converted to string
        class MockPath:
            def __str__(self) -> str:
                msg = "Path conversion error"
                raise PathConversionError(msg)

        result = utilities.validate_ldif_file_extension(MockPath())
        assert result.is_success is False
        assert "Extension validation failed" in result.error

    def test_normalize_dn_format_exception_during_processing(self) -> None:
        """Test normalize_dn_format exception during DN processing."""
        utilities = FlextLdifUtilities()

        # Create a string subclass that raises exception when split is called
        class MockDN(UserString):
            def split(self, _sep: str) -> Never:
                msg = "Split error"
                raise SplitError(msg)

        result = utilities.normalize_dn_format(MockDN("uid=test,ou=people"))
        assert result.is_success is False
        assert (
            "DN must be a non-empty string" in result.error
            or "DN normalization failed" in result.error
        )

    def test_extract_base_dn_exception_during_processing(self) -> None:
        """Test extract_base_dn exception during processing."""
        utilities = FlextLdifUtilities()

        # Create a string subclass that raises exception when split is called
        class MockDN(UserString):
            def split(self, _sep: str) -> Never:
                msg = "Split error"
                raise SplitError(msg)

        result = utilities.extract_base_dn(MockDN("uid=test,ou=people,dc=example"))
        assert result.is_success is False
        assert "Base DN extraction failed" in result.error

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
