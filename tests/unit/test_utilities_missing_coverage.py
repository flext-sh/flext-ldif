"""Tests for missing utilities coverage lines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.utilities import AttributeDict, FlextLDIFUtilities, LDIFAttributeDict


class TestUtilitiesMissingCoverage:
    """Test missing coverage lines in utilities.py."""

    def test_type_aliases_coverage(self) -> None:
        """Test type aliases coverage - covers lines 20-23."""
        # Test that type aliases are properly defined
        utilities = FlextLDIFUtilities()

        # Test AttributeDict type alias

        # Test that aliases work correctly
        test_attrs: AttributeDict = {"cn": "test", "sn": ["Test", "User"], "mail": None}

        result = utilities.converters.attributes_to_ldif_format(test_attrs)
        assert result.is_success

        ldif_attrs: LDIFAttributeDict = result.unwrap()
        assert isinstance(ldif_attrs, dict)
        assert "cn" in ldif_attrs
        assert "sn" in ldif_attrs
        assert ldif_attrs["cn"] == ["test"]
        assert ldif_attrs["sn"] == ["Test", "User"]
