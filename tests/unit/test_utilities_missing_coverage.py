"""Tests for missing utilities coverage lines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLDIFModels
from flext_ldif.utilities import AttributeDict, FlextLDIFUtilities, LDIFAttributeDict


class TestUtilitiesMissingCoverage:
    """Test missing coverage lines in utilities.py."""

    def test_type_aliases_coverage(self) -> None:
        """Test type aliases coverage - covers lines 20-23."""
        # Test that type aliases are properly defined and work correctly
        utilities = FlextLDIFUtilities()

        # Test AttributeDict type alias with real conversion method
        test_attrs: AttributeDict = {"cn": ["test"], "sn": ["Test", "User"]}

        # Create a test entry to validate type aliases work
        entry = FlextLDIFModels.Entry.model_validate({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": test_attrs
        })

        result = utilities.convert_entry_to_dict(entry)
        assert result.is_success

        ldif_attrs: LDIFAttributeDict = result.unwrap()["attributes"]
        assert isinstance(ldif_attrs, dict)
        assert "cn" in ldif_attrs
        assert "sn" in ldif_attrs
        assert ldif_attrs["cn"] == ["test"]
        assert ldif_attrs["sn"] == ["Test", "User"]
