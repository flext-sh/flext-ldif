"""Unit tests for FLEXT-LDIF constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.constants import FlextLDIFConstants


class TestConstants:
    """Test constants are properly defined."""

    def test_ldap_person_classes_defined(self) -> None:
        """Test LDAP person classes are properly defined."""
        assert isinstance(FlextLDIFConstants.LDAP_PERSON_CLASSES, set)
        assert len(FlextLDIFConstants.LDAP_PERSON_CLASSES) > 0
        assert "person" in FlextLDIFConstants.LDAP_PERSON_CLASSES
        assert "inetorgperson" in FlextLDIFConstants.LDAP_PERSON_CLASSES

    def test_ldap_group_classes_defined(self) -> None:
        """Test LDAP group classes are properly defined."""
        assert isinstance(FlextLDIFConstants.LDAP_GROUP_CLASSES, set)
        assert len(FlextLDIFConstants.LDAP_GROUP_CLASSES) > 0
        # Verify standard group classes are present
        assert "groupofnames" in FlextLDIFConstants.LDAP_GROUP_CLASSES
        assert "groupofuniquenames" in FlextLDIFConstants.LDAP_GROUP_CLASSES

    def test_min_dn_components_defined(self) -> None:
        """Test minimum DN components is properly defined."""
        assert isinstance(FlextLDIFConstants.MIN_DN_COMPONENTS, int)
        assert FlextLDIFConstants.MIN_DN_COMPONENTS > 0
        assert FlextLDIFConstants.MIN_DN_COMPONENTS <= 5  # Reasonable limit
