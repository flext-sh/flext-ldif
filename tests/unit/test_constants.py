"""Unit tests for FLEXT-LDIF constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.constants import FlextLdifConstants


class TestConstants:
    """Test constants are properly defined."""

    def test_ldap_person_classes_defined(self) -> None:
        """Test LDAP person classes are properly defined."""
        assert isinstance(FlextLdifConstants.LDAP_PERSON_CLASSES, frozenset)
        assert len(FlextLdifConstants.LDAP_PERSON_CLASSES) > 0
        assert "person" in FlextLdifConstants.LDAP_PERSON_CLASSES
        assert "inetorgperson" in FlextLdifConstants.LDAP_PERSON_CLASSES

    def test_ldap_group_classes_defined(self) -> None:
        """Test LDAP group classes are properly defined."""
        assert isinstance(FlextLdifConstants.LDAP_GROUP_CLASSES, frozenset)
        assert len(FlextLdifConstants.LDAP_GROUP_CLASSES) > 0
        # Verify standard group classes are present
        assert "groupofnames" in FlextLdifConstants.LDAP_GROUP_CLASSES
        assert "groupofuniquenames" in FlextLdifConstants.LDAP_GROUP_CLASSES

    def test_min_dn_components_defined(self) -> None:
        """Test minimum DN components is properly defined."""
        assert isinstance(FlextLdifConstants.MIN_DN_COMPONENTS, int)
        assert FlextLdifConstants.MIN_DN_COMPONENTS > 0
        assert FlextLdifConstants.MIN_DN_COMPONENTS <= 5  # Reasonable limit
