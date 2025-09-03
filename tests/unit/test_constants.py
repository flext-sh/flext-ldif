"""Unit tests for FLEXT-LDIF constants."""

from __future__ import annotations

from flext_ldif.constants import FlextLDIFConstants


class TestConstants:
    """Test constants are properly defined."""

    def test_ldap_person_classes_defined(self) -> None:
        """Test LDAP person classes are properly defined."""
        assert isinstance(FlextLDIFConstants.LDAP_PERSON_CLASSES, frozenset)
        assert len(FlextLDIFConstants.LDAP_PERSON_CLASSES) > 0
        assert "person" in FlextLDIFConstants.LDAP_PERSON_CLASSES
        assert "inetOrgPerson" in FlextLDIFConstants.LDAP_PERSON_CLASSES

    def test_ldap_group_classes_defined(self) -> None:
        """Test LDAP group classes are properly defined."""
        assert isinstance(FlextLDIFConstants.LDAP_GROUP_CLASSES, frozenset)
        assert len(FlextLDIFConstants.LDAP_GROUP_CLASSES) > 0
        # Verify standard group classes are present
        assert "groupOfNames" in FlextLDIFConstants.LDAP_GROUP_CLASSES
        assert "groupOfUniqueNames" in FlextLDIFConstants.LDAP_GROUP_CLASSES

    def test_ldap_dn_attributes_defined(self) -> None:
        """Test LDAP DN attributes are properly defined."""
        assert isinstance(FlextLDIFConstants.LDAP_DN_ATTRIBUTES, frozenset)
        assert len(FlextLDIFConstants.LDAP_DN_ATTRIBUTES) > 0
        assert "member" in FlextLDIFConstants.LDAP_DN_ATTRIBUTES
        assert "manager" in FlextLDIFConstants.LDAP_DN_ATTRIBUTES
        assert "owner" in FlextLDIFConstants.LDAP_DN_ATTRIBUTES

    def test_min_dn_components_defined(self) -> None:
        """Test minimum DN components is properly defined."""
        assert isinstance(FlextLDIFConstants.MIN_DN_COMPONENTS, int)
        assert FlextLDIFConstants.MIN_DN_COMPONENTS > 0
        assert FlextLDIFConstants.MIN_DN_COMPONENTS <= 5  # Reasonable limit
