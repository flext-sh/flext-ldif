"""Unit tests for FLEXT-LDIF constants."""

from __future__ import annotations

from flext_ldif.constants import (
    LDAP_DN_ATTRIBUTES,
    LDAP_GROUP_CLASSES,
    LDAP_PERSON_CLASSES,
    MIN_DN_COMPONENTS,
)


class TestConstants:
    """Test constants are properly defined."""

    def test_ldap_person_classes_defined(self) -> None:
        """Test LDAP person classes are properly defined."""
        assert isinstance(LDAP_PERSON_CLASSES, frozenset)
        assert len(LDAP_PERSON_CLASSES) > 0
        assert "person" in LDAP_PERSON_CLASSES
        assert "inetOrgPerson" in LDAP_PERSON_CLASSES

    def test_ldap_group_classes_defined(self) -> None:
        """Test LDAP group classes are properly defined."""
        assert isinstance(LDAP_GROUP_CLASSES, frozenset)
        assert len(LDAP_GROUP_CLASSES) > 0
        assert "group" in LDAP_GROUP_CLASSES or "groupOfNames" in LDAP_GROUP_CLASSES

    def test_ldap_dn_attributes_defined(self) -> None:
        """Test LDAP DN attributes are properly defined."""
        assert isinstance(LDAP_DN_ATTRIBUTES, frozenset)
        assert len(LDAP_DN_ATTRIBUTES) > 0
        assert "member" in LDAP_DN_ATTRIBUTES
        assert "manager" in LDAP_DN_ATTRIBUTES
        assert "owner" in LDAP_DN_ATTRIBUTES

    def test_min_dn_components_defined(self) -> None:
        """Test minimum DN components is properly defined."""
        assert isinstance(MIN_DN_COMPONENTS, int)
        assert MIN_DN_COMPONENTS > 0
        assert MIN_DN_COMPONENTS <= 5  # Reasonable limit
