"""Tests for AclAttributeRegistry in FlextLdifConstants.

Verifies RFC foundation + server quirks HIERARCHY pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.constants import FlextLdifConstants


class TestAclAttributeRegistry:
    """Test suite for AclAttributeRegistry."""

    def test_acl_registry_rfc_foundation(self) -> None:
        """RFC foundation should be in all servers."""
        attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes()
        assert "aci" in attrs
        assert "acl" in attrs
        assert "olcAccess" in attrs
        assert "aclRights" in attrs
        assert "aclEntry" in attrs

    def test_acl_registry_oid_quirks(self) -> None:
        """OID should have Oracle-specific attributes."""
        attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes("oid")
        assert "orclaci" in attrs
        assert "orclentrylevelaci" in attrs
        assert "orclContainerLevelACL" in attrs
        # Should also have RFC foundation
        assert "aci" in attrs
        assert "acl" in attrs

    def test_acl_registry_oud_quirks(self) -> None:
        """OUD should have Oracle attributes."""
        attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes("oud")
        assert "orclaci" in attrs
        assert "orclentrylevelaci" in attrs
        # Should also have RFC foundation
        assert "aci" in attrs

    def test_acl_registry_ad_quirks(self) -> None:
        """AD should have Active Directory attributes."""
        attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes("ad")
        assert "nTSecurityDescriptor" in attrs
        # Should also have RFC foundation
        assert "aci" in attrs

    def test_acl_registry_generic(self) -> None:
        """Generic should only have RFC foundation."""
        attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes("generic")
        # Should have RFC foundation
        assert "aci" in attrs
        assert "acl" in attrs
        # Should NOT have server-specific quirks
        assert "orclaci" not in attrs
        assert "nTSecurityDescriptor" not in attrs

    def test_acl_registry_is_acl_attribute(self) -> None:
        """Should detect ACL attributes correctly."""
        registry = FlextLdifConstants.AclAttributeRegistry
        assert registry.is_acl_attribute("aci")
        assert registry.is_acl_attribute("acl")
        assert registry.is_acl_attribute("olcAccess")
        assert registry.is_acl_attribute("orclaci", "oid")
        assert registry.is_acl_attribute("orclaci", "oud")
        assert not registry.is_acl_attribute("cn")
        assert not registry.is_acl_attribute("uid")

    def test_acl_registry_case_insensitive(self) -> None:
        """is_acl_attribute should be case-insensitive."""
        registry = FlextLdifConstants.AclAttributeRegistry
        assert registry.is_acl_attribute("ACI")
        assert registry.is_acl_attribute("Acl")
        assert registry.is_acl_attribute("OLCACCESS")
        assert registry.is_acl_attribute("OrclAci", "oid")

    def test_acl_registry_unknown_server_type(self) -> None:
        """Unknown server type should return RFC foundation only."""
        attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes(
            "unknown_server"
        )
        # Should have RFC foundation
        assert "aci" in attrs
        assert "acl" in attrs
        # Should NOT have any server-specific quirks
        assert "orclaci" not in attrs
        assert "nTSecurityDescriptor" not in attrs

    def test_acl_registry_none_server_type(self) -> None:
        """None server type should return RFC foundation only."""
        attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes(None)
        # Should have RFC foundation
        assert "aci" in attrs
        assert "acl" in attrs
        # Should NOT have server-specific quirks
        assert "orclaci" not in attrs

    def test_acl_registry_no_mutation(self) -> None:
        """get_acl_attributes should return new list each time."""
        attrs1 = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes("oid")
        attrs2 = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes("oid")
        # Should be equal but not the same object
        assert attrs1 == attrs2
        assert attrs1 is not attrs2
        # Mutating one should not affect the other
        attrs1.append("test_attribute")
        assert "test_attribute" not in attrs2
