"""Tests for ACL Protocol implementation in OID and OUD servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud


class TestOidAclProtocol:
    """OID should implement ACL protocol with RFC + Oracle extensions."""

    def test_oid_acl_has_rfc_foundation(self) -> None:
        """OID ACL should include RFC foundation attributes."""
        acl = FlextLdifServersOid.Acl()
        attrs = acl.get_acl_attributes()

        # RFC foundation
        assert "aci" in attrs
        assert "acl" in attrs
        assert "olcAccess" in attrs
        assert "aclRights" in attrs
        assert "aclEntry" in attrs

    def test_oid_acl_has_oid_extensions(self) -> None:
        """OID ACL should include Oracle OID-specific extensions."""
        acl = FlextLdifServersOid.Acl()
        attrs = acl.get_acl_attributes()

        # OID extensions
        assert "orclaci" in attrs
        assert "orclentrylevelaci" in attrs
        assert "orclContainerLevelACL" in attrs

    def test_oid_acl_is_acl_attribute_case_insensitive(self) -> None:
        """OID ACL should detect ACL attributes case-insensitively."""
        acl = FlextLdifServersOid.Acl()

        # Case-insensitive checks
        assert acl.is_acl_attribute("aci")
        assert acl.is_acl_attribute("ACI")
        assert acl.is_acl_attribute("Aci")

        assert acl.is_acl_attribute("orclaci")
        assert acl.is_acl_attribute("ORCLACI")
        assert acl.is_acl_attribute("OrclAci")

        # Non-ACL attributes
        assert not acl.is_acl_attribute("cn")
        assert not acl.is_acl_attribute("objectClass")

    def test_oid_acl_protocol_compliance(self) -> None:
        """OID ACL should implement ServerAclProtocol."""
        acl = FlextLdifServersOid.Acl()
        assert isinstance(acl, FlextLdifProtocols.ServerAclProtocol)

    def test_oid_acl_rfc_attributes_constant(self) -> None:
        """OID ACL should have RFC_ACL_ATTRIBUTES class variable."""
        assert hasattr(FlextLdifServersOid.Acl, "RFC_ACL_ATTRIBUTES")
        assert isinstance(FlextLdifServersOid.Acl.RFC_ACL_ATTRIBUTES, list)
        assert len(FlextLdifServersOid.Acl.RFC_ACL_ATTRIBUTES) == 5

    def test_oid_acl_oid_attributes_constant(self) -> None:
        """OID ACL should have OID_ACL_ATTRIBUTES class variable."""
        assert hasattr(FlextLdifServersOid.Acl, "OID_ACL_ATTRIBUTES")
        assert isinstance(FlextLdifServersOid.Acl.OID_ACL_ATTRIBUTES, list)
        assert len(FlextLdifServersOid.Acl.OID_ACL_ATTRIBUTES) == 3


class TestOudAclProtocol:
    """OUD should implement ACL protocol with RFC + OUD extensions."""

    def test_oud_acl_has_rfc_foundation(self) -> None:
        """OUD ACL should include RFC foundation attributes."""
        acl = FlextLdifServersOud.Acl()
        attrs = acl.get_acl_attributes()

        # RFC foundation
        assert "aci" in attrs
        assert "acl" in attrs
        assert "olcAccess" in attrs
        assert "aclRights" in attrs
        assert "aclEntry" in attrs

    def test_oud_acl_has_oud_extensions(self) -> None:
        """OUD ACL should include Oracle OUD-specific extensions."""
        acl = FlextLdifServersOud.Acl()
        attrs = acl.get_acl_attributes()

        # OUD extensions
        assert "orclaci" in attrs
        assert "orclentrylevelaci" in attrs

    def test_oud_acl_should_not_have_oid_only_attributes(self) -> None:
        """OUD ACL should NOT have OID-only attributes."""
        acl = FlextLdifServersOud.Acl()
        attrs = acl.get_acl_attributes()

        # OID-only attribute (not in OUD)
        assert "orclContainerLevelACL" not in attrs

    def test_oud_acl_is_acl_attribute_case_insensitive(self) -> None:
        """OUD ACL should detect ACL attributes case-insensitively."""
        acl = FlextLdifServersOud.Acl()

        # Case-insensitive checks
        assert acl.is_acl_attribute("aci")
        assert acl.is_acl_attribute("ACI")
        assert acl.is_acl_attribute("Aci")

        assert acl.is_acl_attribute("orclaci")
        assert acl.is_acl_attribute("ORCLACI")

        # Non-ACL attributes
        assert not acl.is_acl_attribute("cn")
        assert not acl.is_acl_attribute("objectClass")

    def test_oud_acl_protocol_compliance(self) -> None:
        """OUD ACL should implement ServerAclProtocol."""
        acl = FlextLdifServersOud.Acl()
        assert isinstance(acl, FlextLdifProtocols.ServerAclProtocol)

    def test_oud_acl_rfc_attributes_constant(self) -> None:
        """OUD ACL should have RFC_ACL_ATTRIBUTES class variable."""
        assert hasattr(FlextLdifServersOud.Acl, "RFC_ACL_ATTRIBUTES")
        assert isinstance(FlextLdifServersOud.Acl.RFC_ACL_ATTRIBUTES, list)
        assert len(FlextLdifServersOud.Acl.RFC_ACL_ATTRIBUTES) == 5

    def test_oud_acl_oud_attributes_constant(self) -> None:
        """OUD ACL should have OUD_ACL_ATTRIBUTES class variable."""
        assert hasattr(FlextLdifServersOud.Acl, "OUD_ACL_ATTRIBUTES")
        assert isinstance(FlextLdifServersOud.Acl.OUD_ACL_ATTRIBUTES, list)
        assert len(FlextLdifServersOud.Acl.OUD_ACL_ATTRIBUTES) == 2


class TestAclProtocolComparison:
    """Compare OID vs OUD ACL implementations."""

    def test_oid_has_more_attributes_than_oud(self) -> None:
        """OID should have more ACL attributes than OUD."""
        oid_acl = FlextLdifServersOid.Acl()
        oud_acl = FlextLdifServersOud.Acl()

        oid_attrs = oid_acl.get_acl_attributes()
        oud_attrs = oud_acl.get_acl_attributes()

        assert len(oid_attrs) > len(oud_attrs)

    def test_both_share_rfc_foundation(self) -> None:
        """Both OID and OUD should share RFC foundation."""
        oid_rfc = set(FlextLdifServersOid.Acl.RFC_ACL_ATTRIBUTES)
        oud_rfc = set(FlextLdifServersOud.Acl.RFC_ACL_ATTRIBUTES)

        assert oid_rfc == oud_rfc

    def test_oid_specific_attributes(self) -> None:
        """OID should have specific attributes not in OUD."""
        oid_acl = FlextLdifServersOid.Acl()
        oud_acl = FlextLdifServersOud.Acl()

        oid_attrs = set(oid_acl.get_acl_attributes())
        oud_attrs = set(oud_acl.get_acl_attributes())

        oid_only = oid_attrs - oud_attrs

        assert "orclContainerLevelACL" in oid_only
