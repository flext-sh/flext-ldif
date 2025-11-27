"""Tests for ACL Protocol implementation in OID and OUD servers.

Modules tested:
- FlextLdifProtocols.ServerAclProtocol: ACL protocol definition
- FlextLdifServersOid.Acl: OID server ACL implementation
- FlextLdifServersOud.Acl: OUD server ACL implementation

Scope: ACL attribute definitions, protocol compliance, server-specific extensions,
case-insensitive attribute detection, and cross-server comparison.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum

import pytest

from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud


# Test scenario enums
class ServerType(StrEnum):
    """Server types for ACL protocol testing."""

    OID = "oid"
    OUD = "oud"


class AttributeCategory(StrEnum):
    """ACL attribute categories."""

    RFC_FOUNDATION = "rfc_foundation"
    SERVER_EXTENSIONS = "server_extensions"
    ALL_ATTRIBUTES = "all_attributes"


# Test data structures
@dataclasses.dataclass(frozen=True)
class AclProtocolTestCase:
    """ACL protocol test case."""

    server_type: str
    attribute_category: str
    expected_attributes: list[str]
    description: str = ""


@dataclasses.dataclass(frozen=True)
class CaseInsensitivityTestCase:
    """Case sensitivity test case."""

    server_type: str
    attribute_name: str
    should_match: bool
    description: str = ""


# Test data mappings
RFC_ACL_ATTRIBUTES = ["aci", "acl", "olcAccess", "aclRights", "aclEntry"]

OID_ONLY_ATTRIBUTES = ["orclaci", "orclentrylevelaci", "orclContainerLevelACL"]

OUD_ONLY_ATTRIBUTES = ["ds-privilege-name"]

# ACL protocol test cases for attribute validation
ACL_ATTRIBUTE_TESTS = [
    AclProtocolTestCase(
        ServerType.OID,
        AttributeCategory.RFC_FOUNDATION,
        RFC_ACL_ATTRIBUTES,
        "OID RFC foundation attributes",
    ),
    AclProtocolTestCase(
        ServerType.OID,
        AttributeCategory.SERVER_EXTENSIONS,
        OID_ONLY_ATTRIBUTES,
        "OID-specific extensions",
    ),
    AclProtocolTestCase(
        ServerType.OUD,
        AttributeCategory.RFC_FOUNDATION,
        RFC_ACL_ATTRIBUTES,
        "OUD RFC foundation attributes",
    ),
    AclProtocolTestCase(
        ServerType.OUD,
        AttributeCategory.SERVER_EXTENSIONS,
        OUD_ONLY_ATTRIBUTES,
        "OUD-specific extensions",
    ),
]

# Case sensitivity test cases
CASE_INSENSITIVE_TESTS = [
    # OID case-insensitive tests
    CaseInsensitivityTestCase(ServerType.OID, "aci", True, "OID lowercase aci"),
    CaseInsensitivityTestCase(ServerType.OID, "ACI", True, "OID uppercase ACI"),
    CaseInsensitivityTestCase(ServerType.OID, "Aci", True, "OID mixed case Aci"),
    CaseInsensitivityTestCase(ServerType.OID, "orclaci", True, "OID lowercase orclaci"),
    CaseInsensitivityTestCase(ServerType.OID, "ORCLACI", True, "OID uppercase ORCLACI"),
    CaseInsensitivityTestCase(
        ServerType.OID,
        "OrclAci",
        True,
        "OID mixed case OrclAci",
    ),
    CaseInsensitivityTestCase(ServerType.OID, "cn", False, "OID non-ACL attribute"),
    # OUD case-insensitive tests
    CaseInsensitivityTestCase(ServerType.OUD, "aci", True, "OUD lowercase aci"),
    CaseInsensitivityTestCase(ServerType.OUD, "ACI", True, "OUD uppercase ACI"),
    CaseInsensitivityTestCase(ServerType.OUD, "Aci", True, "OUD mixed case Aci"),
    CaseInsensitivityTestCase(
        ServerType.OUD,
        "ds-privilege-name",
        True,
        "OUD lowercase ds-privilege-name",
    ),
    CaseInsensitivityTestCase(
        ServerType.OUD,
        "DS-PRIVILEGE-NAME",
        True,
        "OUD uppercase DS-PRIVILEGE-NAME",
    ),
    CaseInsensitivityTestCase(
        ServerType.OUD,
        "orclaci",
        False,
        "OUD should not match OID attribute",
    ),
    CaseInsensitivityTestCase(ServerType.OUD, "cn", False, "OUD non-ACL attribute"),
]


# Factory functions
def get_acl_instance(
    server_type: str,
) -> FlextLdifServersOid.Acl | FlextLdifServersOud.Acl:
    """Create ACL instance by server type."""
    if server_type == ServerType.OID:
        return FlextLdifServersOid.Acl()
    if server_type == ServerType.OUD:
        return FlextLdifServersOud.Acl()
    msg = f"Unknown server type: {server_type}"
    raise ValueError(msg)


def get_acl_class(
    server_type: str,
) -> type[FlextLdifServersOid.Acl | FlextLdifServersOud.Acl]:
    """Get ACL class by server type."""
    if server_type == ServerType.OID:
        return FlextLdifServersOid.Acl
    if server_type == ServerType.OUD:
        return FlextLdifServersOud.Acl
    msg = f"Unknown server type: {server_type}"
    raise ValueError(msg)


# Parametrization functions
def get_acl_attribute_tests() -> list[AclProtocolTestCase]:
    """Generate ACL attribute test cases."""
    return ACL_ATTRIBUTE_TESTS


def get_case_insensitive_tests() -> list[CaseInsensitivityTestCase]:
    """Generate case insensitivity test cases."""
    return CASE_INSENSITIVE_TESTS


# Module-level fixtures
@pytest.fixture
def oid_acl() -> FlextLdifServersOid.Acl:
    """Create OID ACL instance."""
    return get_acl_instance(ServerType.OID)


@pytest.fixture
def oud_acl() -> FlextLdifServersOud.Acl:
    """Create OUD ACL instance."""
    return get_acl_instance(ServerType.OUD)


class TestAclProtocolCompliance:
    """Test ACL protocol compliance and attribute definitions."""

    @pytest.mark.parametrize("test_case", get_acl_attribute_tests())
    def test_acl_attributes_presence(
        self,
        test_case: AclProtocolTestCase,
    ) -> None:
        """Test ACL attributes are present based on category."""
        acl = get_acl_instance(test_case.server_type)
        attrs = acl.get_acl_attributes()

        for expected_attr in test_case.expected_attributes:
            assert expected_attr in attrs, (
                f"{test_case.server_type} missing {expected_attr}"
            )

    @pytest.mark.parametrize("test_case", get_case_insensitive_tests())
    def test_acl_attribute_case_insensitive(
        self,
        test_case: CaseInsensitivityTestCase,
    ) -> None:
        """Test ACL attributes are detected case-insensitively."""
        acl = get_acl_instance(test_case.server_type)
        result = acl.is_acl_attribute(test_case.attribute_name)

        if test_case.should_match:
            assert result, (
                f"{test_case.server_type} should match {test_case.attribute_name}"
            )
        else:
            assert not result, (
                f"{test_case.server_type} should not match {test_case.attribute_name}"
            )

    def test_oid_protocol_compliance(
        self,
        oid_acl: FlextLdifServersOid.Acl,
    ) -> None:
        """Test OID ACL implements ServerAclProtocol."""
        assert isinstance(oid_acl, FlextLdifProtocols.ServerAclProtocol)

    def test_oud_protocol_compliance(
        self,
        oud_acl: FlextLdifServersOud.Acl,
    ) -> None:
        """Test OUD ACL implements ServerAclProtocol."""
        assert isinstance(oud_acl, FlextLdifProtocols.ServerAclProtocol)

    def test_oid_class_constants(self) -> None:
        """Test OID ACL class variables are properly defined."""
        oid_class = get_acl_class(ServerType.OID)

        # RFC attributes
        assert hasattr(oid_class, "RFC_ACL_ATTRIBUTES")
        assert isinstance(oid_class.RFC_ACL_ATTRIBUTES, list)
        assert len(oid_class.RFC_ACL_ATTRIBUTES) == 5

        # OID-specific attributes
        assert hasattr(oid_class, "OID_ACL_ATTRIBUTES")
        assert isinstance(oid_class.OID_ACL_ATTRIBUTES, list)
        assert len(oid_class.OID_ACL_ATTRIBUTES) == 3

    def test_oud_class_constants(self) -> None:
        """Test OUD ACL class variables are properly defined."""
        oud_class = get_acl_class(ServerType.OUD)

        # RFC attributes
        assert hasattr(oud_class, "RFC_ACL_ATTRIBUTES")
        assert isinstance(oud_class.RFC_ACL_ATTRIBUTES, list)
        assert len(oud_class.RFC_ACL_ATTRIBUTES) == 5

        # OUD-specific attributes (only ds-privilege-name)
        assert hasattr(oud_class, "OUD_ACL_ATTRIBUTES")
        assert isinstance(oud_class.OUD_ACL_ATTRIBUTES, list)
        assert len(oud_class.OUD_ACL_ATTRIBUTES) == 1
        assert "ds-privilege-name" in oud_class.OUD_ACL_ATTRIBUTES

    def test_oid_has_more_attributes_than_oud(
        self,
        oid_acl: FlextLdifServersOid.Acl,
        oud_acl: FlextLdifServersOud.Acl,
    ) -> None:
        """Test OID has more ACL attributes than OUD."""
        oid_attrs = oid_acl.get_acl_attributes()
        oud_attrs = oud_acl.get_acl_attributes()

        assert len(oid_attrs) > len(oud_attrs)

    def test_shared_rfc_foundation(self) -> None:
        """Test both OID and OUD share RFC foundation."""
        oid_rfc = set(get_acl_class(ServerType.OID).RFC_ACL_ATTRIBUTES)
        oud_rfc = set(get_acl_class(ServerType.OUD).RFC_ACL_ATTRIBUTES)

        assert oid_rfc == oud_rfc

    def test_oid_specific_attributes_not_in_oud(
        self,
        oid_acl: FlextLdifServersOid.Acl,
        oud_acl: FlextLdifServersOud.Acl,
    ) -> None:
        """Test OID-specific attributes are not in OUD."""
        oid_attrs = set(oid_acl.get_acl_attributes())
        oud_attrs = set(oud_acl.get_acl_attributes())

        oid_only = oid_attrs - oud_attrs

        # OID-only attributes that should not be in OUD
        for oid_attr in OID_ONLY_ATTRIBUTES:
            assert oid_attr in oid_only, f"{oid_attr} should be OID-only"

    def test_oud_not_recognize_oid_formats(
        self,
        oud_acl: FlextLdifServersOud.Acl,
    ) -> None:
        """Test OUD does not recognize OID-format attributes."""
        for oid_attr in OID_ONLY_ATTRIBUTES:
            assert not oud_acl.is_acl_attribute(oid_attr), (
                f"OUD should not recognize {oid_attr}"
            )


__all__ = [
    "AclProtocolTestCase",
    "AttributeCategory",
    "CaseInsensitivityTestCase",
    "ServerType",
    "TestAclProtocolCompliance",
]
