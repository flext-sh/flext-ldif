"""Tests for FlextLdif ACL attribute registry constants.

This module tests the ACL attribute registry for server-specific ACL
attribute mappings and validation.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest
from tests import c, s

# =============================================================================
# TEST SCENARIO ENUMS
# =============================================================================


class GetAclAttributesServerType(StrEnum):
    """Server types for get_acl_attributes tests."""

    RFC = "rfc"
    OID = "oid"
    OUD = "oud"
    AD = "ad"
    GENERIC = "generic"
    UNKNOWN = "unknown_server"
    NONE = "none"


class IsAclAttributeType(StrEnum):
    """Is ACL attribute test scenarios."""

    VALID_RFC = "valid_rfc"
    VALID_SERVER_SPECIFIC = "valid_server_specific"
    INVALID = "invalid"
    CASE_INSENSITIVE = "case_insensitive"


# =============================================================================
# PARAMETRIZED TEST DATA
# =============================================================================


@pytest.mark.unit
class TestsTestFlextLdifAclAttributeRegistry(s):
    """Test suite for AclAttributeRegistry."""

    # Get ACL attributes test data - (server_type, required_attrs, forbidden_attrs)
    GET_ACL_ATTRIBUTES_DATA: ClassVar[
        dict[str, tuple[GetAclAttributesServerType, str | None, list[str], list[str]]]
    ] = {
        "get_acl_attributes_rfc_foundation": (
            GetAclAttributesServerType.RFC,
            None,
            ["aci", "acl", "olcAccess", "aclRights", "aclEntry"],
            [],
        ),
        "get_acl_attributes_oid_quirks": (
            GetAclAttributesServerType.OID,
            "oid",
            ["orclaci", "orclentrylevelaci", "aci", "acl"],
            [],
        ),
        "get_acl_attributes_oud_quirks": (
            GetAclAttributesServerType.OUD,
            "oud",
            ["orclaci", "orclentrylevelaci", "aci"],
            [],
        ),
        "get_acl_attributes_ad_quirks": (
            GetAclAttributesServerType.AD,
            "ad",
            ["nTSecurityDescriptor", "aci"],
            [],
        ),
        "get_acl_attributes_generic": (
            GetAclAttributesServerType.GENERIC,
            "generic",
            ["aci", "acl"],
            ["orclaci", "nTSecurityDescriptor"],
        ),
        "get_acl_attributes_unknown": (
            GetAclAttributesServerType.UNKNOWN,
            "unknown_server",
            ["aci", "acl"],
            ["orclaci", "nTSecurityDescriptor"],
        ),
        "get_acl_attributes_none": (
            GetAclAttributesServerType.NONE,
            None,
            ["aci", "acl"],
            ["orclaci"],
        ),
    }

    # Is ACL attribute test data - (attr_name, server_type, expected_result)
    IS_ACL_ATTRIBUTE_DATA: ClassVar[
        dict[str, tuple[IsAclAttributeType, str, str | None, bool]]
    ] = {
        "is_acl_attribute_rfc_aci": (IsAclAttributeType.VALID_RFC, "aci", None, True),
        "is_acl_attribute_rfc_acl": (IsAclAttributeType.VALID_RFC, "acl", None, True),
        "is_acl_attribute_rfc_olcAccess": (
            IsAclAttributeType.VALID_RFC,
            "olcAccess",
            None,
            True,
        ),
        "is_acl_attribute_oid_orclaci": (
            IsAclAttributeType.VALID_SERVER_SPECIFIC,
            "orclaci",
            "oid",
            True,
        ),
        "is_acl_attribute_oud_orclaci": (
            IsAclAttributeType.VALID_SERVER_SPECIFIC,
            "orclaci",
            "oud",
            True,
        ),
        "is_acl_attribute_invalid_cn": (IsAclAttributeType.INVALID, "cn", None, False),
        "is_acl_attribute_invalid_uid": (
            IsAclAttributeType.INVALID,
            "uid",
            None,
            False,
        ),
        "is_acl_attribute_case_insensitive_aci": (
            IsAclAttributeType.CASE_INSENSITIVE,
            "ACI",
            None,
            True,
        ),
        "is_acl_attribute_case_insensitive_acl": (
            IsAclAttributeType.CASE_INSENSITIVE,
            "Acl",
            None,
            True,
        ),
        "is_acl_attribute_case_insensitive_olcAccess": (
            IsAclAttributeType.CASE_INSENSITIVE,
            "OLCACCESS",
            None,
            True,
        ),
        "is_acl_attribute_case_insensitive_orclaci": (
            IsAclAttributeType.CASE_INSENSITIVE,
            "OrclAci",
            "oid",
            True,
        ),
    }

    # =======================================================================
    # Get ACL Attributes Tests
    # =======================================================================

    @pytest.mark.parametrize(
        (
            "scenario",
            "server_type",
            "param_server_type",
            "required_attrs",
            "forbidden_attrs",
        ),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in GET_ACL_ATTRIBUTES_DATA.items()
        ],
    )
    def test_get_acl_attributes(
        self,
        scenario: str,
        server_type: GetAclAttributesServerType,
        param_server_type: str | None,
        required_attrs: list[str],
        forbidden_attrs: list[str],
    ) -> None:
        """Parametrized test for get_acl_attributes."""
        attrs = c.AclAttributeRegistry.get_acl_attributes(
            param_server_type,
        )
        for required in required_attrs:
            assert required in attrs, f"{required} not in {scenario}"
        for forbidden in forbidden_attrs:
            assert forbidden not in attrs, f"{forbidden} should not be in {scenario}"

    # =======================================================================
    # Is ACL Attribute Tests
    # =======================================================================

    @pytest.mark.parametrize(
        ("scenario", "test_type", "attr_name", "server_type", "expected_result"),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in IS_ACL_ATTRIBUTE_DATA.items()
        ],
    )
    def test_is_acl_attribute(
        self,
        scenario: str,
        test_type: IsAclAttributeType,
        attr_name: str,
        server_type: str | None,
        expected_result: bool,
    ) -> None:
        """Parametrized test for is_acl_attribute."""
        registry = c.AclAttributeRegistry
        if server_type is not None:
            result = registry.is_acl_attribute(attr_name, server_type)
        else:
            result = registry.is_acl_attribute(attr_name)
        assert result == expected_result, f"{scenario} failed"

    # =======================================================================
    # Immutability Test
    # =======================================================================

    def test_acl_registry_no_mutation(self) -> None:
        """get_acl_attributes should return new list each time."""
        attrs1 = list(c.AclAttributeRegistry.get_acl_attributes("oid"))
        attrs2 = list(c.AclAttributeRegistry.get_acl_attributes("oid"))
        # Should be equal but not the same object
        assert attrs1 == attrs2
        assert attrs1 is not attrs2
        # Mutating one should not affect the other
        attrs1.append("test_attribute")
        assert "test_attribute" not in attrs2
