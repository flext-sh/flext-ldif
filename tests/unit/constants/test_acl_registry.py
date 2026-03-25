"""Tests for FlextLdif ACL attribute registry constants.

This module tests the ACL attribute registry for server-specific ACL
attribute mappings and validation.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum, unique
from typing import ClassVar

import pytest
from flext_tests import t, tm

from tests import s, u


@unique
class GetAclAttributesServerType(StrEnum):
    """Server types for get_acl_attributes tests."""

    RFC = "rfc"
    OID = "oid"
    OUD = "oud"
    AD = "ad"
    GENERIC = "generic"
    UNKNOWN = "unknown_server"
    NONE = "none"


@unique
class IsAclAttributeType(StrEnum):
    """Is ACL attribute test scenarios."""

    VALID_RFC = "valid_rfc"
    VALID_SERVER_SPECIFIC = "valid_server_specific"
    INVALID = "invalid"
    CASE_INSENSITIVE = "case_insensitive"


@pytest.mark.unit
class TestsTestFlextLdifAclAttributeRegistry(s):
    """Test suite for AclAttributeRegistry."""

    GET_ACL_ATTRIBUTES_DATA: ClassVar[
        Mapping[
            str,
            tuple[GetAclAttributesServerType, str | None, t.StrSequence, t.StrSequence],
        ]
    ] = {
        "get_acl_attributes_rfc_foundation": (
            GetAclAttributesServerType.RFC,
            None,
            ["aci", "acl", "olcAccess", "aclRights", "aclEntry"],
            list[str](),
        ),
        "get_acl_attributes_oid_quirks": (
            GetAclAttributesServerType.OID,
            "oid",
            ["orclaci", "orclentrylevelaci", "aci", "acl"],
            list[str](),
        ),
        "get_acl_attributes_oud_quirks": (
            GetAclAttributesServerType.OUD,
            "oud",
            ["orclaci", "orclentrylevelaci", "aci"],
            list[str](),
        ),
        "get_acl_attributes_ad_quirks": (
            GetAclAttributesServerType.AD,
            "ad",
            ["nTSecurityDescriptor", "aci"],
            list[str](),
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
    IS_ACL_ATTRIBUTE_DATA: ClassVar[
        Mapping[str, tuple[IsAclAttributeType, str, str | None, bool]]
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
        required_attrs: t.StrSequence,
        forbidden_attrs: t.StrSequence,
    ) -> None:
        """Parametrized test for get_acl_attributes."""
        attrs = u.Ldif.get_acl_attributes(param_server_type)
        for required in required_attrs:
            (
                tm.that(attrs, has=required),
                f"{required} not in {scenario}",
            )
        for forbidden in forbidden_attrs:
            (
                tm.that(forbidden not in attrs, eq=True),
                f"{forbidden} should not be in {scenario}",
            )

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
        result = u.Ldif.is_acl_attribute(attr_name, server_type)
        tm.that(result, eq=expected_result), f"{scenario} failed"

    def test_acl_registry_no_mutation(self) -> None:
        """get_acl_attributes should return new list each time."""
        attrs1 = list(u.Ldif.get_acl_attributes("oid"))
        attrs2 = list(u.Ldif.get_acl_attributes("oid"))
        tm.that(attrs1, eq=attrs2)
        tm.that(attrs1 is not attrs2, eq=True)
        attrs1.append("test_attribute")
        tm.that("test_attribute" not in attrs2, eq=True)
