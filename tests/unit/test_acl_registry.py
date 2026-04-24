"""Tests for ldif ACL attribute registry constants.

This module tests the ACL attribute registry for server-specific ACL
attribute mappings and validation.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c, t, u


@pytest.mark.unit
class TestsFlextLdifAclRegistry:
    """Test suite for AclAttributeRegistry."""

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
            for name, data in c.Ldif.Tests.ACL_REGISTRY_GET_ACL_ATTRIBUTES_DATA.items()
        ],
    )
    def test_get_acl_attributes(
        self,
        scenario: str,
        server_type: str,
        param_server_type: str | None,
        required_attrs: t.StrSequence,
        forbidden_attrs: t.StrSequence,
    ) -> None:
        """Parametrized test for get_acl_attributes."""
        attrs = u.Ldif.get_acl_attributes(param_server_type)
        for required in required_attrs:
            _ = tm.that(attrs, has=required)
        for forbidden in forbidden_attrs:
            _ = tm.that(forbidden not in attrs, eq=True)

    @pytest.mark.parametrize(
        ("scenario", "test_type", "attr_name", "server_type", "expected_result"),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in c.Ldif.Tests.ACL_REGISTRY_IS_ACL_ATTRIBUTE_DATA.items()
        ],
    )
    def test_is_acl_attribute(
        self,
        scenario: str,
        test_type: str,
        attr_name: str,
        server_type: str | None,
        expected_result: bool,
    ) -> None:
        """Parametrized test for is_acl_attribute."""
        result = u.Ldif.is_acl_attribute(attr_name, server_type)
        _ = tm.that(result, eq=expected_result)

    def test_acl_registry_no_mutation(self) -> None:
        """get_acl_attributes should return new list each time."""
        attrs1 = list(u.Ldif.get_acl_attributes("oid"))
        attrs2 = list(u.Ldif.get_acl_attributes("oid"))
        tm.that(attrs1, eq=attrs2)
        tm.that(attrs1 is not attrs2, eq=True)
        attrs1.append("test_attribute")
        tm.that("test_attribute" not in attrs2, eq=True)
