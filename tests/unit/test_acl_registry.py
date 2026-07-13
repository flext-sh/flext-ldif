"""Behavioral tests for the LDIF ACL attribute registry.

Exercises the OBSERVABLE public contract of the ACL attribute registry exposed
through ``u.Ldif`` — ``get_acl_attributes`` and ``is_acl_attribute``. Tests
assert only public behavior (return values, membership, case-insensitivity,
input equivalence, mutation isolation, idempotence, and the invariant that
``is_acl_attribute`` agrees with ``get_acl_attributes``). No private attributes,
internal collaborators, or implementation data structures are touched.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from tests.constants import c
from tests.utilities import u

if TYPE_CHECKING:
    from tests.typings import t


@pytest.mark.unit
class TestsFlextLdifAclRegistry:
    """Behavioral suite for the public ACL attribute registry contract."""

    @pytest.mark.parametrize(
        (
            "scenario",
            "param_server_type",
            "required_attrs",
            "forbidden_attrs",
        ),
        [
            (name, data[1], data[2], data[3])
            for name, data in c.Tests.ACL_REGISTRY_GET_ACL_ATTRIBUTES_DATA.items()
        ],
    )
    def test_get_acl_attributes_returns_expected_membership_per_server(
        self,
        scenario: str,
        param_server_type: str | None,
        required_attrs: t.StrSequence,
        forbidden_attrs: t.StrSequence,
    ) -> None:
        """Each server type resolves to its documented ACL attribute set."""
        # Arrange / Act
        attrs = u.Ldif.get_acl_attributes(param_server_type)

        # Assert: every required attribute present, every forbidden one absent.
        for required in required_attrs:
            _ = tm.that(attrs, has=required)
        for forbidden in forbidden_attrs:
            _ = tm.that(forbidden not in attrs, eq=True)

    def test_get_acl_attributes_default_is_rfc_foundation_set(self) -> None:
        """Calling with no server type yields the RFC foundation attributes."""
        # Act
        default_attrs = u.Ldif.get_acl_attributes()
        rfc_attrs = u.Ldif.get_acl_attributes("rfc")

        # Assert: the None default is the RFC contract, including olcAccess.
        tm.that(default_attrs, eq=rfc_attrs)
        tm.that(default_attrs, has="olcAccess")

    @pytest.mark.parametrize(
        "server_type",
        ["oid", "oud", "ad", "rfc", "generic"],
    )
    def test_get_acl_attributes_string_and_enum_inputs_are_equivalent(
        self,
        server_type: str,
    ) -> None:
        """A string server type and its enum member resolve identically."""
        # Arrange
        enum_member = c.Ldif.ServerTypes(server_type)

        # Act
        from_string = u.Ldif.get_acl_attributes(server_type)
        from_enum = u.Ldif.get_acl_attributes(enum_member)

        # Assert
        tm.that(from_string, eq=from_enum)

    @pytest.mark.parametrize(
        "variant",
        ["oid", "OID", "  oid  ", "Oid"],
    )
    def test_get_acl_attributes_normalizes_case_and_whitespace(
        self,
        variant: str,
    ) -> None:
        """Server-type lookup is case-insensitive and whitespace-tolerant."""
        # Act / Assert: every spelling of "oid" yields the canonical result.
        tm.that(u.Ldif.get_acl_attributes(variant), eq=u.Ldif.get_acl_attributes("oid"))

    def test_get_acl_attributes_unknown_server_falls_back_to_generic(self) -> None:
        """An unrecognized server type degrades to the generic aci/acl set."""
        # Act
        unknown = u.Ldif.get_acl_attributes("no_such_server")
        generic = u.Ldif.get_acl_attributes("generic")

        # Assert: fallback equals the generic contract, no server-specific attrs.
        tm.that(unknown, eq=generic)
        tm.that("orclaci" not in unknown, eq=True)

    def test_get_acl_attributes_is_idempotent(self) -> None:
        """Repeated calls for the same server type yield equal contents."""
        # Act / Assert
        tm.that(
            u.Ldif.get_acl_attributes("oid"),
            eq=u.Ldif.get_acl_attributes("oid"),
        )

    def test_get_acl_attributes_returns_independent_mutable_copies(self) -> None:
        """Mutating a returned list must not affect later calls (no shared state)."""
        # Arrange
        first = u.Ldif.get_acl_attributes("oid")
        second = u.Ldif.get_acl_attributes("oid")

        # Assert: distinct objects with equal contents.
        tm.that(first is not second, eq=True)
        tm.that(first, eq=second)

        # Act: mutate the first copy.
        first.append("injected_attribute")

        # Assert: a fresh call is unaffected by the mutation.
        tm.that("injected_attribute" not in u.Ldif.get_acl_attributes("oid"), eq=True)

    @pytest.mark.parametrize(
        ("attr_name", "server_type", "expected_result"),
        [
            (data[1], data[2], data[3])
            for data in c.Tests.ACL_REGISTRY_IS_ACL_ATTRIBUTE_DATA.values()
        ],
    )
    def test_is_acl_attribute_classifies_attributes(
        self,
        attr_name: str,
        server_type: str | None,
        expected_result: bool,
    ) -> None:
        """is_acl_attribute returns the documented boolean per attribute/server."""
        # Act / Assert
        tm.that(u.Ldif.is_acl_attribute(attr_name, server_type), eq=expected_result)

    @pytest.mark.parametrize(
        "spelling",
        ["aci", "ACI", "Aci", "aCi"],
    )
    def test_is_acl_attribute_is_case_insensitive(self, spelling: str) -> None:
        """Recognition of an ACL attribute ignores letter casing."""
        # Act / Assert
        tm.that(u.Ldif.is_acl_attribute(spelling), eq=True)

    @pytest.mark.parametrize(
        "non_acl_attr",
        ["cn", "uid", "mail", "objectClass"],
    )
    def test_is_acl_attribute_rejects_non_acl_attributes(
        self,
        non_acl_attr: str,
    ) -> None:
        """Ordinary directory attributes are not classified as ACL attributes."""
        # Act / Assert
        tm.that(u.Ldif.is_acl_attribute(non_acl_attr), eq=False)

    @pytest.mark.parametrize(
        "server_type",
        [None, "oid", "oud", "ad", "generic"],
    )
    def test_is_acl_attribute_agrees_with_get_acl_attributes(
        self,
        server_type: str | None,
    ) -> None:
        """Invariant: every attribute in the set is recognized (case-insensitively)."""
        # Arrange
        registered = u.Ldif.get_acl_attributes(server_type)

        # Assert: membership and classification agree for every registered attr.
        for attr in registered:
            tm.that(u.Ldif.is_acl_attribute(attr, server_type), eq=True)
            tm.that(u.Ldif.is_acl_attribute(attr.upper(), server_type), eq=True)
