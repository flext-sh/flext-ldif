"""Behavioral tests for the OID→OUD ACL converter public contract.

Exercises the observable behavior of
:class:`flext_ldif.servers._oid.acl_convert_oud.FlextLdifServersOidAclToOud`:
subject → OUD bind-rule mapping, permission-token conversion, targetattr /
targetscope computation, and the DN-scoping helpers. Every assertion targets a
public return value or the ``r[T]`` outcome — never an implementation detail.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import m, p
from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud as Conv


class TestsFlextLdifOidAclConvertOud:
    """Public contract of FlextLdifServersOidAclToOud."""

    @staticmethod
    def _subject(kind: str, value: str = "") -> p.Ldif.OidAclSubject:
        return m.Ldif.OidAclSubject(subject_type=kind, value=value)

    @staticmethod
    def _rule(
        target_type: str, target_attrs: str = "*", acl_type: str = "orclaci"
    ) -> p.Ldif.OidAclRule:
        return m.Ldif.OidAclRule(
            dn="dc=ctbc",
            acl_type=acl_type,
            target_type=target_type,
            target_attrs=target_attrs,
        )

    # -- convert_subject_to_oud: bind-rule mapping -------------------------

    @pytest.mark.parametrize(
        ("kind", "value", "bind_type", "bind_value"),
        [
            ("group", "cn=admins , dc=ctbc", "groupdn", "cn=admins,dc=ctbc"),
            ("user", "uid=joe,dc=ctbc", "userdn", "uid=joe,dc=ctbc"),
            ("self", "self", "userdn", "self"),
            ("anyone", "anyone", "userdn", "anyone"),
            ("superuser", "cn=Directory Manager", "userdn", "cn=Directory Manager"),
            ("dnattr", "manager", "userattr", "manager#USERDN"),
            ("groupattr", "owner", "userattr", "owner#GROUPDN"),
        ],
    )
    def test_subject_maps_to_expected_bind_rule(
        self, kind: str, value: str, bind_type: str, bind_value: str
    ) -> None:
        result = Conv.convert_subject_to_oud(self._subject(kind, value))

        allow = result.unwrap()
        tm.that(allow.subject_type, eq=bind_type)
        tm.that(allow.subject_value, eq=bind_value)

    def test_converted_subject_leaves_permissions_empty(self) -> None:
        result = Conv.convert_subject_to_oud(self._subject("user", "uid=joe,dc=ctbc"))

        tm.that(result.unwrap().permissions, eq=())

    @pytest.mark.parametrize(
        ("kind", "value"), [("guidattr", "orclguid"), ("nosuchkind", "")]
    )
    def test_subject_without_oud_equivalent_surfaces_failure(
        self, kind: str, value: str
    ) -> None:
        result = Conv.convert_subject_to_oud(self._subject(kind, value))

        tm.that(result.failure, eq=True)
        tm.that(result.error, contains="manual review")

    # -- convert_permissions ----------------------------------------------

    @pytest.mark.parametrize(
        ("permissions", "is_entry", "expected"),
        [
            (("browse", "add", "delete"), True, ("read", "search", "add", "delete")),
            (("all", "browse", "add"), True, ("all",)),
            (("all", "noadd"), True, ("read", "search", "delete", "proxy")),
            (("all", "noread"), False, ("search", "write", "selfwrite", "compare")),
            (("search", "read"), False, ("read", "search")),
            (("browse", "noadd"), True, ("read", "search")),
            (("noadd",), True, ("read", "search", "delete", "proxy")),
            (("noread",), False, ("search", "write", "selfwrite", "compare")),
            (("none",), True, ()),
        ],
    )
    def test_convert_permissions_yields_ordered_allow_set(
        self, permissions: tuple[str, ...], is_entry: bool, expected: tuple[str, ...]
    ) -> None:
        result = Conv.convert_permissions(permissions, is_entry=is_entry)

        tm.that(result.unwrap(), eq=expected)

    @pytest.mark.parametrize("permissions", [("bogus",), ("nofoo",)])
    def test_convert_permissions_unknown_token_surfaces_failure(
        self, permissions: tuple[str, ...]
    ) -> None:
        result = Conv.convert_permissions(permissions, is_entry=False)

        tm.that(result.failure, eq=True)

    # -- get_targetattr ---------------------------------------------------

    @pytest.mark.parametrize(
        ("target_type", "target_attrs", "expected"),
        [
            ("entry", "*", "*"),
            ("attr", "cn,sn,mail", "cn||sn||mail"),
            ("attr", "*", "*"),
            ("attr", "!=userpassword", "!=userpassword"),
            ("attr", "!=a, b", "!=a||b"),
        ],
    )
    def test_get_targetattr(
        self, target_type: str, target_attrs: str, expected: str
    ) -> None:
        tm.that(Conv.get_targetattr(self._rule(target_type, target_attrs)), eq=expected)

    # -- calculate_targetscope --------------------------------------------

    def test_scope_orclaci_without_anyone_is_default(self) -> None:
        scope = Conv.calculate_targetscope(
            self._rule("entry"), has_anyone_subject=False
        )

        tm.that(scope is None, eq=True)

    def test_scope_orclaci_with_anyone_is_base(self) -> None:
        scope = Conv.calculate_targetscope(self._rule("entry"), has_anyone_subject=True)

        tm.that(scope, eq="base")

    def test_scope_orclentrylevelaci_is_always_base(self) -> None:
        scope = Conv.calculate_targetscope(
            self._rule("entry", acl_type="orclentrylevelaci"), has_anyone_subject=False
        )

        tm.that(scope, eq="base")

    # -- regex_to_wildcard ------------------------------------------------

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("cn=.*,dc=ctbc", "cn=*,dc=ctbc"),
            ("cn=.+,dc=ctbc", "cn=*,dc=ctbc"),
            (r"cn=a\.b,dc=ctbc", "cn=a.b,dc=ctbc"),
            ("", ""),
            ("cn=a[0-9]b", "cn=a[0-9]b"),
        ],
    )
    def test_regex_to_wildcard(self, value: str, expected: str) -> None:
        tm.that(Conv.regex_to_wildcard(value), eq=expected)

    # -- is_in_scope ------------------------------------------------------

    @pytest.mark.parametrize(
        ("dn", "base_dn", "expected"),
        [
            ("dc=ctbc", "dc=ctbc", True),
            ("uid=joe,dc=ctbc", "dc=ctbc", True),
            ("dc=other", "dc=ctbc", False),
            ("dc=x", "", True),
        ],
    )
    def test_is_in_scope(self, dn: str, base_dn: str, expected: bool) -> None:
        tm.that(Conv.is_in_scope(dn, base_dn), eq=expected)

    # -- high_level_containers --------------------------------------------

    def test_high_level_containers_are_base_relative_and_case_folded(self) -> None:
        containers = Conv.high_level_containers("dc=CTBC")

        tm.that("dc=ctbc" in containers, eq=True)
        tm.that("dc=network,dc=ctbc" in containers, eq=True)
