"""Behavioral tests for the OID→OUD ACL converter public contract.

Exercises the observable behavior of
:class:`flext_ldif.servers._oid.acl_convert_oud.FlextLdifServersOidAclToOud`:
subject → OUD bind-rule mapping, permission-token conversion, targetattr /
targetscope computation, and the DN-scoping helpers. Every assertion targets a
public return value or the ``r[T]`` outcome — never an implementation detail.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.servers import FlextLdifServersOidAclToOud
from tests import c, m, p, tm


class TestsFlextLdifOidAclConvertOud:
    """Public contract of FlextLdifServersOidAclToOud."""

    @staticmethod
    def _subject(kind: str, value: str = "") -> p.Ldif.OidAclSubject:
        return m.Ldif.OidAclSubject(subject_type=kind, value=value)

    @staticmethod
    def _rule(
        target_type: str,
        target_attrs: str = "*",
        acl_type: str = "orclaci",
    ) -> p.Ldif.OidAclRule:
        return m.Ldif.OidAclRule(
            dn="dc=ctbc",
            acl_type=acl_type,
            target_type=target_type,
            target_attrs=target_attrs,
        )

    # -- convert_subject_to_oud: bind-rule mapping -------------------------

    # -- resolve_permissions ----------------------------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("permissions", "is_entry", "allow", "deny"),
        [
            (
                ("browse", "add", "delete"),
                True,
                ("read", "search", "add", "delete"),
                (),
            ),
            (("search", "read"), False, ("read", "search"), ()),
            (("browse", "nobrowse"), True, (), ("read", "search")),
            (
                ("browse", "none"),
                True,
                (),
                ("read", "search", "add", "delete", "proxy"),
            ),
            (("browse", "noadd"), True, ("read", "search"), ("add",)),
            (("noadd",), True, (), ("add",)),
            (
                ("nobrowse", "noadd", "nodelete"),
                True,
                (),
                ("read", "search", "add", "delete"),
            ),
            (("noread",), False, (), ("read",)),
            (
                ("search", "read", "nowrite", "nocompare"),
                False,
                ("read", "search"),
                ("write", "compare"),
            ),
            (("none",), True, (), ("read", "search", "add", "delete", "proxy")),
            (("none",), False, (), ("read", "search", "write", "selfwrite", "compare")),
        ],
    )
    def test_resolve_permissions_resolves_grants_and_denials(
        permissions: tuple[str, ...],
        *,
        is_entry: bool,
        allow: tuple[str, ...],
        deny: tuple[str, ...],
    ) -> None:
        """Each OID access level is granted or denied on its own (OID-30 §30.1.4.3).

        A pure-negation list denies exactly the named rights and grants
        nothing; a right both granted and denied is denied.
        """
        resolved = FlextLdifServersOidAclToOud.resolve_permissions(
            permissions, is_entry=is_entry
        ).unwrap()

        tm.that(resolved.allow, eq=frozenset(allow))
        tm.that(resolved.deny, eq=frozenset(deny))

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("permissions", "is_entry", "message"),
        [
            (("bogus",), False, "Unknown OID permission token"),
            (("nofoo",), False, "Unknown OID permission token"),
            (("all",), True, "Unknown OID permission token 'all'"),
            (("all", "noread"), False, "Unknown OID permission token 'all'"),
            (("*",), False, "Unknown OID permission token"),
            (("read",), True, "not a right of an 'entry' object"),
            (("noread",), True, "not a right of an 'entry' object"),
            (("browse",), False, "not a right of an 'attr' object"),
            ((), True, "Empty OID access list"),
            ((" ",), True, "Empty token in OID access list"),
            (("browse", ""), True, "Empty token in OID access list"),
        ],
    )
    def test_token_outside_access_grammar_surfaces_failure(
        permissions: tuple[str, ...],
        *,
        is_entry: bool,
        message: str,
    ) -> None:
        """Tokens outside the OID access grammar of the object kind fail loud."""
        tm.fail(
            FlextLdifServersOidAclToOud.resolve_permissions(
                permissions, is_entry=is_entry
            ),
            has=message,
        )

    # -- convert_targetattr --------------------------------------------------

    # -- rule_targetscope ---------------------------------------------------

    # -- validate_ldap_filter -----------------------------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("value", "expected"),
        [
            ("objectclass=person", "(objectclass=person)"),
            ("&(a=b)(!(c=*))", "(&(a=b)(!(c=*)))"),
            ("(cn=a*b)", "(cn=a*b)"),
            ("cn:dn:2.5.13.5:=x", "(cn:dn:2.5.13.5:=x)"),
            ("foo", ""),
            ("!(a=b)(c=d)", ""),
            ("&", ""),
            ("(a=b)x", ""),
        ],
    )
    def test_ldap_filter_is_validated(value: str, expected: str) -> None:
        """An RFC 4515 filter renders parenthesized; any other text fails."""
        result = FlextLdifServersOidAclToOud.validate_ldap_filter(value)
        if expected:
            tm.that(result.unwrap(), eq=expected)
        else:
            tm.fail(result, has="not one RFC 4515 LDAP filter")

    # -- regex_dn_to_wildcard / convert_bind_dn ----------------------------

    # -- convert_bindipfilter / convert_bind_modifiers ------------------------

    # -- in_scope ------------------------------------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("dn", "base_dn", "expected"),
        [
            ("dc=ctbc", "dc=ctbc", True),
            ("uid=joe,dc=ctbc", "dc=ctbc", True),
            ("dc=other", "dc=ctbc", False),
            ("dc=x", "", True),
        ],
    )
    def test_is_in_scope(dn: str, base_dn: str, *, expected: bool) -> None:
        """Test is in scope."""
        tm.that(FlextLdifServersOidAclToOud.in_scope(dn, base_dn), eq=expected)
