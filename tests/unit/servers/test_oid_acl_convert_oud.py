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

    @c.Tests.MARK.parametrize(
        ("kind", "value", "bind_type", "bind_value"),
        [
            ("group", "cn=admins , dc=ctbc", "groupdn", "cn=admins,dc=ctbc"),
            (c.ContextScope.USER, "uid=joe,dc=ctbc", "userdn", "uid=joe,dc=ctbc"),
            ("self", "self", "userdn", "self"),
            ("anyone", "anyone", "userdn", "anyone"),
            ("superuser", "cn=Directory Manager", "userdn", "cn=Directory Manager"),
            ("dnattr", "manager", "userattr", "manager#USERDN"),
            ("groupattr", "owner", "userattr", "owner#GROUPDN"),
        ],
    )
    def test_subject_maps_to_expected_bind_rule(
        self,
        kind: str,
        value: str,
        bind_type: str,
        bind_value: str,
    ) -> None:
        """Test subject maps to expected bind rule."""
        result = FlextLdifServersOidAclToOud.convert_subject_to_oud(
            self._subject(kind, value)
        )

        allow = result.unwrap()
        tm.that(allow.subject_type, eq=bind_type)
        tm.that(allow.subject_value, eq=bind_value)

    def test_converted_subject_leaves_permissions_empty(self) -> None:
        """Test converted subject leaves permissions empty."""
        result = FlextLdifServersOidAclToOud.convert_subject_to_oud(
            self._subject(c.ContextScope.USER, "uid=joe,dc=ctbc")
        )

        tm.that(result.unwrap().permissions, eq=())

    @c.Tests.MARK.parametrize(
        ("kind", "value"),
        [("guidattr", "orclguid"), ("nosuchkind", "")],
    )
    def test_subject_without_oud_equivalent_surfaces_failure(
        self,
        kind: str,
        value: str,
    ) -> None:
        """Test subject without oud equivalent surfaces failure."""
        tm.fail(
            FlextLdifServersOidAclToOud.convert_subject_to_oud(
                self._subject(kind, value)
            ),
            has="manual review",
        )

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

        tm.that(tuple(resolved.allow), eq=allow)
        tm.that(tuple(resolved.deny), eq=deny)

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("permissions", "is_entry", "total"),
        [
            (("none",), True, True),
            (("nobrowse", "noadd", "nodelete", "noproxy"), True, True),
            (("nobrowse", "noadd"), True, False),
            (("browse", "none"), True, True),
            (("noread",), False, False),
        ],
    )
    def test_total_denial_covers_every_right_of_the_kind(
        permissions: tuple[str, ...],
        *,
        is_entry: bool,
        total: bool,
    ) -> None:
        """``total_denial`` holds exactly when every right of the kind is denied."""
        resolved = FlextLdifServersOidAclToOud.resolve_permissions(
            permissions, is_entry=is_entry
        ).unwrap()

        tm.that(resolved.total_denial, eq=total)

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
            ((" ",), True, "Empty OID access list"),
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

    # -- resolve_targetattr ---------------------------------------------------

    @c.Tests.MARK.parametrize(
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
        self,
        target_type: str,
        target_attrs: str,
        expected: str,
    ) -> None:
        """Test get targetattr."""
        tm.that(
            FlextLdifServersOidAclToOud.resolve_targetattr(
                self._rule(target_type, target_attrs)
            ),
            eq=expected,
        )

    # -- calculate_targetscope / clause_scopes -----------------------------

    def test_scope_orclaci_without_anyone_is_default(self) -> None:
        """Test scope orclaci without anyone is default."""
        scope = FlextLdifServersOidAclToOud.calculate_targetscope(
            self._rule("entry"),
            has_anyone_subject=False,
        )

        tm.ok(scope is None)

    def test_scope_orclaci_with_anyone_is_base(self) -> None:
        """Test scope orclaci with anyone is base."""
        scope = FlextLdifServersOidAclToOud.calculate_targetscope(
            self._rule("entry"), has_anyone_subject=True
        )

        tm.that(scope, eq="base")

    def test_scope_orclentrylevelaci_is_always_base(self) -> None:
        """Test scope orclentrylevelaci is always base."""
        scope = FlextLdifServersOidAclToOud.calculate_targetscope(
            self._rule("entry", acl_type="orclentrylevelaci"),
            has_anyone_subject=False,
        )

        tm.that(scope, eq="base")

    # -- regex_dn_to_wildcard / convert_bind_dn ----------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("value", "expected"),
        [
            (".*,dc=ctbc", "**,dc=ctbc"),
            (".+, dc=ctbc", "**,dc=ctbc"),
            ("*,ou=people,dc=ctbc", "**,ou=people,dc=ctbc"),
            (r"cn=a\.b,dc=ctbc", "cn=a.b,dc=ctbc"),
            (r"cn=Doe\, John,dc=ctbc", r"cn=Doe\, John,dc=ctbc"),
            ("uid=joe,dc=ctbc", "uid=joe,dc=ctbc"),
            ("", ""),
        ],
    )
    def test_regex_dn_to_wildcard(value: str, expected: str) -> None:
        """A plain DN stays; the leading subtree regex becomes OUD ``**,``."""
        tm.that(
            FlextLdifServersOidAclToOud.regex_dn_to_wildcard(value).unwrap(),
            eq=expected,
        )

    @staticmethod
    @c.Tests.MARK.parametrize(
        "value",
        [
            "cn=.*,dc=ctbc",
            "cn=adm*,dc=ctbc",
            r"cn=a\d,dc=ctbc",
            r"cn=a\.*,dc=ctbc",
            "cn=ab+,dc=ctbc",
            "cn=a[0-9]b",
            "cn=(a|b),dc=ctbc",
            "^cn=a$",
        ],
    )
    def test_unconvertible_regex_dn_surfaces_failure(value: str) -> None:
        """A regex DN beyond the leading subtree wildcard fails, never raw."""
        tm.fail(
            FlextLdifServersOidAclToOud.regex_dn_to_wildcard(value),
            has="no exact OUD wildcard",
        )

    @staticmethod
    def test_group_dn_with_wildcard_surfaces_failure() -> None:
        """A ``group=`` subject names one DN; a wildcard there fails loud."""
        tm.fail(
            FlextLdifServersOidAclToOud.convert_bind_dn("groupdn", ".*,dc=ctbc"),
            has="no exact OUD groupdn",
        )
        tm.that(
            FlextLdifServersOidAclToOud.convert_bind_dn(
                "groupdn", "cn=g,dc=ctbc"
            ).unwrap(),
            eq="cn=g,dc=ctbc",
        )

    # -- convert_bindipfilter / convert_bind_modifiers ------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("value", "expected"),
        [
            ("", ""),
            ("orclipaddress=10.1.2.3", "10.1.2.3"),
            ("orclipaddress=10.10.*", "10.10.*.*"),
            (
                "|(orclipaddress=1.2.3.*)(orclipaddress=1.2.4.*)",
                "1.2.3.*,1.2.4.*",
            ),
        ],
    )
    def test_bindipfilter_translates_to_oud_ip(value: str, expected: str) -> None:
        """An orclipaddress equality (or OR of them) becomes an OUD ip list."""
        tm.that(
            FlextLdifServersOidAclToOud.convert_bindipfilter(value).unwrap(),
            eq=expected,
        )

    @staticmethod
    @c.Tests.MARK.parametrize(
        "value",
        [
            "10.0.0.0",
            "&(orclipaddress!=1.2.*)(orclipaddress!=3.4.*)",
            "orclipaddress=1.2.3*",
            "orclipaddress=1.*.3.4",
            "orclipaddress=300.1.1.1",
        ],
    )
    def test_untranslatable_bindipfilter_surfaces_failure(value: str) -> None:
        """A bindipfilter without an exact OUD ip form fails loud."""
        tm.fail(
            FlextLdifServersOidAclToOud.convert_bindipfilter(value),
            has="no exact OUD ip",
        )

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("subject", "message"),
        [
            (
                m.Ldif.OidAclSubject(subject_type="anyone", bindmode="Simple"),
                "bindmode",
            ),
            (
                m.Ldif.OidAclSubject(
                    subject_type="anyone",
                    added_object_constraint="objectclass=person",
                ),
                "added_object_constraint",
            ),
        ],
    )
    def test_bindmode_and_add_constraint_surface_failure(
        subject: p.Ldif.OidAclSubject,
        message: str,
    ) -> None:
        """Modifiers without an exact OUD form fail instead of passing raw."""
        tm.fail(
            FlextLdifServersOidAclToOud.convert_bind_modifiers(subject),
            has=message,
        )

    @c.Tests.MARK.parametrize(
        ("acl_type", "deny", "rule_scope", "expected"),
        [
            (
                "orclentrylevelaci",
                False,
                "base",
                ((None, ("read", "search")), ("onelevel", ("add",))),
            ),
            (
                "orclentrylevelaci",
                True,
                "base",
                ((None, ("read", "search")), ("onelevel", ("add",))),
            ),
            ("orclaci", True, "base", (("subtree", ("read", "search", "add")),)),
            ("orclaci", True, None, ((None, ("read", "search", "add")),)),
            ("orclaci", False, "base", ((None, ("read", "search", "add")),)),
        ],
    )
    def test_clause_scopes_partition_rights_by_targetscope(
        self,
        acl_type: str,
        *,
        deny: bool,
        rule_scope: str | None,
        expected: tuple[tuple[str | None, tuple[str, ...]], ...],
    ) -> None:
        """Entry-level ``add`` targets children; orclaci denials keep subtree."""
        tm.that(
            FlextLdifServersOidAclToOud.clause_scopes(
                self._rule("entry", acl_type=acl_type),
                ("read", "search", "add"),
                deny=deny,
                rule_scope=rule_scope,
            ),
            eq=expected,
        )

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
