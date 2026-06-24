"""Tests for OID→OUD subject conversion (OidAclSubject → OUD bind-rule)."""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import m
from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud as Conv


class TestsFlextLdifOidAclConvertSubject:
    """convert_subject_to_oud parity with the algar-oud-mig oracle."""

    @staticmethod
    def _subject(kind: str, value: str = "") -> m.Ldif.OidAclSubject:
        return m.Ldif.OidAclSubject(subject_type=kind, value=value)

    def test_group_maps_to_groupdn_with_normalized_dn(self) -> None:
        result = Conv.convert_subject_to_oud(
            self._subject("group", "cn=admins , dc=ctbc"),
        )

        allow = result.unwrap()
        tm.that(allow.subject_type, eq="groupdn")
        tm.that(allow.subject_value, eq="cn=admins,dc=ctbc")
        tm.that(allow.permissions, eq=())

    def test_user_maps_to_userdn(self) -> None:
        result = Conv.convert_subject_to_oud(self._subject("user", "uid=joe,dc=ctbc"))

        allow = result.unwrap()
        tm.that(allow.subject_type, eq="userdn")
        tm.that(allow.subject_value, eq="uid=joe,dc=ctbc")

    def test_self_maps_to_userdn_self_literal(self) -> None:
        result = Conv.convert_subject_to_oud(self._subject("self", "self"))

        allow = result.unwrap()
        tm.that(allow.subject_type, eq="userdn")
        tm.that(allow.subject_value, eq="self")

    def test_anyone_maps_to_userdn_anyone_literal(self) -> None:
        result = Conv.convert_subject_to_oud(self._subject("anyone", "anyone"))

        allow = result.unwrap()
        tm.that(allow.subject_type, eq="userdn")
        tm.that(allow.subject_value, eq="anyone")

    def test_superuser_maps_to_directory_manager(self) -> None:
        result = Conv.convert_subject_to_oud(
            self._subject("superuser", "cn=Directory Manager"),
        )

        allow = result.unwrap()
        tm.that(allow.subject_type, eq="userdn")
        tm.that(allow.subject_value, eq="cn=Directory Manager")

    def test_dnattr_maps_to_userattr_userdn_suffix(self) -> None:
        result = Conv.convert_subject_to_oud(self._subject("dnattr", "manager"))

        allow = result.unwrap()
        tm.that(allow.subject_type, eq="userattr")
        tm.that(allow.subject_value, eq="manager#USERDN")

    def test_groupattr_maps_to_userattr_groupdn_suffix(self) -> None:
        result = Conv.convert_subject_to_oud(self._subject("groupattr", "owner"))

        allow = result.unwrap()
        tm.that(allow.subject_type, eq="userattr")
        tm.that(allow.subject_value, eq="owner#GROUPDN")

    def test_guidattr_surfaces_failure_no_oud_equivalent(self) -> None:
        result = Conv.convert_subject_to_oud(self._subject("guidattr", "orclguid"))

        tm.that(result.failure, eq=True)

    def test_unknown_surfaces_failure(self) -> None:
        result = Conv.convert_subject_to_oud(self._subject("unknown"))

        tm.that(result.failure, eq=True)


class TestsFlextLdifOidAclConvertPermissions:
    """convert_permissions parity with the algar-oud-mig oracle perm maps."""

    def test_entry_browse_expands_to_read_search(self) -> None:
        result = Conv.convert_permissions(("browse", "add", "delete"), is_entry=True)

        tm.that(result.unwrap(), eq=("read", "search", "add", "delete"))

    def test_attr_perms_pass_through_ordered(self) -> None:
        result = Conv.convert_permissions(("search", "read"), is_entry=False)

        tm.that(result.unwrap(), eq=("read", "search"))

    def test_positive_perms_win_over_negations(self) -> None:
        result = Conv.convert_permissions(("browse", "noadd"), is_entry=True)

        tm.that(result.unwrap(), eq=("read", "search"))

    def test_pure_negation_entry_yields_complement(self) -> None:
        result = Conv.convert_permissions(("noadd",), is_entry=True)

        tm.that(result.unwrap(), eq=("read", "search", "delete", "proxy"))

    def test_pure_negation_attr_yields_complement(self) -> None:
        result = Conv.convert_permissions(("noread",), is_entry=False)

        tm.that(result.unwrap(), eq=("search", "write", "selfwrite", "compare"))

    def test_none_yields_no_allow(self) -> None:
        result = Conv.convert_permissions(("none",), is_entry=True)

        tm.that(result.unwrap(), eq=())

    def test_unknown_token_surfaces_failure(self) -> None:
        result = Conv.convert_permissions(("bogus",), is_entry=False)

        tm.that(result.failure, eq=True)

    def test_unknown_negation_surfaces_failure(self) -> None:
        result = Conv.convert_permissions(("nofoo",), is_entry=False)

        tm.that(result.failure, eq=True)


class TestsFlextLdifOidAclConvertTarget:
    """get_targetattr + calculate_targetscope parity with the oracle."""

    @staticmethod
    def _rule(
        target_type: str,
        target_attrs: str = "*",
        acl_type: str = "orclaci",
    ) -> m.Ldif.OidAclRule:
        return m.Ldif.OidAclRule(
            dn="dc=ctbc",
            acl_type=acl_type,
            target_type=target_type,
            target_attrs=target_attrs,
        )

    def test_entry_target_is_wildcard(self) -> None:
        tm.that(Conv.get_targetattr(self._rule("entry")), eq="*")

    def test_attr_list_joins_with_or(self) -> None:
        tm.that(
            Conv.get_targetattr(self._rule("attr", "cn,sn,mail")),
            eq="cn||sn||mail",
        )

    def test_attr_wildcard_stays_wildcard(self) -> None:
        tm.that(Conv.get_targetattr(self._rule("attr", "*")), eq="*")

    def test_attr_negation_keeps_operator(self) -> None:
        tm.that(
            Conv.get_targetattr(self._rule("attr", "!=userpassword")),
            eq="!=userpassword",
        )

    def test_attr_negation_list_joins_and_strips_spaces(self) -> None:
        tm.that(Conv.get_targetattr(self._rule("attr", "!=a, b")), eq="!=a||b")

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
            self._rule("entry", acl_type="orclentrylevelaci"),
            has_anyone_subject=False,
        )
        tm.that(scope, eq="base")
