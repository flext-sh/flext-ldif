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
