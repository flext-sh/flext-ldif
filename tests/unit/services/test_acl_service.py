"""Data-driven unit tests for the public LDIF ACL facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from tests import c, m, u

if TYPE_CHECKING:
    from tests import p


class TestsFlextLdifAclService:
    """Cover ACL behavior through the public ldif facade."""

    @staticmethod
    @pytest.fixture
    def svc(api: p.Ldif.LdifClient) -> p.Ldif.LdifClient:
        """Provide ``svc``.

        Returns:
            The resulting ``p.Ldif.LdifClient``.
        """
        return api

    @staticmethod
    def test_service_check_returns_empty_response(svc: p.Ldif.LdifClient) -> None:
        """Test service check returns empty response."""
        result = svc.service_check()
        resp: m.Ldif.AclResponse = u.Tests.assert_success(result)
        tm.that(resp, is_=m.Ldif.AclResponse)
        tm.that(len(resp.acls), eq=c.Tests.ACL_SERVICE_CHECK_EMPTY_ACLS)

    @staticmethod
    def test_evaluate_empty_acls_denies_access(svc: p.Ldif.LdifClient) -> None:
        """Test evaluate empty acls denies access."""
        result = svc.evaluate_acl_context([], {})
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    @staticmethod
    def test_evaluate_no_permissions_required_grants_access(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test evaluate no permissions required grants access."""
        acl = m.Ldif.Acl(name="test-acl")
        permissions_dict = dict(c.Tests.ACL_PERMISSIONS_EMPTY)
        result = svc.evaluate_acl_context([acl], permissions_dict)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=True)

    @staticmethod
    def test_evaluate_with_dict_permissions_read_only(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test evaluate with dict permissions read only."""
        permissions_dict = dict(c.Tests.ACL_PERMISSIONS_READ_ONLY)
        result = svc.evaluate_acl_context([], permissions_dict)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    @staticmethod
    def test_evaluate_with_acl_permissions_model(svc: p.Ldif.LdifClient) -> None:
        """Test evaluate with acl permissions model."""
        perms = m.Ldif.AclPermissions(read=True)
        result = svc.evaluate_acl_context([], perms)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    @staticmethod
    @pytest.mark.parametrize(
        ("scenario", "acl_string", "server_type"),
        tuple(
            (scenario, case[0], case[1])
            for scenario, case in c.Tests.ACL_PARSE_FAILURE_CASES.items()
        ),
    )
    def test_parse_acl_string_failure_cases(
        scenario: str,
        acl_string: str,
        server_type: str,
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test parse acl string failure cases."""
        result = svc.parse_acl_string(acl_string, server_type)
        tm.that(bool(scenario), eq=True)
        tm.fail(result)

    @staticmethod
    def test_parse_acl_string_oud_succeeds(svc: p.Ldif.LdifClient) -> None:
        """Test parse acl string oud succeeds."""
        result = svc.parse_acl_string(c.Tests.ACL_OUD_STRING, c.Tests.OUD)
        u.Tests.assert_success(result)

    @staticmethod
    def test_parse_acl_string_oid_succeeds(svc: p.Ldif.LdifClient) -> None:
        """Test parse acl string oid succeeds."""
        result = svc.parse_acl_string(c.Tests.ACL_OID_STRING, c.Tests.OID)
        u.Tests.assert_success(result)

    @staticmethod
    @pytest.mark.parametrize(
        ("scenario", "acl_string", "server_type"),
        tuple((sc, data[0], data[1]) for sc, data in c.Tests.ACL_SERVER_CASES.items()),
    )
    def test_parse_acl_string_parametrized(
        scenario: str,
        acl_string: str,
        server_type: str,
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test parse acl string parametrized."""
        result = svc.parse_acl_string(acl_string, server_type)
        tm.that(bool(scenario), eq=True)
        u.Tests.assert_success(result)

    @staticmethod
    def test_extract_acls_from_entry_with_aci_attribute(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test extract acls from entry with aci attribute."""
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Tests.ACL_ENTRY_DN),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"orclaci": [c.Tests.ACL_ENTRY_ORCLACI_VALUE]},
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Tests.OID)
        u.Tests.assert_success(result)

    @staticmethod
    def test_extract_acls_from_entry_with_no_acl_attrs(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test extract acls from entry with no acl attrs."""
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Tests.ACL_ENTRY_DN),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"cn": ["test"]},
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Tests.OID)
        resp = u.Tests.assert_success(result)
        tm.that(len(resp.acls), eq=0)

    @staticmethod
    def test_extract_acls_from_entry_with_oud_aci_attribute(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test extract acls from entry with oud aci attribute."""
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Tests.ACL_ENTRY_DN),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"aci": [c.Tests.ACL_ENTRY_ACI_VALUE]},
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Tests.OUD)
        u.Tests.assert_success(result)

    @staticmethod
    def test_evaluate_acl_grants_when_acl_has_matching_permissions(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test evaluate acl grants when acl has matching permissions."""
        acl = m.Ldif.Acl(name="test-acl", permissions=m.Ldif.AclPermissions(read=True))
        required = m.Ldif.AclPermissions(read=True)
        result = svc.evaluate_acl_context([acl], required)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=True)

    @staticmethod
    def test_evaluate_acl_denies_when_no_acl_matches_permissions(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test evaluate acl denies when no acl matches permissions."""
        acl = m.Ldif.Acl(name="test-acl", permissions=m.Ldif.AclPermissions(read=False))
        required = m.Ldif.AclPermissions(read=True)
        result = svc.evaluate_acl_context([acl], required)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    @staticmethod
    def test_evaluate_acl_with_null_permissions_denies(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """Test evaluate acl with null permissions denies."""
        acl = m.Ldif.Acl(name="no-perms-acl")
        required = m.Ldif.AclPermissions(read=True)
        result = svc.evaluate_acl_context([acl], required)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    @staticmethod
    def test_extract_acls_from_entry_with_failed_parse(
        svc: p.Ldif.LdifClient,
    ) -> None:
        """An invalid OpenLDAP ACL propagates as the first parse failure."""
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Tests.ACL_ENTRY_DN),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"aci": [c.Tests.ACL_INVALID_SERVER_TYPE]},
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Tests.OPENLDAP)
        u.Tests.assert_failure(result)
