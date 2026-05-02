"""Data-driven unit tests for the public LDIF ACL facade."""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c, m, p, u


class TestsFlextLdifAclService:
    """Cover ACL behavior through the public ldif facade."""

    @pytest.fixture
    def svc(self, api: p.Ldif.LdifClient) -> p.Ldif.LdifClient:
        return api

    def test_service_check_returns_empty_response(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        result = svc.service_check()
        resp = u.Tests.assert_success(result)
        tm.that(resp, is_=m.Ldif.AclResponse)
        tm.that(len(resp.acls), eq=c.Tests.ACL_SERVICE_CHECK_EMPTY_ACLS)

    def test_evaluate_empty_acls_denies_access(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        result = svc.evaluate_acl_context([], {})
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    def test_evaluate_no_permissions_required_grants_access(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        acl = m.Ldif.Acl(name="test-acl")
        permissions_dict = dict(c.Tests.ACL_PERMISSIONS_EMPTY)
        result = svc.evaluate_acl_context([acl], permissions_dict)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=True)

    def test_evaluate_with_dict_permissions_read_only(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        permissions_dict = dict(c.Tests.ACL_PERMISSIONS_READ_ONLY)
        result = svc.evaluate_acl_context([], permissions_dict)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    def test_evaluate_with_acl_permissions_model(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        perms = m.Ldif.AclPermissions(read=True)
        result = svc.evaluate_acl_context([], perms)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    @pytest.mark.parametrize(
        ("scenario", "acl_string", "server_type"),
        tuple(
            (scenario, case[0], case[1])
            for scenario, case in c.Tests.ACL_PARSE_FAILURE_CASES.items()
        ),
    )
    def test_parse_acl_string_failure_cases(
        self,
        scenario: str,
        acl_string: str,
        server_type: str,
        svc: p.Ldif.LdifClient,
    ) -> None:
        result = svc.parse_acl_string(acl_string, server_type)
        tm.that(bool(scenario), eq=True)
        tm.fail(result)

    def test_parse_acl_string_oud_succeeds(self, svc: p.Ldif.LdifClient) -> None:
        result = svc.parse_acl_string(c.Tests.ACL_OUD_STRING, c.Tests.OUD)
        u.Tests.assert_success(result)

    def test_parse_acl_string_oid_succeeds(self, svc: p.Ldif.LdifClient) -> None:
        result = svc.parse_acl_string(c.Tests.ACL_OID_STRING, c.Tests.OID)
        u.Tests.assert_success(result)

    @pytest.mark.parametrize(
        ("scenario", "acl_string", "server_type"),
        tuple((sc, data[0], data[1]) for sc, data in c.Tests.ACL_SERVER_CASES.items()),
    )
    def test_parse_acl_string_parametrized(
        self,
        scenario: str,
        acl_string: str,
        server_type: str,
        svc: p.Ldif.LdifClient,
    ) -> None:
        result = svc.parse_acl_string(acl_string, server_type)
        tm.that(bool(scenario), eq=True)
        u.Tests.assert_success(result)

    def test_extract_acls_from_entry_with_aci_attribute(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        entry = m.Ldif.Entry(
            dn=c.Tests.ACL_ENTRY_DN,
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"orclaci": [c.Tests.ACL_ENTRY_ORCLACI_VALUE]}
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Tests.OID)
        u.Tests.assert_success(result)

    def test_extract_acls_from_entry_with_no_acl_attrs(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        entry = m.Ldif.Entry(
            dn=c.Tests.ACL_ENTRY_DN,
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"cn": ["test"]}
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Tests.OID)
        resp = u.Tests.assert_success(result)
        tm.that(len(resp.acls), eq=0)

    def test_extract_acls_from_entry_with_oud_aci_attribute(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        entry = m.Ldif.Entry(
            dn=c.Tests.ACL_ENTRY_DN,
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"aci": [c.Tests.ACL_ENTRY_ACI_VALUE]}
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Tests.OUD)
        u.Tests.assert_success(result)

    def test_evaluate_acl_grants_when_acl_has_matching_permissions(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        acl = m.Ldif.Acl(
            name="test-acl",
            permissions=m.Ldif.AclPermissions(read=True),
        )
        required = m.Ldif.AclPermissions(read=True)
        result = svc.evaluate_acl_context([acl], required)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=True)

    def test_evaluate_acl_denies_when_no_acl_matches_permissions(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        acl = m.Ldif.Acl(
            name="test-acl",
            permissions=m.Ldif.AclPermissions(read=False),
        )
        required = m.Ldif.AclPermissions(read=True)
        result = svc.evaluate_acl_context([acl], required)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    def test_evaluate_acl_with_null_permissions_denies(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        acl = m.Ldif.Acl(name="no-perms-acl")
        required = m.Ldif.AclPermissions(read=True)
        result = svc.evaluate_acl_context([acl], required)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    def test_extract_acls_from_entry_with_failed_parse(
        self,
        svc: p.Ldif.LdifClient,
    ) -> None:
        entry = m.Ldif.Entry(
            dn=c.Tests.ACL_ENTRY_DN,
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"aci": [c.Tests.ACL_INVALID_SERVER_TYPE]}
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Tests.OPENLDAP)
        response = u.Tests.assert_success(result)
        tm.that(response.statistics.failed_entries, eq=1)
