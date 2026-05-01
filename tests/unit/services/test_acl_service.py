"""Data-driven unit tests for FlextLdifAcl service."""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifAcl, m
from tests import c, u


class TestsFlextLdifAclService:
    """Cover ACL service branches using flat constants."""

    @pytest.fixture
    def svc(self) -> FlextLdifAcl:
        return FlextLdifAcl()

    # ── service_check ────────────────────────────────────────────────────────

    def test_service_check_returns_empty_response(self, svc: FlextLdifAcl) -> None:
        result = svc.service_check()
        resp = u.Tests.assert_success(result)
        tm.that(resp, is_=m.Ldif.AclResponse)
        tm.that(len(resp.acls), eq=c.Ldif.ACL_SERVICE_CHECK_EMPTY_ACLS)

    # ── evaluate_acl_context – empty ACL list ────────────────────────────────

    def test_evaluate_empty_acls_denies_access(self) -> None:
        result = FlextLdifAcl.evaluate_acl_context([], {})
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    # ── evaluate_acl_context – no permissions required ───────────────────────

    def test_evaluate_no_permissions_required_grants_access(self) -> None:
        acl = m.Ldif.Acl(name="test-acl")
        result = FlextLdifAcl.evaluate_acl_context(
            [acl],
            c.Ldif.ACL_PERMISSIONS_EMPTY,
        )
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=True)

    # ── evaluate_acl_context – permissions dict (Mapping branch) ─────────────

    def test_evaluate_with_dict_permissions_read_only(self) -> None:
        permissions_dict = dict(c.Ldif.ACL_PERMISSIONS_READ_ONLY)
        result = FlextLdifAcl.evaluate_acl_context(
            [],
            permissions_dict,
        )
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    # ── evaluate_acl_context – AclPermissions model branch ───────────────────

    def test_evaluate_with_acl_permissions_model(self) -> None:
        perms = m.Ldif.AclPermissions(read=True)
        result = FlextLdifAcl.evaluate_acl_context([], perms)
        eval_result = u.Tests.assert_success(result)
        tm.that(eval_result.granted, eq=False)

    # ── parse_acl_string ─────────────────────────────────────────────────────

    def test_parse_acl_string_invalid_server_type_fails(
        self, svc: FlextLdifAcl
    ) -> None:
        result = svc.parse_acl_string(
            c.Ldif.ACL_OUD_STRING,
            c.Ldif.ACL_INVALID_SERVER_TYPE,
        )
        tm.fail(result)

    def test_parse_acl_string_oud_succeeds(self, svc: FlextLdifAcl) -> None:
        result = svc.parse_acl_string(c.Ldif.ACL_OUD_STRING, c.Ldif.OUD)
        u.Tests.assert_success(result)

    def test_parse_acl_string_oid_succeeds(self, svc: FlextLdifAcl) -> None:
        result = svc.parse_acl_string(c.Ldif.ACL_OID_STRING, c.Ldif.OID)
        u.Tests.assert_success(result)

    @pytest.mark.parametrize(
        ("scenario", "acl_string", "server_type"),
        tuple((sc, data[0], data[1]) for sc, data in c.Ldif.ACL_SERVER_CASES.items()),
    )
    def test_parse_acl_string_parametrized(
        self,
        scenario: str,
        acl_string: str,
        server_type: str,
        svc: FlextLdifAcl,
    ) -> None:
        result = svc.parse_acl_string(acl_string, server_type)
        tm.that(bool(scenario), eq=True)
        u.Tests.assert_success(result)

    # ── extract_acls_from_entry ──────────────────────────────────────────────

    def test_extract_acls_from_entry_with_aci_attribute(
        self, svc: FlextLdifAcl
    ) -> None:
        entry = m.Ldif.Entry(
            dn=c.Ldif.ACL_ENTRY_DN,
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"orclaci": [c.Ldif.ACL_ENTRY_ORCLACI_VALUE]}
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Ldif.OID)
        u.Tests.assert_success(result)

    def test_extract_acls_from_entry_with_no_acl_attrs(self, svc: FlextLdifAcl) -> None:
        entry = m.Ldif.Entry(
            dn=c.Ldif.ACL_ENTRY_DN,
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"cn": ["test"]}
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Ldif.OID)
        resp = u.Tests.assert_success(result)
        tm.that(len(resp.acls), eq=0)

    def test_extract_acls_from_entry_with_oud_aci_attribute(
        self, svc: FlextLdifAcl
    ) -> None:
        entry = m.Ldif.Entry(
            dn=c.Ldif.ACL_ENTRY_DN,
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"aci": [c.Ldif.ACL_ENTRY_ACI_VALUE]}
            }),
        )
        result = svc.extract_acls_from_entry(entry, c.Ldif.OUD)
        u.Tests.assert_success(result)

    # ── _build_acl_response ──────────────────────────────────────────────────

    def test_build_acl_response_with_failed_entries(self) -> None:
        response = FlextLdifAcl._build_acl_response(
            [],
            processed_entries=1,
            failed_entries=2,
        )
        tm.that(response.statistics.failed_entries, eq=2)

    # ── _is_schema_entry ─────────────────────────────────────────────────────

    def test_is_schema_entry_returns_false_for_regular_entry(self) -> None:
        entry = m.Ldif.Entry(
            dn=c.Ldif.ACL_ENTRY_DN,
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {"objectClass": ["person"]}
            }),
        )
        result = FlextLdifAcl._is_schema_entry(entry)
        tm.that(result, eq=False)
