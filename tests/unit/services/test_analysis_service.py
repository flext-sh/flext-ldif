"""Behavior tests for public LDIF analysis via the facade."""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests.constants import c
from tests.models import m
from tests.protocols import p
from tests.utilities import u


def _make_entry(dn: str | None, attrs: dict[str, list[str]] | None) -> m.Ldif.Entry:
    attributes = (
        None
        if attrs is None
        else m.Ldif.Attributes.model_validate({"attributes": attrs})
    )
    return m.Ldif.Entry(dn=dn, attributes=attributes)


class TestsFlextLdifAnalysisService:
    """Cover entry validation through the public ldif facade."""

    def test_validate_entries_valid_entry_list(self, api: p.Ldif.LdifClient) -> None:
        entry = _make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_VALID_ENTRY_ATTRS),
        )
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=True)
        tm.that(val_result.total_entries, eq=1)
        tm.that(val_result.valid_entries, eq=1)

    def test_validate_entries_empty_list(self, api: p.Ldif.LdifClient) -> None:
        result = api.validate_entries([])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=0)
        tm.that(val_result.valid, eq=True)

    def test_validate_entries_parse_response_input(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        parse_result = api.parse_ldif(c.Tests.ANALYSIS_PARSE_RESPONSE_LDIF)
        parse_resp = u.Tests.assert_success(parse_result)
        result = api.validate_entries(parse_resp)
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=2)

    def test_validate_entries_invalid_attr_names(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = _make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_INVALID_ATTR_ENTRY_ATTRS),
        )
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)

    def test_validate_entries_none_attributes_returns_invalid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = _make_entry(c.Tests.ANALYSIS_DN_VALID, None)
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)

    def test_validate_multiple_entries_mixed(self, api: p.Ldif.LdifClient) -> None:
        valid_entry = _make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_VALID_ENTRY_ATTRS),
        )
        invalid_entry = _make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_INVALID_ATTR_ENTRY_ATTRS),
        )
        result = api.validate_entries([valid_entry, invalid_entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=2)
        tm.that(val_result.valid, eq=False)

    @pytest.mark.parametrize("oc_name", c.Tests.VALIDATION_VALID_OC_NAMES)
    def test_valid_objectclass_names_pass_validation(
        self,
        oc_name: str,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = _make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            {"objectClass": [oc_name]},
        )
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=True)

    def test_validate_entries_empty_dn_returns_invalid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = _make_entry("", {"objectClass": ["person"]})
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)

    def test_validate_entries_invalid_oc_name_returns_invalid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = _make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            {"objectClass": [c.Tests.ANALYSIS_OC_INVALID]},
        )
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)

    def test_validate_entries_none_dn_returns_invalid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = _make_entry(None, {})
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)
