"""Behavior tests for public LDIF entry validation via the facade."""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c, m, p, u


class TestsFlextLdifAnalysisService:
    """Cover the observable contract of ``validate_entries`` via the ldif facade."""

    @staticmethod
    def _make_entry(
        dn: str | None,
        attrs: dict[str, list[str]] | None,
    ) -> m.Ldif.Entry:
        """Build a public ``m.Ldif.Entry`` for a validation case."""
        attributes = (
            None
            if attrs is None
            else m.Ldif.Attributes.model_validate({"attributes": attrs})
        )
        dn_model = m.Ldif.DN(value=dn) if dn is not None else None
        return m.Ldif.Entry(dn=dn_model, attributes=attributes)

    def test_validate_entries_valid_entry_reports_all_valid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = self._make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_VALID_ENTRY_ATTRS),
        )
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=True)
        tm.that(val_result.total_entries, eq=1)
        tm.that(val_result.valid_entries, eq=1)
        tm.that(val_result.invalid_entries, eq=0)
        tm.that(len(val_result.errors), eq=0)

    def test_validate_entries_empty_list_is_vacuously_valid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.validate_entries([])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=0)
        tm.that(val_result.valid_entries, eq=0)
        tm.that(val_result.invalid_entries, eq=0)
        tm.that(val_result.valid, eq=True)

    def test_validate_entries_accepts_parse_response_input(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        parse_result = api.parse_ldif(c.Tests.ANALYSIS_PARSE_RESPONSE_LDIF)
        parse_resp = u.Tests.assert_success(parse_result)
        result = api.validate_entries(parse_resp)
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=2)
        tm.that(val_result.valid_entries, eq=2)
        tm.that(val_result.valid, eq=True)

    def test_validate_entries_invalid_attr_name_reports_error(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = self._make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_INVALID_ATTR_ENTRY_ATTRS),
        )
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)
        tm.that(val_result.valid_entries, eq=0)
        tm.that(len(val_result.errors) > 0, eq=True)

    def test_validate_entries_none_attributes_reports_invalid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = self._make_entry(c.Tests.ANALYSIS_DN_VALID, None)
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)
        tm.that(len(val_result.errors) > 0, eq=True)

    def test_validate_entries_mixed_batch_counts_each_side(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        valid_entry = self._make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_VALID_ENTRY_ATTRS),
        )
        invalid_entry = self._make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_INVALID_ATTR_ENTRY_ATTRS),
        )
        result = api.validate_entries([valid_entry, invalid_entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=2)
        tm.that(val_result.valid_entries, eq=1)
        tm.that(val_result.invalid_entries, eq=1)
        tm.that(val_result.valid, eq=False)

    def test_validate_entries_order_independent_for_mixed_batch(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        valid_entry = self._make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_VALID_ENTRY_ATTRS),
        )
        invalid_entry = self._make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            dict(c.Tests.ANALYSIS_INVALID_ATTR_ENTRY_ATTRS),
        )
        forward = u.Tests.assert_success(
            api.validate_entries([valid_entry, invalid_entry]),
        )
        reverse = u.Tests.assert_success(
            api.validate_entries([invalid_entry, valid_entry]),
        )
        tm.that(forward.valid, eq=reverse.valid)
        tm.that(forward.total_entries, eq=reverse.total_entries)
        tm.that(forward.valid_entries, eq=reverse.valid_entries)
        tm.that(forward.invalid_entries, eq=reverse.invalid_entries)

    @pytest.mark.parametrize("oc_name", c.Tests.VALIDATION_VALID_OC_NAMES)
    def test_valid_objectclass_names_pass_validation(
        self,
        oc_name: str,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = self._make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            {"objectClass": [oc_name]},
        )
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=True)
        tm.that(val_result.valid_entries, eq=1)

    def test_validate_entries_empty_dn_reports_invalid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = self._make_entry("", {"objectClass": ["person"]})
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)
        tm.that(len(val_result.errors) > 0, eq=True)

    def test_validate_entries_invalid_objectclass_name_reports_invalid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = self._make_entry(
            c.Tests.ANALYSIS_DN_VALID,
            {"objectClass": [c.Tests.ANALYSIS_OC_INVALID]},
        )
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)
        tm.that(len(val_result.errors) > 0, eq=True)

    def test_validate_entries_none_dn_reports_invalid(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = self._make_entry(None, {})
        result = api.validate_entries([entry])
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)
        tm.that(len(val_result.errors) > 0, eq=True)
