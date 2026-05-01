"""Data-driven unit tests for FlextLdifAnalysis service."""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifAnalysis, FlextLdifParser, FlextLdifValidation, m
from tests import c, u


def _make_entry(dn: str, attrs: dict[str, list[str]]) -> m.Ldif.Entry:
    return m.Ldif.Entry(
        dn=dn,
        attributes=m.Ldif.Attributes.model_validate({"attributes": attrs}),
    )


class TestsFlextLdifAnalysisService:
    """Cover FlextLdifAnalysis branches using flat constants."""

    @pytest.fixture
    def validation_svc(self) -> FlextLdifValidation:
        return FlextLdifValidation()

    # ── validate_entries – success path ─────────────────────────────────────

    def test_validate_entries_valid_entry_list(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        entry = _make_entry(
            c.Ldif.ANALYSIS_DN_VALID,
            dict(c.Ldif.ANALYSIS_VALID_ENTRY_ATTRS),
        )
        result = FlextLdifAnalysis.validate_entries([entry], validation_svc)
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=True)
        tm.that(val_result.total_entries, eq=1)
        tm.that(val_result.valid_entries, eq=1)

    def test_validate_entries_empty_list(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        result = FlextLdifAnalysis.validate_entries([], validation_svc)
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=0)
        tm.that(val_result.valid, eq=True)

    def test_validate_entries_parse_response_input(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        parser = FlextLdifParser()
        parse_result = parser.parse_ldif(c.Ldif.ANALYSIS_PARSE_RESPONSE_LDIF)
        parse_resp = u.Tests.assert_success(parse_result)
        result = FlextLdifAnalysis.validate_entries(parse_resp, validation_svc)
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=2)

    def test_validate_entries_invalid_attr_names(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        entry = _make_entry(
            c.Ldif.ANALYSIS_DN_VALID,
            dict(c.Ldif.ANALYSIS_INVALID_ATTR_ENTRY_ATTRS),
        )
        result = FlextLdifAnalysis.validate_entries([entry], validation_svc)
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.valid, eq=False)
        tm.that(val_result.invalid_entries, eq=1)

    # ── _validate_entry_dn ───────────────────────────────────────────────────

    def test_validate_entry_dn_none_returns_invalid(self) -> None:
        entry = m.Ldif.Entry(dn=None, attributes=m.Ldif.Attributes(attributes={}))
        valid, _dn_str, errors = FlextLdifAnalysis._validate_entry_dn(entry)
        tm.that(valid, eq=False)
        tm.that(len(errors), eq=1)

    def test_validate_entry_dn_valid(self) -> None:
        entry = _make_entry(
            c.Ldif.ANALYSIS_DN_VALID,
            {"objectClass": ["person"]},
        )
        valid, dn_str, errors = FlextLdifAnalysis._validate_entry_dn(entry)
        tm.that(valid, eq=True)
        tm.that(len(errors), eq=0)
        tm.that(dn_str, none=False)

    # ── _validate_entry_attributes ───────────────────────────────────────────

    def test_validate_entry_attributes_none_attrs_returns_invalid(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        entry = m.Ldif.Entry(dn=c.Ldif.ANALYSIS_DN_VALID, attributes=None)
        valid, errors = FlextLdifAnalysis._validate_entry_attributes(
            entry, c.Ldif.ANALYSIS_DN_VALID, validation_svc
        )
        tm.that(valid, eq=False)
        tm.that(len(errors), eq=1)

    def test_validate_entry_attributes_valid(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        entry = _make_entry(
            c.Ldif.ANALYSIS_DN_VALID,
            {"cn": [c.Ldif.ANALYSIS_ATTR_CN_VALUE]},
        )
        valid, errors = FlextLdifAnalysis._validate_entry_attributes(
            entry, c.Ldif.ANALYSIS_DN_VALID, validation_svc
        )
        tm.that(valid, eq=True)
        tm.that(len(errors), eq=0)

    # ── _validate_entry_objectclasses ────────────────────────────────────────

    def test_validate_entry_objectclasses_valid(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        entry = _make_entry(
            c.Ldif.ANALYSIS_DN_VALID,
            {"objectClass": [c.Ldif.ANALYSIS_OC_PERSON, "top"]},
        )
        valid, _err = FlextLdifAnalysis._validate_entry_objectclasses(
            entry, c.Ldif.ANALYSIS_DN_VALID, validation_svc
        )
        tm.that(valid, eq=True)

    def test_validate_entry_objectclasses_none_attrs(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        entry = m.Ldif.Entry(dn=c.Ldif.ANALYSIS_DN_VALID, attributes=None)
        valid, _errors = FlextLdifAnalysis._validate_entry_objectclasses(
            entry, c.Ldif.ANALYSIS_DN_VALID, validation_svc
        )
        tm.that(valid, eq=True)

    # ── multiple entries with mix of valid/invalid ───────────────────────────

    def test_validate_multiple_entries_mixed(
        self, validation_svc: FlextLdifValidation
    ) -> None:
        valid_entry = _make_entry(
            c.Ldif.ANALYSIS_DN_VALID,
            dict(c.Ldif.ANALYSIS_VALID_ENTRY_ATTRS),
        )
        invalid_entry = _make_entry(
            c.Ldif.ANALYSIS_DN_VALID,
            dict(c.Ldif.ANALYSIS_INVALID_ATTR_ENTRY_ATTRS),
        )
        result = FlextLdifAnalysis.validate_entries(
            [valid_entry, invalid_entry], validation_svc
        )
        val_result = u.Tests.assert_success(result)
        tm.that(val_result.total_entries, eq=2)
        tm.that(val_result.valid, eq=False)

    # ── parametrized valid OC names ──────────────────────────────────────────

    @pytest.mark.parametrize("oc_name", c.Ldif.VALIDATION_VALID_OC_NAMES)
    def test_valid_objectclass_names_pass_validation(
        self,
        oc_name: str,
        validation_svc: FlextLdifValidation,
    ) -> None:
        entry = _make_entry(
            c.Ldif.ANALYSIS_DN_VALID,
            {"objectClass": [oc_name]},
        )
        valid, _errs = FlextLdifAnalysis._validate_entry_objectclasses(
            entry, c.Ldif.ANALYSIS_DN_VALID, validation_svc
        )
        tm.that(valid, eq=True)
