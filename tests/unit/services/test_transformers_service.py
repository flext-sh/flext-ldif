"""Behavior tests for service transformers."""

from __future__ import annotations

from flext_tests import tm

from tests import c, m, p, u


class TestsFlextLdifTransformerService:
    """Cover public model conversion through the ldif facade."""

    def test_convert_model_with_entry_returns_success(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ANALYSIS_DN_VALID,
            attributes={"cn": ["valid"]},
        )

        result = api.convert_model(c.Tests.RFC, c.Tests.RFC, entry)
        converted = u.Tests.assert_success(result)

        tm.that(isinstance(converted, m.Ldif.Entry), eq=True)
        if not isinstance(converted, m.Ldif.Entry):
            msg = "Expected convert_model to return an Entry"
            raise AssertionError(msg)

        tm.that(converted.dn, is_=m.Ldif.DN)
        tm.that(
            (converted.dn.value if converted.dn is not None else ""),
            eq=c.Tests.ANALYSIS_DN_VALID,
        )
