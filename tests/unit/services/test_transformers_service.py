"""Behavior tests for service transformers."""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import FlextLdifTransformer, m
from tests import c, u


class TestsFlextLdifTransformerService:
    """Cover transformer normalization and failure guard branches."""

    def test_normalize_server_type_with_enum_returns_same_enum(self) -> None:
        result = FlextLdifTransformer._normalize_server_type(c.Ldif.ServerTypes.RFC)
        tm.that(result, eq=c.Ldif.ServerTypes.RFC)

    def test_apply_with_entry_returns_success(self) -> None:
        transformer = FlextLdifTransformer(
            source_server=c.Tests.RFC,
            target_server=c.Tests.RFC,
        )
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ANALYSIS_DN_VALID,
            attributes={"cn": ["valid"]},
        )

        result = transformer.apply(entry)
        converted = u.Tests.assert_success(result)

        tm.that(converted.dn, is_=m.Ldif.DN)
        tm.that(
            (converted.dn.value if converted.dn is not None else ""),
            eq=c.Tests.ANALYSIS_DN_VALID,
        )
