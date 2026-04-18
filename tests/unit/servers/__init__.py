# AUTO-GENERATED FILE — Regenerate with: make gen
"""Servers package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_apache_quirks": ("TestsTestFlextLdifApacheQuirks",),
        ".test_ds389_quirks": ("TestsTestFlextLdifDs389Quirks",),
        ".test_edge_cases": ("TestsFlextLdifEdgeCases",),
        ".test_novell_quirks": (
            "TestNovellAcls",
            "TestNovellEntryDetection",
            "TestNovellSchemaAttributeDetection",
            "TestNovellSchemaAttributeParsing",
            "TestNovellSchemaObjectClassDetection",
            "TestNovellSchemaObjectClassParsing",
            "TestsFlextLdifNovellInitialization",
        ),
        ".test_oid_quirks": ("TestsTestFlextLdifOidQuirks",),
        ".test_relaxed_quirks": ("TestsTestFlextLdifRelaxedQuirks",),
        ".test_schema_transformer": (
            "TestSchemaTransformerNormalizeMatchingRule",
            "TestSchemaTransformerNormalizeSyntaxOid",
            "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
