# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests for flext_ldif._utilities.parser module."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestFlextLdifUtilitiesParser": [
        "tests.unit._utilities.parser.test_parser_utilities",
        "TestFlextLdifUtilitiesParser",
    ],
    "test_parser_utilities": ["tests.unit._utilities.parser.test_parser_utilities", ""],
}

_EXPORTS: Sequence[str] = [
    "TestFlextLdifUtilitiesParser",
    "test_parser_utilities",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
