# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests for flext_ldif._utilities.oid module."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestFlextLdifUtilitiesOID": [
        "tests.unit._utilities.oid.test_oid_utilities",
        "TestFlextLdifUtilitiesOID",
    ],
    "test_oid_utilities": ["tests.unit._utilities.oid.test_oid_utilities", ""],
}

_EXPORTS: Sequence[str] = [
    "TestFlextLdifUtilitiesOID",
    "test_oid_utilities",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
