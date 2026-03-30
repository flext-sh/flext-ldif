# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests for flext_ldif._utilities.server module."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "OidServer": ["tests.unit._utilities.server.test_server_utilities", "OidServer"],
    "OudServer": ["tests.unit._utilities.server.test_server_utilities", "OudServer"],
    "TestFlextLdifUtilitiesServer": [
        "tests.unit._utilities.server.test_server_utilities",
        "TestFlextLdifUtilitiesServer",
    ],
    "test_server_utilities": ["tests.unit._utilities.server.test_server_utilities", ""],
}

_EXPORTS: Sequence[str] = [
    "OidServer",
    "OudServer",
    "TestFlextLdifUtilitiesServer",
    "test_server_utilities",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
