# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests for flext_ldif._utilities.server module."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit._utilities.server import test_server_utilities
    from tests.unit._utilities.server.test_server_utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "OidServer": "tests.unit._utilities.server.test_server_utilities",
    "OudServer": "tests.unit._utilities.server.test_server_utilities",
    "TestFlextLdifUtilitiesServer": "tests.unit._utilities.server.test_server_utilities",
    "test_server_utilities": "tests.unit._utilities.server.test_server_utilities",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
