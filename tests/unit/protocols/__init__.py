# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Protocols package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from tests.unit.protocols import test_protocols
    from tests.unit.protocols.test_protocols import TestsTestFlextLdifProtocols

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "TestsTestFlextLdifProtocols": "tests.unit.protocols.test_protocols",
    "test_protocols": "tests.unit.protocols.test_protocols",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
