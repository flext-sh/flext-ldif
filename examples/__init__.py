# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""ldif Examples - Demonstrating LDIF processing capabilities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from examples import demo_structured_migration
    from examples.demo_structured_migration import main
    from flext_core import FlextTypes

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "demo_structured_migration": "examples.demo_structured_migration",
    "main": "examples.demo_structured_migration",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
