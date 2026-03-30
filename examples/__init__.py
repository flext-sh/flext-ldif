# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""ldif Examples - Demonstrating LDIF processing capabilities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from examples import demo_structured_migration as demo_structured_migration
    from examples.demo_structured_migration import main as main

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "demo_structured_migration": ["examples.demo_structured_migration", ""],
    "main": ["examples.demo_structured_migration", "main"],
}

_EXPORTS: Sequence[str] = [
    "demo_structured_migration",
    "main",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
