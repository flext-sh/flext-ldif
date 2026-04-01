# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""ldif Examples - Demonstrating LDIF processing capabilities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from examples.demo_structured_migration import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "demo_structured_migration": "examples.demo_structured_migration",
    "main": "examples.demo_structured_migration",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
