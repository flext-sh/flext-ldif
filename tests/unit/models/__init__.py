# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Models package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from tests.unit.models.test_models import (
        TestFlextLdifModels,
        TestFlextLdifModels as m,
    )

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestFlextLdifModels": ("tests.unit.models.test_models", "TestFlextLdifModels"),
    "m": ("tests.unit.models.test_models", "TestFlextLdifModels"),
}

__all__ = [
    "TestFlextLdifModels",
    "m",
]


def __getattr__(name: str) -> t.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
