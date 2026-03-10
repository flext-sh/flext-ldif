"""OUD (Oracle Unified Directory) Server Classes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdifServersOudAcl": ("flext_ldif.servers._oud.acl", "FlextLdifServersOudAcl"),
    "FlextLdifServersOudConstants": (
        "flext_ldif.servers._oud.constants",
        "FlextLdifServersOudConstants",
    ),
    "FlextLdifServersOudEntry": (
        "flext_ldif.servers._oud.entry",
        "FlextLdifServersOudEntry",
    ),
    "FlextLdifServersOudSchema": (
        "flext_ldif.servers._oud.schema",
        "FlextLdifServersOudSchema",
    ),
}

__all__ = [
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudSchema",
]


def __getattr__(
    name: str,
) -> Any:  # JUSTIFIED: Ruff (any-type) with PEP 562 dynamic module exports — https://docs.astral.sh/ruff/rules/any-type/
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
