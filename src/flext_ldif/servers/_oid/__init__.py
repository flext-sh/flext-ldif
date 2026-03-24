# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""OID (Oracle Internet Directory) Server Classes."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants, c
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema, logger

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifServersOidAcl": ["flext_ldif.servers._oid.acl", "FlextLdifServersOidAcl"],
    "FlextLdifServersOidConstants": ["flext_ldif.servers._oid.constants", "FlextLdifServersOidConstants"],
    "FlextLdifServersOidEntry": ["flext_ldif.servers._oid.entry", "FlextLdifServersOidEntry"],
    "FlextLdifServersOidSchema": ["flext_ldif.servers._oid.schema", "FlextLdifServersOidSchema"],
    "c": ["flext_ldif.servers._oid.constants", "c"],
    "logger": ["flext_ldif.servers._oid.schema", "logger"],
}

__all__ = [
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "c",
    "logger",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
