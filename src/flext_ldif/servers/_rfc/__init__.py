# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""RFC 4512 Compliant Server Classes for LDIF/LDAP processing."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_ldif.servers._rfc import acl, constants, entry, schema
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants, c
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema, logger

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifServersRfcAcl": ["flext_ldif.servers._rfc.acl", "FlextLdifServersRfcAcl"],
    "FlextLdifServersRfcConstants": [
        "flext_ldif.servers._rfc.constants",
        "FlextLdifServersRfcConstants",
    ],
    "FlextLdifServersRfcEntry": [
        "flext_ldif.servers._rfc.entry",
        "FlextLdifServersRfcEntry",
    ],
    "FlextLdifServersRfcSchema": [
        "flext_ldif.servers._rfc.schema",
        "FlextLdifServersRfcSchema",
    ],
    "acl": ["flext_ldif.servers._rfc.acl", ""],
    "c": ["flext_ldif.servers._rfc.constants", "c"],
    "constants": ["flext_ldif.servers._rfc.constants", ""],
    "entry": ["flext_ldif.servers._rfc.entry", ""],
    "logger": ["flext_ldif.servers._rfc.schema", "logger"],
    "schema": ["flext_ldif.servers._rfc.schema", ""],
}

__all__ = [
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "acl",
    "c",
    "constants",
    "entry",
    "logger",
    "schema",
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
