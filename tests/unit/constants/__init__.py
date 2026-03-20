# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Constants package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from .test_acl_registry import (
        GetAclAttributesServerType,
        IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry,
    )

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "GetAclAttributesServerType": ("tests.unit.constants.test_acl_registry", "GetAclAttributesServerType"),
    "IsAclAttributeType": ("tests.unit.constants.test_acl_registry", "IsAclAttributeType"),
    "TestsTestFlextLdifAclAttributeRegistry": ("tests.unit.constants.test_acl_registry", "TestsTestFlextLdifAclAttributeRegistry"),
}

__all__ = [
    "GetAclAttributesServerType",
    "IsAclAttributeType",
    "TestsTestFlextLdifAclAttributeRegistry",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
