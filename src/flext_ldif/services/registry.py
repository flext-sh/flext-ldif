"""Service Registry using FlextRegistry class-level plugin API.

Provides factory registration for services that would otherwise cause
circular imports. Uses class-level storage so all instances share
the same registered factories.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from flext_core import FlextResult as r, FlextTypes as t
from flext_core.protocols import p
from flext_core.registry import FlextRegistry

# Factory type aliases (using object since services cannot import protocols)
type FilterFactoryType = Callable[[], object]
type CategorizationFactoryType = Callable[[str], object]


class FlextLdifServiceRegistry(FlextRegistry):
    """Service registry using FlextRegistry class-level plugin API.

    Breaks circular dependencies between categorization and filter services
    by providing a central registry for factory functions. Uses class-level
    storage so all instances see the same registered factories.
    """

    FACTORIES: ClassVar[str] = "ldif_factories"

    def __init__(
        self, dispatcher: p.CommandBus | None = None, **data: t.GeneralValueType
    ) -> None:
        """Initialize with FlextRegistry infrastructure."""
        super().__init__(dispatcher=dispatcher, **data)

    # Factory registration using class-level plugin API

    def register_filter_factory(self, factory: FilterFactoryType) -> r[bool]:
        """Register factory function for filter service."""
        return self.register_class_plugin(self.FACTORIES, "filter", factory)

    def register_categorization_factory(
        self,
        factory: CategorizationFactoryType,
    ) -> r[bool]:
        """Register factory for categorization service."""
        return self.register_class_plugin(self.FACTORIES, "categorization", factory)

    # Service resolution using class-level plugin API

    def get_filter_service(self) -> r[object]:
        """Get filter service instance from registered factory."""
        factory_result = self.get_class_plugin(self.FACTORIES, "filter")
        if factory_result.is_failure:
            return r[object].fail(
                "Filter service factory not registered. Import flext_ldif.api first.",
            )
        factory_raw = factory_result.value
        if not callable(factory_raw):
            return r[object].fail("Filter factory is not callable")
        return r[object].ok(factory_raw())

    def get_categorization_service(self, server_type: str = "rfc") -> r[object]:
        """Get categorization service instance from registered factory."""
        factory_result = self.get_class_plugin(self.FACTORIES, "categorization")
        if factory_result.is_failure:
            return r[object].fail(
                "Categorization factory not registered. Import flext_ldif.api first.",
            )
        factory_raw = factory_result.value
        if not callable(factory_raw):
            return r[object].fail("Categorization factory is not callable")
        return r[object].ok(factory_raw(server_type))

    def is_initialized(self) -> bool:
        """Check if all factories are registered."""
        plugins = self.list_class_plugins(self.FACTORIES).value or []
        return "filter" in plugins and "categorization" in plugins

    def reset(self) -> None:
        """Reset registry (for testing only)."""
        self.unregister_class_plugin(self.FACTORIES, "filter")
        self.unregister_class_plugin(self.FACTORIES, "categorization")


# Global instance for backward compatibility
_global_registry: FlextLdifServiceRegistry | None = None


def get_registry() -> FlextLdifServiceRegistry:
    """Get or create global registry instance."""
    global _global_registry  # noqa: PLW0603
    if _global_registry is None:
        _global_registry = FlextLdifServiceRegistry()
    return _global_registry


def reset_registry() -> None:
    """Reset global registry (for testing)."""
    global _global_registry  # noqa: PLW0603
    if _global_registry is not None:
        _global_registry.reset()
    _global_registry = None


__all__ = [
    "FlextLdifServiceRegistry",
    "get_registry",
    "reset_registry",
]
