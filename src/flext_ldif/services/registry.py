"""Service Registry using FlextRegistry class-level plugin API."""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from flext_core import FlextTypes as t
from flext_core.protocols import p
from flext_core.registry import FlextRegistry

type FilterFactoryType = Callable[[], t.GeneralValueType]
type CategorizationFactoryType = Callable[[str], t.GeneralValueType]


class FlextLdifServiceRegistry(FlextRegistry):
    """Service registry using FlextRegistry class-level plugin API."""

    FACTORIES: ClassVar[str] = "ldif_factories"
    _global_instance: ClassVar[FlextLdifServiceRegistry | None] = None

    def __init__(
        self, dispatcher: p.CommandBus | None = None, **data: t.GeneralValueType
    ) -> None:
        """Initialize with FlextRegistry infrastructure."""
        super().__init__(dispatcher=dispatcher, **data)

    def reset(self) -> None:
        """Reset registry (for testing only)."""
        _ = self.unregister_class_plugin(self.FACTORIES, "filter")
        _ = self.unregister_class_plugin(self.FACTORIES, "categorization")

    @classmethod
    def get_global(cls) -> FlextLdifServiceRegistry:
        """Get or create global registry instance."""
        if cls._global_instance is None:
            cls._global_instance = cls()
        return cls._global_instance

    @classmethod
    def reset_global(cls) -> None:
        """Reset global registry (for testing)."""
        if cls._global_instance is not None:
            cls._global_instance.reset()
        cls._global_instance = None


def get_registry() -> FlextLdifServiceRegistry:
    """Get or create global registry instance."""
    return FlextLdifServiceRegistry.get_global()


def reset_registry() -> None:
    """Reset global registry (for testing)."""
    FlextLdifServiceRegistry.reset_global()


__all__ = [
    "FlextLdifServiceRegistry",
    "get_registry",
    "reset_registry",
]
