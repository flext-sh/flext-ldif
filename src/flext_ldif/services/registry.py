"""Service Registry using FlextRegistry class-level plugin API."""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from flext_core import FlextRegistry, p

from flext_ldif import t

type FilterFactoryType = Callable[[], t.ContainerValue]
type CategorizationFactoryType = Callable[[str], t.ContainerValue]


class FlextLdifServiceRegistry(FlextRegistry):
    """Service registry using FlextRegistry class-level plugin API."""

    FACTORIES: ClassVar[str] = "ldif_factories"
    _global_instance: ClassVar[FlextLdifServiceRegistry | None] = None

    def __init__(
        self, dispatcher: p.CommandBus | None = None, **data: t.ContainerValue
    ) -> None:
        """Initialize with FlextRegistry infrastructure."""
        _ = data
        super().__init__(dispatcher=dispatcher)

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

    def reset(self) -> None:
        """Reset registry (for testing only)."""
        _ = self.unregister_class_plugin(self.FACTORIES, "filter")
        _ = self.unregister_class_plugin(self.FACTORIES, "categorization")


__all__ = ["FlextLdifServiceRegistry"]
