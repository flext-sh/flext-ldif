"""Service Registry using FlextRegistry class-level plugin API."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, ClassVar

from flext_core import FlextRegistry, p

if TYPE_CHECKING:
    from flext_ldif.typings import FlextLdifTypes as t

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
        _ = self.unregister_plugin(self.FACTORIES, "filter", scope="class")
        _ = self.unregister_plugin(self.FACTORIES, "categorization", scope="class")


__all__ = ["FlextLdifServiceRegistry"]
