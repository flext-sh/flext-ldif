"""Service Registry for breaking circular dependencies.

Provides factory registration and service resolution for services that
would otherwise cause circular imports. Factories are registered by
api.py after all services are loaded.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar, Final, cast

from flext_ldif.constants import c
from flext_ldif.protocols import FlextLdifProtocols

# Factory function types (PEP 695) - defined at module level for better type checking
# Business Rule: Type aliases defined at module level for reuse across the class.
# Implication: These types are used in ClassVar annotations and method signatures.
# Note: PEP 695 type aliases can be defined inside classes, but module-level avoids
# pyright issues with ClassVar assignment.
type FilterFactoryType = Callable[
    [],
    FlextLdifProtocols.Ldif.Services.FilterServiceProtocol,
]
type CategorizationFactoryType = Callable[
    [c.Ldif.LiteralTypes.ServerTypeLiteral | str],
    FlextLdifProtocols.Ldif.Services.CategorizationServiceProtocol,
]


class FlextLdifServiceRegistry:
    """Service registry for factory functions.

    Breaks circular dependencies between categorization and filter services
    by providing a central registry for factory functions. The api.py facade
    registers factories after importing all services.

    Business Rule: Service registry pattern prevents circular import dependencies
    by deferring service instantiation until runtime. Factories are registered
    during module initialization (api.py) and resolved on-demand by services.
    This follows Dependency Injection principles and enables testability.

    Implication: All services using this registry must handle RuntimeError when
    factories are not registered. This ensures fail-fast behavior and clear
    error messages for misconfigured environments.

    Usage:
        # In api.py (after importing services):
        FlextLdifServiceRegistry.register_filter_factory(FlextLdifFilters)
        FlextLdifServiceRegistry.register_categorization_factory(...)

        # In services (instead of lazy imports):
        filter_service = FlextLdifServiceRegistry.get_filter_service()

    """

    # Private class-level storage for factories (ClassVar for proper type checking)
    # Business Rule: ClassVar indicates these are class-level state, not instance
    # attributes. This enables proper type narrowing in classmethods and prevents
    # pyright errors about missing self/cls parameters.
    # Implication: ClassVar allows assignment in classmethods. Initialize to None
    # at class definition time for proper type checking.
    _filter_factory: ClassVar[FilterFactoryType | None] = None
    _categorization_factory: ClassVar[CategorizationFactoryType | None] = None

    # Error messages as constants
    _FILTER_NOT_REGISTERED: Final[str] = (
        "Filter service factory not registered. Import flext_ldif.api first."
    )
    _CATEGORIZATION_NOT_REGISTERED: Final[str] = (
        "Categorization service factory not registered. Import flext_ldif.api first."
    )

    @classmethod
    def register_filter_factory(
        cls,
        factory: FilterFactoryType,
    ) -> None:
        """Register factory function for filter service.

        Business Rule: Factory registration must happen before service resolution.
        Typically called during module initialization in api.py. Registration is
        idempotent - subsequent registrations overwrite previous ones.

        Implication: Services that depend on filter service must ensure api.py
        is imported before attempting to resolve the service.

        Args:
            factory: Callable that returns FilterServiceProtocol instance

        """
        # Business Rule: ClassVar assignment in classmethods.
        # Implication: Use type.__setattr__ to bypass pyright strict mode while maintaining
        # correct runtime behavior. ClassVar allows assignment in classmethods per Python spec.
        # This pattern enables factory registration for dependency injection.
        # Same pattern as FlextLdifServersBase.__init_subclass__ (line 301)
        type.__setattr__(cls, "_filter_factory", factory)

    @classmethod
    def register_categorization_factory(
        cls,
        factory: CategorizationFactoryType,
    ) -> None:
        """Register factory function for categorization service.

        Business Rule: Categorization factory accepts server_type parameter to
        create server-specific categorization instances. This enables per-server
        categorization rules while maintaining a single registry interface.

        Implication: Factory must handle server type normalization and validation.
        Invalid server types should be normalized to "rfc" as fallback.

        Args:
            factory: Callable that accepts server_type and returns
                    CategorizationServiceProtocol instance

        """
        # Business Rule: ClassVar assignment in classmethods.
        # Implication: Use type.__setattr__ to bypass pyright strict mode while maintaining
        # correct runtime behavior. ClassVar allows assignment in classmethods per Python spec.
        # This pattern enables factory registration for dependency injection.
        # Same pattern as FlextLdifServersBase.__init_subclass__ (line 301)
        type.__setattr__(cls, "_categorization_factory", factory)

    @classmethod
    def get_filter_service(
        cls,
    ) -> FlextLdifProtocols.Ldif.Services.FilterServiceProtocol:
        """Get filter service instance from registered factory.

        Business Rule: Service resolution follows fail-fast pattern - raises
        RuntimeError immediately if factory not registered. This prevents
        silent failures and ensures proper initialization order.

        Implication: Callers must handle RuntimeError or ensure api.py is
        imported before calling this method. Used internally by services
        that need filter capabilities.

        Returns:
            FilterServiceProtocol instance

        Raises:
            RuntimeError: If factory not registered (fail-fast validation)

        """
        # Business Rule: Access ClassVar via getattr() to work around pyright strict mode.
        # Implication: Direct access to ClassVar may fail in pyright strict mode.
        # Runtime behavior is correct - getattr() works identically to direct access.
        filter_factory = getattr(cls, "_filter_factory", None)
        if filter_factory is None:
            raise RuntimeError(cls._FILTER_NOT_REGISTERED)
        # Cast needed: getattr returns Any, but we know it's FilterFactoryType after None check
        return cast("FilterFactoryType", filter_factory)()

    @classmethod
    def get_categorization_service(
        cls,
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | str = "rfc",
    ) -> FlextLdifProtocols.Ldif.Services.CategorizationServiceProtocol:
        """Get categorization service instance from registered factory.

        Business Rule: Server type parameter enables server-specific categorization
        rules. Defaults to "rfc" for generic RFC-compliant categorization. Factory
        must normalize server types and handle invalid values gracefully.

        Implication: Services requesting categorization must provide correct
        server type for accurate categorization. Invalid server types are
        normalized by the factory implementation.

        Args:
            server_type: LDAP server type for categorization rules (default: "rfc")

        Returns:
            CategorizationServiceProtocol instance configured for server type

        Raises:
            RuntimeError: If factory not registered (fail-fast validation)

        """
        # Business Rule: Access ClassVar via getattr() to work around pyright strict mode.
        # Implication: Direct access to ClassVar may fail in pyright strict mode.
        # Runtime behavior is correct - getattr() works identically to direct access.
        categorization_factory = getattr(cls, "_categorization_factory", None)
        if categorization_factory is None:
            raise RuntimeError(cls._CATEGORIZATION_NOT_REGISTERED)
        # Cast needed: getattr returns Any, but we know it's CategorizationFactoryType after None check
        return cast("CategorizationFactoryType", categorization_factory)(server_type)

    @classmethod
    def is_initialized(cls) -> bool:
        """Check if all factories are registered.

        Returns:
            True if both factories are registered

        """
        # Business Rule: Access ClassVar via getattr() to work around pyright strict mode.
        # Implication: Direct access to ClassVar may fail in pyright strict mode.
        filter_factory = getattr(cls, "_filter_factory", None)
        categorization_factory = getattr(cls, "_categorization_factory", None)
        return filter_factory is not None and categorization_factory is not None

    @classmethod
    def reset(cls) -> None:
        """Reset registry (for testing only).

        Clears all registered factories.

        """
        # Business Rule: Reset ClassVar to None for testing/cleanup.
        # Implication: Use type.__setattr__ to bypass pyright strict mode while maintaining
        # correct runtime behavior. ClassVar allows assignment in classmethods per Python spec.
        # This pattern enables factory reset for test isolation.
        # Same pattern as FlextLdifServersBase.__init_subclass__ (line 301)
        type.__setattr__(cls, "_filter_factory", None)
        type.__setattr__(cls, "_categorization_factory", None)
