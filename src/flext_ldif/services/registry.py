"""Service Registry for breaking circular dependencies.

Provides factory registration and service resolution for services that
would otherwise cause circular imports. Factories are registered by
api.py after all services are loaded.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.protocols import FlextLdifProtocols


class FlextLdifServiceRegistry:
    """Service registry for factory functions.

    Breaks circular dependencies between categorization and filter services
    by providing a central registry for factory functions. The api.py facade
    registers factories after importing all services.

    Usage:
        # In api.py (after importing services):
        FlextLdifServiceRegistry.register_filter_factory(FlextLdifFilters)
        FlextLdifServiceRegistry.register_categorization_factory(...)

        # In services (instead of lazy imports):
        filter_service = FlextLdifServiceRegistry.get_filter_service()

    """

    # Factory function types
    type FilterFactoryType = Callable[
        [], FlextLdifProtocols.Services.FilterServiceProtocol
    ]
    type CategorizationFactoryType = Callable[
        [FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str],
        FlextLdifProtocols.Services.CategorizationServiceProtocol,
    ]

    # Private class-level storage for factories
    _filter_factory: FilterFactoryType | None = None
    _categorization_factory: CategorizationFactoryType | None = None

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

        Args:
            factory: Callable that returns FilterServiceProtocol instance

        """
        cls._filter_factory = factory

    @classmethod
    def register_categorization_factory(
        cls,
        factory: CategorizationFactoryType,
    ) -> None:
        """Register factory function for categorization service.

        Args:
            factory: Callable that accepts server_type and returns
                    CategorizationServiceProtocol instance

        """
        cls._categorization_factory = factory

    @classmethod
    def get_filter_service(
        cls,
    ) -> FlextLdifProtocols.Services.FilterServiceProtocol:
        """Get filter service instance from registered factory.

        Returns:
            FilterServiceProtocol instance

        Raises:
            RuntimeError: If factory not registered

        """
        if cls._filter_factory is None:
            raise RuntimeError(cls._FILTER_NOT_REGISTERED)
        return cls._filter_factory()

    @classmethod
    def get_categorization_service(
        cls,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str = "rfc",
    ) -> FlextLdifProtocols.Services.CategorizationServiceProtocol:
        """Get categorization service instance from registered factory.

        Args:
            server_type: LDAP server type for categorization rules

        Returns:
            CategorizationServiceProtocol instance

        Raises:
            RuntimeError: If factory not registered

        """
        if cls._categorization_factory is None:
            raise RuntimeError(cls._CATEGORIZATION_NOT_REGISTERED)
        return cls._categorization_factory(server_type)

    @classmethod
    def is_initialized(cls) -> bool:
        """Check if all factories are registered.

        Returns:
            True if both factories are registered

        """
        return (
            cls._filter_factory is not None and cls._categorization_factory is not None
        )

    @classmethod
    def reset(cls) -> None:
        """Reset registry (for testing only).

        Clears all registered factories.

        """
        cls._filter_factory = None
        cls._categorization_factory = None
