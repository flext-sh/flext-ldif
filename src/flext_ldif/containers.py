"""FLEXT LDIF Dependency Injection Container.

Provides centralized dependency injection for all flext-ldif components.
Uses dependency_injector for type-safe service registration and resolution.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Any

from dependency_injector import containers, providers

from flext_ldif.acl.parser import FlextLdifAclParser
from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.client import FlextLdifClient
from flext_ldif.config import FlextLdifConfig
from flext_ldif.entry.builder import FlextLdifEntryBuilder
from flext_ldif.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.schema.builder import FlextLdifSchemaBuilder
from flext_ldif.schema.validator import FlextLdifSchemaValidator


class FlextLdifContainer(containers.DeclarativeContainer):
    """Centralized dependency injection container for flext-ldif.

    Provides type-safe service registration and resolution for all
    flext-ldif components using dependency_injector patterns.

    This container follows the global container pattern from flext-core,
    providing singleton instances of core services and factories for
    request-scoped components.
    """

    # =========================================================================
    # CONFIGURATION PROVIDERS
    # =========================================================================

    # Configuration provider - uses singleton for shared config
    config = providers.Singleton(FlextLdifConfig)

    # =========================================================================
    # CORE SERVICE PROVIDERS
    # =========================================================================

    # Client provider - factory for configurable client instances
    client = providers.Factory(
        FlextLdifClient,
        config=config,
    )

    # =========================================================================
    # BUILDER PROVIDERS
    # =========================================================================

    # Entry builder - singleton for shared instance
    entry_builder = providers.Singleton(FlextLdifEntryBuilder)

    # Schema builder - singleton for shared instance
    schema_builder = providers.Singleton(FlextLdifSchemaBuilder)

    # =========================================================================
    # VALIDATOR PROVIDERS
    # =========================================================================

    # Schema validator - factory for configurable instances
    schema_validator = providers.Factory(FlextLdifSchemaValidator)

    # =========================================================================
    # ACL PROVIDERS
    # =========================================================================

    # ACL parser - singleton for shared instance
    acl_parser = providers.Singleton(FlextLdifAclParser)

    # ACL service - singleton for shared instance
    acl_service = providers.Singleton(FlextLdifAclService)

    # =========================================================================
    # QUIRKS PROVIDERS
    # =========================================================================

    # Quirks registry - singleton for shared registry
    quirks_registry = providers.Singleton(FlextLdifQuirksRegistry)

    # Quirks manager - factory for configurable instances
    quirks_manager = providers.Factory(
        FlextLdifQuirksManager,
        config=config,
    )

    # =========================================================================
    # MIGRATION PROVIDERS
    # =========================================================================

    # Migration pipeline - factory for configurable instances
    migration_pipeline = providers.Factory(
        FlextLdifMigrationPipeline,
        config=config,
    )

    # =========================================================================
    # CONTAINER LIFECYCLE METHODS
    # =========================================================================

    def get_service_providers(self) -> dict[str, providers.Provider[Any]]:
        """Get all service providers for inspection.

        Returns:
            Dictionary mapping service names to provider instances.

        """
        # All provider attributes are already providers.Provider instances
        # Type annotations ensure correctness without needing cast()
        # Note: Specific provider types (Singleton/Factory) are subtypes of Provider
        return {
            "config": self.config,
            "client": self.client,
            "entry_builder": self.entry_builder,
            "schema_builder": self.schema_builder,
            "schema_validator": self.schema_validator,
            "acl_parser": self.acl_parser,
            "acl_service": self.acl_service,
            "quirks_registry": self.quirks_registry,
            "quirks_manager": self.quirks_manager,
            "migration_pipeline": self.migration_pipeline,
        }

    def initialize_services(self) -> None:
        """Initialize all singleton services.

        Call this method to ensure all singleton services are created
        and properly initialized before use.
        """
        # Force initialization of singleton services
        _ = self.entry_builder()
        _ = self.schema_builder()
        _ = self.acl_parser()
        _ = self.acl_service()
        _ = self.quirks_registry()

    def shutdown_services(self) -> None:
        """Shutdown all services and clean up resources.

        Call this method during application shutdown to ensure
        proper cleanup of all services.
        """
        # Override providers to None to force recreation
        self.entry_builder.override(None)
        self.schema_builder.override(None)
        self.acl_parser.override(None)
        self.acl_service.override(None)
        self.quirks_registry.override(None)

    @classmethod
    def get_global_container(cls) -> FlextLdifContainer:
        """Get the global flext-ldif container instance.

        Returns:
            Global FlextLdifContainer instance.

        """
        return flext_ldif_container


# Global container instance
flext_ldif_container = FlextLdifContainer()


__all__ = [
    "FlextLdifContainer",
    "flext_ldif_container",
]
