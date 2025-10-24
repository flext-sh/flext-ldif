"""Comprehensive Container Tests for FLEXT LDIF Dependency Injection.

Tests the FlextLdifContainer dependency injection container:
- Service provider registration and configuration
- Singleton vs Factory provider semantics
- Container lifecycle (initialization, shutdown)
- Global container access
- Service dependency resolution

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifConfig
from flext_ldif.acl.parser import FlextLdifAclParser
from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.client import FlextLdifClient
from flext_ldif.containers import FlextLdifContainer, flext_ldif_container
from flext_ldif.entry.builder import FlextLdifEntryBuilder
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.schema.builder import FlextLdifSchemaBuilder
from flext_ldif.schema.validator import FlextLdifSchemaValidator


class TestContainerConfigProvider:
    """Test configuration provider in container."""

    def test_config_provider_exists(self) -> None:
        """Test that config provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "config")
        assert container.config is not None

    def test_config_provider_returns_config(self) -> None:
        """Test that config provider returns FlextLdifConfig instance."""
        container = FlextLdifContainer()
        config = container.config()
        assert isinstance(config, FlextLdifConfig)

    def test_config_provider_is_singleton(self) -> None:
        """Test that config provider uses singleton pattern."""
        container = FlextLdifContainer()
        config1 = container.config()
        config2 = container.config()
        assert config1 is config2  # Same instance


class TestContainerClientProvider:
    """Test client provider in container."""

    def test_client_provider_exists(self) -> None:
        """Test that client provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "client")
        assert container.client is not None

    def test_client_provider_returns_client(self) -> None:
        """Test that client provider returns FlextLdifClient instance."""
        container = FlextLdifContainer()
        client = container.client()
        assert isinstance(client, FlextLdifClient)

    def test_client_provider_is_factory(self) -> None:
        """Test that client provider uses factory pattern."""
        container = FlextLdifContainer()
        client1 = container.client()
        client2 = container.client()
        assert client1 is not client2  # Different instances


class TestContainerBuilderProviders:
    """Test builder providers in container."""

    def test_entry_builder_provider_exists(self) -> None:
        """Test that entry builder provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "entry_builder")

    def test_entry_builder_returns_instance(self) -> None:
        """Test that entry builder provider returns instance."""
        container = FlextLdifContainer()
        builder = container.entry_builder()
        assert isinstance(builder, FlextLdifEntryBuilder)

    def test_entry_builder_is_singleton(self) -> None:
        """Test that entry builder uses singleton pattern."""
        container = FlextLdifContainer()
        builder1 = container.entry_builder()
        builder2 = container.entry_builder()
        assert builder1 is builder2

    def test_schema_builder_provider_exists(self) -> None:
        """Test that schema builder provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "schema_builder")

    def test_schema_builder_returns_instance(self) -> None:
        """Test that schema builder provider returns instance."""
        container = FlextLdifContainer()
        builder = container.schema_builder()
        assert isinstance(builder, FlextLdifSchemaBuilder)

    def test_schema_builder_is_singleton(self) -> None:
        """Test that schema builder uses singleton pattern."""
        container = FlextLdifContainer()
        builder1 = container.schema_builder()
        builder2 = container.schema_builder()
        assert builder1 is builder2


class TestContainerValidatorProviders:
    """Test validator providers in container."""

    def test_schema_validator_provider_exists(self) -> None:
        """Test that schema validator provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "schema_validator")

    def test_schema_validator_returns_instance(self) -> None:
        """Test that schema validator provider returns instance."""
        container = FlextLdifContainer()
        validator = container.schema_validator()
        assert isinstance(validator, FlextLdifSchemaValidator)

    def test_schema_validator_is_factory(self) -> None:
        """Test that schema validator uses factory pattern."""
        container = FlextLdifContainer()
        validator1 = container.schema_validator()
        validator2 = container.schema_validator()
        assert validator1 is not validator2


class TestContainerAclProviders:
    """Test ACL providers in container."""

    def test_acl_parser_provider_exists(self) -> None:
        """Test that ACL parser provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "acl_parser")

    def test_acl_parser_returns_instance(self) -> None:
        """Test that ACL parser provider returns instance."""
        container = FlextLdifContainer()
        parser = container.acl_parser()
        assert isinstance(parser, FlextLdifAclParser)

    def test_acl_parser_is_singleton(self) -> None:
        """Test that ACL parser uses singleton pattern."""
        container = FlextLdifContainer()
        parser1 = container.acl_parser()
        parser2 = container.acl_parser()
        assert parser1 is parser2

    def test_acl_service_provider_exists(self) -> None:
        """Test that ACL service provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "acl_service")

    def test_acl_service_returns_instance(self) -> None:
        """Test that ACL service provider returns instance."""
        container = FlextLdifContainer()
        service = container.acl_service()
        assert isinstance(service, FlextLdifAclService)

    def test_acl_service_is_singleton(self) -> None:
        """Test that ACL service uses singleton pattern."""
        container = FlextLdifContainer()
        service1 = container.acl_service()
        service2 = container.acl_service()
        assert service1 is service2


class TestContainerQuirksProviders:
    """Test quirks providers in container."""

    def test_quirks_registry_provider_exists(self) -> None:
        """Test that quirks registry provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "quirks_registry")

    def test_quirks_registry_returns_instance(self) -> None:
        """Test that quirks registry provider returns instance."""
        container = FlextLdifContainer()
        registry = container.quirks_registry()
        assert isinstance(registry, FlextLdifQuirksRegistry)

    def test_quirks_registry_is_singleton(self) -> None:
        """Test that quirks registry uses singleton pattern."""
        container = FlextLdifContainer()
        registry1 = container.quirks_registry()
        registry2 = container.quirks_registry()
        assert registry1 is registry2

    def test_quirks_manager_provider_exists(self) -> None:
        """Test that quirks manager provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "quirks_manager")

    def test_quirks_manager_returns_instance(self) -> None:
        """Test that quirks manager provider returns instance."""
        container = FlextLdifContainer()
        manager = container.quirks_manager()
        assert isinstance(manager, FlextLdifQuirksManager)

    def test_quirks_manager_is_factory(self) -> None:
        """Test that quirks manager uses factory pattern."""
        container = FlextLdifContainer()
        manager1 = container.quirks_manager()
        manager2 = container.quirks_manager()
        assert manager1 is not manager2


class TestContainerMigrationProviders:
    """Test migration providers in container."""

    def test_migration_pipeline_provider_exists(self) -> None:
        """Test that migration pipeline provider is registered."""
        container = FlextLdifContainer()
        assert hasattr(container, "migration_pipeline")
        assert container.migration_pipeline is not None


class TestContainerServiceDiscovery:
    """Test service discovery in container."""

    def test_container_has_all_expected_providers(self) -> None:
        """Test that container has all expected service providers."""
        container = FlextLdifContainer()

        # Verify all expected services are accessible
        expected_services = [
            "config",
            "client",
            "entry_builder",
            "schema_builder",
            "schema_validator",
            "acl_parser",
            "acl_service",
            "quirks_registry",
            "quirks_manager",
            "migration_pipeline",
        ]

        for service_name in expected_services:
            assert hasattr(container, service_name), f"Container missing {service_name}"

    def test_container_service_count(self) -> None:
        """Test that container has expected number of services."""
        container = FlextLdifContainer()
        provider_attrs = [
            attr
            for attr in dir(container)
            if not attr.startswith("_") and callable(getattr(container, attr))
        ]
        # Should have at least 10 service providers
        assert len(provider_attrs) >= 10


class TestContainerInitialization:
    """Test container initialization."""

    def test_container_provides_config_on_initialization(self) -> None:
        """Test that container provides config after initialization."""
        container = FlextLdifContainer()

        # Verify config is accessible
        config = container.config()
        assert isinstance(config, FlextLdifConfig)

    def test_container_singleton_instances(self) -> None:
        """Test that singleton providers return same instance."""
        container = FlextLdifContainer()

        # Entry builder should be singleton
        builder1 = container.entry_builder()
        builder2 = container.entry_builder()
        assert builder1 is builder2

    def test_container_factory_instances(self) -> None:
        """Test that factory providers create new instances."""
        container = FlextLdifContainer()

        # Client should be factory
        client1 = container.client()
        client2 = container.client()
        assert client1 is not client2


class TestContainerMultipleInstances:
    """Test multiple container instances."""

    def test_separate_containers_provide_same_services(self) -> None:
        """Test that separate container instances provide same service types."""
        container1 = FlextLdifContainer()
        container2 = FlextLdifContainer()

        # Both containers should provide the same service types
        registry1 = container1.quirks_registry()
        registry2 = container2.quirks_registry()

        # Both should be instances of the same type
        assert isinstance(registry1, FlextLdifQuirksRegistry)
        assert isinstance(registry2, FlextLdifQuirksRegistry)

    def test_container_idempotent_provider_calls(self) -> None:
        """Test that provider calls are consistent."""
        container = FlextLdifContainer()

        # Multiple calls to singleton should return same instance
        builder1 = container.entry_builder()
        builder2 = container.entry_builder()
        builder3 = container.entry_builder()

        assert builder1 is builder2
        assert builder2 is builder3


class TestGlobalContainer:
    """Test global container functionality."""

    def test_global_container_is_accessible(self) -> None:
        """Test that global container is accessible."""
        assert flext_ldif_container is not None

    def test_global_container_provides_services(self) -> None:
        """Test that global container provides services."""
        # Verify global container can provide config
        config = flext_ldif_container.config()
        assert isinstance(config, FlextLdifConfig)

    def test_global_container_consistent(self) -> None:
        """Test that global container is consistent."""
        # Get config twice from global container
        config1 = flext_ldif_container.config()
        config2 = flext_ldif_container.config()

        # Should be same singleton instance
        assert config1 is config2


class TestGlobalContainerServices:
    """Test services from global container."""

    def test_global_container_provides_all_services(self) -> None:
        """Test that global container can provide all services."""
        config = flext_ldif_container.config()
        assert isinstance(config, FlextLdifConfig)

        client = flext_ldif_container.client()
        assert isinstance(client, FlextLdifClient)

        registry = flext_ldif_container.quirks_registry()
        assert isinstance(registry, FlextLdifQuirksRegistry)

        builder = flext_ldif_container.entry_builder()
        assert isinstance(builder, FlextLdifEntryBuilder)

    def test_global_container_services_are_accessible(self) -> None:
        """Test that all services are accessible from global container."""
        services_to_check = [
            ("config", FlextLdifConfig),
            ("client", FlextLdifClient),
            ("entry_builder", FlextLdifEntryBuilder),
            ("schema_builder", FlextLdifSchemaBuilder),
            ("schema_validator", FlextLdifSchemaValidator),
            ("acl_parser", FlextLdifAclParser),
            ("acl_service", FlextLdifAclService),
            ("quirks_registry", FlextLdifQuirksRegistry),
        ]

        for service_name, expected_type in services_to_check:
            assert hasattr(
                flext_ldif_container, service_name
            ), f"Global container missing {service_name}"
            service = getattr(flext_ldif_container, service_name)()
            assert isinstance(service, expected_type)


class TestContainerDependencyInjection:
    """Test dependency injection behavior of container."""

    def test_client_is_properly_initialized(self) -> None:
        """Test that client is properly initialized from container."""
        container = FlextLdifContainer()
        client = container.client()

        # Client should be instance of FlextLdifClient
        assert isinstance(client, FlextLdifClient)

    def test_quirks_manager_is_properly_initialized(self) -> None:
        """Test that quirks manager is properly initialized."""
        container = FlextLdifContainer()
        manager = container.quirks_manager()

        # Manager should be instance of FlextLdifQuirksManager
        assert isinstance(manager, FlextLdifQuirksManager)

    def test_entry_builder_is_properly_initialized(self) -> None:
        """Test that entry builder is properly initialized."""
        container = FlextLdifContainer()
        builder = container.entry_builder()

        # Builder should be instance of FlextLdifEntryBuilder
        assert isinstance(builder, FlextLdifEntryBuilder)


__all__ = [
    "TestContainerAclProviders",
    "TestContainerBuilderProviders",
    "TestContainerClientProvider",
    "TestContainerConfigProvider",
    "TestContainerDependencyInjection",
    "TestContainerInitialization",
    "TestContainerMigrationProviders",
    "TestContainerMultipleInstances",
    "TestContainerQuirksProviders",
    "TestContainerServiceDiscovery",
    "TestContainerValidatorProviders",
    "TestGlobalContainer",
    "TestGlobalContainerServices",
]
