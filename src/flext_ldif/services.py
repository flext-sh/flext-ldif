"""FLEXT LDIF Services - Service container for accessing individual LDIF services.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.analytics_service import FlextLdifAnalyticsService
from flext_ldif.config import FlextLdifConfig
from flext_ldif.parser_service import FlextLdifParserService
from flext_ldif.repository_service import FlextLdifRepositoryService
from flext_ldif.transformer_service import FlextLdifTransformerService
from flext_ldif.validator_service import FlextLdifValidatorService
from flext_ldif.writer_service import FlextLdifWriterService


class FlextLdifServices(FlextDomainService[dict[str, object]]):
    """Service container providing access to all FLEXT-LDIF services.

    This class follows the FLEXT ecosystem pattern of providing a unified
    service container that manages service instances and their lifecycles.

    All services use the same configuration instance and are lazily initialized
    for optimal resource usage.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize service container with optional configuration.

        Args:
            config: Optional configuration instance. If None, uses global config.

        """
        super().__init__()
        self._logger = FlextLogger(__name__)

        # Configuration management
        if config is None:
            try:
                self._config = FlextLdifConfig.get_global_ldif_config()
            except RuntimeError:
                self._config = FlextLdifConfig()
        else:
            self._config = config

        # Service instances (lazy initialization)
        self._parser: FlextLdifParserService | None = None
        self._validator: FlextLdifValidatorService | None = None
        self._writer: FlextLdifWriterService | None = None
        self._repository: FlextLdifRepositoryService | None = None
        self._transformer: FlextLdifTransformerService | None = None
        self._analytics: FlextLdifAnalyticsService | None = None

        self._logger.debug("FlextLdifServices container initialized")

    @property
    def parser(self) -> FlextLdifParserService:
        """Get parser service instance (lazy initialization)."""
        if self._parser is None:
            self._parser = FlextLdifParserService()
            self._logger.debug("Parser service initialized")
        return self._parser

    @property
    def validator(self) -> FlextLdifValidatorService:
        """Get validator service instance (lazy initialization)."""
        if self._validator is None:
            self._validator = FlextLdifValidatorService(config=self._config)
            self._logger.debug("Validator service initialized")
        return self._validator

    @property
    def writer(self) -> FlextLdifWriterService:
        """Get writer service instance (lazy initialization)."""
        if self._writer is None:
            self._writer = FlextLdifWriterService(config=self._config)
            self._logger.debug("Writer service initialized")
        return self._writer

    @property
    def repository(self) -> FlextLdifRepositoryService:
        """Get repository service instance (lazy initialization)."""
        if self._repository is None:
            self._repository = FlextLdifRepositoryService(config=self._config)
            self._logger.debug("Repository service initialized")
        return self._repository

    @property
    def transformer(self) -> FlextLdifTransformerService:
        """Get transformer service instance (lazy initialization)."""
        if self._transformer is None:
            self._transformer = FlextLdifTransformerService()
            self._logger.debug("Transformer service initialized")
        return self._transformer

    @property
    def analytics(self) -> FlextLdifAnalyticsService:
        """Get analytics service instance (lazy initialization)."""
        if self._analytics is None:
            self._analytics = FlextLdifAnalyticsService(config=self._config)
            self._logger.debug("Analytics service initialized")
        return self._analytics

    @property
    def config(self) -> FlextLdifConfig:
        """Get configuration instance."""
        return self._config

    def get_service_info(self) -> dict[str, object]:
        """Get information about all available services."""
        return {
            "service_container": "FlextLdifServices",
            "available_services": [
                "parser",
                "validator",
                "writer",
                "repository",
                "transformer",
                "analytics",
            ],
            "initialized_services": [
                name
                for name, service in [
                    ("parser", self._parser),
                    ("validator", self._validator),
                    ("writer", self._writer),
                    ("repository", self._repository),
                    ("transformer", self._transformer),
                    ("analytics", self._analytics),
                ]
                if service is not None
            ],
            "config": {
                "type": type(self._config).__name__,
                "memory_management": getattr(
                    self._config, "memory_management_enabled", "unknown"
                ),
                "validation_mode": getattr(
                    self._config, "strict_validation", "unknown"
                ),
            },
        }

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform health check on all initialized services."""
        try:
            services: dict[str, dict[str, object]] = {}
            health_status: dict[str, object] = {
                "service_container": "FlextLdifServices",
                "status": "healthy",
                "services": services,
            }

            # Check each initialized service
            service_checks = [
                ("parser", self._parser),
                ("validator", self._validator),
                ("writer", self._writer),
                ("repository", self._repository),
                ("transformer", self._transformer),
                ("analytics", self._analytics),
            ]

            for service_name, service_instance in service_checks:
                if service_instance is not None:
                    try:
                        # Most services should have a health_check method
                        if hasattr(service_instance, "health_check"):
                            service_health = service_instance.health_check()
                            if service_health.is_success:
                                services[service_name] = {"status": "healthy"}
                            else:
                                services[service_name] = {
                                    "status": "unhealthy",
                                    "error": service_health.error,
                                }
                                health_status["status"] = "degraded"
                        else:
                            services[service_name] = {"status": "no_health_check"}
                    except Exception as e:
                        services[service_name] = {"status": "error", "error": str(e)}
                        health_status["status"] = "degraded"
                else:
                    services[service_name] = {"status": "not_initialized"}

            return FlextResult[dict[str, object]].ok(health_status)

        except Exception as e:
            self._logger.exception("Service container health check failed")
            return FlextResult[dict[str, object]].fail(f"Health check error: {e}")

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute service container operation (returns service info)."""
        return FlextResult[dict[str, object]].ok(self.get_service_info())


__all__ = [
    "FlextLdifServices",
]
