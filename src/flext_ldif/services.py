"""FLEXT LDIF Services - Unified LDIF service orchestration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDomainService, FlextResult
from flext_ldif.analytics_service import FlextLdifAnalyticsService
from flext_ldif.config import FlextLdifConfig
from flext_ldif.format_handlers import FlextLdifFormatHandler
from flext_ldif.parser_service import FlextLdifParserService
from flext_ldif.repository_service import FlextLdifRepositoryService
from flext_ldif.transformer_service import FlextLdifTransformerService
from flext_ldif.validator_service import FlextLdifValidatorService
from flext_ldif.writer_service import FlextLdifWriterService


class FlextLdifServices(FlextDomainService[dict[str, object]]):
    """Unified LDIF Services - Simplified with direct flext-core usage.

    Orchestrates specialized services following Single Responsibility Principle.
    Uses flext-core patterns directly without unnecessary abstractions.
    """

    def __init__(self, config: FlextLdifConfig | None = None, **_: object) -> None:
        """Initialize unified LDIF services with simplified dependency injection."""
        super().__init__()
        if config is None:
            try:
                self._config = FlextLdifConfig.get_global_ldif_config()
            except RuntimeError:
                # Global config not initialized, create default one
                self._config = FlextLdifConfig()
        else:
            self._config = config

        # Initialize shared dependencies
        format_handler = FlextLdifFormatHandler()

        # Initialize specialized services with direct instantiation
        self._parser = FlextLdifParserService(format_handler)
        self._validator = FlextLdifValidatorService()
        self._writer = FlextLdifWriterService(format_handler)
        self._analytics = FlextLdifAnalyticsService()
        self._transformer = FlextLdifTransformerService()
        self._repository = FlextLdifRepositoryService()

    @property
    def config(self) -> FlextLdifConfig:
        """Get services configuration."""
        return self._config

    @property
    def parser(self) -> FlextLdifParserService:
        """Get parser service."""
        return self._parser

    @property
    def validator(self) -> FlextLdifValidatorService:
        """Get validator service."""
        return self._validator

    @property
    def writer(self) -> FlextLdifWriterService:
        """Get writer service."""
        return self._writer

    @property
    def analytics(self) -> FlextLdifAnalyticsService:
        """Get analytics service."""
        return self._analytics

    @property
    def transformer(self) -> FlextLdifTransformerService:
        """Get transformer service."""
        return self._transformer

    @property
    def repository(self) -> FlextLdifRepositoryService:
        """Get repository service."""
        return self._repository

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute services operation."""
        return FlextResult[dict[str, object]].ok({"status": "ready"})


__all__ = ["FlextLdifServices"]
