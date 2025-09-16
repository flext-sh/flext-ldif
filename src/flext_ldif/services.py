"""FLEXT LDIF Services - Unified LDIF service orchestration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDomainService, FlextResult

from flext_ldif.config import FlextLDIFConfig, get_ldif_config
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidators
from flext_ldif.models import FlextLDIFModels
from flext_ldif.parser_service import FlextLDIFParserService
from flext_ldif.repository_service import FlextLDIFRepositoryService
from flext_ldif.transformer_service import FlextLDIFTransformerService
from flext_ldif.validator_service import FlextLDIFValidatorService
from flext_ldif.writer_service import FlextLDIFWriterService


class FlextLDIFAnalyticsService:
    """LDIF Analytics Service - Simplified with direct flext-core usage.

    Handles all LDIF analytics operations with minimal complexity.
    Uses flext-core patterns directly without unnecessary abstractions.
    """

    def analyze_entries(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze LDIF entries and return statistics."""
        stats = {
            "total_entries": len(entries),
            "person_entries": sum(1 for e in entries if e.is_person()),
            "group_entries": sum(1 for e in entries if e.is_group()),
            "organizational_unit_entries": sum(
                1
                for e in entries
                if "organizationalunit"
                in (oc.lower() for oc in (e.get_attribute("objectClass") or []))
            ),
        }
        return FlextResult[dict[str, int]].ok(stats)

    def get_objectclass_distribution(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Get object class distribution."""
        distribution: dict[str, int] = {}
        for entry in entries:
            object_classes = entry.get_attribute("objectClass") or []
            for oc in object_classes:
                oc_lower = oc.lower()
                distribution[oc_lower] = distribution.get(oc_lower, 0) + 1
        return FlextResult[dict[str, int]].ok(distribution)

    def get_dn_depth_analysis(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        depth_distribution: dict[str, int] = {}
        for entry in entries:
            dn_parts = entry.dn.value.split(",")
            depth = len(dn_parts)
            depth_key = f"depth_{depth}"
            depth_distribution[depth_key] = depth_distribution.get(depth_key, 0) + 1
        return FlextResult[dict[str, int]].ok(depth_distribution)

    def analyze_patterns(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries - alias for analyze_entries."""
        return self.analyze_entries(entries)

    def get_config_info(self) -> dict[str, object]:
        """Get analytics service configuration information."""
        return {
            "service": "FlextLDIFAnalyticsService",
            "config": {
                "analytics_enabled": True,
                "supported_metrics": [
                    "entry_count",
                    "attribute_count",
                    "dn_depth_analysis",
                ],
            },
        }


class FlextLDIFServices(FlextDomainService[dict[str, object]]):
    """Unified LDIF Services - Simplified with direct flext-core usage.

    Orchestrates specialized services following Single Responsibility Principle.
    Uses flext-core patterns directly without unnecessary abstractions.
    """

    def __init__(
        self, config: FlextLDIFConfig | None = None, **_: object
    ) -> None:
        """Initialize unified LDIF services with simplified dependency injection."""
        super().__init__()
        if config is None:
            try:
                self._config = get_ldif_config()
            except RuntimeError:
                # Global config not initialized, create default one
                self._config = FlextLDIFConfig()
        else:
            self._config = config

        # Initialize shared dependencies
        format_handler = FlextLDIFFormatHandler()
        format_validator = FlextLDIFFormatValidators()

        # Initialize specialized services with direct instantiation
        self._parser = FlextLDIFParserService(format_handler)
        self._validator = FlextLDIFValidatorService(format_validator)
        self._writer = FlextLDIFWriterService(format_handler)
        self._analytics = FlextLDIFAnalyticsService()
        self._transformer = FlextLDIFTransformerService()
        self._repository = FlextLDIFRepositoryService()

    @property
    def config(self) -> FlextLDIFConfig:
        """Get services configuration."""
        return self._config

    @property
    def parser(self) -> FlextLDIFParserService:
        """Get parser service."""
        return self._parser

    @property
    def validator(self) -> FlextLDIFValidatorService:
        """Get validator service."""
        return self._validator

    @property
    def writer(self) -> FlextLDIFWriterService:
        """Get writer service."""
        return self._writer

    @property
    def analytics(self) -> FlextLDIFAnalyticsService:
        """Get analytics service."""
        return self._analytics

    @property
    def transformer(self) -> FlextLDIFTransformerService:
        """Get transformer service."""
        return self._transformer

    @property
    def repository(self) -> FlextLDIFRepositoryService:
        """Get repository service."""
        return self._repository

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute services operation."""
        return FlextResult[dict[str, object]].ok({"status": "ready"})


# Backward compatibility alias
# FlextLDIFAnalyticsService is now defined as a standalone class above


__all__ = ["FlextLDIFAnalyticsService", "FlextLDIFServices"]
