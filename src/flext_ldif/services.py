"""FLEXT LDIF Services - Unified LDIF service orchestration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextConfig, FlextDomainService, FlextResult
from pydantic import ConfigDict, Field as PydanticField

from flext_ldif.analytics_service import FlextLDIFAnalyticsService
from flext_ldif.config import FlextLDIFConfig, initialize_ldif_config
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidators
from flext_ldif.models import FlextLDIFModels
from flext_ldif.parser_service import FlextLDIFParserService
from flext_ldif.repository_service import FlextLDIFRepositoryService
from flext_ldif.transformer_service import FlextLDIFTransformerService
from flext_ldif.validator_service import FlextLDIFValidatorService
from flext_ldif.writer_service import FlextLDIFWriterService


class FlextLDIFServices(FlextDomainService[dict[str, object]]):
    """Unified LDIF Services - SOLID Principles Implementation.

    Orchestrates specialized services following Single Responsibility Principle.
    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=False, validate_assignment=False, arbitrary_types_allowed=True
    )  # Override validation

    # Specialized services following SOLID principles
    parser: FlextLDIFParserService | None = None
    validator: FlextLDIFValidatorService | None = None
    writer: FlextLDIFWriterService | None = None
    analytics: FlextLDIFAnalyticsService | None = None
    transformer: FlextLDIFTransformerService | None = None
    repository: FlextLDIFRepositoryService | None = None

    # Private attributes for internal state
    _config: FlextLDIFModels.Config | None = None
    _ldif_config: object | None = None
    _format_handler: FlextLDIFFormatHandler | None = None
    _format_validator: FlextLDIFFormatValidators | None = None

    def __init__(
        self, config: FlextLDIFModels.Config | None = None, **_: object
    ) -> None:
        """Initialize unified LDIF services with dependency injection."""
        # Initialize parent class first
        super().__init__()

        # Set private attributes using object.__setattr__ to bypass Pydantic
        object.__setattr__(self, "_config", config or FlextLDIFModels.Config())

        # Initialize global config - use a simpler approach
        try:
            # Try to get existing global config
            global_config = FlextConfig.get_global_instance()
            if isinstance(global_config, FlextLDIFConfig):
                ldif_config = global_config
            else:
                # Initialize with default LDIF config
                init_result = initialize_ldif_config()
                if init_result.is_failure:
                    # Fallback to creating a local config
                    ldif_config = FlextLDIFConfig()
                else:
                    ldif_config = init_result.value
        except Exception:
            # Fallback to creating a local config
            ldif_config = FlextLDIFConfig()

        object.__setattr__(self, "_ldif_config", ldif_config)

        # Initialize shared dependencies
        format_handler = FlextLDIFFormatHandler()
        format_validator = FlextLDIFFormatValidators()

        object.__setattr__(self, "_format_handler", format_handler)
        object.__setattr__(self, "_format_validator", format_validator)

        # Initialize specialized services with dependency injection
        parser = FlextLDIFParserService(format_handler)
        validator = FlextLDIFValidatorService(format_validator)
        writer = FlextLDIFWriterService(format_handler)
        analytics = FlextLDIFAnalyticsService()
        transformer = FlextLDIFTransformerService()
        repository = FlextLDIFRepositoryService()

        # Set service attributes
        object.__setattr__(self, "parser", parser)
        object.__setattr__(self, "validator", validator)
        object.__setattr__(self, "writer", writer)
        object.__setattr__(self, "analytics", analytics)
        object.__setattr__(self, "transformer", transformer)
        object.__setattr__(self, "repository", repository)

    @property
    def config(self) -> FlextLDIFModels.Config:
        """Get services configuration."""
        if self._config is None:
            error_msg = "Configuration not initialized"
            raise RuntimeError(error_msg)
        return self._config

    @property
    def ldif_config(self) -> object:
        """Get LDIF-specific configuration."""
        return self._ldif_config

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute services operation."""
        return FlextResult[dict[str, object]].ok({"status": "ready"})

    @staticmethod
    def object_class_field(
        description: str = "LDAP Object Class",
        pattern: str | None = r"^[A-Z][a-zA-Z0-9]*$",
        max_length: int = 255,
        min_length: int = 1,
    ) -> object:
        """Create a Pydantic field for LDAP object class validation."""
        if pattern:
            return PydanticField(
                ...,
                description=description,
                min_length=min_length,
                max_length=max_length,
                pattern=pattern,
            )
        return PydanticField(
            ..., description=description, min_length=min_length, max_length=max_length
        )

    @staticmethod
    def dn_field(
        description: str = "LDAP Distinguished Name",
        max_length: int = 1024,
        min_length: int = 1,
    ) -> object:
        """Create a Pydantic field for LDAP DN validation."""
        return PydanticField(
            ..., description=description, min_length=min_length, max_length=max_length
        )

    @staticmethod
    def attribute_name_field(
        description: str = "LDAP Attribute Name",
        pattern: str | None = r"^[a-zA-Z][a-zA-Z0-9-]*$",
        max_length: int = 255,
        min_length: int = 1,
    ) -> object:
        """Create a Pydantic field for LDAP attribute name validation."""
        if pattern:
            return PydanticField(
                ...,
                description=description,
                min_length=min_length,
                max_length=max_length,
                pattern=pattern,
            )
        return PydanticField(
            ..., description=description, min_length=min_length, max_length=max_length
        )

    @staticmethod
    def attribute_value_field(
        description: str = "LDAP Attribute Value",
        max_length: int = 4096,
        min_length: int = 0,
    ) -> object:
        """Create a Pydantic field for LDAP attribute value validation."""
        return PydanticField(
            ..., description=description, min_length=min_length, max_length=max_length
        )


__all__ = ["FlextLDIFServices"]
