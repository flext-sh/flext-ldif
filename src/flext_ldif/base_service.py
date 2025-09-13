"""FLEXT LDIF Base Service - Base classes for LDIF services.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TypeVar

from flext_core import FlextDomainService, FlextResult

from flext_ldif.models import FlextLDIFModels

T = TypeVar("T")


class FlextLDIFBaseService(FlextDomainService[T], ABC):
    """Unified base service eliminating code duplication.

    Provides common functionality for all LDIF services:
    - Unified configuration management
    - Standardized error handling
    - Common service information methods
    - Consistent FlextResult patterns

    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def __init__(self, service_name: str, service_type: str) -> None:
        """Initialize base service with unified configuration."""
        super().__init__()
        self._service_name = service_name
        self._service_type = service_type
        self._capabilities: list[str] = []

    def get_config_info(self) -> dict[str, object]:
        """Get unified service configuration information."""
        return {
            "service": self._service_name,
            "config": {
                "service_type": self._service_type,
                "status": "ready",
                "capabilities": self._capabilities,
            },
        }

    def get_service_info(self) -> dict[str, object]:
        """Get unified service information."""
        return {
            "service_name": self._service_name,
            "service_type": self._service_type,
            "capabilities": self._capabilities,
            "status": "ready",
        }

    def _add_capability(self, capability: str) -> None:
        """Add capability to service capabilities list."""
        if capability not in self._capabilities:
            self._capabilities.append(capability)

    def _handle_error(self, operation: str, error: Exception | str) -> FlextResult[T]:
        """Unified error handling using flext-core patterns."""
        error_msg = str(error) if isinstance(error, Exception) else error
        return FlextResult[T].fail(f"{operation} failed: {error_msg}")

    def _handle_error_bool(
        self, operation: str, error: Exception | str
    ) -> FlextResult[bool]:
        """Error handling for boolean return types."""
        error_msg = str(error) if isinstance(error, Exception) else error
        return FlextResult[bool].fail(f"{operation} failed: {error_msg}")

    def _handle_error_str(
        self, operation: str, error: Exception | str
    ) -> FlextResult[str]:
        """Error handling for string return types."""
        error_msg = str(error) if isinstance(error, Exception) else error
        return FlextResult[str].fail(f"{operation} failed: {error_msg}")

    def _handle_error_list(
        self, operation: str, error: Exception | str
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Error handling for list return types."""
        error_msg = str(error) if isinstance(error, Exception) else error
        return FlextResult[list[FlextLDIFModels.Entry]].fail(
            f"{operation} failed: {error_msg}"
        )

    @abstractmethod
    def execute(self) -> FlextResult[T]:
        """Execute main service operation - must be implemented by subclasses."""
        ...


__all__ = ["FlextLDIFBaseService"]
