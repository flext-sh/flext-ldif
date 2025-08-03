"""FLEXT-LDIF Logging Utilities.

This module provides standardized logging utilities and patterns for FLEXT-LDIF
operations, implementing structured logging with flext-core integration and
enterprise-grade logging configuration for consistent log formatting across
all architectural layers.

Key Components:
    - Module logger factory with consistent naming patterns
    - Performance logging utilities for operation monitoring
    - Structured logging helpers with correlation IDs
    - Logger mixins for class-based logging integration

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import get_logger

if TYPE_CHECKING:
    from flext_core.logging import FlextLogger


def get_module_logger(module_name: str) -> FlextLogger:
    """Get a logger for a specific module using flext-core patterns.

    This function standardizes logger creation across all flext-ldif modules,
    reducing the duplicated `logger = get_logger(__name__)` pattern.

    Args:
        module_name: The module name (typically __name__)

    Returns:
        FlextLogger instance configured for the module

    """
    return get_logger(module_name)


class LoggerMixin:
    """Mixin class to provide logger functionality to any class.

    This eliminates the need for every class to declare its own logger,
    following the DRY principle.
    """

    @property
    def logger(self) -> FlextLogger:
        """Get logger for this class instance."""
        if not hasattr(self, "_logger"):
            self._logger = get_logger(self.__class__.__module__)
        return self._logger
