"""FLEXT-LDIF Cross-cutting Utilities.

This package provides cross-cutting utilities and helper functions that support
LDIF processing operations across all architectural layers while maintaining
separation of concerns and avoiding circular dependencies.

The utilities module implements common patterns for validation, error handling,
logging, and CLI operations following DRY (Don't Repeat Yourself) principles
and SOLID design patterns for maximum reusability and maintainability.

Key Components:
    - Validation utilities: Reusable validation patterns and predicates
    - Error handling utilities: Structured error reporting and exception management
    - Logging utilities: Structured logging configuration and performance monitoring
    - CLI utilities: Command-line interface helpers and formatting functions

Architecture:
    Cross-cutting concerns that can be used by any architectural layer without
    creating dependencies. These utilities contain only technical helpers without
    business logic, ensuring they remain layer-neutral and highly reusable.

Design Principles:
    - Single Responsibility: Each utility has one clear, focused purpose
    - Layer Neutral: No dependencies on business logic or specific architectural layers
    - Reusable: Composable functions that can be combined for complex operations
    - Testable: Pure functions with clear inputs and outputs for comprehensive testing

Integration:
    - Built on flext-core utility patterns and logging infrastructure
    - Supports structured logging with correlation IDs and trace context
    - Integrates with FlextResult patterns for consistent error handling
    - Provides enterprise-grade configuration and validation utilities

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from .cli_utils import (
    confirm_operation,
    display_entry_count,
    display_success_message,
    exit_with_error,
    handle_file_operation_result,
    handle_parse_result,
    safe_click_echo,
    validate_cli_result,
)
from .error_handling import (
    FlextLdifErrorHandler,
    handle_async_exceptions,
    handle_common_exceptions,
    handle_file_operation_error,
    handle_parsing_error,
)
from .logging import LoggerMixin, get_module_logger
from .validation import LdifSchemaValidator, LdifValidator

__all__ = [
    "FlextLdifErrorHandler",
    "LdifSchemaValidator",
    "LdifValidator",
    "LoggerMixin",
    "confirm_operation",
    "display_entry_count",
    "display_success_message",
    "exit_with_error",
    "get_module_logger",
    "handle_async_exceptions",
    "handle_common_exceptions",
    "handle_file_operation_error",
    "handle_file_operation_result",
    "handle_parse_result",
    "handle_parsing_error",
    "safe_click_echo",
    "validate_cli_result",
]
