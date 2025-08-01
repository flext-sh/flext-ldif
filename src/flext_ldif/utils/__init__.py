"""Flext LDIF Utilities - Common utility functions and decorators.

This package provides common utilities to reduce code duplication across
the flext-ldif codebase following SOLID and DRY principles.
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
