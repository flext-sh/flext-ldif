"""Error handling utilities for flext-ldif to reduce code duplication.

This module provides common error handling patterns used throughout the
flext-ldif codebase, following Clean Architecture principles.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar

from flext_core import FlextResult, get_logger

if TYPE_CHECKING:
    from collections.abc import Awaitable

F = TypeVar("F", bound=Callable[..., Any])
T = TypeVar("T")
P = ParamSpec("P")

logger = get_logger(__name__)


class FlextLdifErrorHandler:
    """Error handling utility class with common patterns."""

    @staticmethod
    def handle_result_failure(
        result: FlextResult[T],
        operation_name: str,
        fallback_error: str = "Operation failed",
    ) -> FlextResult[T]:
        """Handle FlextResult failure with consistent logging.

        Args:
            result: The failed FlextResult
            operation_name: Name of the operation for logging
            fallback_error: Default error message if result.error is None

        Returns:
            FlextResult with consistent error handling

        """
        error_msg = result.error or fallback_error
        logger.error("%s failed: %s", operation_name, error_msg)
        return FlextResult.fail(error_msg)

    @staticmethod
    def propagate_failure(
        result: FlextResult[T],
        context: str = "",
    ) -> FlextResult[T]:
        """Propagate failure with additional context.

        Args:
            result: The failed FlextResult
            context: Additional context for the error

        Returns:
            FlextResult with propagated failure

        """
        if result.is_success:
            return result

        error_msg = result.error or "Unknown error"
        if context:
            error_msg = f"{context}: {error_msg}"

        logger.debug("Propagating failure: %s", error_msg)
        return FlextResult.fail(error_msg)

    @staticmethod
    def handle_validation_failure(
        validation_result: FlextResult[bool],
        item_name: str,
    ) -> FlextResult[bool]:
        """Handle validation failure with consistent messaging.

        Args:
            validation_result: The validation FlextResult
            item_name: Name of the item being validated

        Returns:
            FlextResult with consistent validation error handling

        """
        if validation_result.is_success:
            return validation_result

        error_msg = f"{item_name} validation failed: {validation_result.error}"
        logger.warning("Validation failure: %s", error_msg)
        return FlextResult.fail(error_msg)


def handle_common_exceptions(
    operation_name: str,
    fallback_error: str = "Operation failed with unexpected error",
) -> Callable[[Callable[P, T]], Callable[P, FlextResult[T]]]:
    """Handle common exceptions with consistent logging.

    Args:
        operation_name: Name of the operation for logging
        fallback_error: Default error message for unexpected exceptions

    Returns:
        Decorator function

    """

    def decorator(func: Callable[P, T]) -> Callable[P, FlextResult[T]]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> FlextResult[T]:
            try:
                result = func(*args, **kwargs)
                if isinstance(result, FlextResult):
                    return result
                return FlextResult.ok(data=result)
            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("%s failed with common exception", operation_name)
                return FlextResult.fail(f"{operation_name} failed: {e}")
            except Exception as e:
                logger.exception("%s failed with unexpected exception", operation_name)
                return FlextResult.fail(f"{fallback_error}: {e}")

        return wrapper

    return decorator


def handle_async_exceptions(
    operation_name: str,
    fallback_error: str = "Async operation failed with unexpected error",
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[FlextResult[T]]]]:
    """Handle common exceptions in async functions.

    Args:
        operation_name: Name of the operation for logging
        fallback_error: Default error message for unexpected exceptions

    Returns:
        Decorator function for async operations

    """

    def decorator(
        func: Callable[P, Awaitable[T]],
    ) -> Callable[P, Awaitable[FlextResult[T]]]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> FlextResult[T]:
            try:
                result = await func(*args, **kwargs)
                if isinstance(result, FlextResult):
                    return result
                return FlextResult.ok(data=result)
            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("%s failed with common exception", operation_name)
                return FlextResult.fail(f"{operation_name} failed: {e}")
            except Exception as e:
                logger.exception("%s failed with unexpected exception", operation_name)
                return FlextResult.fail(f"{fallback_error}: {e}")

        return wrapper

    return decorator


# Convenience functions for common error patterns
def handle_file_operation_error(
    operation_name: str,
    file_path: str,
    error: Exception,
) -> FlextResult[None]:
    """Handle file operation errors consistently.

    Args:
        operation_name: Name of the file operation
        file_path: Path to the file being operated on
        error: The exception that occurred

    Returns:
        FlextResult with consistent file error handling

    """
    error_msg = f"{operation_name} failed for file '{file_path}': {error}"
    logger.error("File operation error: %s", error_msg)
    return FlextResult.fail(error_msg)


def handle_parsing_error(
    content_type: str,
    error: Exception,
    line_number: int | None = None,
) -> FlextResult[None]:
    """Handle parsing errors consistently.

    Args:
        content_type: Type of content being parsed (e.g., "LDIF", "DN")
        error: The parsing exception
        line_number: Optional line number where error occurred

    Returns:
        FlextResult with consistent parsing error handling

    """
    location = f" at line {line_number}" if line_number else ""
    error_msg = f"{content_type} parsing failed{location}: {error}"
    logger.error("Parsing error: %s", error_msg)
    return FlextResult.fail(error_msg)
