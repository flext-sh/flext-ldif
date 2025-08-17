"""Legacy compatibility layer for flext-ldif modernization.

This module provides backward compatibility for legacy exception classes and APIs
that were refactored during the flext-core modernization. All legacy names are
maintained as facades to the new FlextErrorMixin-based exceptions.

This layer will be deprecated in a future version. Please migrate to the new
FlextLdif* exception classes for modern error handling patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings

from flext_ldif.api import FlextLdifAPI
from flext_ldif.exceptions import (
    FlextLdifAuthenticationError,
    FlextLdifConfigurationError,
    FlextLdifConnectionError,
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifProcessingError,
    FlextLdifTimeoutError,
    FlextLdifValidationError,
)
from flext_ldif.models import FlextLdifEntry


def _deprecation_warning(old_name: str, new_name: str) -> None:
    """Issue deprecation warning for legacy API usage."""
    warnings.warn(
        f"{old_name} is deprecated. Use {new_name} instead. "
        f"Legacy compatibility will be removed in a future version.",
        DeprecationWarning,
        stacklevel=3,
    )


# Legacy exception aliases following facade pattern
def LdifError(*args: object, **kwargs: object) -> FlextLdifError:  # noqa: N802
    """Legacy: Use FlextLdifError instead."""
    _deprecation_warning("LdifError", "FlextLdifError")
    return FlextLdifError(*args, **kwargs)


def LdifValidationError(*args: object, **kwargs: object) -> FlextLdifValidationError:  # noqa: N802
    """Legacy: Use FlextLdifValidationError instead."""
    _deprecation_warning("LdifValidationError", "FlextLdifValidationError")
    return FlextLdifValidationError(*args, **kwargs)


def LdifParseError(*args: object, **kwargs: object) -> FlextLdifParseError:  # noqa: N802
    """Legacy: Use FlextLdifParseError instead."""
    _deprecation_warning("LdifParseError", "FlextLdifParseError")
    return FlextLdifParseError(*args, **kwargs)


def LdifEntryError(*args: object, **kwargs: object) -> FlextLdifEntryError:  # noqa: N802
    """Legacy: Use FlextLdifEntryError instead."""
    _deprecation_warning("LdifEntryError", "FlextLdifEntryError")
    return FlextLdifEntryError(*args, **kwargs)


def LdifConfigurationError(  # noqa: N802
    *args: object,
    **kwargs: object,
) -> FlextLdifConfigurationError:
    """Legacy: Use FlextLdifConfigurationError instead."""
    _deprecation_warning("LdifConfigurationError", "FlextLdifConfigurationError")
    return FlextLdifConfigurationError(*args, **kwargs)


def LdifProcessingError(*args: object, **kwargs: object) -> FlextLdifProcessingError:  # noqa: N802
    """Legacy: Use FlextLdifProcessingError instead."""
    _deprecation_warning("LdifProcessingError", "FlextLdifProcessingError")
    return FlextLdifProcessingError(*args, **kwargs)


def LdifConnectionError(*args: object, **kwargs: object) -> FlextLdifConnectionError:  # noqa: N802
    """Legacy: Use FlextLdifConnectionError instead."""
    _deprecation_warning("LdifConnectionError", "FlextLdifConnectionError")
    return FlextLdifConnectionError(*args, **kwargs)


def LdifAuthenticationError(  # noqa: N802
    *args: object,
    **kwargs: object,
) -> FlextLdifAuthenticationError:
    """Legacy: Use FlextLdifAuthenticationError instead."""
    _deprecation_warning("LdifAuthenticationError", "FlextLdifAuthenticationError")
    return FlextLdifAuthenticationError(*args, **kwargs)


def LdifTimeoutError(*args: object, **kwargs: object) -> FlextLdifTimeoutError:  # noqa: N802
    """Legacy: Use FlextLdifTimeoutError instead."""
    _deprecation_warning("LdifTimeoutError", "FlextLdifTimeoutError")
    return FlextLdifTimeoutError(*args, **kwargs)


# Legacy API function aliases
def create_ldif_api(*args: object, **kwargs: object) -> object:
    """Legacy: Use FlextLdifAPI directly instead."""
    try:
        _deprecation_warning("create_ldif_api", "FlextLdifAPI")
        return FlextLdifAPI(*args, **kwargs)
    except ImportError:
        msg = "FlextLdifAPI not available"
        raise ImportError(msg) from None


def simple_ldif_parser(*args: object, **kwargs: object) -> object:
    """Legacy: Use FlextLdifAPI.parse instead."""
    try:
        _deprecation_warning("simple_ldif_parser", "FlextLdifAPI.parse")
        api = FlextLdifAPI()
        return api.parse(*args, **kwargs)
    except ImportError:
        msg = "FlextLdifAPI not available"
        raise ImportError(msg) from None


def ldif_validate(*args: object, **kwargs: object) -> object:
    """Legacy: Use FlextLdifAPI.validate instead."""
    try:
        _deprecation_warning("ldif_validate", "FlextLdifAPI.validate")
        api = FlextLdifAPI()
        return api.validate(*args, **kwargs)
    except ImportError:
        msg = "FlextLdifAPI not available"
        raise ImportError(msg) from None


def create_ldif_entry(*args: object, **kwargs: object) -> object:
    """Legacy: Use FlextLdifEntry directly instead."""
    try:
        _deprecation_warning("create_ldif_entry", "FlextLdifEntry")
        return FlextLdifEntry(*args, **kwargs)
    except ImportError:
        msg = "FlextLdifEntry not available"
        raise ImportError(msg) from None


# Legacy constants and configuration
LDIF_DEFAULT_ENCODING = "utf-8"
LDIF_MAX_LINE_LENGTH = 76
LDIF_BUFFER_SIZE = 8192


# Legacy parameter factories for compatibility
def LdifParseErrorParams(*args: object, **kwargs: object) -> dict[str, object]:  # noqa: ARG001, N802
    """Legacy: Create parameters for LdifParseError - use FlextLdifParseError context instead."""
    _deprecation_warning(
        "LdifParseErrorParams",
        "FlextLdifParseError context parameter",
    )
    return {
        "file_path": kwargs.get("file_path"),
        "line_number": kwargs.get("line_number"),
        "operation": kwargs.get("operation", "parse"),
        "encoding": kwargs.get("encoding", LDIF_DEFAULT_ENCODING),
    }


def LdifEntryErrorParams(*args: object, **kwargs: object) -> dict[str, object]:  # noqa: ARG001, N802
    """Legacy: Create parameters for LdifEntryError - use FlextLdifEntryError context instead."""
    _deprecation_warning(
        "LdifEntryErrorParams",
        "FlextLdifEntryError context parameter",
    )
    return {
        "dn": kwargs.get("dn"),
        "attribute_name": kwargs.get("attribute_name"),
        "attribute_value": kwargs.get("attribute_value"),
        "entry_index": kwargs.get("entry_index"),
        "validation_rule": kwargs.get("validation_rule"),
    }


__all__: list[str] = [
    # Legacy constants
    "LDIF_BUFFER_SIZE",
    "LDIF_DEFAULT_ENCODING",
    "LDIF_MAX_LINE_LENGTH",
    # Legacy exception aliases
    "LdifAuthenticationError",
    "LdifConfigurationError",
    "LdifConnectionError",
    "LdifEntryError",
    # Legacy parameter factories
    "LdifEntryErrorParams",
    "LdifError",
    "LdifParseError",
    "LdifParseErrorParams",
    "LdifProcessingError",
    "LdifTimeoutError",
    "LdifValidationError",
    # Legacy API functions
    "create_ldif_api",
    "create_ldif_entry",
    "ldif_validate",
    "simple_ldif_parser",
]
