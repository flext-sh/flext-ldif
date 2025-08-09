"""FLEXT-LDIF Legacy Compatibility Layer - Deprecated Functions.

⚠️ DEPRECATION NOTICE: All functions in this module are deprecated and will be
   removed in v1.0.0. Use the modern FlextLdifAPI instead.

This module provides backward compatibility for legacy function-based APIs
while encouraging migration to the modern class-based approach.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from flext_core import FlextResult

from .api import FlextLdifAPI
from .config import FlextLdifConfig

if TYPE_CHECKING:
    from pathlib import Path

    from .models import FlextLdifEntry

# Private API instance for legacy compatibility
_legacy_api: FlextLdifAPI | None = None


def _get_legacy_api() -> FlextLdifAPI:
    """Get or create legacy API instance."""
    # Use module-level variable without global statement
    if _legacy_api is None:
        # Initialize a new API instance
        return FlextLdifAPI()
    return _legacy_api


def flext_ldif_get_api(config: object | None = None) -> FlextLdifAPI:
    """Legacy function - use FlextLdifAPI() directly.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI() directly
    💡 Import: from flext_ldif import FlextLdifAPI
    📖 Migration will be required in v1.0.0
    """
    warnings.warn(
        "flext_ldif_get_api() is deprecated. Use FlextLdifAPI() directly.",
        DeprecationWarning,
        stacklevel=2,
    )

    if config is None:
        return FlextLdifAPI()

    if isinstance(config, FlextLdifConfig):
        return FlextLdifAPI(config)

    # Try to convert if it's a compatible object
    return FlextLdifAPI()


def flext_ldif_parse(content: str) -> list[FlextLdifEntry]:
    """Legacy function - use FlextLdifAPI().parse() for FlextResult.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI().parse() for proper error handling
    💡 Example: api = FlextLdifAPI(); result = api.parse(content)
    📖 Legacy imports will be removed in v1.0.0
    """
    warnings.warn(
        "flext_ldif_parse() is deprecated. Use FlextLdifAPI().parse() for proper error handling.",
        DeprecationWarning,
        stacklevel=2,
    )
    api = _get_legacy_api()
    result = api.parse(content)
    if result.success and result.data is not None:
        return result.data
    # Return empty list for invalid content (legacy compatibility)
    return []


def flext_ldif_validate(entries: list[FlextLdifEntry] | str) -> bool:
    """Legacy function - use FlextLdifAPI().validate() for FlextResult.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI().validate() for proper error handling
    💡 Example: api = FlextLdifAPI(); result = api.validate(entries)
    📖 Legacy imports will be removed in v1.0.0
    """
    warnings.warn(
        "flext_ldif_validate() is deprecated. Use FlextLdifAPI().validate() for proper error handling.",
        DeprecationWarning,
        stacklevel=2,
    )
    api = _get_legacy_api()

    # Handle string input by parsing first
    if isinstance(entries, str):
        parse_result = api.parse(entries)
        if parse_result.is_failure or not parse_result.data:
            return False  # Invalid LDIF content
        entries = parse_result.data

    result = api.validate(entries)
    if result.success and result.data is not None:
        return result.data
    # Return False for validation failures (legacy compatibility)
    return False


def flext_ldif_write(entries: list[FlextLdifEntry], file_path: str | None = None) -> str:
    """Legacy function - use FlextLdifAPI().write() or write_file() for FlextResult.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI().write() or write_file() for proper error handling
    💡 Example: api = FlextLdifAPI(); result = api.write(entries)
    📖 Legacy imports will be removed in v1.0.0
    """
    warnings.warn(
        "flext_ldif_write() is deprecated. Use FlextLdifAPI().write() or write_file() for proper error handling.",
        DeprecationWarning,
        stacklevel=2,
    )
    api = _get_legacy_api()

    if file_path:
        # Write to file
        result = api.write_file(entries, file_path)
        if result.success:
            return "File written successfully"
        error_msg = f"Write to file failed: {result.error or 'Unknown error'}"
        raise ValueError(error_msg)
    # Write to string
    write_result = api.write(entries)
    if write_result.success and write_result.data is not None:
        return write_result.data
    error_msg = f"Write failed: {write_result.error or 'Unknown error'}"
    raise ValueError(error_msg)


def flext_ldif_parse_file(file_path: str | Path) -> list[FlextLdifEntry]:
    """Legacy function - use FlextLdifAPI().parse_file() for FlextResult.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI().parse_file() for proper error handling
    💡 Example: api = FlextLdifAPI(); result = api.parse_file(file_path)
    📖 Legacy imports will be removed in v1.0.0
    """
    warnings.warn(
        "flext_ldif_parse_file() is deprecated. Use FlextLdifAPI().parse_file() for proper error handling.",
        DeprecationWarning,
        stacklevel=2,
    )
    api = _get_legacy_api()
    result = api.parse_file(file_path)
    if result.success and result.data is not None:
        return result.data
    # Return empty list for invalid files (legacy compatibility)
    return []


def flext_ldif_entries_to_ldif(entries: list[FlextLdifEntry]) -> str:
    """Legacy function - use FlextLdifAPI().entries_to_ldif() instead.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI().entries_to_ldif()
    💡 Example: api = FlextLdifAPI(); ldif_str = api.entries_to_ldif(entries)
    📖 Legacy imports will be removed in v1.0.0
    """
    warnings.warn(
        "flext_ldif_entries_to_ldif() is deprecated. Use FlextLdifAPI().entries_to_ldif().",
        DeprecationWarning,
        stacklevel=2,
    )
    api = _get_legacy_api()
    return api.entries_to_ldif(entries)


# Legacy service creation functions
def get_ldif_parser() -> FlextLdifAPI:
    """Legacy service function - use FlextLdifAPI() instead.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI() directly
    💡 Import: from flext_ldif import FlextLdifAPI
    📖 Migration will be required in v1.0.0
    """
    warnings.warn(
        "get_ldif_parser() is deprecated. Use FlextLdifAPI() directly.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _get_legacy_api()


def get_ldif_validator() -> FlextLdifAPI:
    """Legacy service function - use FlextLdifAPI() instead.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI() directly
    💡 Import: from flext_ldif import FlextLdifAPI
    📖 Migration will be required in v1.0.0
    """
    warnings.warn(
        "get_ldif_validator() is deprecated. Use FlextLdifAPI() directly.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _get_legacy_api()


def get_ldif_writer() -> FlextLdifAPI:
    """Legacy service function - use FlextLdifAPI() instead.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: Use FlextLdifAPI() directly
    💡 Import: from flext_ldif import FlextLdifAPI
    📖 Migration will be required in v1.0.0
    """
    warnings.warn(
        "get_ldif_writer() is deprecated. Use FlextLdifAPI() directly.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _get_legacy_api()


def register_ldif_services() -> FlextResult[None]:
    """Legacy service registration - no longer needed.

    ⚠️ DEPRECATED: This function is deprecated.
    ✅ MODERN SOLUTION: No service registration needed with FlextLdifAPI
    💡 Import: from flext_ldif import FlextLdifAPI
    📖 Migration will be required in v1.0.0
    """
    warnings.warn(
        "register_ldif_services() is deprecated. No service registration needed with FlextLdifAPI.",
        DeprecationWarning,
        stacklevel=2,
    )
    return FlextResult.ok(None)


__all__ = [
    "flext_ldif_entries_to_ldif",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_parse_file",
    "flext_ldif_validate",
    "flext_ldif_write",
    "get_ldif_parser",
    "get_ldif_validator",
    "get_ldif_writer",
    "register_ldif_services",
]
