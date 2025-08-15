"""FLEXT-LDIF - LDIF Processing Library."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING
from collections.abc import Callable

from flext_core import FlextResult

# Application layer API
from .api import FlextLdifAPI, TLdif

# Configuration management
from .config import FlextLdifConfig

# Service classes
from .entry_analytics import FlextLdifAnalyticsService
from .entry_repository import FlextLdifRepositoryService
from .entry_transformer import FlextLdifTransformerService
from .entry_validator import FlextLdifValidatorService

# Domain exceptions
from .exceptions import (
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)
from .ldif_parser import FlextLdifParserService
from .ldif_writer import FlextLdifWriterService

# Domain models and value objects
from .models import (
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
    FlextLdifFactory,
)
from .types import (
    AttributeValue,
    FilePath,
    FlextLdifAttributesDict,
    FlextLdifDNDict,
    FlextLdifEntryDict,
    LDAPObjectClass,
    LDIFContent,
    LDIFLines,
    ProcessingMode,
    StringList,
    ValidationLevel,
)

# Centralized type system
from .types import AttributeName  # Additional commonly used types

if TYPE_CHECKING:
    from collections.abc import Callable

"""Expose optional CLI entry point without importing CLI at type-check time."""
cli_main: Callable[[], None] | None
if not TYPE_CHECKING:
    try:
        from .cli import main as cli_main
    except Exception:
        # Provide a no-op CLI entry point when optional deps are missing
        # Magic constants for CLI arg positions
        _CMD_INDEX = 1
        _ARG_INDEX = 2

        def _noop_cli() -> None:
            argv = sys.argv
            # For help/normal runs, behave as success; for invalid parse target, error.
            has_command = len(argv) >= _CMD_INDEX + 1
            is_parse = has_command and argv[_CMD_INDEX] == "parse"
            missing_arg = len(argv) < _ARG_INDEX + 1
            missing_file = (not missing_arg) and (not Path(argv[_ARG_INDEX]).exists())
            if is_parse and (missing_arg or missing_file):
                raise SystemExit(2)
            raise SystemExit(0)

        cli_main = _noop_cli
else:
    cli_main = None

__version__ = "0.9.0"
__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())


# Convenience functions
def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Get LDIF API instance with optional configuration."""
    return FlextLdifAPI(config)


def flext_ldif_parse(content: str) -> list[FlextLdifEntry]:
    """Parse LDIF content using default configuration."""
    api = flext_ldif_get_api()
    result = api.parse(content)
    if result.is_failure:
        raise FlextLdifParseError(result.error or "Parse failed")
    return result.data or []


def flext_ldif_validate(entries: list[FlextLdifEntry]) -> bool:
    """Validate LDIF entries using default configuration."""
    api = flext_ldif_get_api()
    result = api.validate(entries)
    if result.is_failure:
        raise FlextLdifValidationError(result.error or "Validation failed")
    return result.data or False


def flext_ldif_write(entries: list[FlextLdifEntry]) -> str:
    """Write LDIF entries to string using default configuration."""
    api = flext_ldif_get_api()
    result = api.write(entries)
    if result.is_failure:
        raise FlextLdifError(result.error or "Write failed")
    return result.data or ""


__all__: list[str] = [
    "AttributeName",
    "AttributeValue",
    "FilePath",
    "FlextLdifAPI",
    "FlextLdifAnalyticsService",
    "FlextLdifAttributes",
    "FlextLdifAttributesDict",
    "FlextLdifConfig",
    "FlextLdifDNDict",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryDict",
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifFactory",
    "FlextLdifParseError",
    "FlextLdifParserService",
    "FlextLdifRepositoryService",
    "FlextLdifTransformerService",
    "FlextLdifValidationError",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
    "LDAPObjectClass",
    "LDIFContent",
    "LDIFLines",
    "ProcessingMode",
    "StringList",
    "TLdif",
    "ValidationLevel",
    "__version__",
    "__version_info__",
    "cli_main",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
