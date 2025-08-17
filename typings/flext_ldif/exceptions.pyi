from collections.abc import Mapping
from enum import Enum

from flext_core import FlextError
from flext_core.exceptions import FlextErrorMixin

__all__ = [
    "FlextLdifAuthenticationError",
    "FlextLdifConfigurationError",
    "FlextLdifConnectionError",
    "FlextLdifEntryError",
    "FlextLdifEntryValidationError",
    "FlextLdifError",
    "FlextLdifErrorCodes",
    "FlextLdifFileError",
    "FlextLdifParseError",
    "FlextLdifProcessingError",
    "FlextLdifTimeoutError",
    "FlextLdifValidationError",
]

class FlextLdifErrorCodes(Enum):
    LDIF_ERROR = "LDIF_ERROR"
    LDIF_VALIDATION_ERROR = "LDIF_VALIDATION_ERROR"
    LDIF_PARSE_ERROR = "LDIF_PARSE_ERROR"
    LDIF_ENTRY_ERROR = "LDIF_ENTRY_ERROR"
    LDIF_CONFIGURATION_ERROR = "LDIF_CONFIGURATION_ERROR"
    LDIF_PROCESSING_ERROR = "LDIF_PROCESSING_ERROR"
    LDIF_CONNECTION_ERROR = "LDIF_CONNECTION_ERROR"
    LDIF_AUTHENTICATION_ERROR = "LDIF_AUTHENTICATION_ERROR"
    LDIF_TIMEOUT_ERROR = "LDIF_TIMEOUT_ERROR"

class FlextLdifError(FlextError, FlextErrorMixin): ...
class FlextLdifValidationError(FlextLdifError): ...
class FlextLdifParseError(FlextLdifError): ...
class FlextLdifEntryError(FlextLdifValidationError): ...
class FlextLdifConfigurationError(FlextLdifError): ...
class FlextLdifProcessingError(FlextLdifError): ...
class FlextLdifConnectionError(FlextLdifError): ...
class FlextLdifAuthenticationError(FlextLdifError): ...
class FlextLdifTimeoutError(FlextLdifError): ...

class FlextLdifFileError(FlextLdifError):
    def __init__(
        self,
        message: str,
        *,
        file_path: str | None = None,
        line_number: int | None = None,
        operation: str | None = None,
        encoding: str | None = None,
        code: FlextLdifErrorCodes | None = ...,
        context: Mapping[str, object] | None = None,
    ) -> None: ...

class FlextLdifEntryValidationError(FlextLdifEntryError):
    def __init__(
        self,
        message: str,
        *,
        dn: str | None = None,
        attribute_name: str | None = None,
        attribute_value: str | None = None,
        entry_index: int | None = None,
        validation_rule: str | None = None,
        code: FlextLdifErrorCodes | None = ...,
        context: Mapping[str, object] | None = None,
    ) -> None: ...
