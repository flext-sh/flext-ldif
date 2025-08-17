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

__all__ = [
    "LDIF_BUFFER_SIZE",
    "LDIF_DEFAULT_ENCODING",
    "LDIF_MAX_LINE_LENGTH",
    "LdifAuthenticationError",
    "LdifConfigurationError",
    "LdifConnectionError",
    "LdifEntryError",
    "LdifEntryErrorParams",
    "LdifError",
    "LdifParseError",
    "LdifParseErrorParams",
    "LdifProcessingError",
    "LdifTimeoutError",
    "LdifValidationError",
    "create_ldif_api",
    "create_ldif_entry",
    "ldif_validate",
    "simple_ldif_parser",
]

def LdifError(*args: object, **kwargs: object) -> FlextLdifError: ...
def LdifValidationError(
    *args: object, **kwargs: object
) -> FlextLdifValidationError: ...
def LdifParseError(*args: object, **kwargs: object) -> FlextLdifParseError: ...
def LdifEntryError(*args: object, **kwargs: object) -> FlextLdifEntryError: ...
def LdifConfigurationError(
    *args: object, **kwargs: object
) -> FlextLdifConfigurationError: ...
def LdifProcessingError(
    *args: object, **kwargs: object
) -> FlextLdifProcessingError: ...
def LdifConnectionError(
    *args: object, **kwargs: object
) -> FlextLdifConnectionError: ...
def LdifAuthenticationError(
    *args: object, **kwargs: object
) -> FlextLdifAuthenticationError: ...
def LdifTimeoutError(*args: object, **kwargs: object) -> FlextLdifTimeoutError: ...
def create_ldif_api(*args: object, **kwargs: object) -> object: ...
def simple_ldif_parser(*args: object, **kwargs: object) -> object: ...
def ldif_validate(*args: object, **kwargs: object) -> object: ...
def create_ldif_entry(*args: object, **kwargs: object) -> object: ...

LDIF_DEFAULT_ENCODING: str
LDIF_MAX_LINE_LENGTH: int
LDIF_BUFFER_SIZE: int

def LdifParseErrorParams(*args: object, **kwargs: object) -> dict[str, object]: ...
def LdifEntryErrorParams(*args: object, **kwargs: object) -> dict[str, object]: ...
