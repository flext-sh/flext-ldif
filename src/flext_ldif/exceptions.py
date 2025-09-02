"""FLEXT-LDIF Exceptions - Consolidated Class Structure.

Single consolidated class containing ALL LDIF exceptions following FLEXT patterns.
Individual exceptions available as nested classes for organization.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum

from flext_core import FlextExceptions, FlextModels


# Error codes enum for LDIF operations
class FlextLDIFErrorCodes(Enum):
    """Error codes for LDIF domain operations."""

    LDIF_ERROR = "LDIF_ERROR"
    LDIF_VALIDATION_ERROR = "LDIF_VALIDATION_ERROR"
    LDIF_PARSE_ERROR = "LDIF_PARSE_ERROR"
    LDIF_ENTRY_ERROR = "LDIF_ENTRY_ERROR"
    LDIF_CONFIGURATION_ERROR = "LDIF_CONFIGURATION_ERROR"
    LDIF_PROCESSING_ERROR = "LDIF_PROCESSING_ERROR"
    LDIF_CONNECTION_ERROR = "LDIF_CONNECTION_ERROR"
    LDIF_AUTHENTICATION_ERROR = "LDIF_AUTHENTICATION_ERROR"
    LDIF_TIMEOUT_ERROR = "LDIF_TIMEOUT_ERROR"
    LDIF_FILE_ERROR = "LDIF_FILE_ERROR"


# =============================================================================
# CONSOLIDATED EXCEPTIONS CLASS - Single class containing ALL LDIF exceptions
# =============================================================================


class FlextLDIFExceptions(FlextModels):
    """Single consolidated class containing ALL LDIF exceptions.

    Consolidates ALL exception definitions into one class following FLEXT patterns.
    Individual exceptions available as nested classes for organization.
    """

    class Error(FlextExceptions.BaseError):
        """Base LDIF error."""

        def __init__(
            self,
            message: str = "LDIF operation failed",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
        ) -> None:
            """Initialize LDIF error with proper defaults."""
            super().__init__(
                message,
                code=error_code or FlextLDIFErrorCodes.LDIF_ERROR.value,
                context=dict(context) if context else None,
            )

    class ValidationError(Error):
        """LDIF validation error."""

        def __init__(
            self,
            message: str = "LDIF validation failed",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
        ) -> None:
            """Initialize validation error."""
            super().__init__(
                message,
                error_code=error_code
                or FlextLDIFErrorCodes.LDIF_VALIDATION_ERROR.value,
                context=context,
            )

    class ParseError(Error):
        """LDIF parsing error."""

        def __init__(
            self,
            message: str = "LDIF parsing failed",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            line_number: int | None = None,
            column: int | None = None,
        ) -> None:
            """Initialize parse error with location information."""
            # Add location information to context
            parse_context = dict(context) if context else {}
            if line_number is not None:
                parse_context["line_number"] = line_number
            if column is not None:
                parse_context["column"] = column

            super().__init__(
                message,
                error_code=error_code or FlextLDIFErrorCodes.LDIF_PARSE_ERROR.value,
                context=parse_context,
            )

    class EntryError(ValidationError):
        """LDIF entry-specific error."""

        def __init__(
            self,
            message: str = "LDIF entry error",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            entry_dn: str | None = None,
        ) -> None:
            """Initialize entry error with DN information."""
            # Add DN information to context
            entry_context = dict(context) if context else {}
            if entry_dn is not None:
                entry_context["entry_dn"] = entry_dn

            super().__init__(
                message,
                error_code=error_code or FlextLDIFErrorCodes.LDIF_ENTRY_ERROR.value,
                context=entry_context,
            )

    class ConfigurationError(Error):
        """LDIF configuration error."""

        def __init__(
            self,
            message: str = "LDIF configuration error",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            config_key: str | None = None,
        ) -> None:
            """Initialize configuration error."""
            # Add config key to context
            config_context = dict(context) if context else {}
            if config_key is not None:
                config_context["config_key"] = config_key

            super().__init__(
                message,
                error_code=error_code
                or FlextLDIFErrorCodes.LDIF_CONFIGURATION_ERROR.value,
                context=config_context,
            )

    class ProcessingError(Error):
        """LDIF processing error."""

        def __init__(
            self,
            message: str = "LDIF processing failed",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            operation: str | None = None,
        ) -> None:
            """Initialize processing error."""
            # Add operation information to context
            processing_context = dict(context) if context else {}
            if operation is not None:
                processing_context["operation"] = operation

            super().__init__(
                message,
                error_code=error_code
                or FlextLDIFErrorCodes.LDIF_PROCESSING_ERROR.value,
                context=processing_context,
            )

    class LdifConnectionError(Error):
        """LDIF connection error."""

        def __init__(
            self,
            message: str = "LDIF connection failed",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            server: str | None = None,
            port: int | None = None,
        ) -> None:
            """Initialize connection error."""
            # Add connection information to context
            conn_context = dict(context) if context else {}
            if server is not None:
                conn_context["server"] = server
            if port is not None:
                conn_context["port"] = port

            super().__init__(
                message,
                error_code=error_code
                or FlextLDIFErrorCodes.LDIF_CONNECTION_ERROR.value,
                context=conn_context,
            )

    class AuthenticationError(Error):
        """LDIF authentication error."""

        def __init__(
            self,
            message: str = "LDIF authentication failed",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            username: str | None = None,
        ) -> None:
            """Initialize authentication error."""
            # Add username to context (but not password!)
            auth_context = dict(context) if context else {}
            if username is not None:
                auth_context["username"] = username

            super().__init__(
                message,
                error_code=error_code
                or FlextLDIFErrorCodes.LDIF_AUTHENTICATION_ERROR.value,
                context=auth_context,
            )

    class LdifTimeoutError(Error):
        """LDIF timeout error."""

        def __init__(
            self,
            message: str = "LDIF operation timed out",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            timeout_seconds: float | None = None,
        ) -> None:
            """Initialize timeout error."""
            # Add timeout information to context
            timeout_context = dict(context) if context else {}
            if timeout_seconds is not None:
                timeout_context["timeout_seconds"] = timeout_seconds

            super().__init__(
                message,
                error_code=error_code or FlextLDIFErrorCodes.LDIF_TIMEOUT_ERROR.value,
                context=timeout_context,
            )

    class FileError(Error):
        """LDIF file operation error."""

        def __init__(
            self,
            message: str = "LDIF file operation failed",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            file_path: str | None = None,
            operation: str | None = None,
            line_number: int | None = None,
            encoding: str | None = None,
        ) -> None:
            """Initialize file error."""
            # Add file information to context
            file_context = dict(context) if context else {}
            if file_path is not None:
                file_context["file_path"] = file_path
            if operation is not None:
                file_context["operation"] = operation
            if line_number is not None:
                file_context["line_number"] = line_number
            if encoding is not None:
                file_context["encoding"] = encoding

            super().__init__(
                message,
                error_code=error_code or FlextLDIFErrorCodes.LDIF_FILE_ERROR.value,
                context=file_context,
            )

    class EntryValidationError(EntryError):
        """LDIF entry validation error (specific validation rules)."""

        def __init__(
            self,
            message: str = "LDIF entry validation failed",
            *,
            error_code: str | None = None,
            context: Mapping[str, object] | None = None,
            entry_dn: str | None = None,
            dn: str
            | None = None,  # Alternative parameter name for backward compatibility
            attribute_name: str | None = None,
            attribute_value: str | None = None,
            validation_rule: str | None = None,
            entry_index: int | None = None,
        ) -> None:
            """Initialize entry validation error with detailed information."""
            # Add validation details to context
            validation_context = dict(context) if context else {}
            if attribute_name is not None:
                validation_context["attribute_name"] = attribute_name
            if attribute_value is not None:
                # Truncate very long attribute values for readability
                max_attribute_value_length = 100
                if len(attribute_value) > max_attribute_value_length:
                    truncated_value = attribute_value[:97] + "..."
                    validation_context["attribute_value"] = truncated_value
                else:
                    validation_context["attribute_value"] = attribute_value
            if validation_rule is not None:
                validation_context["validation_rule"] = validation_rule
            if entry_index is not None:
                validation_context["entry_index"] = entry_index

            # Use 'dn' as alternative for 'entry_dn' if provided
            final_dn = entry_dn or dn

            super().__init__(
                message,
                error_code=error_code,
                context=validation_context,
                entry_dn=final_dn,
            )


# =============================================================================
# BACKWARD COMPATIBILITY - Legacy class aliases
# =============================================================================

# Direct aliases to nested classes for backward compatibility
FlextLDIFError = FlextLDIFExceptions.Error
FlextLDIFValidationError = FlextLDIFExceptions.ValidationError
FlextLDIFParseError = FlextLDIFExceptions.ParseError
FlextLDIFEntryError = FlextLDIFExceptions.EntryError
FlextLDIFConfigurationError = FlextLDIFExceptions.ConfigurationError
FlextLDIFProcessingError = FlextLDIFExceptions.ProcessingError
FlextLDIFConnectionError = FlextLDIFExceptions.LdifConnectionError
FlextLDIFAuthenticationError = FlextLDIFExceptions.AuthenticationError
FlextLDIFTimeoutError = FlextLDIFExceptions.LdifTimeoutError
FlextLDIFFileError = FlextLDIFExceptions.FileError
FlextLDIFEntryValidationError = FlextLDIFExceptions.EntryValidationError

# Export consolidated class and legacy aliases
__all__ = [
    "FlextLDIFAuthenticationError",
    "FlextLDIFConfigurationError",
    "FlextLDIFConnectionError",
    "FlextLDIFEntryError",
    "FlextLDIFEntryValidationError",
    # Legacy compatibility aliases
    "FlextLDIFError",
    # Error codes
    "FlextLDIFErrorCodes",
    # Consolidated class (FLEXT Pattern)
    "FlextLDIFExceptions",
    "FlextLDIFFileError",
    "FlextLDIFParseError",
    "FlextLDIFProcessingError",
    "FlextLDIFTimeoutError",
    "FlextLDIFValidationError",
]
