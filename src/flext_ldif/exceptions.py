"""LDIF-specific exceptions for flext-ldif library.

This module provides LDIF domain-specific exception classes extending
flext-core exception patterns with full correlation ID support and
standardized helper methods for context management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextExceptions, FlextResult


class FlextLdifExceptions:
    """LDIF-specific exceptions extending FlextExceptions.

    Provides LDIF domain-specific exception classes for all LDIF processing
    error scenarios while maintaining compatibility with flext-core
    exception hierarchy.

    All LDIF exceptions inherit from FlextExceptions specialized base classes
    and include proper error codes, context, correlation tracking, and
    standardized helper methods for context management.
    """

    # =========================================================================
    # FACTORY METHODS - Create FlextResult.fail() with specific exceptions
    # =========================================================================

    @staticmethod
    def validation_error(
        message: str,
        *,
        field: str | None = None,
        value: object = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create validation error result."""
        error = FlextLdifExceptions.LdifValidationError(message, field=field, value=value, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def parse_error(
        message: str,
        *,
        line_number: int | None = None,
        line_content: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create parse error result."""
        error = FlextLdifExceptions.LdifParseError(message, line_number=line_number, line_content=line_content, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def processing_error(
        message: str,
        *,
        operation: str | None = None,
        entry_dn: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create processing error result."""
        error = FlextLdifExceptions.LdifProcessingError(message, operation=operation, entry_dn=entry_dn, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def file_error(
        message: str,
        *,
        file_path: str | None = None,
        operation: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create file error result."""
        error = FlextLdifExceptions.LdifFileError(message, file_path=file_path, operation=operation, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def configuration_error(
        message: str,
        *,
        config_key: str | None = None,
        config_file: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create configuration error result."""
        error = FlextLdifExceptions.LdifConfigurationError(message, config_key=config_key, config_file=config_file, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def connection_error(message: str, **kwargs: object) -> FlextResult[object]:
        """Create connection error result."""
        # Use generic operation error for connection issues
        error = FlextExceptions._OperationError(message, operation="CONNECTION", code="CONNECTION_ERROR", **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def timeout_error(message: str, **kwargs: object) -> FlextResult[object]:
        """Create timeout error result."""
        error = FlextExceptions._OperationError(message, operation="TIMEOUT", code="TIMEOUT_ERROR", **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def authentication_error(message: str, **kwargs: object) -> FlextResult[object]:
        """Create authentication error result."""
        error = FlextExceptions._ValidationError(message, field="authentication", code="AUTHENTICATION_ERROR", **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def error(message: str, **kwargs: object) -> FlextResult[object]:
        """Create generic error result."""
        error = FlextExceptions._OperationError(message, operation="GENERIC", code="GENERIC_ERROR", **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def entry_error(
        message: str,
        *,
        entry_dn: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create entry error result."""
        error = FlextLdifExceptions.LdifEntryError(message, entry_dn=entry_dn, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def dn_validation_error(
        message: str,
        *,
        dn_value: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create DN validation error result."""
        error = FlextLdifExceptions.LdifDnValidationError(message, dn_value=dn_value, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def attribute_validation_error(
        message: str,
        *,
        attribute_name: str | None = None,
        attribute_value: object = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create attribute validation error result."""
        error = FlextLdifExceptions.LdifAttributeValidationError(message, attribute_name=attribute_name, attribute_value=attribute_value, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def encoding_error(
        message: str,
        *,
        encoding: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create encoding error result."""
        error = FlextLdifExceptions.LdifEncodingError(message, encoding=encoding, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def url_validation_error(
        message: str,
        *,
        url: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create URL validation error result."""
        error = FlextLdifExceptions.LdifUrlValidationError(message, url=url, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def schema_validation_error(
        message: str,
        *,
        schema_name: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create schema validation error result."""
        error = FlextLdifExceptions.LdifSchemaValidationError(message, schema_name=schema_name, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def objectclass_error(
        message: str,
        *,
        objectclass: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create objectClass error result."""
        error = FlextLdifExceptions.LdifObjectClassError(message, objectclass=objectclass, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def ldif_format_error(
        message: str,
        *,
        line_number: int | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create LDIF format error result."""
        error = FlextLdifExceptions.LdifFormatError(message, line_number=line_number, **kwargs)
        return FlextResult[object].fail(error)

    @staticmethod
    def rfc_compliance_error(
        message: str,
        *,
        rfc_section: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Create RFC compliance error result."""
        error = FlextLdifExceptions.LdifRfcComplianceError(message, rfc_section=rfc_section, **kwargs)
        return FlextResult[object].fail(error)

    # =========================================================================
    # EXCEPTION CLASSES
    # =========================================================================

    class LdifValidationError(FlextExceptions._ValidationError):
        """LDIF data validation failure.

        Raised when LDIF data validation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            field: str | None = None,
            value: object = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF validation error.

            Args:
                message: Error message
                field: LDIF field/attribute that failed validation
                value: Invalid value
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.ldif_field = field
            self.invalid_value = value

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                ldif_field=field,
                invalid_value=value,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                field=field,
                code=error_code or "LDIF_VALIDATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifParseError(FlextExceptions._OperationError):
        """LDIF parsing failure.

        Raised when LDIF parsing operation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            line_number: int | None = None,
            line_content: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF parse error.

            Args:
                message: Error message
                line_number: Line number where parsing failed
                line_content: Content of the line that failed parsing
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.line_number = line_number
            self.line_content = line_content

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                line_number=line_number,
                line_content=line_content,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                operation="LDIF_PARSE",
                code=error_code or "LDIF_PARSE_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifProcessingError(FlextExceptions._OperationError):
        """LDIF processing operation failure.

        Raised when LDIF processing operation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            operation: str | None = None,
            entry_dn: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF processing error.

            Args:
                message: Error message
                operation: LDIF operation that failed
                entry_dn: DN of entry being processed
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.ldif_operation = operation
            self.entry_dn = entry_dn

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                ldif_operation=operation,
                entry_dn=entry_dn,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                operation=operation or "LDIF_PROCESSING",
                code=error_code or "LDIF_PROCESSING_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifFileError(FlextExceptions._OperationError):
        """LDIF file operation failure.

        Raised when LDIF file operations fail.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            file_path: str | None = None,
            operation: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF file error.

            Args:
                message: Error message
                file_path: Path to LDIF file
                operation: File operation that failed
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.file_path = file_path
            self.file_operation = operation

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                file_path=file_path,
                file_operation=operation,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                operation=operation or "LDIF_FILE_OPERATION",
                code=error_code or "LDIF_FILE_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifConfigurationError(FlextExceptions._ConfigurationError):
        """LDIF configuration error.

        Raised when LDIF configuration is invalid or missing.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            config_key: str | None = None,
            config_file: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF configuration error.

            Args:
                message: Error message
                config_key: Configuration key that is invalid
                config_file: Configuration file path
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.ldif_config_key = config_key
            self.config_file = config_file

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                ldif_config_key=config_key,
                config_file=config_file,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                config_key=config_key,
                code=error_code or "LDIF_CONFIGURATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifDnValidationError(FlextExceptions._ValidationError):
        """LDIF DN validation failure.

        Raised when Distinguished Name validation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn_value: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF DN validation error.

            Args:
                message: Error message
                dn_value: Invalid DN value
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.dn_value = dn_value

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                dn_value=dn_value,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                field="dn",
                code=error_code or "LDIF_DN_VALIDATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifAttributeValidationError(FlextExceptions._ValidationError):
        """LDIF attribute validation failure.

        Raised when LDIF attribute validation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            attribute_name: str | None = None,
            attribute_value: object = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF attribute validation error.

            Args:
                message: Error message
                attribute_name: Name of invalid attribute
                attribute_value: Invalid attribute value
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.attribute_name = attribute_name
            self.attribute_value = attribute_value

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                attribute_name=attribute_name,
                attribute_value=attribute_value,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                field=attribute_name,
                code=error_code or "LDIF_ATTRIBUTE_VALIDATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifEncodingError(FlextExceptions._OperationError):
        """LDIF encoding/decoding failure.

        Raised when LDIF encoding or decoding fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            encoding: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF encoding error.

            Args:
                message: Error message
                encoding: Character encoding that failed
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.encoding = encoding

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                encoding=encoding,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                operation="LDIF_ENCODING",
                code=error_code or "LDIF_ENCODING_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifUrlValidationError(FlextExceptions._ValidationError):
        """LDIF URL validation failure.

        Raised when LDIF URL validation fails (for URL-encoded entries).
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            url: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF URL validation error.

            Args:
                message: Error message
                url: Invalid URL value
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.url_value = url

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                url_value=url,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                field="url",
                code=error_code or "LDIF_URL_VALIDATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifSchemaValidationError(FlextExceptions._ValidationError):
        """LDIF schema validation failure.

        Raised when LDIF schema validation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            schema_name: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF schema validation error.

            Args:
                message: Error message
                schema_name: Schema name that validation failed against
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.schema_name = schema_name

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                schema_name=schema_name,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                field="schema",
                code=error_code or "LDIF_SCHEMA_VALIDATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifObjectClassError(FlextExceptions._ValidationError):
        """LDIF objectClass error.

        Raised when objectClass validation or processing fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            objectclass: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF objectClass error.

            Args:
                message: Error message
                objectclass: ObjectClass value that caused error
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.objectclass = objectclass

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                objectclass=objectclass,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                field="objectClass",
                code=error_code or "LDIF_OBJECTCLASS_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifFormatError(FlextExceptions._OperationError):
        """LDIF format error.

        Raised when LDIF format is invalid or doesn't conform to RFC 2849.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            line_number: int | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF format error.

            Args:
                message: Error message
                line_number: Line number where format error occurred
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.line_number = line_number

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                line_number=line_number,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                operation="LDIF_FORMAT_VALIDATION",
                code=error_code or "LDIF_FORMAT_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifRfcComplianceError(FlextExceptions._ValidationError):
        """LDIF RFC compliance error.

        Raised when LDIF doesn't comply with RFC 2849 standard.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            rfc_section: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF RFC compliance error.

            Args:
                message: Error message
                rfc_section: RFC 2849 section that was violated
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.rfc_section = rfc_section

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                rfc_section=rfc_section,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                field="rfc_compliance",
                code=error_code or "LDIF_RFC_COMPLIANCE_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class LdifEntryError(FlextExceptions._OperationError):
        """LDIF entry processing error.

        Raised when LDIF entry processing fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            entry_dn: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDIF entry error.

            Args:
                message: Error message
                entry_dn: DN of entry that caused error
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.entry_dn = entry_dn

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with LDIF-specific fields
            context = self._build_context(
                base_context,
                entry_dn=entry_dn,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                operation="LDIF_ENTRY_PROCESSING",
                code=error_code or "LDIF_ENTRY_ERROR",
                context=context,
                correlation_id=correlation_id,
            )


# Export nested exception classes for easier importing
LdifValidationError = FlextLdifExceptions.LdifValidationError
LdifParseError = FlextLdifExceptions.LdifParseError
LdifProcessingError = FlextLdifExceptions.LdifProcessingError
LdifFileError = FlextLdifExceptions.LdifFileError
LdifConfigurationError = FlextLdifExceptions.LdifConfigurationError
LdifDnValidationError = FlextLdifExceptions.LdifDnValidationError
LdifAttributeValidationError = FlextLdifExceptions.LdifAttributeValidationError
LdifEncodingError = FlextLdifExceptions.LdifEncodingError
LdifUrlValidationError = FlextLdifExceptions.LdifUrlValidationError
LdifSchemaValidationError = FlextLdifExceptions.LdifSchemaValidationError
LdifObjectClassError = FlextLdifExceptions.LdifObjectClassError
LdifFormatError = FlextLdifExceptions.LdifFormatError
LdifRfcComplianceError = FlextLdifExceptions.LdifRfcComplianceError
LdifEntryError = FlextLdifExceptions.LdifEntryError

__all__ = [
    "FlextLdifExceptions",
    "LdifAttributeValidationError",
    "LdifConfigurationError",
    "LdifDnValidationError",
    "LdifEncodingError",
    "LdifEntryError",
    "LdifFileError",
    "LdifFormatError",
    "LdifObjectClassError",
    "LdifParseError",
    "LdifProcessingError",
    "LdifRfcComplianceError",
    "LdifSchemaValidationError",
    "LdifUrlValidationError",
    "LdifValidationError",
]
