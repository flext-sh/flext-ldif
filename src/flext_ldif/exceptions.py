"""FLEXT-LDIF Exception System - Direct flext-core usage.

Minimal LDIF-specific exception extensions using flext-core directly.
No duplication of existing functionality - only domain-specific additions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar, cast

from flext_core import FlextConstants, FlextExceptions, FlextModels


class FlextLDIFExceptions(FlextModels.AggregateRoot):
    """LDIF Exception System using flext-core directly.

    Provides LDIF-specific convenience methods while using flext-core
    exception infrastructure directly. No duplication of base functionality.
    """

    # LDIF-specific error codes (ClassVar to avoid Pydantic field detection)
    LDIF_PARSE_ERROR: ClassVar[str] = "LDIF_PARSE_ERROR"
    LDIF_ENTRY_ERROR: ClassVar[str] = "LDIF_ENTRY_ERROR"
    LDIF_SCHEMA_ERROR: ClassVar[str] = "LDIF_SCHEMA_ERROR"
    LDIF_FORMAT_ERROR: ClassVar[str] = "LDIF_FORMAT_ERROR"
    LDIF_ENCODING_ERROR: ClassVar[str] = "LDIF_ENCODING_ERROR"

    # Direct access to flext-core exception classes (using Any for mypy compatibility)
    BaseError: ClassVar[type] = FlextExceptions.BaseError  # type: ignore[type-arg]
    ValidationError: ClassVar[type] = FlextExceptions.ValidationError  # type: ignore[type-arg]

    # Compatibility class aliases for tests
    Error: ClassVar[type] = FlextExceptions.BaseError  # type: ignore[type-arg]
    ParseError: ClassVar[type] = FlextExceptions.ProcessingError  # type: ignore[type-arg]
    EntryError: ClassVar[type] = FlextExceptions.ProcessingError  # type: ignore[type-arg]
    LdifConnectionError: ClassVar[type] = FlextExceptions.ConnectionError  # type: ignore[type-arg]
    LdifFileError: ClassVar[type] = FlextExceptions.OperationError  # type: ignore[type-arg]
    LdifValidationError: ClassVar[type] = FlextExceptions.ValidationError  # type: ignore[type-arg]
    ProcessingError: ClassVar[type] = FlextExceptions.ProcessingError  # type: ignore[type-arg]
    ConfigurationError: ClassVar[type] = FlextExceptions.ConfigurationError  # type: ignore[type-arg]
    ConnectionError: ClassVar[type] = FlextExceptions.ConnectionError  # type: ignore[type-arg]
    AuthenticationError: ClassVar[type] = FlextExceptions.AuthenticationError  # type: ignore[type-arg]
    TimeoutError: ClassVar[type] = FlextExceptions.TimeoutError  # type: ignore[type-arg]
    NotFoundError: ClassVar[type] = FlextExceptions.NotFoundError  # type: ignore[type-arg]

    @classmethod
    def parse_error(
        cls,
        message: str,
        *,
        line: int | None = None,
        column: int | None = None,
        **kwargs: object,
    ) -> FlextExceptions.BaseError:
        """Create LDIF parse error with location context."""
        context_data = kwargs.get("context", {})
        context: dict[str, object] = dict(context_data) if isinstance(context_data, dict) else {}
        if line is not None:
            context["line"] = line
        if column is not None:
            context["column"] = column

        return FlextExceptions.ProcessingError(
            message,
            operation="ldif_parsing",
            code=cls.LDIF_PARSE_ERROR,
            context=context,
        )

    @classmethod
    def entry_error(
        cls,
        message: str,
        *,
        entry_dn: str | None = None,
        entry_data: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> FlextExceptions.BaseError:
        """Create LDIF entry processing error."""
        context_data = kwargs.get("context", {})
        context: dict[str, object] = dict(context_data) if isinstance(context_data, dict) else {}
        if entry_dn is not None:
            context["entry_dn"] = entry_dn
        if entry_data is not None:
            context["entry_data"] = dict(entry_data)

        return FlextExceptions.ProcessingError(
            message,
            operation="ldif_entry_processing",
            code=cls.LDIF_ENTRY_ERROR,
            context=context,
        )

    @classmethod
    def validation_error(
        cls,
        message: str,
        *,
        entry_dn: str | None = None,
        validation_rule: str | None = None,
        **kwargs: object,
    ) -> FlextExceptions.BaseError:  # type: ignore[return-value]
        """Create LDIF validation error with domain context."""
        context_data = kwargs.get("context", {})
        context: dict[str, object] = dict(context_data) if isinstance(context_data, dict) else {}
        if entry_dn is not None:
            context["entry_dn"] = entry_dn
        if validation_rule is not None:
            context["validation_rule"] = validation_rule

        return FlextExceptions.ValidationError(
            message,
            field="ldif_entry",
            validation_details=validation_rule,
            code=FlextConstants.Errors.VALIDATION_ERROR,
            context=context,
        )

    # ALIASES SIMPLES para métodos que os testes esperam (SOURCE OF TRUTH: flext-core)
    @classmethod
    def processing_error(cls, message: str, *, operation: str | None = None, **kwargs: object) -> FlextExceptions.BaseError:  # type: ignore[return-value]
        """Alias simples para FlextExceptions.ProcessingError."""
        # Usa flext-core create como SOURCE OF TRUTH
        # Filter kwargs to only include valid parameters
        valid_keys = {"field", "config_key"}
        filtered_kwargs = {k: v for k, v in kwargs.items() if k in valid_keys}
        return FlextExceptions.create(
            message,
            operation=operation,
            error_code=cls.LDIF_PARSE_ERROR,
            **filtered_kwargs  # type: ignore[arg-type]
        )

    @classmethod
    def timeout_error(cls, message: str, *, timeout_duration: float | None = None, **kwargs: object) -> FlextExceptions.BaseError:
        """Alias simples para FlextExceptions.TimeoutError."""
        # Usa flext-core create como SOURCE OF TRUTH
        # Filter kwargs to only include valid parameters
        valid_keys = {"operation", "field", "config_key"}
        filtered_kwargs = {k: v for k, v in kwargs.items() if k in valid_keys}
        # Store timeout_duration in filtered_kwargs since create() doesn't have this parameter
        filtered_kwargs["timeout_duration"] = timeout_duration
        return FlextExceptions.create(
            message,
            error_code=cls.LDIF_PARSE_ERROR,
            **filtered_kwargs  # type: ignore[arg-type]
        )

    @classmethod
    def error(cls, message: str, **kwargs: object) -> FlextExceptions.BaseError:
        """Create generic LDIF error."""
        # BaseError accepts specific keyword arguments only - cast types properly
        code_val = kwargs.get("code")
        context_val = kwargs.get("context")
        correlation_id_val = kwargs.get("correlation_id")

        return FlextExceptions.BaseError(
            message,
            code=str(code_val) if code_val is not None else None,
            context=cast("Mapping[str, object]", context_val) if context_val is not None else None,
            correlation_id=str(correlation_id_val) if correlation_id_val is not None else None
        )

    @classmethod
    def connection_error(cls, message: str, **kwargs: object) -> FlextExceptions.BaseError:
        """Create LDIF connection error."""
        return FlextExceptions.ConnectionError(message, **kwargs)  # type: ignore[arg-type]

    @classmethod
    def file_error(cls, message: str, *, file_path: str | None = None, operation: str | None = None, **kwargs: object) -> FlextExceptions.BaseError:
        """Create LDIF file error."""
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            if file_path is not None:
                context["file_path"] = file_path
            if operation is not None:
                context["operation"] = operation
            kwargs["context"] = context
        return FlextExceptions.OperationError(message, **kwargs)  # type: ignore[arg-type]

    @classmethod
    def configuration_error(cls, message: str = "LDIF configuration error", **kwargs: object) -> FlextExceptions.BaseError:
        """Create LDIF configuration error."""
        kwargs["code"] = FlextLDIFErrorCodes.LDIF_CONFIGURATION_ERROR.value
        return FlextExceptions.BaseError(message, **kwargs)  # type: ignore[arg-type]

    @classmethod
    def authentication_error(cls, message: str, **kwargs: object) -> FlextExceptions.BaseError:
        """Create LDIF authentication error."""
        return FlextExceptions.AuthenticationError(message, **kwargs)  # type: ignore[arg-type]

    # ALIASES SIMPLES para compatibilidade de testes (SOURCE OF TRUTH: flext-core)
    @classmethod
    def builder(cls) -> ExceptionBuilder:
        """Alias simples para flext-core builder pattern."""
        return ExceptionBuilder()


# Classe simples para compatibilidade de testes - usa flext-core SOURCE OF TRUTH
class ExceptionBuilder:
    """Builder simples usando flext-core create method como SOURCE OF TRUTH."""

    def __init__(self) -> None:
        self._params: dict[str, object] = {}

    def message(self, message: str) -> ExceptionBuilder:
        self._params["message"] = message
        return self

    def code(self, code: str) -> ExceptionBuilder:
        self._params["code"] = code
        return self

    def location(self, line: int | None = None, column: int | None = None) -> ExceptionBuilder:
        if line is not None:
            self._params["line"] = line
        if column is not None:
            self._params["column"] = column
        return self

    def entry_data(self, data: dict[str, object]) -> ExceptionBuilder:
        self._params["entry_data"] = data
        return self

    def validation_rule(self, rule: str) -> ExceptionBuilder:
        self._params["validation_rule"] = rule
        return self

    def context(self, context: dict[str, object]) -> ExceptionBuilder:
        self._params["context"] = context
        return self

    def dn(self, dn: str) -> ExceptionBuilder:
        self._params["dn"] = dn
        return self

    def attribute(self, attribute: str) -> ExceptionBuilder:
        self._params["attribute"] = attribute
        return self

    def entry_index(self, index: int) -> ExceptionBuilder:
        self._params["entry_index"] = index
        return self

    def file_path(self, path: str) -> ExceptionBuilder:
        self._params["file_path"] = path
        return self

    def operation(self, operation: str) -> ExceptionBuilder:
        self._params["operation"] = operation
        return self

    def build(self) -> FlextExceptions.BaseError:
        # Usa FlextExceptions.create como SOURCE OF TRUTH
        message = self._params.get("message", "LDIF error")
        error_code = self._params.get("code", "LDIF_ERROR")
        operation = self._params.get("operation")
        field = self._params.get("field")
        config_key = self._params.get("config_key")

        # Cast to proper types for mypy
        message_str = str(message) if message is not None else "LDIF error"
        error_code_str = str(error_code) if error_code is not None else None
        operation_str = str(operation) if operation is not None else None
        field_str = str(field) if field is not None else None
        config_key_str = str(config_key) if config_key is not None else None

        return FlextExceptions.create(
            message_str,
            error_code=error_code_str,
            operation=operation_str,
            field=field_str,
            config_key=config_key_str,
            **{k: v for k, v in self._params.items() if k not in ["message", "code", "operation", "field", "config_key"]}
        )


# Alias simples para códigos de erro - compatibilidade de testes
class _ErrorCode:
    """Simple error code with value attribute for enum compatibility."""

    def __init__(self, value: str) -> None:
        self.value = value


class FlextLDIFErrorCodes:
    """Códigos de erro LDIF - alias simples para testes com enum compatibility."""

    # Cada constante tem seu próprio valor para compatibilidade de testes
    LDIF_PARSE_ERROR = _ErrorCode("LDIF_PARSE_ERROR")
    LDIF_ENTRY_ERROR = _ErrorCode("LDIF_ENTRY_ERROR")
    LDIF_VALIDATION_ERROR = _ErrorCode("LDIF_VALIDATION_ERROR")
    LDIF_ERROR = _ErrorCode("LDIF_ERROR")
    LDIF_CONNECTION_ERROR = _ErrorCode("LDIF_CONNECTION_ERROR")
    LDIF_FILE_ERROR = _ErrorCode("LDIF_FILE_ERROR")
    LDIF_PROCESSING_ERROR = _ErrorCode("LDIF_PROCESSING_ERROR")
    LDIF_TIMEOUT_ERROR = _ErrorCode("LDIF_TIMEOUT_ERROR")
    LDIF_AUTHENTICATION_ERROR = _ErrorCode("LDIF_AUTHENTICATION_ERROR")
    LDIF_CONFIGURATION_ERROR = _ErrorCode("LDIF_CONFIGURATION_ERROR")


# Aliases simples para compatibilidade de testes - classes com argumentos flexíveis
class FlextLDIFError(Exception):
    """LDIF Error base alias para testes."""

    def __init__(self, message: str, *, context: dict[str, object] | None = None, **kwargs: object) -> None:
        super().__init__(message)
        self.context = context
        self.kwargs = kwargs


class FlextLDIFParseError(FlextLDIFError):
    """LDIF Parse error alias para testes."""


class FlextLDIFValidationError(FlextLDIFError):
    """LDIF Validation error alias para testes."""


class FlextLDIFConnectionError(FlextLDIFError):
    """LDIF Connection error alias para testes."""


class FlextLDIFFileError(FlextLDIFError):
    """LDIF File error alias para testes."""


class FlextLDIFProcessingError(FlextLDIFError):
    """LDIF Processing error alias para testes."""


class FlextLDIFTimeoutError(FlextLDIFError):
    """LDIF Timeout error alias para testes."""


class FlextLDIFAuthenticationError(FlextLDIFError):
    """LDIF Authentication error alias para testes."""


__all__ = [
    "ExceptionBuilder",
    "FlextLDIFAuthenticationError",
    "FlextLDIFConnectionError",
    "FlextLDIFError",
    "FlextLDIFErrorCodes",
    "FlextLDIFExceptions",
    "FlextLDIFFileError",
    "FlextLDIFParseError",
    "FlextLDIFProcessingError",
    "FlextLDIFTimeoutError",
    "FlextLDIFValidationError",
]
