"""Real tests for exceptions module - 100% coverage, zero mocks."""

from __future__ import annotations

import pytest

from flext_ldif.exceptions import FlextLDIFErrorCodes, FlextLDIFExceptions


class TestFlextLDIFErrorCodes:
    """Test FlextLDIFErrorCodes enumeration."""

    def test_all_error_codes_exist(self) -> None:
        """Test that all expected error codes are defined."""
        expected_codes = [
            "LDIF_ERROR",
            "LDIF_VALIDATION_ERROR",
            "LDIF_PARSE_ERROR",
            "LDIF_ENTRY_ERROR",
            "LDIF_CONFIGURATION_ERROR",
            "LDIF_PROCESSING_ERROR",
            "LDIF_CONNECTION_ERROR",
            "LDIF_AUTHENTICATION_ERROR",
            "LDIF_TIMEOUT_ERROR",
            "LDIF_FILE_ERROR",
        ]

        for code in expected_codes:
            assert hasattr(FlextLDIFErrorCodes, code)
            assert FlextLDIFErrorCodes[code].value == code

    def test_error_codes_are_strings(self) -> None:
        """Test that all error codes are strings."""
        for error_code in FlextLDIFErrorCodes:
            assert isinstance(error_code.value, str)
            assert error_code.value == error_code.name


class TestFlextLDIFExceptionsError:
    """Test FlextLDIFExceptions.Error base class."""

    def test_init_default_message(self) -> None:
        """Test Error initialization with default message."""
        error = FlextLDIFExceptions.Error()

        assert "LDIF operation failed" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_ERROR.value
        # FlextCore may initialize empty context as empty dict
        assert error.context is None or error.context == {}

    def test_init_custom_message(self) -> None:
        """Test Error initialization with custom message."""
        custom_message = "Custom LDIF error message"
        error = FlextLDIFExceptions.Error(custom_message)

        assert custom_message in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_ERROR.value

    def test_init_custom_error_code(self) -> None:
        """Test Error initialization with custom error code."""
        custom_code = "CUSTOM_LDIF_ERROR"
        error = FlextLDIFExceptions.Error("Test message", error_code=custom_code)

        assert error.code == custom_code

    def test_init_with_context(self) -> None:
        """Test Error initialization with context."""
        context = {"operation": "parse", "line": 42}
        error = FlextLDIFExceptions.Error("Test message", context=context)

        assert error.context == context

    def test_init_context_conversion(self) -> None:
        """Test that context is converted to dict."""

        # Use a mapping that's not a dict
        class CustomMapping:
            def __init__(self, data: dict[str, object]) -> None:
                self._data = data

            def __iter__(self):
                return iter(self._data)

            def __getitem__(self, key):
                return self._data[key]

            def keys(self):
                return self._data.keys()

            def values(self):
                return self._data.values()

            def items(self):
                return self._data.items()

        custom_context = CustomMapping({"key": "value"})
        error = FlextLDIFExceptions.Error("Test", context=custom_context)

        assert isinstance(error.context, dict)
        assert error.context == {"key": "value"}

    def test_init_none_context(self) -> None:
        """Test Error initialization with None context."""
        error = FlextLDIFExceptions.Error("Test message", context=None)

        # FlextCore may initialize empty context as empty dict
        assert error.context is None or error.context == {}


class TestFlextLDIFExceptionsValidationError:
    """Test FlextLDIFExceptions.ValidationError class."""

    def test_init_default_message(self) -> None:
        """Test ValidationError initialization with default message."""
        error = FlextLDIFExceptions.ValidationError()

        assert "LDIF validation failed" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_VALIDATION_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test ValidationError initialization with custom message."""
        custom_message = "DN validation failed"
        error = FlextLDIFExceptions.ValidationError(custom_message)

        assert custom_message in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_VALIDATION_ERROR.value

    def test_init_custom_error_code(self) -> None:
        """Test ValidationError initialization with custom error code."""
        custom_code = "CUSTOM_VALIDATION_ERROR"
        error = FlextLDIFExceptions.ValidationError("Test", error_code=custom_code)

        assert error.code == custom_code

    def test_init_with_context(self) -> None:
        """Test ValidationError initialization with context."""
        context = {"field": "dn", "value": "invalid-dn"}
        error = FlextLDIFExceptions.ValidationError(
            "Validation failed", context=context
        )

        assert error.context == context

    def test_inheritance(self) -> None:
        """Test that ValidationError inherits from Error."""
        error = FlextLDIFExceptions.ValidationError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsParseError:
    """Test FlextLDIFExceptions.ParseError class."""

    def test_init_default_message(self) -> None:
        """Test ParseError initialization with default message."""
        error = FlextLDIFExceptions.ParseError()

        assert "LDIF parsing failed" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_PARSE_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test ParseError initialization with custom message."""
        custom_message = "Invalid LDIF syntax"
        error = FlextLDIFExceptions.ParseError(custom_message)

        assert custom_message in str(error)

    def test_init_with_line_number(self) -> None:
        """Test ParseError initialization with line number."""
        error = FlextLDIFExceptions.ParseError("Parse error", line_number=42)

        assert error.context is not None
        assert error.context["line_number"] == 42

    def test_init_with_column(self) -> None:
        """Test ParseError initialization with column."""
        error = FlextLDIFExceptions.ParseError("Parse error", column=15)

        assert error.context is not None
        assert error.context["column"] == 15

    def test_init_with_line_and_column(self) -> None:
        """Test ParseError initialization with line and column."""
        error = FlextLDIFExceptions.ParseError("Parse error", line_number=42, column=15)

        assert error.context is not None
        assert error.context["line_number"] == 42
        assert error.context["column"] == 15

    def test_init_with_context_and_location(self) -> None:
        """Test ParseError initialization with both context and location."""
        context = {"operation": "parse_entry"}
        error = FlextLDIFExceptions.ParseError(
            "Parse error", context=context, line_number=42, column=15
        )

        assert error.context is not None
        assert error.context["operation"] == "parse_entry"
        assert error.context["line_number"] == 42
        assert error.context["column"] == 15

    def test_init_with_custom_error_code(self) -> None:
        """Test ParseError initialization with custom error code."""
        custom_code = "CUSTOM_PARSE_ERROR"
        error = FlextLDIFExceptions.ParseError("Test", error_code=custom_code)

        assert error.code == custom_code

    def test_inheritance(self) -> None:
        """Test that ParseError inherits from Error."""
        error = FlextLDIFExceptions.ParseError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsEntryError:
    """Test FlextLDIFExceptions.EntryError class."""

    def test_init_default_message(self) -> None:
        """Test EntryError initialization with default message."""
        error = FlextLDIFExceptions.EntryError()

        assert "LDIF entry error" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_ENTRY_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test EntryError initialization with custom message."""
        custom_message = "Entry DN is invalid"
        error = FlextLDIFExceptions.EntryError(custom_message)

        assert custom_message in str(error)

    def test_init_with_entry_dn(self) -> None:
        """Test EntryError initialization with entry DN."""
        dn = "uid=test,ou=people,dc=example,dc=com"
        error = FlextLDIFExceptions.EntryError("Entry error", entry_dn=dn)

        assert error.context is not None
        assert error.context["entry_dn"] == dn

    def test_init_with_context_and_entry_dn(self) -> None:
        """Test EntryError initialization with context and entry DN."""
        dn = "uid=test,ou=people,dc=example,dc=com"
        context = {"operation": "validate"}
        error = FlextLDIFExceptions.EntryError(
            "Entry error", context=context, entry_dn=dn
        )

        assert error.context is not None
        assert error.context["operation"] == "validate"
        assert error.context["entry_dn"] == dn

    def test_inheritance(self) -> None:
        """Test that EntryError inherits from Error."""
        error = FlextLDIFExceptions.EntryError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsConfigurationError:
    """Test FlextLDIFExceptions.ConfigurationError class."""

    def test_init_default_message(self) -> None:
        """Test ConfigurationError initialization with default message."""
        error = FlextLDIFExceptions.ConfigurationError()

        assert "LDIF configuration error" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_CONFIGURATION_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test ConfigurationError initialization with custom message."""
        custom_message = "Invalid LDIF configuration setting"
        error = FlextLDIFExceptions.ConfigurationError(custom_message)

        assert custom_message in str(error)

    def test_init_with_config_key(self) -> None:
        """Test ConfigurationError initialization with config key."""
        config_key = "ldif_encoding"
        error = FlextLDIFExceptions.ConfigurationError(
            "Config error", config_key=config_key
        )

        assert error.context is not None
        assert error.context["config_key"] == config_key

    def test_inheritance(self) -> None:
        """Test that ConfigurationError inherits from Error."""
        error = FlextLDIFExceptions.ConfigurationError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsProcessingError:
    """Test FlextLDIFExceptions.ProcessingError class."""

    def test_init_default_message(self) -> None:
        """Test ProcessingError initialization with default message."""
        error = FlextLDIFExceptions.ProcessingError()

        assert "LDIF processing failed" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_PROCESSING_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test ProcessingError initialization with custom message."""
        custom_message = "LDIF transformation failed"
        error = FlextLDIFExceptions.ProcessingError(custom_message)

        assert custom_message in str(error)

    def test_init_with_operation(self) -> None:
        """Test ProcessingError initialization with operation."""
        operation = "transform"
        error = FlextLDIFExceptions.ProcessingError(
            "Processing failed", operation=operation
        )

        assert error.context is not None
        assert error.context["operation"] == operation

    def test_inheritance(self) -> None:
        """Test that ProcessingError inherits from Error."""
        error = FlextLDIFExceptions.ProcessingError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsLdifConnectionError:
    """Test FlextLDIFExceptions.LdifConnectionError class."""

    def test_init_default_message(self) -> None:
        """Test LdifConnectionError initialization with default message."""
        error = FlextLDIFExceptions.LdifConnectionError()

        assert "LDIF connection failed" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_CONNECTION_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test LdifConnectionError initialization with custom message."""
        custom_message = "Failed to connect to LDAP server"
        error = FlextLDIFExceptions.LdifConnectionError(custom_message)

        assert custom_message in str(error)

    def test_init_with_server_and_port(self) -> None:
        """Test LdifConnectionError initialization with server and port."""
        server = "ldap.example.com"
        port = 389
        error = FlextLDIFExceptions.LdifConnectionError(
            "Connection failed", server=server, port=port
        )

        assert error.context is not None
        assert error.context["server"] == server
        assert error.context["port"] == port

    def test_inheritance(self) -> None:
        """Test that LdifConnectionError inherits from Error."""
        error = FlextLDIFExceptions.LdifConnectionError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsAuthenticationError:
    """Test FlextLDIFExceptions.AuthenticationError class."""

    def test_init_default_message(self) -> None:
        """Test AuthenticationError initialization with default message."""
        error = FlextLDIFExceptions.AuthenticationError()

        assert "LDIF authentication failed" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_AUTHENTICATION_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test AuthenticationError initialization with custom message."""
        custom_message = "Invalid LDAP credentials"
        error = FlextLDIFExceptions.AuthenticationError(custom_message)

        assert custom_message in str(error)

    def test_init_with_username(self) -> None:
        """Test AuthenticationError initialization with username."""
        username = "testuser"
        error = FlextLDIFExceptions.AuthenticationError(
            "Auth failed", username=username
        )

        assert error.context is not None
        assert error.context["username"] == username

    def test_inheritance(self) -> None:
        """Test that AuthenticationError inherits from Error."""
        error = FlextLDIFExceptions.AuthenticationError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsLdifTimeoutError:
    """Test FlextLDIFExceptions.LdifTimeoutError class."""

    def test_init_default_message(self) -> None:
        """Test LdifTimeoutError initialization with default message."""
        error = FlextLDIFExceptions.LdifTimeoutError()

        assert "LDIF operation timed out" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_TIMEOUT_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test LdifTimeoutError initialization with custom message."""
        custom_message = "LDAP operation timed out after 30 seconds"
        error = FlextLDIFExceptions.LdifTimeoutError(custom_message)

        assert custom_message in str(error)

    def test_init_with_timeout_seconds(self) -> None:
        """Test LdifTimeoutError initialization with timeout seconds."""
        timeout_seconds = 30.5
        error = FlextLDIFExceptions.LdifTimeoutError(
            "Timeout", timeout_seconds=timeout_seconds
        )

        assert error.context is not None
        assert error.context["timeout_seconds"] == timeout_seconds

    def test_inheritance(self) -> None:
        """Test that LdifTimeoutError inherits from Error."""
        error = FlextLDIFExceptions.LdifTimeoutError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsFileError:
    """Test FlextLDIFExceptions.FileError class."""

    def test_init_default_message(self) -> None:
        """Test FileError initialization with default message."""
        error = FlextLDIFExceptions.FileError()

        assert "LDIF file operation failed" in str(error)
        assert error.code == FlextLDIFErrorCodes.LDIF_FILE_ERROR.value

    def test_init_custom_message(self) -> None:
        """Test FileError initialization with custom message."""
        custom_message = "LDIF file not found"
        error = FlextLDIFExceptions.FileError(custom_message)

        assert custom_message in str(error)

    def test_init_with_file_details(self) -> None:
        """Test FileError initialization with file details."""
        file_path = "/path/to/ldif/file.ldif"
        operation = "read"
        line_number = 42
        encoding = "utf-8"
        error = FlextLDIFExceptions.FileError(
            "File error",
            file_path=file_path,
            operation=operation,
            line_number=line_number,
            encoding=encoding,
        )

        assert error.context is not None
        assert error.context["file_path"] == file_path
        assert error.context["operation"] == operation
        assert error.context["line_number"] == line_number
        assert error.context["encoding"] == encoding

    def test_inheritance(self) -> None:
        """Test that FileError inherits from Error."""
        error = FlextLDIFExceptions.FileError()

        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsEntryValidationError:
    """Test FlextLDIFExceptions.EntryValidationError class."""

    def test_init_default_message(self) -> None:
        """Test EntryValidationError initialization with default message."""
        error = FlextLDIFExceptions.EntryValidationError()

        assert "LDIF entry validation failed" in str(error)

    def test_init_custom_message(self) -> None:
        """Test EntryValidationError initialization with custom message."""
        custom_message = "Entry validation failed for specific rule"
        error = FlextLDIFExceptions.EntryValidationError(custom_message)

        assert custom_message in str(error)

    def test_init_with_validation_details(self) -> None:
        """Test EntryValidationError initialization with validation details."""
        entry_dn = "uid=test,ou=people,dc=example,dc=com"
        attribute_name = "mail"
        attribute_value = "invalid-email"
        validation_rule = "email_format"
        entry_index = 5

        error = FlextLDIFExceptions.EntryValidationError(
            "Validation failed",
            entry_dn=entry_dn,
            attribute_name=attribute_name,
            attribute_value=attribute_value,
            validation_rule=validation_rule,
            entry_index=entry_index,
        )

        assert error.context is not None
        assert error.context["entry_dn"] == entry_dn
        assert error.context["attribute_name"] == attribute_name
        assert error.context["attribute_value"] == attribute_value
        assert error.context["validation_rule"] == validation_rule
        assert error.context["entry_index"] == entry_index

    def test_init_with_dn_alias(self) -> None:
        """Test EntryValidationError initialization with dn alias parameter."""
        dn = "uid=test,ou=people,dc=example,dc=com"
        error = FlextLDIFExceptions.EntryValidationError("Validation failed", dn=dn)

        assert error.context is not None
        # dn is used as entry_dn internally
        assert error.context["entry_dn"] == dn

    def test_inheritance(self) -> None:
        """Test that EntryValidationError inherits from EntryError."""
        error = FlextLDIFExceptions.EntryValidationError()

        assert isinstance(error, FlextLDIFExceptions.EntryError)
        assert isinstance(error, FlextLDIFExceptions.Error)


class TestFlextLDIFExceptionsRaising:
    """Test raising and catching LDIF exceptions."""

    def test_raise_and_catch_error(self) -> None:
        """Test raising and catching base Error."""
        with pytest.raises(FlextLDIFExceptions.Error) as exc_info:
            msg = "Test error"
            raise FlextLDIFExceptions.Error(msg)

        assert "Test error" in str(exc_info.value)
        assert exc_info.value.code == FlextLDIFErrorCodes.LDIF_ERROR.value

    def test_raise_and_catch_validation_error(self) -> None:
        """Test raising and catching ValidationError."""
        with pytest.raises(FlextLDIFExceptions.ValidationError) as exc_info:
            msg = "Validation failed"
            raise FlextLDIFExceptions.ValidationError(msg)

        assert "Validation failed" in str(exc_info.value)
        assert exc_info.value.code == FlextLDIFErrorCodes.LDIF_VALIDATION_ERROR.value

    def test_raise_and_catch_parse_error(self) -> None:
        """Test raising and catching ParseError."""
        with pytest.raises(FlextLDIFExceptions.ParseError) as exc_info:
            msg = "Parse failed"
            raise FlextLDIFExceptions.ParseError(msg, line_number=10)

        assert "Parse failed" in str(exc_info.value)
        assert exc_info.value.context["line_number"] == 10

    def test_catch_derived_as_base(self) -> None:
        """Test catching derived exception as base exception."""
        with pytest.raises(FlextLDIFExceptions.Error) as exc_info:
            msg = "Validation error"
            raise FlextLDIFExceptions.ValidationError(msg)

        # Should catch ValidationError as Error since it inherits from Error
        assert isinstance(exc_info.value, FlextLDIFExceptions.ValidationError)
        assert isinstance(exc_info.value, FlextLDIFExceptions.Error)
