"""FLEXT-LDIF core processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable as _Callable
from functools import reduce
from pathlib import Path
from typing import TypeVar

from flext_core import FlextConstants, FlextLogger, FlextResult, FlextTypes

from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidator
from flext_ldif.models import FlextLDIFModels

T = TypeVar("T")

logger = FlextLogger(__name__)

# Constants for error messages and configuration
MODERNIZED_LDIF_WRITE_FAILED_WITH_ERROR_MSG = "Modernized LDIF write failed: {error}"
FILE_WRITE_FAILED_MSG = "File write operation failed: {error}"
CONTENT_GENERATION_FAILED_FOR_ENTRIES_MSG = "Content generation failed for {entries_count} entries: {error}"
LDIF_FILE_NOT_FOUND_ERROR_MSG = "LDIF file not found: {absolute_path}"
PATH_NOT_FILE_ERROR_MSG = "Path is not a file: {absolute_path}"
ENCODING_ERROR_READING_FILE_MSG = "Encoding error reading file with {encoding}: {error}"
FILE_READ_CONTENT_PREVIEW_SIZE = 200
NEWLINE_TO_ESCAPED_NEWLINE = "\\n"


class ExceptionHandlingStrategy:
    """Strategy Pattern for exception handling with zero duplication.

    Eliminates 22+ lines of duplicated exception handling code by providing
    a unified strategy that handles logging, error formatting, and result
    creation with configurable behavior for different operation types.
    """

    def __init__(
        self,
        operation_name: str,
        constants_class: type = FlextConstants.LDIF,
    ) -> None:
        self.operation_name = operation_name
        self.constants = constants_class

    def handle_exceptions(
        self,
        operation: _Callable[[], FlextResult[T]],
        exception_types: tuple[type[Exception], ...],
        exception_context_log: str,
        exception_details_log: str,
        exception_operation_log: str,
        error_message_template: str,
    ) -> FlextResult[T]:
        """Handle exceptions with unified logging and error handling strategy."""
        try:
            return operation()
        except exception_types as e:
            # Unified logging pattern
            logger.debug(exception_context_log, type(e).__name__)
            logger.debug(exception_details_log, exc_info=True)
            logger.exception(exception_operation_log)

            # Unified error result creation
            error_msg = error_message_template.format(error=e)
            return FlextResult.fail(error_msg)


class LdifOperationStrategies:
    """Pre-configured strategies for different LDIF operations."""

    @staticmethod
    def parsing_strategy() -> ExceptionHandlingStrategy:
        """Strategy for parsing operations."""
        return ExceptionHandlingStrategy("parsing")

    @staticmethod
    def validation_strategy() -> ExceptionHandlingStrategy:
        """Strategy for validation operations.

        Returns:
            ExceptionHandlingStrategy: Validation strategy.

        """
        return ExceptionHandlingStrategy("validation")

    @staticmethod
    def file_operation_strategy() -> ExceptionHandlingStrategy:
        """Strategy for file operations."""
        return ExceptionHandlingStrategy("file_operation")


class FlextLDIFCore:
    """Core LDIF processing functionality.

    Returns:
        ExceptionHandlingStrategy: Core processing result.

    """

    # Standard validation patterns following RFC compliance
    # These provide consistent LDIF validation rules
    # Use flext-core LDIF patterns instead of duplicating
    # Pattern validation is handled by FlextValidators from flext-core
    DN_PATTERN = re.compile(r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$")
    ATTR_NAME_PATTERN = re.compile(r"^[a-zA-Z][\w-]*$")

    # Use local validators to avoid circular dependency
    @classmethod
    def _load_validators(cls) -> tuple[_Callable[[str], bool], _Callable[[str], bool]]:
        """Use local validators to avoid circular dependency with flext-ldap."""
        return FlextLDIFFormatValidator.get_ldap_validators()

    @classmethod
    def parse(cls, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF content into domain entities.

        Args:
            content: LDIF content as string

        Returns:
            FlextResult: Parsed entries or error

        """
        logger.debug(
            "LDIF parse called with content type: %s",
            type(content).__name__,
        )
        logger.debug(
            "Content length: %d",
            len(str(content)),
        )
        try:
            content_str = str(content)
            logger.debug(
                "Content converted: %d characters",
                len(content_str),
            )
            logger.debug(
                "Content preview: %s",
                content_str[:100].replace("\n", "\\n"),
            )

            # Use modernized LDIF parser (no external dependencies)
            logger.debug("Delegating to modernized LDIF parser")
            return cls._parse_with_modernized_ldif(content_str)

        except (
            ValueError,
            TypeError,
            AttributeError,
            OSError,
            ImportError,
        ) as e:
            logger.debug(
                "Exception type: %s",
                type(e).__name__,
            )
            logger.debug(
                "Full exception details",
                exc_info=True,
            )
            logger.exception(
                "Exception in LDIF parse"
            )
            return FlextResult.fail(
                f"Parse failed: {e}"
            )

    @classmethod
    def _parse_with_modernized_ldif(
        cls,
        content: str,
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse using modernized LDIF parser with full string compatibility."""
        logger.debug("Starting modernized parsing")
        logger.debug(
            "Content has %d lines",
            len(content.splitlines()),
        )
        try:
            # Use modernized parser with railway-oriented programming
            logger.debug(
                "Calling modernized LDIF parser"
            )

            def convert_raw_entries(
                raw_entries: list[tuple[str, dict[str, FlextTypes.Core.StringList]]],
            ) -> FlextResult[list[FlextLDIFModels.Entry]]:
                """Convert raw entries to FlextLDIFModels.Entry objects using railway-oriented programming."""
                logger.debug(
                    "Modernized parser returned %d entries",
                    len(raw_entries),
                )
                logger.debug(
                    "Raw entries DNs: %s",
                    [dn for dn, _ in raw_entries[:5]],
                )

                logger.debug(
                    "Converting entries"
                )

                # Process each entry using railway-oriented programming with reduce pattern
                def process_indexed_entry(
                    acc: FlextResult[list[FlextLDIFModels.Entry]],
                    indexed_raw: tuple[
                        int, tuple[str, dict[str, FlextTypes.Core.StringList]]
                    ],
                ) -> FlextResult[list[FlextLDIFModels.Entry]]:
                    i, (dn, attrs) = indexed_raw
                    logger.debug(
                        "Processing entry %d: %s (%d attributes)",
                        i,
                        dn,
                        len(attrs),
                    )

                    def process_entry(
                        entries_list: list[FlextLDIFModels.Entry],
                    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
                        try:
                            entry = FlextLDIFModels.Factory.create_entry(
                                {
                                    "dn": dn,
                                    "attributes": attrs,
                                }
                            )
                        except Exception as e:
                            return FlextResult.fail(
                                f"Failed to create entry from data: {e!s}"
                            )
                        return FlextResult.ok(
                            [
                                *entries_list,
                                entry,
                            ]
                        )

                    return acc.flat_map(process_entry)

                return (
                    reduce(
                        process_indexed_entry,
                        enumerate(raw_entries),
                        FlextResult[list[FlextLDIFModels.Entry]].ok([]),
                    )
                    .tap(
                        lambda entries: logger.debug(
                            "Successfully converted %d entries",
                            len(entries),
                        )
                    )
                    .tap(
                        lambda entries: logger.info(
                            "Modernized parsing completed successfully: %d raw entries -> %d converted entries",
                            len(raw_entries),
                            len(entries),
                        )
                    )
                )

            # Parse LDIF content - format handler already returns FlextResult
            return FlextLDIFFormatHandler.parse_ldif(content)

        except (
            ValueError,
            TypeError,
            AttributeError,
            ImportError,
        ) as e:
            logger.debug(
                "Exception type: %s",
                type(e).__name__,
            )
            logger.debug(
                "Full exception details",
                exc_info=True,
            )
            logger.exception(
                "Exception in modernized parsing"
            )
            return FlextResult.fail(
                f"Modernized LDIF parse failed: {e}",
            )

    @classmethod
    def validate(cls, entry: FlextLDIFModels.Entry | None) -> FlextResult[bool]:
        """Validate LDIF entry with format and business rule validation.

        Args:
            entry: FlextLDIFModels.Entry domain object to validate

        Returns:
            FlextResult: True if valid, error details on failure

        """
        try:
            error_message = cls._get_validation_error(entry)
            if error_message is not None:
                return FlextResult.fail(error_message)
            return FlextResult.ok(data=True)
        except (ValueError, TypeError, AttributeError) as e:
            logger.debug(
                "Exception type: %s",
                type(e).__name__,
            )
            logger.debug(
                "Validation exception details",
                exc_info=True,
            )
            logger.exception(
                "Exception during entry validation",
            )
            return FlextResult.fail(
                f"Entry parse error validation failed: {e}"
            )

    @classmethod
    def _get_validation_error(cls, entry: FlextLDIFModels.Entry | None) -> str | None:
        """Return an error message if validation fails; otherwise None."""
        if entry is None:
            logger.error(
                "Cannot validate None entry"
            )
            return "Entry cannot be None"

        logger.debug(
            "Validating LDIF entry: %s",
            entry.dn,
        )
        logger.debug(
            "Entry has %d attributes",
            len(entry.attributes.data),
        )
        dn_str = str(entry.dn)
        logger.debug(
            "Validating DN format: %s", dn_str
        )
        if not cls.DN_PATTERN.match(dn_str):
            logger.warning(
                "DN failed pattern validation: %s",
                dn_str,
            )
            return (
                FlextConstants.LDIF.VALIDATION_MESSAGES["INVALID_DN"].format(
                    dn=entry.dn
                )
            )
        attr_validator, dn_validator = cls._load_validators()
        if not dn_validator(dn_str):
            logger.warning(
                "DN failed pattern validation: %s",
                dn_str,
            )
            logger.debug(
                "DN failed FLEXT-LDAP validation"
            )
            return (
                FlextConstants.LDIF.VALIDATION_MESSAGES["INVALID_DN"].format(
                    dn=entry.dn
                )
            )
        logger.debug(
            "DN format validation passed"
        )

        logger.debug(
             "Validating %d attribute names",
            len(entry.attributes.data),
        )
        for attr_name in entry.attributes.data:
            logger.debug(
                 "Validating attribute name: %s",
                attr_name,
            )
            if not cls.ATTR_NAME_PATTERN.match(attr_name) or not attr_validator(
                attr_name,
            ):
                logger.warning(
                     "Invalid attribute name: %s",
                    attr_name,
                )
                logger.debug(
                     "Attribute name failed validation",
                )
                return FlextConstants.LDIF.VALIDATION_MESSAGES["INVALID_ATTRIBUTE_NAME"]
        logger.debug(
            "All attribute names validated"
        )

        logger.debug(
            "Checking required objectClass"
        )
        if not entry.has_attribute(
            "objectclass"
        ):
            logger.warning(
                 "Missing objectClass in entry: %s",
                entry.dn,
            )
            logger.debug(
                 "OBJECTCLASS_REQUIRED_NOT_FOUND_LOG"
            )
            return FlextConstants.LDIF.VALIDATION_MESSAGES["MISSING_OBJECTCLASS"]

        object_classes = entry.get_attribute(
            "objectclass",
        )
        logger.debug(
             "Found object classes: %s",
            object_classes,
        )
        logger.debug(
             "Validating entry DN: %s",
            entry.dn,
        )
        logger.info(
             "Entry validation completed for %s with %d attributes, objectClasses: %s",
            str(entry.dn),
            len(entry.attributes.data),
            object_classes,
        )
        return None

    @classmethod
    def validate_entries(
        cls, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[bool]:
        """Validate multiple LDIF entries with early failure detection.

        Args:
            entries: List of FlextLDIFModels.Entry domain objects to validate

        Returns:
            FlextResult: True if all valid, error with entry index on failure

        """
        try:
            # Railway-oriented programming for bulk validation
            total_entries = len(entries)
            logger.debug(
                 "Validating %d entries",
                total_entries,
            )

            def validate_single_entry(
                entry_with_index: tuple[int, FlextLDIFModels.Entry],
            ) -> FlextResult[bool]:
                """Validate single entry with index for error context."""
                i, entry = entry_with_index
                logger.debug(
                     "Validating entry %d/%d: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                entry_result = cls.validate(entry)
                if entry_result.is_failure:
                    return FlextResult.fail(
                        f"Bulk validation failed for entry {i + 1}/{total_entries} ({entry.dn}): {entry_result.error}"
                    )
                return entry_result

            # Use railway programming with reduce to chain all validations
            def chain_validations(
                acc: FlextResult[bool],
                indexed_entry: tuple[int, FlextLDIFModels.Entry],
            ) -> FlextResult[bool]:
                return acc.flat_map(lambda _: validate_single_entry(indexed_entry))

            return (
                reduce(
                    chain_validations,
                    enumerate(entries),
                    FlextResult.ok(data=True),
                )
                .tap(
                    lambda _: logger.debug(
                         "Bulk validation debug: %d entries processed",
                        total_entries,
                    )
                )
                .tap(
                    lambda _: logger.info(
                         "Bulk validation completed: %d entries validated",
                        total_entries,
                    )
                )
            )

        except (ValueError, TypeError, AttributeError):
            logger.exception(
                 "Exception during bulk validation of %d entries",
                len(entries),
            )
            return FlextResult.fail(
                 "Bulk validation failed during processing",
            )

    @classmethod
    def write(cls, entries: list[FlextLDIFModels.Entry]) -> FlextResult[str]:
        """Write entries to RFC 2849 compliant LDIF string.

        Args:
            entries: List of FlextLDIFModels.Entry domain objects to serialize

        Returns:
            FlextResult: LDIF string or error

        """
        try:
            # REFACTORING: Enhanced error handling and performance logging
            entries_count = len(entries)
            logger.debug(
                 "Writing LDIF content for %d entries",
                entries_count,
            )
            logger.debug(
                 "WRITE_OPERATION_USING_MODERNIZED_LOG"
            )

            # Use modernized LDIF writer (no external dependencies)
            result = cls._write_with_modernized_ldif(entries)

            # REFACTORING: Enhanced result logging and metrics
            content = FlextResult.safe_unwrap_or_none(result) or ""
            if content:
                content_length = len(content)
                logger.debug(
                     "Generated LDIF content length: %d characters",
                    content_length,
                )
                logger.info(
                     "LDIF write completed: %d entries generated %d characters",
                    entries_count,
                    content_length,
                )
            else:
                logger.warning(
                     "LDIF write result was empty or failed: %s",
                    result.error,
                )

            return result

        except (ValueError, TypeError, AttributeError, OSError, ImportError):
            logger.exception(
                 "Exception during LDIF write operation",
            )
            return FlextResult.fail(
                 "LDIF write operation failed",
            )

    @classmethod
    def _write_with_modernized_ldif(
        cls,
        entries: list[FlextLDIFModels.Entry],
    ) -> FlextResult[str]:
        """Write using modernized LDIF writer with full string compatibility."""
        try:
            # Use modernized writer - pass entries directly
            # Railway-oriented programming for LDIF writing
            return (
                FlextLDIFFormatHandler.write_ldif(entries)
                .map(
                    lambda content: content
                    or "EMPTY_WRITE_RESULT_MSG"
                )
                .or_else(
                    FlextResult.fail(
                         "MODERNIZED_LDIF_WRITE_FAILED_NO_ERROR_MSG"
                    )
                )
            )

        except (ValueError, TypeError, AttributeError, ImportError) as e:
            return FlextResult.fail(
                 MODERNIZED_LDIF_WRITE_FAILED_WITH_ERROR_MSG.format(
                    error=e,
                ),
            )

    @classmethod
    def write_file(
        cls,
        entries: list[FlextLDIFModels.Entry],
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[None]:
        """Write LDIF entries to file with automatic directory creation.

        Args:
            entries: List of FlextLDIFModels.Entry domain objects to write
            file_path: Target file path for LDIF output
            encoding: File encoding (default: utf-8)

        Returns:
            FlextResult: True if successful, error details on failure

        """
        # REFACTORING: Enhanced validation and error context
        entries_count = len(entries)
        logger.debug(
             "Writing %d entries to file: %s",
            entries_count,
            file_path,
        )
        logger.debug(
             "Using file encoding: %s", encoding
        )

        try:
            file_path = Path(file_path)
            logger.debug(
                 "Resolved absolute file path: %s",
                file_path.absolute(),
            )

            # REFACTORING: Enhanced directory handling with automatic creation
            parent_dir = file_path.parent
            if not parent_dir.exists():
                logger.debug(
                     "Creating parent directory: %s",
                    parent_dir,
                )
                parent_dir.mkdir(parents=True, exist_ok=True)
                logger.debug(
                     "PARENT_DIRECTORY_CREATED_LOG"
                )

            logger.debug(
                 "Target file exists: %s",
                file_path.exists(),
            )

            # Get LDIF content with enhanced error handling
            logger.debug(
                 "Generating LDIF content for %d entries",
                entries_count,
            )

            # Railway-oriented programming for content generation and file writing
            def write_content_to_file(content: str) -> FlextResult[None]:
                """Write content to file with proper error handling."""
                content_size = len(content)
                logger.debug(
                     "Content size to write: %d bytes",
                    content_size,
                )
                logger.debug(
                     "Content preview (first 100 chars): %s",
                    content[
                        : 100
                    ].replace(
                        "\\n",
                         "\n",
                    ),
                )

                # Enhanced file writing with atomic operations
                logger.debug(
                     "Writing file with encoding: %s",
                    encoding,
                )
                try:
                    with file_path.open(
                        "w",
                        encoding=encoding,
                    ) as f:
                        f.write(content)
                    return FlextResult.ok(None)
                except (OSError, UnicodeError) as e:
                    error_msg = FILE_WRITE_FAILED_MSG.format(
                        error=str(e)
                    )
                    logger.exception(error_msg)
                    return FlextResult.fail(error_msg)

            return (
                cls.write(entries)
                .flat_map(write_content_to_file)
                .or_else_get(
                    lambda: FlextResult.fail(
                         CONTENT_GENERATION_FAILED_FOR_ENTRIES_MSG.format(
                            entries_count=entries_count,
                            error="Content generation failed",
                        )
                    )
                )
                .tap(
                    lambda success: logger.debug(
                         "File write operation completed successfully: %s",
                        file_path,
                    )
                    if success
                    else None
                )
                .tap(
                    lambda success: logger.info(
                         "LDIF file written successfully: %d entries to %s (encoding: %s)",
                        entries_count,
                        str(file_path.absolute()),
                        encoding,
                    )
                    if success
                    else None
                )
            )

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug(
                "Exception type: %s",
                type(e).__name__,
            )
            logger.debug(
                 "File write exception details for %s",
                str(e),
                exc_info=True,
            )
            logger.exception(
                 "Exception during file write operation"
            )
            return FlextResult.fail(
                 "File write operation failed",
            )

    @classmethod
    def read_file(
        cls,
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Read and parse LDIF file with comprehensive validation.

        Args:
            file_path: Input file path for LDIF file reading
            encoding: File encoding (default: utf-8)

        Returns:
            FlextResult: Parsed entries or error

        """
        # REFACTORING: Enhanced file validation and error context
        logger.debug(
             "Reading LDIF file: %s",
            file_path,
        )
        logger.debug(
             "Using file encoding: %s", encoding
        )

        try:
            file_path = Path(file_path)
            absolute_path = file_path.absolute()
            logger.debug(
                 "Resolved absolute file path: %s",
                absolute_path,
            )

            # REFACTORING: Enhanced file validation with detailed error context
            if not file_path.exists():
                not_found_error_msg: str = LDIF_FILE_NOT_FOUND_ERROR_MSG.format(
                    absolute_path=absolute_path,
                )
                logger.error(not_found_error_msg)
                return FlextResult.fail(not_found_error_msg)

            if not file_path.is_file():
                not_file_error_msg: str = PATH_NOT_FILE_ERROR_MSG.format(
                    absolute_path=absolute_path,
                )
                logger.error(not_file_error_msg)
                return FlextResult.fail(not_file_error_msg)

            # REFACTORING: Enhanced file metadata collection
            logger.debug(
                 "FILE_EXISTS_COLLECTING_METADATA_LOG"
            )
            file_stat = file_path.stat()
            file_size = file_stat.st_size
            logger.debug(
                 "File metadata - size: %d bytes, mode: %o",
                file_size,
                file_stat.st_mode,
            )

            # REFACTORING: Enhanced file size validation
            if file_size == 0:
                logger.warning(
                     "File is empty: %s",
                    absolute_path,
                )
                return FlextResult.ok([])  # Return empty list for empty files

            # Read file content with enhanced error handling
            logger.debug(
                 "Reading file content with encoding: %s",
                encoding,
            )
            try:
                with file_path.open(
                    "r",
                    encoding=encoding,
                ) as f:
                    content = f.read()
            except UnicodeDecodeError as e:
                encoding_error_msg: str = ENCODING_ERROR_READING_FILE_MSG.format(
                    encoding=encoding,
                    error=e,
                )
                logger.exception(encoding_error_msg)
                return FlextResult.fail(encoding_error_msg)

            # REFACTORING: Enhanced content validation and metrics
            content_size = len(content)
            lines_count = len(content.splitlines())
            logger.debug(
                 "File content loaded - size: %d characters, lines: %d",
                content_size,
                lines_count,
            )
            logger.debug(
                 "Content preview (first %d chars): %s",
                FILE_READ_CONTENT_PREVIEW_SIZE,
                content[
                    :  FILE_READ_CONTENT_PREVIEW_SIZE
                ].replace(
                    "\\n",
                     NEWLINE_TO_ESCAPED_NEWLINE,
                ),
            )

            # Parse content with enhanced error context
            logger.debug(
                "Delegating to parse method for content",
            )
            result = cls.parse(content)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug(
                "Exception type during file read: %s",
                type(e).__name__,
            )
            logger.debug(
                "File read exception details",
                exc_info=True,
            )
            logger.exception(
                "Exception during file read operation",
            )
            return FlextResult.fail(
                "LDIF file read failed",
            )
        else:
            # REFACTORING: Enhanced result logging with comprehensive metrics
            entries = FlextResult.safe_unwrap_or_none(result) or []
            if entries:
                entries_count = len(entries)
                logger.debug(
                    "File read and parse success: %d entries from %s",
                    entries_count,
                    absolute_path,
                )
                logger.info(
                    "LDIF file processing completed successfully: %s (file: %d bytes, content: %d chars, %d lines, %d entries, encoding: %s)",
                    str(absolute_path),
                    file_size,
                    content_size,
                    lines_count,
                    entries_count,
                    encoding,
                )
            else:
                # REFACTORING: Enhanced parse failure logging with context
                error_msg = f"LDIF parsing failed for file {absolute_path}: {result.error}"
                logger.error(error_msg)
                logger.debug(
                    "Parse method failed after successful read",
                )

            return result


__all__: FlextTypes.Core.StringList = [
    "FlextLDIFCore",
]
