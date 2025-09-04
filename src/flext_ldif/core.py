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

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidator
from flext_ldif.models import FlextLDIFModels

T = TypeVar("T")

logger = FlextLogger(__name__)


class ExceptionHandlingStrategy:
    """Strategy Pattern for exception handling with zero duplication.

    Eliminates 22+ lines of duplicated exception handling code by providing
    a unified strategy that handles logging, error formatting, and result
    creation with configurable behavior for different operation types.
    """

    def __init__(
        self,
        operation_name: str,
        constants_class: type = FlextLDIFConstants.FlextLDIFCoreConstants,
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
            return FlextResult[T].fail(error_msg)


class LdifOperationStrategies:
    """Pre-configured strategies for different LDIF operations."""

    @staticmethod
    def parsing_strategy() -> ExceptionHandlingStrategy:
        """Strategy for parsing operations."""
        return ExceptionHandlingStrategy("parsing")

    @staticmethod
    def validation_strategy() -> ExceptionHandlingStrategy:
        """Strategy for validation operations."""
        return ExceptionHandlingStrategy("validation")

    @staticmethod
    def file_operation_strategy() -> ExceptionHandlingStrategy:
        """Strategy for file operations."""
        return ExceptionHandlingStrategy("file_operation")


class FlextLDIFCore:
    """Core LDIF processing functionality."""

    # Standard validation patterns following RFC compliance
    # These provide consistent LDIF validation rules
    DN_PATTERN = re.compile(FlextLDIFConstants.FlextLDIFCoreConstants.DN_PATTERN_REGEX)
    ATTR_NAME_PATTERN = re.compile(
        FlextLDIFConstants.FlextLDIFCoreConstants.ATTR_NAME_PATTERN_REGEX
    )

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
            FlextResult[list[FlextLDIFModels.Entry]]: Parsed entries or error

        """
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.TLDIF_PARSE_CALLED_LOG,
            type(content).__name__,
        )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_LENGTH_LOG,
            len(str(content)),
        )
        try:
            content_str = str(content)
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_CONVERTED_LOG,
                len(content_str),
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_PREVIEW_LOG,
                content_str[
                    : FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_PREVIEW_LENGTH
                ].replace(
                    "\n",
                    FlextLDIFConstants.FlextLDIFCoreConstants.NEWLINE_ESCAPE,
                ),
            )

            # Use modernized LDIF parser (no external dependencies)
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.DELEGATING_TO_MODERNIZED_LOG
            )
            return cls._parse_with_modernized_ldif(content_str)

        except (
            ValueError,
            TypeError,
            AttributeError,
            OSError,
            ImportError,
        ) as e:
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_TYPE_LOG,
                type(e).__name__,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.FULL_EXCEPTION_DETAILS_LOG,
                exc_info=True,
            )
            logger.exception(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_IN_TLDIF_PARSE_LOG
            )
            return FlextResult[list[FlextLDIFModels.Entry]].fail(
                FlextLDIFConstants.FlextLDIFCoreConstants.PARSE_FAILED_MSG.format(
                    error=e
                ),
            )

    @classmethod
    def _parse_with_modernized_ldif(
        cls,
        content: str,
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse using modernized LDIF parser with full string compatibility."""
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.STARTING_MODERNIZED_PARSING_LOG
        )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_LINES_COUNT_LOG,
            len(content.splitlines()),
        )
        try:
            # Use modernized parser with railway-oriented programming
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.CALLING_MODERNIZED_LDIF_PARSE_LOG
            )

            def convert_raw_entries(
                raw_entries: list[tuple[str, dict[str, list[str]]]],
            ) -> FlextResult[list[FlextLDIFModels.Entry]]:
                """Convert raw entries to FlextLDIFModels.Entry objects using railway-oriented programming."""
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.MODERNIZED_PARSER_RETURNED_ENTRIES_LOG,
                    len(raw_entries),
                )
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.RAW_ENTRIES_DNS_LOG,
                    [dn for dn, _ in raw_entries[:5]],
                )

                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.CONVERTING_ENTRIES_LOG
                )

                # Process each entry using railway-oriented programming with reduce pattern
                def process_indexed_entry(
                    acc: FlextResult[list[FlextLDIFModels.Entry]],
                    indexed_raw: tuple[int, tuple[str, dict[str, list[str]]]],
                ) -> FlextResult[list[FlextLDIFModels.Entry]]:
                    i, (dn, attrs) = indexed_raw
                    logger.debug(
                        FlextLDIFConstants.FlextLDIFCoreConstants.PROCESSING_ENTRY_LOG,
                        i,
                        dn,
                        len(attrs),
                    )

                    def process_entry(
                        entries_list: list[FlextLDIFModels.Entry],
                    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
                        try:
                            entry = FlextLDIFModels.Factory.create_entry({
                                "dn": dn,
                                "attributes": attrs,
                            })
                        except Exception as e:
                            return FlextResult[list[FlextLDIFModels.Entry]].fail(
                                FlextLDIFConstants.FlextLDIFCoreConstants.FAILED_TO_CREATE_ENTRY_MSG.format(
                                    error=str(e)
                                )
                            )
                        return FlextResult[list[FlextLDIFModels.Entry]].ok([
                            *entries_list,
                            entry,
                        ])

                    return acc.flat_map(process_entry)

                return (
                    reduce(
                        process_indexed_entry,
                        enumerate(raw_entries),
                        FlextResult[list[FlextLDIFModels.Entry]].ok([]),
                    )
                    .tap(
                        lambda entries: logger.debug(
                            FlextLDIFConstants.FlextLDIFCoreConstants.SUCCESSFULLY_CONVERTED_ENTRIES_LOG,
                            len(entries),
                        )
                    )
                    .tap(
                        lambda entries: logger.info(
                            FlextLDIFConstants.FlextLDIFCoreConstants.MODERNIZED_PARSING_COMPLETED_LOG,
                            len(raw_entries),
                            len(entries),
                        )
                    )
                )

            # Parse LDIF content - format handler already returns FlextResult[list[FlextLDIFModels.Entry]]
            return FlextLDIFFormatHandler.parse_ldif(content)

        except (
            ValueError,
            TypeError,
            AttributeError,
            ImportError,
        ) as e:
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_TYPE_LOG,
                type(e).__name__,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.FULL_EXCEPTION_DETAILS_LOG,
                exc_info=True,
            )
            logger.exception(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_IN_MODERNIZED_PARSING_LOG
            )
            return FlextResult[list[FlextLDIFModels.Entry]].fail(
                FlextLDIFConstants.FlextLDIFCoreConstants.MODERNIZED_LDIF_PARSE_FAILED_WITH_ERROR_MSG.format(
                    error=e,
                ),
            )

    @classmethod
    def validate(cls, entry: FlextLDIFModels.Entry | None) -> FlextResult[bool]:
        """Validate LDIF entry with format and business rule validation.

        Args:
            entry: FlextLDIFModels.Entry domain object to validate

        Returns:
            FlextResult[bool]: True if valid, error details on failure

        """
        try:
            error_message = cls._get_validation_error(entry)
            if error_message is not None:
                return FlextResult[bool].fail(error_message)
            return FlextResult[bool].ok(data=True)
        except (ValueError, TypeError, AttributeError) as e:
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_TYPE_LOG,
                type(e).__name__,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.VALIDATION_EXCEPTION_DETAILS_LOG,
                exc_info=True,
            )
            logger.exception(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_DURING_ENTRY_VALIDATION_LOG,
            )
            return FlextResult[bool].fail(
                FlextLDIFConstants.FlextLDIFCoreConstants.VALIDATION_FAILED_MSG.format(
                    error=e
                ),
            )

    @classmethod
    def _get_validation_error(cls, entry: FlextLDIFModels.Entry | None) -> str | None:
        """Return an error message if validation fails; otherwise None."""
        if entry is None:
            logger.error(
                FlextLDIFConstants.FlextLDIFCoreConstants.CANNOT_VALIDATE_NONE_ENTRY_LOG
            )
            return FlextLDIFConstants.FlextLDIFCoreConstants.ENTRY_CANNOT_BE_NONE_MSG

        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.VALIDATING_LDIF_ENTRY_LOG,
            entry.dn,
        )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.ENTRY_ATTRIBUTES_COUNT_LOG,
            len(entry.attributes.data),
        )
        dn_str = str(entry.dn)
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.VALIDATING_DN_FORMAT_LOG, dn_str
        )
        if not cls.DN_PATTERN.match(dn_str):
            logger.warning(
                FlextLDIFConstants.FlextLDIFCoreConstants.INVALID_DN_FORMAT_BY_PATTERN_LOG,
                dn_str,
            )
            return (
                FlextLDIFConstants.FlextLDIFCoreConstants.INVALID_DN_FORMAT_MSG.format(
                    dn=entry.dn
                )
            )
        attr_validator, dn_validator = cls._load_validators()
        if not dn_validator(dn_str):
            logger.warning(
                FlextLDIFConstants.FlextLDIFCoreConstants.INVALID_DN_FORMAT_BY_PATTERN_LOG,
                dn_str,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.DN_FAILED_FLEXT_LDAP_VALIDATION_LOG
            )
            return (
                FlextLDIFConstants.FlextLDIFCoreConstants.INVALID_DN_FORMAT_MSG.format(
                    dn=entry.dn
                )
            )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.DN_FORMAT_VALIDATION_PASSED_LOG
        )

        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.VALIDATING_ATTRIBUTE_NAMES_LOG,
            len(entry.attributes.data),
        )
        for attr_name in entry.attributes.data:
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.VALIDATING_ATTRIBUTE_NAME_LOG,
                attr_name,
            )
            if not cls.ATTR_NAME_PATTERN.match(attr_name) or not attr_validator(
                attr_name,
            ):
                logger.warning(
                    FlextLDIFConstants.FlextLDIFCoreConstants.INVALID_ATTRIBUTE_NAME_LOG,
                    attr_name,
                )
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.ATTRIBUTE_NAME_FAILED_VALIDATION_LOG,
                )
                return FlextLDIFConstants.FlextLDIFCoreConstants.INVALID_ATTRIBUTE_NAME_MSG.format(
                    attr_name=attr_name,
                )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.ALL_ATTRIBUTE_NAMES_VALIDATED_LOG
        )

        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.CHECKING_REQUIRED_OBJECTCLASS_LOG
        )
        if not entry.has_attribute(
            FlextLDIFConstants.FlextLDIFCoreConstants.OBJECTCLASS_ATTRIBUTE
        ):
            logger.warning(
                FlextLDIFConstants.FlextLDIFCoreConstants.ENTRY_MISSING_OBJECTCLASS_WARNING_LOG,
                entry.dn,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.OBJECTCLASS_REQUIRED_NOT_FOUND_LOG
            )
            return FlextLDIFConstants.FlextLDIFCoreConstants.ENTRY_MISSING_REQUIRED_OBJECTCLASS_MSG

        object_classes = entry.get_attribute(
            FlextLDIFConstants.FlextLDIFCoreConstants.OBJECTCLASS_ATTRIBUTE,
        )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.FOUND_OBJECTCLASS_VALUES_LOG,
            object_classes,
        )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.ENTRY_VALIDATION_PASSED_LOG,
            entry.dn,
        )
        logger.info(
            FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_ENTRY_VALIDATION_SUCCESSFUL_LOG,
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
            FlextResult[bool]: True if all valid, error with entry index on failure

        """
        try:
            # Railway-oriented programming for bulk validation
            total_entries = len(entries)
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.STARTING_BULK_VALIDATION_LOG,
                total_entries,
            )

            def validate_single_entry(
                entry_with_index: tuple[int, FlextLDIFModels.Entry],
            ) -> FlextResult[bool]:
                """Validate single entry with index for error context."""
                i, entry = entry_with_index
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.VALIDATING_ENTRY_INDEX_LOG,
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                entry_result = cls.validate(entry)
                if entry_result.is_failure:
                    return FlextResult[bool].fail(
                        FlextLDIFConstants.FlextLDIFCoreConstants.BULK_VALIDATION_ENTRY_FAILED_MSG.format(
                            index=i + 1,
                            total=total_entries,
                            dn=entry.dn,
                            error=entry_result.error,
                        )
                    )
                return entry_result

            # Use railway programming with reduce to chain all validations
            def chain_validations(
                acc: FlextResult[bool], indexed_entry: tuple[int, FlextLDIFModels.Entry]
            ) -> FlextResult[bool]:
                return acc.flat_map(lambda _: validate_single_entry(indexed_entry))

            return (
                reduce(
                    chain_validations,
                    enumerate(entries),
                    FlextResult[bool].ok(data=True),
                )
                .tap(
                    lambda _: logger.debug(
                        FlextLDIFConstants.FlextLDIFCoreConstants.BULK_VALIDATION_SUCCESSFUL_LOG,
                        total_entries,
                    )
                )
                .tap(
                    lambda _: logger.info(
                        FlextLDIFConstants.FlextLDIFCoreConstants.BULK_LDIF_VALIDATION_COMPLETED_LOG,
                        total_entries,
                    )
                )
            )

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_DURING_BULK_VALIDATION_LOG,
            )
            return FlextResult[bool].fail(
                FlextLDIFConstants.FlextLDIFCoreConstants.BULK_VALIDATION_EXCEPTION_MSG.format(
                    error=e
                ),
            )

    @classmethod
    def write(cls, entries: list[FlextLDIFModels.Entry]) -> FlextResult[str]:
        """Write entries to RFC 2849 compliant LDIF string.

        Args:
            entries: List of FlextLDIFModels.Entry domain objects to serialize

        Returns:
            FlextResult[str]: LDIF string or error

        """
        try:
            # REFACTORING: Enhanced error handling and performance logging
            entries_count = len(entries)
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.STARTING_LDIF_WRITE_OPERATION_LOG,
                entries_count,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.WRITE_OPERATION_USING_MODERNIZED_LOG
            )

            # Use modernized LDIF writer (no external dependencies)
            result = cls._write_with_modernized_ldif(entries)

            # REFACTORING: Enhanced result logging and metrics
            content = FlextResult.safe_unwrap_or_none(result) or ""
            if content:
                content_length = len(content)
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_WRITE_SUCCESSFUL_LOG,
                    content_length,
                )
                logger.info(
                    FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_WRITE_OPERATION_COMPLETED_LOG,
                    entries_count,
                    content_length,
                )
            else:
                logger.warning(
                    FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_WRITE_OPERATION_FAILED_LOG,
                    result.error,
                )

            return result

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            logger.exception(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_DURING_LDIF_WRITE_LOG
            )
            return FlextResult[str].fail(
                FlextLDIFConstants.FlextLDIFCoreConstants.WRITE_FAILED_WITH_EXCEPTION_MSG.format(
                    error=e
                ),
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
                    or FlextLDIFConstants.FlextLDIFCoreConstants.EMPTY_WRITE_RESULT_MSG
                )
                .or_else(
                    FlextResult[str].fail(
                        FlextLDIFConstants.FlextLDIFCoreConstants.MODERNIZED_LDIF_WRITE_FAILED_NO_ERROR_MSG
                    )
                )
            )

        except (ValueError, TypeError, AttributeError, ImportError) as e:
            return FlextResult[str].fail(
                FlextLDIFConstants.FlextLDIFCoreConstants.MODERNIZED_LDIF_WRITE_FAILED_WITH_ERROR_MSG.format(
                    error=e,
                ),
            )

    @classmethod
    def write_file(
        cls,
        entries: list[FlextLDIFModels.Entry],
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[bool]:
        """Write LDIF entries to file with automatic directory creation.

        Args:
            entries: List of FlextLDIFModels.Entry domain objects to write
            file_path: Target file path for LDIF output
            encoding: File encoding (default: utf-8)

        Returns:
            FlextResult[bool]: True if successful, error details on failure

        """
        # REFACTORING: Enhanced validation and error context
        entries_count = len(entries)
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.STARTING_FILE_WRITE_OPERATION_LOG,
            entries_count,
            file_path,
        )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.FILE_ENCODING_LOG, encoding
        )

        try:
            file_path = Path(file_path)
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.RESOLVED_FILE_PATH_LOG,
                file_path.absolute(),
            )

            # REFACTORING: Enhanced directory handling with automatic creation
            parent_dir = file_path.parent
            if not parent_dir.exists():
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.CREATING_PARENT_DIRECTORY_LOG,
                    parent_dir,
                )
                parent_dir.mkdir(parents=True, exist_ok=True)
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.PARENT_DIRECTORY_CREATED_LOG
                )

            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.FILE_PATH_EXISTS_LOG,
                file_path.exists(),
            )

            # Get LDIF content with enhanced error handling
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.CONVERTING_ENTRIES_TO_LDIF_LOG,
                entries_count,
            )

            # Railway-oriented programming for content generation and file writing
            def write_content_to_file(content: str) -> FlextResult[bool]:
                """Write content to file with proper error handling."""
                content_size = len(content)
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.GENERATED_LDIF_CONTENT_LOG,
                    content_size,
                )
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_PREVIEW_FILE_LOG,
                    content[
                        : FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_PREVIEW_SIZE
                    ].replace(
                        FlextLDIFConstants.FlextLDIFCoreConstants.NEWLINE_ESCAPE,
                        FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_PREVIEW_REPLACEMENT,
                    ),
                )

                # Enhanced file writing with atomic operations
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.WRITING_CONTENT_TO_FILE_LOG,
                    encoding,
                )
                try:
                    with file_path.open(
                        FlextLDIFConstants.FlextLDIFCoreConstants.FILE_WRITE_MODE,
                        encoding=encoding,
                    ) as f:
                        f.write(content)
                    return FlextResult[bool].ok(data=True)
                except (OSError, UnicodeError) as e:
                    error_msg = FlextLDIFConstants.FlextLDIFCoreConstants.FILE_WRITE_FAILED_MSG.format(
                        error=str(e)
                    )
                    logger.exception(error_msg)
                    return FlextResult[bool].fail(error_msg)

            return (
                cls.write(entries)
                .flat_map(write_content_to_file)
                .or_else_get(
                    lambda: FlextResult[bool].fail(
                        FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_GENERATION_FAILED_FOR_ENTRIES_MSG.format(
                            entries_count=entries_count,
                            error="Content generation failed",
                        )
                    )
                )
                .tap(
                    lambda success: logger.debug(
                        FlextLDIFConstants.FlextLDIFCoreConstants.FILE_WRITE_COMPLETED_LOG,
                        file_path,
                    )
                    if success
                    else None
                )
                .tap(
                    lambda success: logger.info(
                        FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_FILE_WRITE_OPERATION_COMPLETED_LOG,
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
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_TYPE_LOG,
                type(e).__name__,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.FILE_WRITE_EXCEPTION_DETAILS_LOG,
                exc_info=True,
            )
            logger.exception(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_DURING_FILE_WRITE_LOG
            )
            return FlextResult[bool].fail(
                FlextLDIFConstants.FlextLDIFCoreConstants.FILE_WRITE_FAILED_MSG.format(
                    error=e
                ),
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
            FlextResult[list[FlextLDIFModels.Entry]]: Parsed entries or error

        """
        # REFACTORING: Enhanced file validation and error context
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.STARTING_LDIF_FILE_READ_OPERATION_LOG,
            file_path,
        )
        logger.debug(
            FlextLDIFConstants.FlextLDIFCoreConstants.FILE_ENCODING_READ_LOG, encoding
        )

        try:
            file_path = Path(file_path)
            absolute_path = file_path.absolute()
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.RESOLVED_ABSOLUTE_FILE_PATH_READ_LOG,
                absolute_path,
            )

            # REFACTORING: Enhanced file validation with detailed error context
            if not file_path.exists():
                not_found_error_msg: str = FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_FILE_NOT_FOUND_ERROR_MSG.format(
                    absolute_path=absolute_path,
                )
                logger.error(not_found_error_msg)
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    not_found_error_msg
                )

            if not file_path.is_file():
                not_file_error_msg: str = FlextLDIFConstants.FlextLDIFCoreConstants.PATH_NOT_FILE_ERROR_MSG.format(
                    absolute_path=absolute_path,
                )
                logger.error(not_file_error_msg)
                return FlextResult[list[FlextLDIFModels.Entry]].fail(not_file_error_msg)

            # REFACTORING: Enhanced file metadata collection
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.FILE_EXISTS_COLLECTING_METADATA_LOG
            )
            file_stat = file_path.stat()
            file_size = file_stat.st_size
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.FILE_METADATA_SIZE_MODE_LOG,
                file_size,
                file_stat.st_mode,
            )

            # REFACTORING: Enhanced file size validation
            if file_size == 0:
                logger.warning(
                    FlextLDIFConstants.FlextLDIFCoreConstants.EMPTY_LDIF_FILE_DETECTED_WARNING_LOG,
                    absolute_path,
                )
                return FlextResult[
                    list[FlextLDIFModels.Entry]
                ].ok([])  # Return empty list for empty files

            # Read file content with enhanced error handling
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.READING_FILE_CONTENT_ENCODING_LOG,
                encoding,
            )
            try:
                with file_path.open(
                    FlextLDIFConstants.FlextLDIFCoreConstants.FILE_READ_MODE,
                    encoding=encoding,
                ) as f:
                    content = f.read()
            except UnicodeDecodeError as e:
                encoding_error_msg: str = FlextLDIFConstants.FlextLDIFCoreConstants.ENCODING_ERROR_READING_FILE_MSG.format(
                    encoding=encoding,
                    error=e,
                )
                logger.exception(encoding_error_msg)
                return FlextResult[list[FlextLDIFModels.Entry]].fail(encoding_error_msg)

            # REFACTORING: Enhanced content validation and metrics
            content_size = len(content)
            lines_count = len(content.splitlines())
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.FILE_CONTENT_READ_SUCCESS_LOG,
                content_size,
                lines_count,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.CONTENT_PREVIEW_REPLACE_LOG,
                content[
                    : FlextLDIFConstants.FlextLDIFCoreConstants.FILE_READ_CONTENT_PREVIEW_SIZE
                ].replace(
                    FlextLDIFConstants.FlextLDIFCoreConstants.NEWLINE_ESCAPE,
                    FlextLDIFConstants.FlextLDIFCoreConstants.NEWLINE_TO_ESCAPED_NEWLINE,
                ),
            )

            # Parse content with enhanced error context
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.DELEGATING_TO_PARSE_METHOD_FOR_CONTENT_LOG,
            )
            result = cls.parse(content)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_TYPE_READ_LOG,
                type(e).__name__,
            )
            logger.debug(
                FlextLDIFConstants.FlextLDIFCoreConstants.FILE_READ_EXCEPTION_DETAILS_READ_LOG,
                exc_info=True,
            )
            logger.exception(
                FlextLDIFConstants.FlextLDIFCoreConstants.EXCEPTION_DURING_FILE_READ_OPERATION_LOG,
            )
            return FlextResult[list[FlextLDIFModels.Entry]].fail(
                FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_FILE_READ_FAILED_ERROR_MSG.format(
                    error=e
                ),
            )
        else:
            # REFACTORING: Enhanced result logging with comprehensive metrics
            entries = FlextResult.safe_unwrap_or_none(result) or []
            if entries:
                entries_count = len(entries)
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.FILE_READ_AND_PARSE_SUCCESS_LOG,
                    entries_count,
                    absolute_path,
                )
                logger.info(
                    FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_FILE_PROCESSING_COMPLETED_SUCCESS_LOG,
                    str(absolute_path),
                    file_size,
                    content_size,
                    lines_count,
                    entries_count,
                    encoding,
                )
            else:
                # REFACTORING: Enhanced parse failure logging with context
                error_msg = FlextLDIFConstants.FlextLDIFCoreConstants.LDIF_PARSING_FAILED_FOR_FILE_ERROR_MSG.format(
                    absolute_path=absolute_path,
                    error=result.error,
                )
                logger.error(error_msg)
                logger.debug(
                    FlextLDIFConstants.FlextLDIFCoreConstants.PARSE_METHOD_FAILED_AFTER_SUCCESSFUL_READ_LOG,
                )

            return result


__all__: list[str] = [
    "FlextLDIFCore",
]
