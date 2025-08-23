"""FLEXT-LDIF core processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from collections.abc import Callable as _Callable
from functools import reduce
from pathlib import Path

from flext_core import FlextResult, get_logger
from flext_core.exceptions import FlextValidationError

from flext_ldif.constants import FlextLdifCoreConstants
from flext_ldif.format_handler_service import (
    modernized_ldif_parse,
    modernized_ldif_write,
)
from flext_ldif.models import FlextLdifEntry, FlextLdifFactory
from flext_ldif.typings import LDIFContent

logger = get_logger(__name__)


def _validate_ldap_attribute_name(name: str) -> bool:
    """Local LDAP attribute name validator - breaks circular dependency.

    Validates attribute names per RFC 4512: base name + optional language tags/options.
    Supports: displayname;lang-es_es, orclinstancecount;oid-prd-app01.network.ctbc
    """
    if not name or not isinstance(name, str):
        return False
    attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9_.-]+)*$")
    return bool(attr_pattern.match(name))


def _validate_ldap_dn(dn: str) -> bool:
    """Local LDAP DN validator - breaks circular dependency.

    Basic DN validation pattern to avoid circular import from flext-ldap.
    """
    if not dn or not isinstance(dn, str):
        return False
    # Basic DN validation pattern
    dn_pattern = re.compile(r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$")
    return bool(dn_pattern.match(dn.strip()))


class TLdif:
    """Core LDIF processing functionality."""

    # Standard validation patterns following RFC compliance
    # These provide consistent LDIF validation rules
    DN_PATTERN = re.compile(FlextLdifCoreConstants.DN_PATTERN_REGEX)
    ATTR_NAME_PATTERN = re.compile(FlextLdifCoreConstants.ATTR_NAME_PATTERN_REGEX)

    # Use local validators to avoid circular dependency
    @classmethod
    def _load_validators(cls) -> tuple[_Callable[[str], bool], _Callable[[str], bool]]:
        """Use local validators to avoid circular dependency with flext-ldap."""
        return (_validate_ldap_attribute_name, _validate_ldap_dn)

    @classmethod
    def parse(cls, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into domain entities.

        Args:
            content: LDIF content as string or LDIFContent type

        Returns:
            FlextResult[list[FlextLdifEntry]]: Parsed entries or error

        """
        logger.debug(
            FlextLdifCoreConstants.TLDIF_PARSE_CALLED_LOG,
            type(content).__name__,
        )
        logger.debug(FlextLdifCoreConstants.CONTENT_LENGTH_LOG, len(str(content)))
        try:
            content_str = str(content)
            logger.debug(FlextLdifCoreConstants.CONTENT_CONVERTED_LOG, len(content_str))
            logger.debug(
                FlextLdifCoreConstants.CONTENT_PREVIEW_LOG,
                content_str[: FlextLdifCoreConstants.CONTENT_PREVIEW_LENGTH].replace(
                    "\n",
                    FlextLdifCoreConstants.NEWLINE_ESCAPE,
                ),
            )

            # Use modernized LDIF parser (no external dependencies)
            logger.debug(FlextLdifCoreConstants.DELEGATING_TO_MODERNIZED_LOG)
            return cls._parse_with_modernized_ldif(content_str)

        except (
            ValueError,
            TypeError,
            AttributeError,
            OSError,
            ImportError,
            FlextValidationError,
        ) as e:
            logger.debug(FlextLdifCoreConstants.EXCEPTION_TYPE_LOG, type(e).__name__)
            logger.debug(
                FlextLdifCoreConstants.FULL_EXCEPTION_DETAILS_LOG,
                exc_info=True,
            )
            logger.exception(FlextLdifCoreConstants.EXCEPTION_IN_TLDIF_PARSE_LOG)
            return FlextResult[list[FlextLdifEntry]].fail(
                FlextLdifCoreConstants.PARSE_FAILED_MSG.format(error=e),
            )

    @classmethod
    def _parse_with_modernized_ldif(
        cls,
        content: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse using modernized LDIF parser with full string compatibility."""
        logger.debug(FlextLdifCoreConstants.STARTING_MODERNIZED_PARSING_LOG)
        logger.debug(
            FlextLdifCoreConstants.CONTENT_LINES_COUNT_LOG,
            len(content.splitlines()),
        )
        try:
            # Use modernized parser with railway-oriented programming
            logger.debug(FlextLdifCoreConstants.CALLING_MODERNIZED_LDIF_PARSE_LOG)

            def convert_raw_entries(
                raw_entries: list[tuple[str, dict[str, list[str]]]],
            ) -> FlextResult[list[FlextLdifEntry]]:
                """Convert raw entries to FlextLdifEntry objects using railway-oriented programming."""
                logger.debug(
                    FlextLdifCoreConstants.MODERNIZED_PARSER_RETURNED_ENTRIES_LOG,
                    len(raw_entries),
                )
                logger.debug(
                    FlextLdifCoreConstants.RAW_ENTRIES_DNS_LOG,
                    [dn for dn, _ in raw_entries[:5]],
                )

                logger.debug(FlextLdifCoreConstants.CONVERTING_ENTRIES_LOG)

                # Process each entry using railway-oriented programming with reduce pattern
                def process_indexed_entry(
                    acc: FlextResult[list[FlextLdifEntry]],
                    indexed_raw: tuple[int, tuple[str, dict[str, list[str]]]],
                ) -> FlextResult[list[FlextLdifEntry]]:
                    i, (dn, attrs) = indexed_raw
                    logger.debug(
                        FlextLdifCoreConstants.PROCESSING_ENTRY_LOG,
                        i,
                        dn,
                        len(attrs),
                    )

                    def process_entry(
                        entries_list: list[FlextLdifEntry],
                    ) -> FlextResult[list[FlextLdifEntry]]:
                        entry_result = FlextLdifFactory.create_entry(dn, attrs)
                        if entry_result.is_failure:
                            return FlextResult[list[FlextLdifEntry]].fail(
                                FlextLdifCoreConstants.FAILED_TO_CREATE_ENTRY_MSG.format(
                                    error=entry_result.error
                                )
                            )
                        return FlextResult[list[FlextLdifEntry]].ok(
                            [
                                *entries_list,
                                entry_result.value,
                            ]
                        )

                    return acc.flat_map(process_entry)

                return (
                    reduce(
                        process_indexed_entry,
                        enumerate(raw_entries),
                        FlextResult[list[FlextLdifEntry]].ok([]),
                    )
                    .tap(
                        lambda entries: logger.debug(
                            FlextLdifCoreConstants.SUCCESSFULLY_CONVERTED_ENTRIES_LOG,
                            len(entries),
                        )
                    )
                    .tap(
                        lambda entries: logger.info(
                            FlextLdifCoreConstants.MODERNIZED_PARSING_COMPLETED_LOG,
                            len(raw_entries),
                            len(entries),
                        )
                    )
                )

            # Railway-oriented programming chain
            return modernized_ldif_parse(content).flat_map(convert_raw_entries)

        except (
            ValueError,
            TypeError,
            AttributeError,
            ImportError,
            FlextValidationError,
        ) as e:
            logger.debug(FlextLdifCoreConstants.EXCEPTION_TYPE_LOG, type(e).__name__)
            logger.debug(
                FlextLdifCoreConstants.FULL_EXCEPTION_DETAILS_LOG,
                exc_info=True,
            )
            logger.exception(FlextLdifCoreConstants.EXCEPTION_IN_MODERNIZED_PARSING_LOG)
            return FlextResult[list[FlextLdifEntry]].fail(
                FlextLdifCoreConstants.MODERNIZED_LDIF_PARSE_FAILED_WITH_ERROR_MSG.format(
                    error=e,
                ),
            )

    @classmethod
    def validate(cls, entry: FlextLdifEntry | None) -> FlextResult[bool]:
        """Validate LDIF entry with format and business rule validation.

        Args:
            entry: FlextLdifEntry domain object to validate

        Returns:
            FlextResult[bool]: True if valid, error details on failure

        """
        try:
            error_message = cls._get_validation_error(entry)
            if error_message is not None:
                return FlextResult[bool].fail(error_message)
            return FlextResult[bool].ok(data=True)  # noqa: FBT003
        except (ValueError, TypeError, AttributeError) as e:
            logger.debug(FlextLdifCoreConstants.EXCEPTION_TYPE_LOG, type(e).__name__)
            logger.debug(
                FlextLdifCoreConstants.VALIDATION_EXCEPTION_DETAILS_LOG,
                exc_info=True,
            )
            logger.exception(
                FlextLdifCoreConstants.EXCEPTION_DURING_ENTRY_VALIDATION_LOG,
            )
            return FlextResult[bool].fail(
                FlextLdifCoreConstants.VALIDATION_FAILED_MSG.format(error=e),
            )

    @classmethod
    def _get_validation_error(cls, entry: FlextLdifEntry | None) -> str | None:
        """Return an error message if validation fails; otherwise None."""
        if entry is None:
            logger.error(FlextLdifCoreConstants.CANNOT_VALIDATE_NONE_ENTRY_LOG)
            return FlextLdifCoreConstants.ENTRY_CANNOT_BE_NONE_MSG

        logger.debug(FlextLdifCoreConstants.VALIDATING_LDIF_ENTRY_LOG, entry.dn)
        logger.debug(
            FlextLdifCoreConstants.ENTRY_ATTRIBUTES_COUNT_LOG,
            len(entry.attributes.attributes),
        )
        dn_str = str(entry.dn)
        logger.debug(FlextLdifCoreConstants.VALIDATING_DN_FORMAT_LOG, dn_str)
        if not cls.DN_PATTERN.match(dn_str):
            logger.warning(
                FlextLdifCoreConstants.INVALID_DN_FORMAT_BY_PATTERN_LOG,
                dn_str,
            )
            return FlextLdifCoreConstants.INVALID_DN_FORMAT_MSG.format(dn=entry.dn)
        attr_validator, dn_validator = cls._load_validators()
        if not dn_validator(dn_str):
            logger.warning(
                FlextLdifCoreConstants.INVALID_DN_FORMAT_BY_PATTERN_LOG,
                dn_str,
            )
            logger.debug(FlextLdifCoreConstants.DN_FAILED_FLEXT_LDAP_VALIDATION_LOG)
            return FlextLdifCoreConstants.INVALID_DN_FORMAT_MSG.format(dn=entry.dn)
        logger.debug(FlextLdifCoreConstants.DN_FORMAT_VALIDATION_PASSED_LOG)

        logger.debug(
            FlextLdifCoreConstants.VALIDATING_ATTRIBUTE_NAMES_LOG,
            len(entry.attributes.attributes),
        )
        for attr_name in entry.attributes.attributes:
            logger.debug(
                FlextLdifCoreConstants.VALIDATING_ATTRIBUTE_NAME_LOG,
                attr_name,
            )
            if not cls.ATTR_NAME_PATTERN.match(attr_name) or not attr_validator(
                attr_name,
            ):
                logger.warning(
                    FlextLdifCoreConstants.INVALID_ATTRIBUTE_NAME_LOG,
                    attr_name,
                )
                logger.debug(
                    FlextLdifCoreConstants.ATTRIBUTE_NAME_FAILED_VALIDATION_LOG,
                )
                return FlextLdifCoreConstants.INVALID_ATTRIBUTE_NAME_MSG.format(
                    attr_name=attr_name,
                )
        logger.debug(FlextLdifCoreConstants.ALL_ATTRIBUTE_NAMES_VALIDATED_LOG)

        logger.debug(FlextLdifCoreConstants.CHECKING_REQUIRED_OBJECTCLASS_LOG)
        if not entry.has_attribute(FlextLdifCoreConstants.OBJECTCLASS_ATTRIBUTE):
            logger.warning(
                FlextLdifCoreConstants.ENTRY_MISSING_OBJECTCLASS_WARNING_LOG,
                entry.dn,
            )
            logger.debug(FlextLdifCoreConstants.OBJECTCLASS_REQUIRED_NOT_FOUND_LOG)
            return FlextLdifCoreConstants.ENTRY_MISSING_REQUIRED_OBJECTCLASS_MSG

        object_classes = entry.get_attribute(
            FlextLdifCoreConstants.OBJECTCLASS_ATTRIBUTE,
        )
        logger.debug(
            FlextLdifCoreConstants.FOUND_OBJECTCLASS_VALUES_LOG,
            object_classes,
        )
        logger.debug(FlextLdifCoreConstants.ENTRY_VALIDATION_PASSED_LOG, entry.dn)
        logger.info(
            FlextLdifCoreConstants.LDIF_ENTRY_VALIDATION_SUCCESSFUL_LOG,
            str(entry.dn),
            len(entry.attributes.attributes),
            object_classes,
        )
        return None

    @classmethod
    def validate_entries(cls, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries with early failure detection.

        Args:
            entries: List of FlextLdifEntry domain objects to validate

        Returns:
            FlextResult[bool]: True if all valid, error with entry index on failure

        """
        try:
            # Railway-oriented programming for bulk validation
            total_entries = len(entries)
            logger.debug(
                FlextLdifCoreConstants.STARTING_BULK_VALIDATION_LOG,
                total_entries,
            )

            def validate_single_entry(
                entry_with_index: tuple[int, FlextLdifEntry],
            ) -> FlextResult[bool]:
                """Validate single entry with index for error context."""
                i, entry = entry_with_index
                logger.debug(
                    FlextLdifCoreConstants.VALIDATING_ENTRY_INDEX_LOG,
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                entry_result = cls.validate(entry)
                if entry_result.is_failure:
                    return FlextResult[bool].fail(
                        FlextLdifCoreConstants.BULK_VALIDATION_ENTRY_FAILED_MSG.format(
                            index=i + 1,
                            total=total_entries,
                            dn=entry.dn,
                            error=entry_result.error,
                        )
                    )
                return entry_result

            # Use railway programming with reduce to chain all validations
            def chain_validations(
                acc: FlextResult[bool], indexed_entry: tuple[int, FlextLdifEntry]
            ) -> FlextResult[bool]:
                return acc.flat_map(lambda _: validate_single_entry(indexed_entry))

            return (
                reduce(
                    chain_validations,
                    enumerate(entries),
                    FlextResult[bool].ok(data=True),  # noqa: FBT003
                )
                .tap(
                    lambda _: logger.debug(
                        FlextLdifCoreConstants.BULK_VALIDATION_SUCCESSFUL_LOG,
                        total_entries,
                    )
                )
                .tap(
                    lambda _: logger.info(
                        FlextLdifCoreConstants.BULK_LDIF_VALIDATION_COMPLETED_LOG,
                        total_entries,
                    )
                )
            )

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception(
                FlextLdifCoreConstants.EXCEPTION_DURING_BULK_VALIDATION_LOG,
            )
            return FlextResult[bool].fail(
                FlextLdifCoreConstants.BULK_VALIDATION_EXCEPTION_MSG.format(error=e),
            )

    @classmethod
    def write(cls, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to RFC 2849 compliant LDIF string.

        Args:
            entries: List of FlextLdifEntry domain objects to serialize

        Returns:
            FlextResult[str]: LDIF string or error

        """
        try:
            # REFACTORING: Enhanced error handling and performance logging
            entries_count = len(entries)
            logger.debug(
                FlextLdifCoreConstants.STARTING_LDIF_WRITE_OPERATION_LOG,
                entries_count,
            )
            logger.debug(FlextLdifCoreConstants.WRITE_OPERATION_USING_MODERNIZED_LOG)

            # Use modernized LDIF writer (no external dependencies)
            result = cls._write_with_modernized_ldif(entries)

            # REFACTORING: Enhanced result logging and metrics
            content = result.unwrap_or("")
            if content:
                content_length = len(content)
                logger.debug(
                    FlextLdifCoreConstants.LDIF_WRITE_SUCCESSFUL_LOG,
                    content_length,
                )
                logger.info(
                    FlextLdifCoreConstants.LDIF_WRITE_OPERATION_COMPLETED_LOG,
                    entries_count,
                    content_length,
                )
            else:
                logger.warning(
                    FlextLdifCoreConstants.LDIF_WRITE_OPERATION_FAILED_LOG,
                    result.error,
                )

            return result

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            logger.exception(FlextLdifCoreConstants.EXCEPTION_DURING_LDIF_WRITE_LOG)
            return FlextResult[str].fail(
                FlextLdifCoreConstants.WRITE_FAILED_WITH_EXCEPTION_MSG.format(error=e),
            )

    @classmethod
    def _write_with_modernized_ldif(
        cls,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[str]:
        """Write using modernized LDIF writer with full string compatibility."""
        try:
            # Convert FlextLdifEntry objects to (dn, attrs) tuples
            raw_entries: list[tuple[str, dict[str, list[str]]]] = []
            for entry in entries:
                dn = str(entry.dn)
                attrs = entry.attributes.attributes
                raw_entries.append((dn, attrs))

            # Use modernized writer
            # Railway-oriented programming for LDIF writing
            return (
                modernized_ldif_write(raw_entries)
                .map(
                    lambda content: content
                    or FlextLdifCoreConstants.EMPTY_WRITE_RESULT_MSG
                )
                .or_else(
                    FlextResult[str].fail(
                        FlextLdifCoreConstants.MODERNIZED_LDIF_WRITE_FAILED_NO_ERROR_MSG
                    )
                )
            )

        except (ValueError, TypeError, AttributeError, ImportError) as e:
            return FlextResult[str].fail(
                FlextLdifCoreConstants.MODERNIZED_LDIF_WRITE_FAILED_WITH_ERROR_MSG.format(
                    error=e,
                ),
            )

    @classmethod
    def write_file(
        cls,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[bool]:
        """Write LDIF entries to file with automatic directory creation.

        Args:
            entries: List of FlextLdifEntry domain objects to write
            file_path: Target file path for LDIF output
            encoding: File encoding (default: utf-8)

        Returns:
            FlextResult[bool]: True if successful, error details on failure

        """
        # REFACTORING: Enhanced validation and error context
        entries_count = len(entries)
        logger.debug(
            FlextLdifCoreConstants.STARTING_FILE_WRITE_OPERATION_LOG,
            entries_count,
            file_path,
        )
        logger.debug(FlextLdifCoreConstants.FILE_ENCODING_LOG, encoding)

        try:
            file_path = Path(file_path)
            logger.debug(
                FlextLdifCoreConstants.RESOLVED_FILE_PATH_LOG,
                file_path.absolute(),
            )

            # REFACTORING: Enhanced directory handling with automatic creation
            parent_dir = file_path.parent
            if not parent_dir.exists():
                logger.debug(
                    FlextLdifCoreConstants.CREATING_PARENT_DIRECTORY_LOG,
                    parent_dir,
                )
                parent_dir.mkdir(parents=True, exist_ok=True)
                logger.debug(FlextLdifCoreConstants.PARENT_DIRECTORY_CREATED_LOG)

            logger.debug(
                FlextLdifCoreConstants.FILE_PATH_EXISTS_LOG,
                file_path.exists(),
            )

            # Get LDIF content with enhanced error handling
            logger.debug(
                FlextLdifCoreConstants.CONVERTING_ENTRIES_TO_LDIF_LOG,
                entries_count,
            )

            # Railway-oriented programming for content generation and file writing
            def write_content_to_file(content: str) -> FlextResult[bool]:
                """Write content to file with proper error handling."""
                content_size = len(content)
                logger.debug(
                    FlextLdifCoreConstants.GENERATED_LDIF_CONTENT_LOG,
                    content_size,
                )
                logger.debug(
                    FlextLdifCoreConstants.CONTENT_PREVIEW_FILE_LOG,
                    content[: FlextLdifCoreConstants.CONTENT_PREVIEW_SIZE].replace(
                        FlextLdifCoreConstants.NEWLINE_ESCAPE,
                        FlextLdifCoreConstants.CONTENT_PREVIEW_REPLACEMENT,
                    ),
                )

                # Enhanced file writing with atomic operations
                logger.debug(
                    FlextLdifCoreConstants.WRITING_CONTENT_TO_FILE_LOG, encoding
                )
                try:
                    with file_path.open(
                        FlextLdifCoreConstants.FILE_WRITE_MODE,
                        encoding=encoding,
                    ) as f:
                        f.write(content)
                    return FlextResult[bool].ok(data=True)  # noqa: FBT003  # noqa: FBT003
                except (OSError, UnicodeError) as e:
                    error_msg = FlextLdifCoreConstants.FILE_WRITE_FAILED_MSG.format(
                        error=str(e)
                    )
                    logger.exception(error_msg)
                    return FlextResult[bool].fail(error_msg)

            return (
                cls.write(entries)
                .flat_map(write_content_to_file)
                .or_else_get(
                    lambda: FlextResult[bool].fail(
                        FlextLdifCoreConstants.CONTENT_GENERATION_FAILED_FOR_ENTRIES_MSG.format(
                            entries_count=entries_count,
                            error="Content generation failed",
                        )
                    )
                )
                .tap(
                    lambda success: logger.debug(
                        FlextLdifCoreConstants.FILE_WRITE_COMPLETED_LOG, file_path
                    )
                    if success
                    else None
                )
                .tap(
                    lambda success: logger.info(
                        FlextLdifCoreConstants.LDIF_FILE_WRITE_OPERATION_COMPLETED_LOG,
                        entries_count,
                        str(file_path.absolute()),
                        encoding,
                    )
                    if success
                    else None
                )
            )

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug(FlextLdifCoreConstants.EXCEPTION_TYPE_LOG, type(e).__name__)
            logger.debug(
                FlextLdifCoreConstants.FILE_WRITE_EXCEPTION_DETAILS_LOG,
                exc_info=True,
            )
            logger.exception(FlextLdifCoreConstants.EXCEPTION_DURING_FILE_WRITE_LOG)
            return FlextResult[bool].fail(
                FlextLdifCoreConstants.FILE_WRITE_FAILED_MSG.format(error=e),
            )

    @classmethod
    def read_file(
        cls,
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Read and parse LDIF file with comprehensive validation.

        Args:
            file_path: Input file path for LDIF file reading
            encoding: File encoding (default: utf-8)

        Returns:
            FlextResult[list[FlextLdifEntry]]: Parsed entries or error

        """
        # REFACTORING: Enhanced file validation and error context
        logger.debug(
            FlextLdifCoreConstants.STARTING_LDIF_FILE_READ_OPERATION_LOG,
            file_path,
        )
        logger.debug(FlextLdifCoreConstants.FILE_ENCODING_READ_LOG, encoding)

        try:
            file_path = Path(file_path)
            absolute_path = file_path.absolute()
            logger.debug(
                FlextLdifCoreConstants.RESOLVED_ABSOLUTE_FILE_PATH_READ_LOG,
                absolute_path,
            )

            # REFACTORING: Enhanced file validation with detailed error context
            if not file_path.exists():
                not_found_error_msg: str = (
                    FlextLdifCoreConstants.LDIF_FILE_NOT_FOUND_ERROR_MSG.format(
                        absolute_path=absolute_path,
                    )
                )
                logger.error(not_found_error_msg)
                return FlextResult[list[FlextLdifEntry]].fail(not_found_error_msg)

            if not file_path.is_file():
                not_file_error_msg: str = (
                    FlextLdifCoreConstants.PATH_NOT_FILE_ERROR_MSG.format(
                        absolute_path=absolute_path,
                    )
                )
                logger.error(not_file_error_msg)
                return FlextResult[list[FlextLdifEntry]].fail(not_file_error_msg)

            # REFACTORING: Enhanced file metadata collection
            logger.debug(FlextLdifCoreConstants.FILE_EXISTS_COLLECTING_METADATA_LOG)
            file_stat = file_path.stat()
            file_size = file_stat.st_size
            logger.debug(
                FlextLdifCoreConstants.FILE_METADATA_SIZE_MODE_LOG,
                file_size,
                file_stat.st_mode,
            )

            # REFACTORING: Enhanced file size validation
            if file_size == 0:
                logger.warning(
                    FlextLdifCoreConstants.EMPTY_LDIF_FILE_DETECTED_WARNING_LOG,
                    absolute_path,
                )
                return FlextResult[list[FlextLdifEntry]].ok(
                    []
                )  # Return empty list for empty files

            # Read file content with enhanced error handling
            logger.debug(
                FlextLdifCoreConstants.READING_FILE_CONTENT_ENCODING_LOG,
                encoding,
            )
            try:
                with file_path.open(
                    FlextLdifCoreConstants.FILE_READ_MODE,
                    encoding=encoding,
                ) as f:
                    content = f.read()
            except UnicodeDecodeError as e:
                encoding_error_msg: str = (
                    FlextLdifCoreConstants.ENCODING_ERROR_READING_FILE_MSG.format(
                        encoding=encoding,
                        error=e,
                    )
                )
                logger.exception(encoding_error_msg)
                return FlextResult[list[FlextLdifEntry]].fail(encoding_error_msg)

            # REFACTORING: Enhanced content validation and metrics
            content_size = len(content)
            lines_count = len(content.splitlines())
            logger.debug(
                FlextLdifCoreConstants.FILE_CONTENT_READ_SUCCESS_LOG,
                content_size,
                lines_count,
            )
            logger.debug(
                FlextLdifCoreConstants.CONTENT_PREVIEW_REPLACE_LOG,
                content[
                    : FlextLdifCoreConstants.FILE_READ_CONTENT_PREVIEW_SIZE
                ].replace(
                    FlextLdifCoreConstants.NEWLINE_ESCAPE,
                    FlextLdifCoreConstants.NEWLINE_TO_ESCAPED_NEWLINE,
                ),
            )

            # Parse content with enhanced error context
            logger.debug(
                FlextLdifCoreConstants.DELEGATING_TO_PARSE_METHOD_FOR_CONTENT_LOG,
            )
            result = cls.parse(content)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug(
                FlextLdifCoreConstants.EXCEPTION_TYPE_READ_LOG,
                type(e).__name__,
            )
            logger.debug(
                FlextLdifCoreConstants.FILE_READ_EXCEPTION_DETAILS_READ_LOG,
                exc_info=True,
            )
            logger.exception(
                FlextLdifCoreConstants.EXCEPTION_DURING_FILE_READ_OPERATION_LOG,
            )
            return FlextResult[list[FlextLdifEntry]].fail(
                FlextLdifCoreConstants.LDIF_FILE_READ_FAILED_ERROR_MSG.format(error=e),
            )
        else:
            # REFACTORING: Enhanced result logging with comprehensive metrics
            entries = result.unwrap_or([])
            if entries:
                entries_count = len(entries)
                logger.debug(
                    FlextLdifCoreConstants.FILE_READ_AND_PARSE_SUCCESS_LOG,
                    entries_count,
                    absolute_path,
                )
                logger.info(
                    FlextLdifCoreConstants.LDIF_FILE_PROCESSING_COMPLETED_SUCCESS_LOG,
                    str(absolute_path),
                    file_size,
                    content_size,
                    lines_count,
                    entries_count,
                    encoding,
                )
            else:
                # REFACTORING: Enhanced parse failure logging with context
                error_msg = FlextLdifCoreConstants.LDIF_PARSING_FAILED_FOR_FILE_ERROR_MSG.format(
                    absolute_path=absolute_path,
                    error=result.error,
                )
                logger.error(error_msg)
                logger.debug(
                    FlextLdifCoreConstants.PARSE_METHOD_FAILED_AFTER_SUCCESSFUL_READ_LOG,
                )

            return result


__all__: list[str] = [
    "TLdif",
]
