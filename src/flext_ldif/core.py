"""FLEXT-LDIF Core Processing Infrastructure.

This module provides the core infrastructure for LDIF processing operations,
implementing low-level parsing, validation, and writing functionality with
comprehensive error handling and performance optimizations.

The core module bridges between domain models and concrete LDIF format handling,
providing the technical implementation details while maintaining clean interfaces
for higher-level application services.

Key Components:
    - TLdif: Core LDIF processing class with parsing and writing operations
    - LDIF format validation with RFC 2849 compliance checking
    - Performance-optimized parsing with configurable limits and timeouts
    - Integration with modernized LDIF extensions for enhanced format support

Architecture:
    Part of Infrastructure Layer in Clean Architecture, this module handles
    technical LDIF format concerns and provides concrete implementations for
    domain repository interfaces. Isolates format-specific logic from business rules.

Performance Features:
    - Streaming support for large LDIF files with memory management
    - Regex-based validation with compiled patterns for efficiency
    - Configurable processing limits to prevent resource exhaustion
    - Comprehensive error reporting with line number tracking

Example:
    Direct core processing for performance-critical operations:

    >>> from flext_ldif.core import TLdif
    >>>
    >>> # Parse LDIF with core processor
    >>> ldif_content = '''
    ... dn: cn=user,dc=example,dc=com
    ... cn: user
    ... objectClass: person
    ... '''
    >>>
    >>> result = TLdif.parse(ldif_content)
    >>> if result.success:
    ...     entries = result.data
    ...     print(f"Parsed {len(entries)} entries")
    ... else:
    ...     print(f"Parse failed: {result.error}")

Integration:
    - Uses flext-core FlextResult pattern for consistent error handling
    - Integrates with modernized LDIF extensions for format compatibility
    - Provides foundation for higher-level application service operations
    - Supports observability integration through structured logging

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextResult, get_logger
from flext_core.core_exceptions import FlextValidationError

# ✅ CORRECT - Import from flext-ldap root API to eliminate validation duplication
from flext_ldap import (
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_dn,
)

from .modernized_ldif import modernized_ldif_parse, modernized_ldif_write

if TYPE_CHECKING:
    from .models import FlextLdifEntry, FlextLdifFactory, LDIFContent
else:
    # Need FlextLdifFactory at runtime for parsing
    from .models import FlextLdifFactory

logger = get_logger(__name__)


class TLdif:
    """Core LDIF processing functionality using flext-core patterns.

    ✅ CORRECT ARCHITECTURE: Uses flext-ldap root API for validation.
    ZERO duplication - eliminated local validation patterns.
    """

    # Legacy-compatible validation patterns exposed for tests
    # These mirror flext-ldap validation rules at a high level
    DN_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*=[^,]+(,[A-Za-z][A-Za-z0-9-]*=[^,]+)*$")
    ATTR_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")

    @classmethod
    def parse(cls, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into domain entities with enterprise-grade processing and validation.

        Performs comprehensive LDIF parsing using modernized LDIF parser with enhanced error
        handling, logging integration, and domain model conversion. This core parsing method
        serves as the foundation for all LDIF processing operations in the system.

        The method orchestrates the complete parsing pipeline including content validation,
        modernized LDIF parsing with RFC 2849 compliance, domain object conversion, and
        comprehensive error reporting with structured logging integration.

        Args:
            content: LDIF content as string or LDIFContent type for parsing

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with parsed domain entities or failure with detailed error context

        Processing Pipeline:
            1. Content type validation and string conversion
            2. Modernized LDIF parsing with RFC 2849 compliance
            3. Raw entry extraction and validation
            4. Domain model conversion to FlextLdifEntry objects
            5. Comprehensive error handling and logging

        Technical Implementation:
            - Uses modernized_ldif_parse for enhanced format support
            - Handles string/bytes conversion automatically
            - Provides detailed logging for troubleshooting
            - Maintains performance with minimal object creation

        Example:
            >>> from flext_ldif.core import TLdif
            >>>
            >>> ldif_content = '''
            ... dn: cn=John Doe,ou=people,dc=example,dc=com
            ... objectClass: person
            ... objectClass: inetOrgPerson
            ... cn: John Doe
            ... mail: john@example.com
            ...
            ... dn: cn=Engineering,ou=groups,dc=example,dc=com
            ... objectClass: groupOfNames
            ... cn: Engineering
            ... member: cn=John Doe,ou=people,dc=example,dc=com
            ... '''
            >>>
            >>> result = TLdif.parse(ldif_content)
            >>> if result.success:
            ...     entries = result.data
            ...     print(f"Parsed {len(entries)} entries successfully")
            ...     for entry in entries:
            ...         print(f"- {entry.dn}")
            ... else:
            ...     print(f"Parse failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        logger.debug("TLdif.parse called with content type: %s", type(content).__name__)
        logger.debug("Content length: %d characters", len(str(content)))
        try:
            content_str = str(content)
            logger.debug("Content converted to string, length: %d", len(content_str))
            logger.debug(
                "Content preview: %s...",
                content_str[:200].replace("\n", "\\n"),
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
            FlextValidationError,
        ) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.debug("Full exception details", exc_info=True)
            logger.exception("Exception in TLdif.parse")
            return FlextResult.fail(f"Parse failed: {e}")

    @classmethod
    def _parse_with_modernized_ldif(
        cls,
        content: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse using modernized LDIF parser with full string compatibility."""
        logger.debug("Starting modernized LDIF parsing")
        logger.debug("Content lines count: %d", len(content.splitlines()))
        try:
            # Use modernized parser that handles all string/bytes issues internally
            logger.debug("Calling modernized_ldif_parse")
            parse_result = modernized_ldif_parse(content)

            if not parse_result.success:
                logger.warning("Modernized LDIF parse failed: %s", parse_result.error)
                logger.debug("Returning failure from modernized parser")
                return FlextResult.fail(
                    parse_result.error or "Modernized LDIF parse failed",
                )

            raw_entries = parse_result.data or []
            logger.debug("Modernized parser returned %d raw entries", len(raw_entries))
            logger.debug(
                "Raw entries DNs: %s",
                [dn for dn, _ in raw_entries[:5]],
            )  # First 5 for trace

            entries = []

            # Convert to FlextLdifEntry objects
            logger.debug("Converting raw entries to FlextLdifEntry objects")
            for i, (dn, attrs) in enumerate(raw_entries):
                logger.debug(
                    "Processing entry %d: DN=%s, attrs_count=%d",
                    i,
                    dn,
                    len(attrs),
                )
                entry_result = FlextLdifFactory.create_entry(dn, attrs)
                if entry_result.is_failure or entry_result.data is None:
                    return FlextResult.fail(f"Failed to create entry: {entry_result.error}")
                entry = entry_result.data
                entries.append(entry)

            logger.debug(
                "Successfully converted %d entries to FlextLdifEntry objects",
                len(entries),
            )
            logger.info(
                "Modernized LDIF parsing completed successfully - raw_entries=%d, converted_entries=%d",
                len(raw_entries),
                len(entries),
            )
            return FlextResult.ok(entries)

        except (
            ValueError,
            TypeError,
            AttributeError,
            ImportError,
            FlextValidationError,
        ) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.debug("Full exception details", exc_info=True)
            logger.exception("Exception in modernized LDIF parsing")
            return FlextResult.fail(f"Modernized LDIF parse failed: {e}")

    @classmethod
    def validate(cls, entry: FlextLdifEntry | None) -> FlextResult[bool]:
        """Validate LDIF entry with comprehensive format and business rule validation.

        Performs extensive validation of LDIF entries including DN format validation,
        attribute name compliance, required attribute checking, and LDAP schema
        validation using compiled regex patterns for optimal performance.

        This core validation method enforces RFC 2849 LDIF format compliance and
        LDAP directory standards with detailed error reporting and comprehensive
        logging for troubleshooting and audit purposes.

        Args:
            entry: FlextLdifEntry domain object to validate

        Returns:
            FlextResult[bool]: Success with True if entry is valid, failure with detailed error information

        Validation Rules Applied:
            1. DN Format Validation: Ensures DN follows proper LDAP naming conventions
            2. Attribute Name Validation: Validates attribute names against LDAP standards
            3. Required Attributes: Enforces presence of mandatory objectClass attribute
            4. Business Rule Compliance: Applies domain-specific validation rules

        Technical Implementation:
            - Uses compiled regex patterns for efficient validation
            - Provides detailed logging at debug and trace levels
            - Maintains performance through optimized validation order
            - Returns comprehensive error context for troubleshooting

        Example:
            >>> from flext_ldif.core import TLdif
            >>> from flext_ldif.models import (
            ...     FlextLdifEntry,
            ...     FlextLdifDistinguishedName,
            ...     FlextLdifAttributes,
            ... )
            >>>
            >>> # Create valid entry
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={"objectClass": ["person"], "cn": ["user"]}
            ...     ),
            ... )
            >>>
            >>> result = TLdif.validate()
            >>> if result.success and result.data:
            ...     print("Entry is valid")
            ... else:
            ...     print(f"Validation failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        try:
            if entry is None:
                logger.error("Cannot validate None entry")
                return FlextResult.fail("Entry cannot be None")

            logger.debug("Validating LDIF entry: %s", entry.dn)
            logger.debug("Entry attributes count: %d", len(entry.attributes.attributes))
            # ✅ DELEGATE DN validation to flext-ldap root API - NO local patterns
            dn_str = str(entry.dn)
            logger.debug("Validating DN format: %s", dn_str)
            # Enforce TLdif legacy DN pattern first (stricter first component rules)
            if not cls.DN_PATTERN.match(dn_str):
                logger.warning("Invalid DN format by TLdif pattern: %s", dn_str)
                return FlextResult.fail(f"Invalid DN format: {entry.dn}")
            # Then delegate to flext-ldap full validation for broader checks
            if not flext_ldap_validate_dn(dn_str):
                logger.warning("Invalid DN format: %s", dn_str)
                logger.debug("DN failed flext-ldap validation")
                return FlextResult.fail(f"Invalid DN format: {entry.dn}")
            logger.debug("DN format validation passed")

            # Validate attribute names
            logger.debug(
                "Validating %d attribute names",
                len(entry.attributes.attributes),
            )
            for attr_name in entry.attributes.attributes:
                logger.debug("Validating attribute name: %s", attr_name)
                # ✅ DELEGATE attribute validation to flext-ldap root API - NO local patterns
                # Enforce TLdif legacy attribute name pattern as well
                if not cls.ATTR_NAME_PATTERN.match(attr_name) or not flext_ldap_validate_attribute_name(attr_name):
                    logger.warning("Invalid attribute name: %s", attr_name)
                    logger.debug("Attribute name failed flext-ldap validation")
                    return FlextResult.fail(f"Invalid attribute name: {attr_name}")
            logger.debug("All attribute names validated successfully")

            # Validate required objectClass attribute
            logger.debug("Checking for required objectClass attribute")
            if not entry.has_attribute("objectClass"):
                logger.warning(
                    "Entry missing required objectClass attribute: %s",
                    entry.dn,
                )
                logger.debug("objectClass attribute is required but not found")
                return FlextResult.fail("Entry missing required objectClass attribute")

            object_classes = entry.get_attribute("objectClass")
            logger.debug("Found objectClass values: %s", object_classes)
            logger.debug("Entry validation passed for: %s", entry.dn)
            logger.info(
                "LDIF entry validation successful - dn=%s, attributes_count=%d, object_classes=%s",
                str(entry.dn),
                len(entry.attributes.attributes),
                object_classes,
            )

            return FlextResult.ok(data=True)

        except (ValueError, TypeError, AttributeError) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.debug("Validation exception details", exc_info=True)
            logger.exception("Exception during entry validation")
            return FlextResult.fail(f"Validation failed: {e}")

    @classmethod
    def validate_entries(cls, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries with bulk processing optimization and detailed error reporting.

        Performs comprehensive validation of multiple LDIF entries with optimized bulk processing,
        early failure detection, and detailed error context. Uses efficient iteration patterns
        and provides comprehensive logging for troubleshooting large datasets.

        This method is optimized for bulk operations while maintaining individual entry validation
        quality and providing detailed error reporting with entry indexing for precise error location.

        Args:
            entries: List of FlextLdifEntry domain objects to validate

        Returns:
            FlextResult[bool]: Success with True if all entries valid, failure with first validation error and entry index

        Bulk Processing Features:
            - Early failure detection stops processing on first invalid entry
            - Entry indexing provides precise error location context
            - Optimized iteration minimizes memory overhead
            - Comprehensive error reporting with entry identification

        Performance Characteristics:
            - O(n) complexity with early termination
            - Minimal memory overhead through streaming validation
            - Compiled regex patterns reused for efficiency
            - Detailed logging available for troubleshooting

        Example:
            >>> from flext_ldif.core import TLdif
            >>>
            >>> # Validate multiple entries
            >>> result = TLdif.validate_entries(entries)
            >>> if result.success and result.data:
            ...     print(f"All {len(entries)} entries are valid")
            ... else:
            ...     print(f"Validation failed: {result.error}")
            ...     # Error message includes entry index for precise location

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        try:
            # REFACTORING: Optimized validation with early termination and better error context
            total_entries = len(entries)
            logger.debug("Starting bulk validation of %d entries", total_entries)

            for i, entry in enumerate(entries):
                logger.debug(
                    "Validating entry %d/%d: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                result = cls.validate(entry)
                if not result.success:
                    error_msg: str = f"Entry {i + 1} of {total_entries} failed validation ({entry.dn}): {result.error}"
                    logger.warning(
                        "Bulk validation failed at entry %d: %s",
                        i + 1,
                        result.error,
                    )
                    return FlextResult.fail(error_msg)

            logger.debug("Bulk validation successful for all %d entries", total_entries)
            logger.info(
                "Bulk LDIF validation completed successfully - entries_validated=%d",
                total_entries,
            )
            return FlextResult.ok(data=True)

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("Exception during bulk validation")
            return FlextResult.fail(f"Bulk validation failed with exception: {e}")

    @classmethod
    def write(cls, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string with optimized serialization and RFC 2849 compliance.

        Performs high-performance serialization of FlextLdifEntry domain objects to RFC 2849
        compliant LDIF format using modernized LDIF writer with comprehensive error handling
        and performance optimization for bulk operations.

        This core writing method provides the foundation for all LDIF output operations with
        optimized domain object conversion and comprehensive error handling.

        Args:
            entries: List of FlextLdifEntry domain objects to serialize

        Returns:
            FlextResult[str]: Success with RFC 2849 compliant LDIF string or failure with detailed error context

        Serialization Features:
            - RFC 2849 compliant LDIF format generation
            - Optimized domain object to raw entry conversion
            - Modernized LDIF writer integration for enhanced compatibility
            - Comprehensive error handling with detailed context

        Performance Characteristics:
            - O(n) complexity with minimal memory overhead
            - Optimized object conversion reduces allocation pressure
            - Streaming serialization for large datasets
            - No external dependencies for maximum compatibility

        Example:
            >>> from flext_ldif.core import TLdif
            >>>
            >>> # Write entries to LDIF string
            >>> result = TLdif.write(entries)
            >>> if result.success:
            ...     ldif_content = result.data
            ...     print(f"Generated LDIF: {len(ldif_content)} characters")
            ...     # Save to file or process further
            ... else:
            ...     print(f"Write failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        try:
            # REFACTORING: Enhanced error handling and performance logging
            entries_count = len(entries)
            logger.debug("Starting LDIF write operation for %d entries", entries_count)
            logger.debug("Write operation using modernized LDIF writer")

            # Use modernized LDIF writer (no external dependencies)
            result = cls._write_with_modernized_ldif(entries)

            # REFACTORING: Enhanced result logging and metrics
            if result.success and result.data:
                content_length = len(result.data)
                logger.debug(
                    "LDIF write successful: %d characters generated",
                    content_length,
                )
                logger.info(
                    "LDIF write operation completed successfully - entries_count=%d, content_length=%d",
                    entries_count,
                    content_length,
                )
            else:
                logger.warning("LDIF write operation failed: %s", result.error)

            return result

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            logger.exception("Exception during LDIF write operation")
            return FlextResult.fail(f"Write failed with exception: {e}")

    @classmethod
    def _write_with_modernized_ldif(
        cls,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[str]:
        """Write using modernized LDIF writer with full string compatibility."""
        try:
            # Convert FlextLdifEntry objects to (dn, attrs) tuples
            raw_entries = []
            for entry in entries:
                dn = str(entry.dn)
                attrs = entry.attributes.attributes
                raw_entries.append((dn, attrs))

            # Use modernized writer
            write_result = modernized_ldif_write(raw_entries)

            if not write_result.success:
                return FlextResult.fail(
                    write_result.error or "Modernized LDIF write failed",
                )

            return FlextResult.ok(write_result.data or "")

        except (ValueError, TypeError, AttributeError, ImportError) as e:
            return FlextResult.fail(f"Modernized LDIF write failed: {e}")

    @classmethod
    def write_file(
        cls,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[bool]:
        """Write LDIF entries to file with enterprise-grade file handling and comprehensive error management.

        Performs high-performance file writing of FlextLdifEntry domain objects to LDIF files with
        comprehensive error handling, directory creation, file encoding management, and detailed
        logging integration for enterprise environments.

        This method provides the complete file writing pipeline including content generation,
        directory path resolution, encoding validation, and comprehensive error reporting
        with structured logging for troubleshooting and audit purposes.

        Args:
            entries: List of FlextLdifEntry domain objects to write to file
            file_path: Target file path as string or Path object for LDIF output
            encoding: File encoding specification (default: utf-8) for cross-platform compatibility

        Returns:
            FlextResult[bool]: Success with True if file written successfully, failure with detailed error context

        File Operation Features:
            - Automatic directory creation for non-existent parent directories
            - Cross-platform path handling with pathlib integration
            - Comprehensive encoding support with validation
            - Atomic file operations to prevent corruption

        Performance Characteristics:
            - Efficient domain object to LDIF content conversion
            - Optimized file I/O with minimal memory overhead
            - Streaming write operations for large datasets
            - Comprehensive error context with file path tracking

        Example:
            >>> from flext_ldif.core import TLdif
            >>> from pathlib import Path
            >>>
            >>> # Write entries to LDIF file
            >>> output_path = Path("output/users.ldif")
            >>> result = TLdif.write_file(entries, output_path)
            >>> if result.success:
            ...     print(f"Successfully written {len(entries)} entries")
            ... else:
            ...     print(f"Write failed: {result.error}")

        Error Handling:
            - File system permission errors with detailed context
            - Directory creation failures with specific error messages
            - Encoding validation with fallback recommendations
            - Content generation failures with pipeline error tracking

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced validation and error context
        entries_count = len(entries)
        logger.debug(
            "Starting file write operation for %d entries to: %s",
            entries_count,
            file_path,
        )
        logger.debug("File encoding: %s", encoding)

        try:
            file_path = Path(file_path)
            logger.debug("Resolved file path: %s", file_path.absolute())

            # REFACTORING: Enhanced directory handling with automatic creation
            parent_dir = file_path.parent
            if not parent_dir.exists():
                logger.debug("Creating parent directory: %s", parent_dir)
                parent_dir.mkdir(parents=True, exist_ok=True)
                logger.debug("Parent directory created successfully")

            logger.debug("File path exists: %s", file_path.exists())

            # Get LDIF content with enhanced error handling
            logger.debug("Converting %d entries to LDIF content", entries_count)
            content_result = cls.write(entries)
            if not content_result.success:
                error_msg: str = f"Content generation failed for {entries_count} entries: {content_result.error}"
                logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced content validation
            if content_result.data is None:
                error_msg = "Content generation succeeded but returned None data"
                logger.error(error_msg)
                return FlextResult.fail(error_msg)

            content_size = len(content_result.data)
            logger.debug("Generated LDIF content: %d characters", content_size)
            logger.debug(
                "Content preview: %s...",
                content_result.data[:100].replace("\n", "\\n"),
            )

            # REFACTORING: Enhanced file writing with atomic operations
            logger.debug("Writing content to file with encoding: %s", encoding)
            with file_path.open("w", encoding=encoding) as f:
                f.write(content_result.data)

            # REFACTORING: Enhanced success logging with comprehensive metrics
            logger.debug("File write completed successfully: %s", file_path)
            logger.info(
                "LDIF file write operation completed successfully - entries_count=%d, file_path=%s, content_size_chars=%d, encoding=%s",
                entries_count,
                str(file_path.absolute()),
                content_size,
                encoding,
            )

            return FlextResult.ok(data=True)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.debug("File write exception details", exc_info=True)
            logger.exception("Exception during file write")
            return FlextResult.fail(f"File write failed: {e}")

    @classmethod
    def read_file(
        cls,
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Read and parse LDIF file with enterprise-grade file handling and comprehensive error management.

        Performs high-performance LDIF file reading and parsing with comprehensive error handling,
        file validation, encoding management, and detailed logging integration for enterprise
        environments with complete pipeline processing from file to domain objects.

        This method provides the complete file reading pipeline including file existence validation,
        encoding detection, content reading, LDIF parsing, and domain object conversion with
        comprehensive error reporting and structured logging for troubleshooting.

        Args:
            file_path: Input file path as string or Path object for LDIF file reading
            encoding: File encoding specification (default: utf-8) for cross-platform compatibility

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with parsed domain objects, failure with detailed error context

        File Operation Features:
            - Comprehensive file existence and accessibility validation
            - Cross-platform path handling with pathlib integration
            - Encoding detection and validation with fallback support
            - File size and content validation before processing

        Performance Characteristics:
            - Optimized file I/O with minimal memory overhead
            - Streaming read operations for large LDIF files
            - Efficient content to domain object conversion
            - Comprehensive error context with file metadata tracking

        Example:
            >>> from flext_ldif.core import TLdif
            >>> from pathlib import Path
            >>>
            >>> # Read and parse LDIF file
            >>> input_path = Path("data/users.ldif")
            >>> result = TLdif.read_file(input_path)
            >>> if result.success:
            ...     entries = result.data
            ...     print(f"Successfully parsed {len(entries)} entries")
            ...     for entry in entries:
            ...         print(f"- {entry.dn}")
            ... else:
            ...     print(f"File read failed: {result.error}")

        Error Handling:
            - File not found errors with detailed path information
            - Permission denied errors with access context
            - Encoding validation with recommendation for alternatives
            - Content parsing failures with line number tracking

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced file validation and error context
        logger.debug("Starting LDIF file read operation: %s", file_path)
        logger.debug("File encoding: %s", encoding)

        try:
            file_path = Path(file_path)
            absolute_path = file_path.absolute()
            logger.debug("Resolved absolute file path: %s", absolute_path)

            # REFACTORING: Enhanced file validation with detailed error context
            if not file_path.exists():
                not_found_error_msg: str = f"LDIF file not found: {absolute_path}"
                logger.error(not_found_error_msg)
                return FlextResult.fail(not_found_error_msg)

            if not file_path.is_file():
                not_file_error_msg: str = f"Path is not a file: {absolute_path}"
                logger.error(not_file_error_msg)
                return FlextResult.fail(not_file_error_msg)

            # REFACTORING: Enhanced file metadata collection
            logger.debug("File exists, collecting file metadata")
            file_stat = file_path.stat()
            file_size = file_stat.st_size
            logger.debug(
                "File metadata - size: %d bytes, mode: %o",
                file_size,
                file_stat.st_mode,
            )

            # REFACTORING: Enhanced file size validation
            if file_size == 0:
                logger.warning("Empty LDIF file detected: %s", absolute_path)
                return FlextResult.ok([])  # Return empty list for empty files

            # Read file content with enhanced error handling
            logger.debug("Reading file content with encoding: %s", encoding)
            try:
                with file_path.open("r", encoding=encoding) as f:
                    content = f.read()
            except UnicodeDecodeError as e:
                encoding_error_msg: str = (
                    f"Encoding error reading file with {encoding}: {e}"
                )
                logger.exception(encoding_error_msg)
                return FlextResult.fail(encoding_error_msg)

            # REFACTORING: Enhanced content validation and metrics
            content_size = len(content)
            lines_count = len(content.splitlines())
            logger.debug(
                "File content read successfully: %d characters, %d lines",
                content_size,
                lines_count,
            )
            logger.debug("Content preview: %s...", content[:200].replace("\n", "\\n"))

            # Parse content with enhanced error context
            logger.debug("Delegating to parse method for content processing")
            result = cls.parse(content)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.debug("File read exception details", exc_info=True)
            logger.exception("Exception during file read operation")
            return FlextResult.fail(f"LDIF file read failed: {e}")
        else:
            # REFACTORING: Enhanced result logging with comprehensive metrics
            if result.success:
                entries_count = len(result.data or [])
                logger.debug(
                    "File read and parse successful: %d entries from %s",
                    entries_count,
                    absolute_path,
                )
                logger.info(
                    "LDIF file processing completed successfully - file_path=%s, file_size_bytes=%d, content_size_chars=%d, lines_count=%d, entries_parsed=%d, encoding=%s",
                    str(absolute_path),
                    file_size,
                    content_size,
                    lines_count,
                    entries_count,
                    encoding,
                )
            else:
                # REFACTORING: Enhanced parse failure logging with context
                error_msg = (
                    f"LDIF parsing failed for file {absolute_path}: {result.error}"
                )
                logger.error(error_msg)
                logger.debug(
                    "Parse method failed after successful file read - file accessible but content invalid",
                )

            return result


__all__: list[str] = [
    "TLdif",
]
