"""FLEXT LDIF Utilities - Unified utilities class following FLEXT standards.

Provides LDIF-specific utility methods extending flext-core FlextUtilities.
Single FlextLdifUtilities class with nested utility subclasses following FLEXT pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from flext_core import FlextProcessors, FlextResult, FlextUtilities
from flext_ldif.constants import FlextLdifConstants


class FlextLdifUtilities(FlextUtilities):
    """Single unified LDIF utilities class following FLEXT standards.

    Contains all utility subclasses for LDIF domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    Extends FlextUtilities with LDIF-specific functionality.
    """

    # =========================================================================
    # TIME UTILITIES - Timestamp and time-related operations
    # =========================================================================

    class TimeUtilities:
        """Time-related utility methods for LDIF operations."""

        @staticmethod
        def get_timestamp() -> str:
            """Get current timestamp string.

            Returns:
                str: ISO format timestamp string.

            """
            return datetime.now(UTC).isoformat()

        @staticmethod
        def get_formatted_timestamp(format_string: str = "%Y-%m-%d %H:%M:%S") -> str:
            """Get formatted timestamp string.

            Args:
                format_string: Format string for timestamp

            Returns:
                str: Formatted timestamp string.

            """
            return datetime.now(UTC).strftime(format_string)

    class TextUtilities:
        """Text-related utility methods for LDIF operations."""

        BYTES_PER_UNIT: Final[float] = 1024.0

        @staticmethod
        def format_byte_size(size_bytes: object) -> str:
            """Format byte size to human-readable string.

            Args:
                size_bytes: Size in bytes to format

            Returns:
                str: Formatted size string (e.g., "1.5 KB", "2.0 MB")

            """
            if not isinstance(size_bytes, (int, float)):
                msg = f"size_bytes must be int or float, got {type(size_bytes)}"
                raise TypeError(msg)

            # Handle special cases
            if size_bytes <= 0:
                return "0 B"

            units = ["B", "KB", "MB", "GB", "TB"]
            unit_index = 0
            size = float(size_bytes)

            bytes_per_unit = FlextLdifUtilities.TextUtilities.BYTES_PER_UNIT
            while size >= bytes_per_unit and unit_index < len(units) - 1:
                size /= bytes_per_unit
                unit_index += 1

            return f"{size:.1f} {units[unit_index]}"

    # =========================================================================
    # FILE UTILITIES - File and path-related operations
    # =========================================================================

    class FileUtilities:
        """File-related utility methods for LDIF operations."""

        @staticmethod
        def validate_file_path(
            file_path: Path, *, check_writable: bool = False
        ) -> FlextResult[Path]:
            """Validate file path for read/write operations.

            Args:
                file_path: Path to validate
                check_writable: If True, check if file/parent directory is writable

            Returns:
                FlextResult[Path]: Success with validated path (resolved), failure with error message

            """
            try:
                # Resolve the path to absolute
                resolved_path = file_path.resolve()

                # Check if path exists
                if not resolved_path.exists():
                    # If file doesn't exist, check if we can create it
                    if check_writable:
                        # Check if parent directory exists and is writable
                        parent_dir = resolved_path.parent
                        if not parent_dir.exists():
                            return FlextResult[Path].fail(
                                f"Parent directory does not exist: {parent_dir}"
                            )

                        if (
                            not parent_dir.stat().st_mode & 0o200
                        ):  # Check write permission
                            return FlextResult[Path].fail(
                                f"Parent directory is not writable: {parent_dir}"
                            )

                        # For write operations, allow creating new files
                        return FlextResult[Path].ok(resolved_path)
                    # For read operations, file must exist
                    return FlextResult[Path].fail(
                        f"Path does not exist: {resolved_path}"
                    )

                # Check if it's a directory
                if resolved_path.is_dir():
                    return FlextResult[Path].fail(
                        f"Path is a directory: {resolved_path}"
                    )

                # Check if it's a file
                if not resolved_path.is_file():
                    return FlextResult[Path].fail(
                        f"Path exists but is not a file: {resolved_path}"
                    )

                # Check writable permissions if requested
                if check_writable:
                    # Check if file is writable
                    if (
                        not resolved_path.stat().st_mode & 0o200
                    ):  # Check write permission
                        return FlextResult[Path].fail(
                            f"File is not writable: {resolved_path}"
                        )

                    # Check if parent directory is writable
                    parent_dir = resolved_path.parent
                    if not parent_dir.stat().st_mode & 0o200:
                        return FlextResult[Path].fail(
                            f"Parent directory is not writable: {parent_dir}"
                        )

                return FlextResult[Path].ok(resolved_path)
            except Exception as e:  # pragma: no cover
                return FlextResult[Path].fail(f"File path validation failed: {e}")

        @staticmethod
        def ensure_file_extension(file_path: Path, extension: str) -> Path:
            """Ensure file has the specified extension.

            Args:
                file_path: File path to check
                extension: Extension to ensure (with or without dot)

            Returns:
                Path: File path with correct extension

            """
            if not extension.startswith("."):
                extension = f".{extension}"

            if file_path.suffix.lower() != extension.lower():
                return file_path.with_suffix(extension)
            return file_path

        @staticmethod
        def count_lines_in_file(file_path: Path) -> FlextResult[int]:
            """Count lines in a text file.

            Args:
                file_path: Path to the file to count lines in

            Returns:
                FlextResult[int]: Success with line count, failure with error message

            """
            try:
                # Check if file exists
                if not file_path.exists():
                    return FlextResult[int].fail(f"File does not exist: {file_path}")

                # Check if it's a file
                if not file_path.is_file():
                    return FlextResult[int].fail(f"Path is not a file: {file_path}")

                # Count lines
                line_count = 0
                with Path(file_path).open(
                    "r", encoding=FlextLdifConstants.Encoding.DEFAULT_ENCODING
                ) as file:
                    for _ in file:
                        line_count += 1

                return FlextResult[int].ok(line_count)
            except UnicodeDecodeError as e:
                return FlextResult[int].fail(
                    f"Encoding error reading file {file_path}: {e}"
                )
            except Exception as e:  # pragma: no cover
                return FlextResult[int].fail(
                    f"Error counting lines in file {file_path}: {e}"
                )

    # =========================================================================
    # DN UTILITIES - Distinguished Name operations (SINGLE SOURCE OF TRUTH)
    # =========================================================================

    class DnUtilities:
        """Distinguished Name utility methods - centralized DN operations.

        This is the SINGLE SOURCE OF TRUTH for all DN operations in flext-ldif.
        All DN parsing, validation, and normalization should use these methods.
        """

        @staticmethod
        def parse_dn_components(dn: str) -> FlextResult[list[str]]:
            r"""Parse DN into components - SINGLE SOURCE OF TRUTH for DN splitting.

            Handles escaped commas (\,) properly according to RFC 4514.

            Args:
                dn: Distinguished Name string

            Returns:
                FlextResult[list[str]]: List of DN components or error

            """
            if not dn or not dn.strip():
                return FlextResult[list[str]].fail("DN cannot be empty")

            try:
                # Split by comma but respect escaped commas (\\,)
                # RFC 4514: Commas can be escaped with backslash
                components: list[str] = []
                current_component = ""
                i = 0
                while i < len(dn):
                    if dn[i] == "\\" and i + 1 < len(dn):
                        # Escaped character - include backslash and next char
                        current_component += dn[i : i + 2]
                        i += 2
                    elif dn[i] == ",":
                        # Unescaped comma - component boundary
                        if current_component.strip():
                            components.append(current_component.strip())
                        current_component = ""
                        i += 1
                    else:
                        current_component += dn[i]
                        i += 1

                # Add last component
                if current_component.strip():
                    components.append(current_component.strip())

                if not components:
                    return FlextResult[list[str]].fail("DN has no valid components")
                return FlextResult[list[str]].ok(components)
            except Exception as e:
                return FlextResult[list[str]].fail(
                    f"Failed to parse DN components: {e}"
                )

        @staticmethod
        def validate_dn_format(dn: str) -> FlextResult[bool]:
            """Validate DN format - SINGLE SOURCE OF TRUTH for DN validation.

            Args:
                dn: Distinguished Name string to validate

            Returns:
                FlextResult[bool]: True if valid, error message if invalid

            """
            if not dn or not dn.strip():
                return FlextResult[bool].fail(
                    FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR
                )

            # Check length limit (RFC 4514)
            if len(dn) > FlextLdifConstants.LdifValidation.MAX_DN_LENGTH:
                return FlextResult[bool].fail(
                    f"DN exceeds maximum length of "
                    f"{FlextLdifConstants.LdifValidation.MAX_DN_LENGTH}"
                )

            # Parse components using centralized method
            components_result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)
            if components_result.is_failure:
                return FlextResult[bool].fail(
                    f"{FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR}: "
                    f"{components_result.error}"
                )

            components = components_result.unwrap()

            # Validate minimum components
            if len(components) < FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS:
                return FlextResult[bool].fail(
                    f"DN must have at least "
                    f"{FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS} component(s)"
                )

            # Validate each component has attribute=value format
            for component in components:
                if "=" not in component:
                    return FlextResult[bool].fail(
                        f"{FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR}: "
                        f"Component '{component}' missing '=' separator"
                    )

                attr, value = component.split("=", 1)
                if not attr.strip() or not value.strip():
                    return FlextResult[bool].fail(
                        f"{FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR}: "
                        f"Empty attribute or value in component '{component}'"
                    )

            return FlextResult[bool].ok(True)

        @staticmethod
        def normalize_dn(dn: str) -> FlextResult[str]:
            """Normalize DN to canonical form - SINGLE SOURCE OF TRUTH.

            Args:
                dn: Distinguished Name string to normalize

            Returns:
                FlextResult[str]: Normalized DN or error

            """
            # Validate first
            validation_result = FlextLdifUtilities.DnUtilities.validate_dn_format(dn)
            if validation_result.is_failure:
                return FlextResult[str].fail(validation_result.error or "Invalid DN")

            # Parse components
            components_result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)
            if components_result.is_failure:
                return FlextResult[str].fail(
                    components_result.error or "Failed to parse DN"
                )

            components = components_result.unwrap()

            # Normalize each component
            normalized_components: list[str] = []
            for component in components:
                attr, value = component.split("=", 1)
                # Normalize: lowercase attribute, trim spaces from value
                attr_normalized = attr.strip().lower()
                value_normalized = " ".join(value.strip().split())
                normalized_components.append(f"{attr_normalized}={value_normalized}")

            return FlextResult[str].ok(",".join(normalized_components))

        @staticmethod
        def get_dn_depth(dn: str) -> FlextResult[int]:
            """Get DN depth (number of components).

            Args:
                dn: Distinguished Name string

            Returns:
                FlextResult[int]: DN depth or error

            """
            components_result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)
            if components_result.is_failure:
                return FlextResult[int].fail(
                    components_result.error or "Failed to parse DN"
                )
            return FlextResult[int].ok(len(components_result.unwrap()))

        @staticmethod
        def extract_dn_attribute(dn: str, attribute_name: str) -> FlextResult[str]:
            """Extract specific attribute value from DN.

            Args:
                dn: Distinguished Name string
                attribute_name: Attribute name to extract (case-insensitive)

            Returns:
                FlextResult[str]: Attribute value or error if not found

            """
            components_result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)
            if components_result.is_failure:
                return FlextResult[str].fail(
                    components_result.error or "Failed to parse DN"
                )

            components = components_result.unwrap()
            attr_lower = attribute_name.lower()

            for component in components:
                if "=" in component:
                    attr, value = component.split("=", 1)
                    if attr.strip().lower() == attr_lower:
                        return FlextResult[str].ok(value.strip())

            return FlextResult[str].fail(
                f"Attribute '{attribute_name}' not found in DN"
            )

    # =========================================================================
    # PROCESSORS - FlextProcessors integration for data transformations
    # =========================================================================

    class Processors:
        """Processing utilities for LDIF data transformations using FlextProcessors.

        Provides access to flext-core processing capabilities for batch operations,
        parallel processing, and pipeline creation through processor registration.
        """

        @staticmethod
        def create_processor(
            config: dict[str, object] | None = None,
        ) -> FlextProcessors:
            """Create a FlextProcessors instance for LDIF processing.

            Args:
                config: Optional processor configuration

            Returns:
                FlextProcessors: Configured processor instance

            """
            processor_config: dict[str, object] = {}
            if config:
                processor_config = config
            return FlextProcessors(config=processor_config)

        @staticmethod
        def process_entries_batch(
            processor_name: str,
            entries: list[object],
            processors: FlextProcessors | None = None,
        ) -> FlextResult[list[object]]:
            """Process LDIF entries in batches using registered processor.

            Args:
                processor_name: Name of registered processor
                entries: List of entry dictionaries to process
                processors: Optional FlextProcessors instance (creates new if None)

            Returns:
                FlextResult[list[object]]: Processed entries or error

            """
            if processors is None:
                processors = FlextLdifUtilities.Processors.create_processor()

            return processors.process_batch(processor_name, entries)

        @staticmethod
        def process_entries_parallel(
            processor_name: str,
            entries: list[object],
            processors: FlextProcessors | None = None,
        ) -> FlextResult[list[object]]:
            """Process LDIF entries in parallel using registered processor.

            Args:
                processor_name: Name of registered processor
                entries: List of entry dictionaries to process
                processors: Optional FlextProcessors instance (creates new if None)

            Returns:
                FlextResult[list[object]]: Processed entries or error

            """
            if processors is None:
                processors = FlextLdifUtilities.Processors.create_processor()

            return processors.process_parallel(processor_name, entries)

        @staticmethod
        def register_processor(
            name: str,
            processor_func: object,
            processors: FlextProcessors | None = None,
        ) -> FlextResult[FlextProcessors]:
            """Register a processor function for batch/parallel processing.

            Args:
                name: Processor name for registration
                processor_func: Callable to process entries
                processors: Optional FlextProcessors instance (creates new if None)

            Returns:
                FlextResult[FlextProcessors]: Processors instance or error

            """
            if processors is None:
                processors = FlextLdifUtilities.Processors.create_processor()

            result = processors.register(name, processor_func)
            if result.is_failure:
                return FlextResult[FlextProcessors].fail(
                    f"Processor registration failed: {result.error}"
                )

            return FlextResult[FlextProcessors].ok(processors)
