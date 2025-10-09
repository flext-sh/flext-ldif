"""FLEXT LDIF Utilities - Unified utilities class following FLEXT standards.

Provides LDIF-specific utility methods extending flext-core FlextUtilities.
Single FlextLdifUtilities class with nested utility subclasses following FLEXT pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast

from flext_core import FlextProcessors, FlextResult, FlextUtilities

# Configure logger for utilities
logger = logging.getLogger(__name__)

# MANDATORY ldap3 imports - flext-ldif OWNS ldap3 wrapping
from ldap3.utils.dn import parse_dn

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.typings import FlextLdifTypes


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

            # For bytes, show as integer; for larger units, show with 1 decimal
            if unit_index == 0:
                return f"{int(size)} {units[unit_index]}"
            return f"{size:.1f} {units[unit_index]}"

    # =========================================================================
    # DN UTILITIES - Distinguished Name operations (SINGLE SOURCE OF TRUTH)
    # =========================================================================

    class DnUtilities:
        """Distinguished Name utility methods - centralized DN operations.

        This is the SINGLE SOURCE OF TRUTH for all DN operations in flext-ldif.
        All DN parsing, validation, and normalization should use these methods.

        Uses ldap3.utils.dn for RFC 4514 compliant DN parsing (zero duplication).
        """

        @staticmethod
        def parse_dn_components(dn: str) -> FlextResult[FlextLdifTypes.StringList]:
            r"""Parse DN into components using ldap3.utils.dn.

            Handles escaped commas (\,) properly according to RFC 4514.
            Uses ldap3 library to avoid reimplementing DN parsing.

            Args:
                dn: Distinguished Name string

            Returns:
                FlextResult[FlextLdifTypes.StringList]: List of DN components or error

            """
            if not dn or not dn.strip():
                return FlextResult[FlextLdifTypes.StringList].fail("DN cannot be empty")

            try:
                # Pre-process: Clean up common non-canonical DN formatting
                # RFC 4514 canonical form has no extraneous spaces
                cleaned_dn = dn.strip()
                # Remove all spaces around commas (handle multiple spaces)
                cleaned_dn = re.sub(r"\s*,\s*", ",", cleaned_dn)
                # Remove all spaces around equals signs
                cleaned_dn = re.sub(r"\s*=\s*", "=", cleaned_dn)

                # Use ldap3.utils.dn.parse_dn for RFC 4514 compliant parsing
                # parse_dn returns list of (attr, value, separator) tuples
                parsed = parse_dn(cleaned_dn)

                if not parsed:
                    return FlextResult[FlextLdifTypes.StringList].fail(
                        "DN has no valid components"
                    )

                # Convert to "attr=value" format, stripping spaces from attrs
                # Note: parse_dn may include leading/trailing spaces in attributes
                components: FlextLdifTypes.StringList = [
                    f"{attr.strip()}={value}" for attr, value, _ in parsed
                ]

                return FlextResult[FlextLdifTypes.StringList].ok(components)
            except Exception as e:
                return FlextResult[FlextLdifTypes.StringList].fail(
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
            """Normalize DN to canonical form using ldap3.utils.dn.

            Uses ldap3.parse_dn for RFC 4514 compliant parsing and normalization.

            Args:
                dn: Distinguished Name string to normalize

            Returns:
                FlextResult[str]: Normalized DN or error

            """
            # Validate first
            validation_result = FlextLdifUtilities.DnUtilities.validate_dn_format(dn)
            if validation_result.is_failure:
                return FlextResult[str].fail(validation_result.error or "Invalid DN")

            try:
                # Parse DN components using ldap3 for RFC 4514 compliance
                components_result = FlextLdifUtilities.DnUtilities.parse_dn_components(
                    dn
                )
                if components_result.is_failure:
                    return FlextResult[str].fail(
                        components_result.error or "Failed to parse DN"
                    )

                components = components_result.unwrap()
                normalized_components: FlextLdifTypes.StringList = []
                for component in components:
                    attr, value = component.split("=", 1)
                    # Normalize: lowercase attribute, trim and normalize spaces in value
                    attr_normalized = attr.strip().lower()
                    value_normalized = " ".join(value.strip().split())
                    normalized_components.append(
                        f"{attr_normalized}={value_normalized}"
                    )

                # Join without spaces - RFC 4514 canonical form
                return FlextResult[str].ok(",".join(normalized_components))
            except Exception as e:
                return FlextResult[str].fail(f"Failed to normalize DN: {e}")

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
            config: FlextLdifTypes.Dict | None = None,
        ) -> FlextProcessors:
            """Create a FlextProcessors instance for LDIF processing.

            Args:
                config: Optional processor configuration

            Returns:
                FlextProcessors: Configured processor instance

            """
            processor_config: FlextLdifTypes.Dict = {}
            if config:
                processor_config = config
            return FlextProcessors(config=processor_config)

        @staticmethod
        def process_entries_batch(
            processor_name: str,
            entries: FlextLdifTypes.List,
            processors: FlextProcessors | None = None,
        ) -> FlextResult[FlextLdifTypes.List]:
            """Process LDIF entries in batches using registered processor.

            Args:
                processor_name: Name of registered processor
                entries: List of entry dictionaries to process
                processors: Optional FlextProcessors instance (creates new if None)

            Returns:
                FlextResult[FlextLdifTypes.List]: Processed entries or error

            """
            if processors is None:
                processors = FlextLdifUtilities.Processors.create_processor()

            return processors.process_batch(processor_name, entries)

        @staticmethod
        def process_entries_parallel(
            processor_name: str,
            entries: FlextLdifTypes.List,
            processors: FlextProcessors | None = None,
        ) -> FlextResult[FlextLdifTypes.List]:
            """Process LDIF entries in parallel using registered processor.

            Args:
                processor_name: Name of registered processor
                entries: List of entry dictionaries to process
                processors: Optional FlextProcessors instance (creates new if None)

            Returns:
                FlextResult[FlextLdifTypes.List]: Processed entries or error

            """
            if processors is None:
                processors = FlextLdifUtilities.Processors.create_processor()

            return processors.process_parallel(processor_name, entries)

    # =========================================================================
    # VALIDATION UTILITIES - LDIF validation operations
    # =========================================================================

    class ValidationUtilities:
        """Validation utility methods for LDIF operations."""

        @staticmethod
        def validate_object_class_name(name: str) -> FlextResult[str]:
            """Validate object class name.

            Args:
                name: Object class name to validate

            Returns:
                FlextResult containing validated name if valid

            """
            if not name:
                return FlextResult[str].fail("Object class name cannot be empty")
            if not re.match(
                FlextLdifConstants.LdifValidation.ATTRIBUTE_NAME_PATTERN, name
            ):
                return FlextResult[str].fail(
                    f"Invalid object class name format: {name}"
                )
            return FlextResult[str].ok(name)

        @staticmethod
        def validate_attribute_name(name: str) -> FlextResult[str]:
            """Validate attribute name.

            Args:
                name: Attribute name to validate

            Returns:
                FlextResult containing validated name if valid

            """
            if not name:
                return FlextResult[str].fail("Attribute name cannot be empty")
            if not re.match(
                FlextLdifConstants.LdifValidation.ATTRIBUTE_NAME_PATTERN, name
            ):
                return FlextResult[str].fail(f"Invalid attribute name format: {name}")
            return FlextResult[str].ok(name)

    # =========================================================================
    # LDIF UTILITIES - Core LDIF operations
    # =========================================================================

    class LdifUtilities:
        """Core LDIF utility methods."""

        @staticmethod
        def count_ldif_entries(content: str) -> FlextResult[int]:
            """Count number of LDIF entries in content.

            Args:
                content: LDIF content string

            Returns:
                FlextResult containing number of entries

            """
            try:
                if not content.strip():
                    return FlextResult[int].ok(0)
                # Simple count based on dn: lines
                count = content.count("\ndn: ") + (
                    1 if content.startswith("dn:") else 0
                )
                return FlextResult[int].ok(count)
            except Exception as e:
                return FlextResult[int].fail(f"Failed to count entries: {e}")

        @staticmethod
        def validate_ldif_syntax(content: str) -> FlextResult[dict[str, object]]:
            """Validate basic LDIF syntax.

            Args:
                content: LDIF content to validate

            Returns:
                FlextResult containing validation results dict

            """
            try:
                if not content.strip():
                    return FlextResult[dict[str, object]].ok({
                        "valid": False,
                        "reason": "Empty content",
                    })

                has_dn = "dn:" in content
                result = {
                    "valid": has_dn,
                    "has_dn": has_dn,
                    "length": len(content),
                }
                return FlextResult[dict[str, object]].ok(
                    cast("dict[str, object]", result)
                )
            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"Failed to validate syntax: {e}"
                )

    # =========================================================================
    # ENCODING UTILITIES - Character encoding detection
    # =========================================================================

    class EncodingUtilities:
        """Character encoding utility methods."""

        @staticmethod
        def detect_encoding(content: bytes) -> FlextResult[str]:
            """Detect character encoding of content using comprehensive analysis.

            Uses multiple detection strategies:
            1. BOM (Byte Order Mark) detection
            2. Charset declaration in content
            3. Statistical analysis of byte patterns
            4. Fallback to common encodings

            Args:
                content: Content bytes to analyze

            Returns:
                FlextResult containing detected encoding

            """

            # Nested helper function: BOM detection
            def _detect_bom_encoding(data: bytes) -> str | None:
                """Detect encoding from Byte Order Mark (BOM)."""
                if len(data) < FlextLdifConstants.Encoding.MIN_BOM_LENGTH:
                    return None
                # UTF-32 BOMs (BE/LE)
                if len(data) >= FlextLdifConstants.Encoding.MIN_UTF32_LENGTH:
                    if data.startswith(b"\x00\x00\xfe\xff"):
                        return "utf-32-be"
                    if data.startswith(b"\xff\xfe\x00\x00"):
                        return "utf-32-le"
                # UTF-16 BOMs (BE/LE)
                if data.startswith(b"\xfe\xff"):
                    return "utf-16-be"
                if data.startswith(b"\xff\xfe"):
                    return "utf-16-le"
                # UTF-8 BOM
                if data.startswith(b"\xef\xbb\xbf"):
                    return "utf-8"
                return None

            # Nested helper function: Charset declaration detection
            def _detect_charset_declaration(data: bytes) -> str | None:
                """Detect encoding from charset declaration in content."""
                try:
                    # Try to decode as ASCII first to find declarations
                    text_sample = data[:1024].decode("ascii", errors="ignore")
                    # XML declaration
                    xml_match = re.search(
                        FlextLdifConstants.LdifPatterns.XML_ENCODING,
                        text_sample,
                        re.IGNORECASE,
                    )
                    if xml_match:
                        return xml_match.group(1).lower()
                    # HTML meta charset
                    html_match = re.search(
                        FlextLdifConstants.LdifPatterns.HTML_CHARSET,
                        text_sample,
                        re.IGNORECASE,
                    )
                    if html_match:
                        return html_match.group(1).lower()
                    # Python coding declaration
                    coding_match = re.search(
                        FlextLdifConstants.LdifPatterns.PYTHON_CODING,
                        text_sample,
                        re.IGNORECASE,
                    )
                    if coding_match:
                        return coding_match.group(1).lower()
                    # LDIF-specific patterns
                    ldif_match = re.search(
                        FlextLdifConstants.LdifPatterns.LDIF_ENCODING,
                        text_sample,
                        re.IGNORECASE,
                    )
                    if ldif_match:
                        return ldif_match.group(1).lower()
                except Exception as e:
                    logger.debug(f"Error during charset pattern matching: {e}")
                return None

            # Nested helper function: Statistical analysis
            def _detect_encoding_statistically(data: bytes) -> str | None:
                """Detect encoding using statistical analysis of byte patterns."""
                if len(data) < FlextLdifConstants.Encoding.MIN_STATISTICAL_LENGTH:
                    return None
                # Count null bytes (indicates UTF-16/32)
                null_count = data.count(0)
                null_ratio = null_count / len(data)
                # UTF-32 typically has many null bytes
                if null_ratio > FlextLdifConstants.Encoding.UTF32_NULL_RATIO_THRESHOLD:
                    if len(data) >= FlextLdifConstants.Encoding.MIN_UTF32_LENGTH:
                        if data[0] == 0 and data[1] == 0:
                            return (
                                "utf-32-be" if data[2:4] != b"\xfe\xff" else "utf-32-le"
                            )
                        if data[1] == 0 and data[3] == 0:
                            return (
                                "utf-16-be" if data[0:2] != b"\xfe\xff" else "utf-16-le"
                            )
                    return "utf-32"
                # UTF-16 has null bytes in even positions
                if null_ratio > FlextLdifConstants.Encoding.UTF16_NULL_RATIO_THRESHOLD:
                    return "utf-16"
                # Check for Latin-1 vs UTF-8 patterns
                utf8_sequences = 0
                i = 0
                while i < len(data) - 1:
                    byte = data[i]
                    if (
                        byte & FlextLdifConstants.Encoding.UTF8_HIGH_BIT_MASK
                    ):  # High bit set
                        if (
                            byte & FlextLdifConstants.Encoding.UTF8_2BYTE_LEAD_MASK
                            == FlextLdifConstants.Encoding.UTF8_2BYTE_LEAD_VALUE
                            and i < len(data) - 1
                        ):  # 2-byte sequence
                            if (
                                data[i + 1]
                                & FlextLdifConstants.Encoding.UTF8_CONTINUATION_MASK
                                == FlextLdifConstants.Encoding.UTF8_CONTINUATION_VALUE
                            ):
                                utf8_sequences += 1
                                i += 2
                                continue
                        elif (
                            byte & FlextLdifConstants.Encoding.UTF8_3BYTE_LEAD_MASK
                            == FlextLdifConstants.Encoding.UTF8_3BYTE_LEAD_VALUE
                            and i < len(data) - 2
                            and (
                                data[i + 1]
                                & FlextLdifConstants.Encoding.UTF8_CONTINUATION_MASK
                                == FlextLdifConstants.Encoding.UTF8_CONTINUATION_VALUE
                                and data[i + 2]
                                & FlextLdifConstants.Encoding.UTF8_CONTINUATION_MASK
                                == FlextLdifConstants.Encoding.UTF8_CONTINUATION_VALUE
                            )
                        ):  # 3-byte sequence
                            utf8_sequences += 1
                            i += 3
                            continue
                        elif (
                            byte & FlextLdifConstants.Encoding.UTF8_4BYTE_LEAD_MASK
                            == FlextLdifConstants.Encoding.UTF8_4BYTE_LEAD_VALUE
                            and i < len(data) - 3
                            and (
                                data[i + 1]
                                & FlextLdifConstants.Encoding.UTF8_CONTINUATION_MASK
                                == FlextLdifConstants.Encoding.UTF8_CONTINUATION_VALUE
                                and data[i + 2]
                                & FlextLdifConstants.Encoding.UTF8_CONTINUATION_MASK
                                == FlextLdifConstants.Encoding.UTF8_CONTINUATION_VALUE
                                and data[i + 3]
                                & FlextLdifConstants.Encoding.UTF8_CONTINUATION_MASK
                                == FlextLdifConstants.Encoding.UTF8_CONTINUATION_VALUE
                            )
                        ):  # 4-byte sequence
                            utf8_sequences += 1
                            i += 4
                            continue
                    i += 1
                # If we found UTF-8 sequences, likely UTF-8
                if utf8_sequences > 0:
                    return "utf-8"
                # Check for Windows-1252 specific characters
                cp1252_chars = sum(
                    1
                    for byte in data
                    if FlextLdifConstants.Encoding.CP1252_RANGE_START
                    <= byte
                    <= FlextLdifConstants.Encoding.CP1252_RANGE_END
                )
                if (
                    cp1252_chars
                    > len(data) * FlextLdifConstants.Encoding.CP1252_RATIO_THRESHOLD
                ):
                    return "cp1252"
                # Default to Latin-1 for high bytes
                high_bytes = sum(
                    1 for byte in data if byte > FlextLdifConstants.Encoding.ASCII_MAX
                )
                if (
                    high_bytes
                    > len(data) * FlextLdifConstants.Encoding.HIGH_BYTES_RATIO_THRESHOLD
                ):
                    return "iso-8859-1"
                return None

            try:
                if not content:
                    return FlextResult[str].ok("utf-8")  # Default for empty content

                # Strategy 1: Check for BOM (Byte Order Mark)
                bom_encoding = _detect_bom_encoding(content)
                if bom_encoding:
                    return FlextResult[str].ok(bom_encoding)

                # Strategy 2: Look for charset declarations in content
                charset_encoding = _detect_charset_declaration(content)
                if charset_encoding:
                    return FlextResult[str].ok(charset_encoding)

                # Strategy 3: Statistical analysis of byte patterns
                statistical_encoding = _detect_encoding_statistically(content)
                if statistical_encoding:
                    return FlextResult[str].ok(statistical_encoding)

                # Strategy 4: Try common encodings in order of preference
                common_encodings = [
                    "utf-8",
                    "utf-16",
                    "utf-32",
                    "ascii",
                    "iso-8859-1",
                    "latin-1",
                    "cp1252",
                    "iso-8859-15",
                    "mac_roman",
                    "cp437",
                ]

                for encoding in common_encodings:
                    try:
                        content.decode(encoding)
                        return FlextResult[str].ok(encoding)
                    except (UnicodeDecodeError, LookupError):
                        continue

                # Final fallback - assume UTF-8
                return FlextResult[str].ok("utf-8")

            except Exception as e:
                return FlextResult[str].fail(f"Failed to detect encoding: {e}")

    # =========================================================================
    # FILE UTILITIES - File system operations
    # =========================================================================

    class FileUtilities:
        """File system utility methods."""

        @staticmethod
        def get_file_info(file_path: Path) -> FlextResult[dict[str, object]]:
            """Get file information.

            Args:
                file_path: Path to the file

            Returns:
                FlextResult containing file info dict

            """
            try:
                if not file_path.exists():
                    return FlextResult[dict[str, object]].fail(
                        f"File does not exist: {file_path}"
                    )

                stat = file_path.stat()
                # Read first N bytes to detect encoding
                with Path(file_path).open("rb") as f:
                    sample = f.read(FlextLdifConstants.Encoding.ENCODING_SAMPLE_SIZE)
                encoding_result = FlextLdifUtilities.EncodingUtilities.detect_encoding(
                    sample
                )
                encoding = (
                    encoding_result.unwrap()
                    if encoding_result.is_success
                    else "unknown"
                )

                # Explicitly type as dict[str, object] for FlextResult
                info: dict[str, object] = {
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "encoding": encoding,
                }
                return FlextResult[dict[str, object]].ok(info)
            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"Failed to get file info: {e}"
                )

        @staticmethod
        def validate_directory_path(path: str | Path) -> FlextResult[str]:
            """Validate directory path.

            Args:
                path: Directory path to validate

            Returns:
                FlextResult containing validated path string

            """
            try:
                dir_path = Path(path)
                if not dir_path.exists():
                    return FlextResult[str].fail(f"Directory does not exist: {path}")
                if not dir_path.is_dir():
                    return FlextResult[str].fail(f"Path is not a directory: {path}")
                return FlextResult[str].ok(str(dir_path))
            except Exception as e:
                return FlextResult[str].fail(f"Invalid directory path: {e}")

        @staticmethod
        def validate_file_path(file_path: str | Path) -> FlextResult[str]:
            """Validate file path.

            Args:
                file_path: Path to validate

            Returns:
                FlextResult containing validated path or error

            """
            try:
                path = Path(file_path)
                if not path.exists():
                    return FlextResult[str].fail(f"File does not exist: {file_path}")
                if not path.is_file():
                    return FlextResult[str].fail(f"Path is not a file: {file_path}")
                return FlextResult[str].ok(str(path))
            except Exception as e:
                return FlextResult[str].fail(f"Invalid file path: {e}")

        @staticmethod
        def count_lines_in_file(file_path: str | Path) -> FlextResult[int]:
            """Count lines in a file.

            Args:
                file_path: Path to the file

            Returns:
                FlextResult containing line count or error

            """
            try:
                path = Path(file_path)
                if not path.exists():
                    return FlextResult[int].fail(f"File does not exist: {file_path}")

                with path.open("r", encoding="utf-8") as f:
                    return FlextResult[int].ok(sum(1 for _ in f))
            except Exception as e:
                return FlextResult[int].fail(f"Failed to count lines: {e}")

        @staticmethod
        def ensure_file_extension(file_path: str | Path, extension: str) -> str:
            """Ensure file has the specified extension.

            Args:
                file_path: File path to check/modify
                extension: Extension to ensure (without leading dot)

            Returns:
                File path with ensured extension

            """
            path = Path(file_path)
            if path.suffix != f".{extension}":
                path = path.with_suffix(f".{extension}")
            return str(path)

        @staticmethod
        def validate_encoding(encoding: str) -> FlextResult[str]:
            """Validate character encoding.

            Args:
                encoding: Encoding to validate

            Returns:
                FlextResult containing validated encoding or error

            """
            try:
                # Test encoding by encoding/decoding a test string
                test_string = "test encoding validation"
                encoded = test_string.encode(encoding)
                decoded = encoded.decode(encoding)
                if decoded == test_string:
                    return FlextResult[str].ok(encoding)
                return FlextResult[str].fail(f"Encoding validation failed: {encoding}")
            except (UnicodeError, LookupError) as e:
                return FlextResult[str].fail(f"Invalid encoding: {e}")


__all__ = ["FlextLdifUtilities"]
