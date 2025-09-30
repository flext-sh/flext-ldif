"""Unified LDIF Processor - Main entry point for all LDIF operations.

This module provides the unified FlextLdifProcessor class that consolidates
functionality from multiple overlapping modules into a single, coherent API
following FLEXT unified class patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, cast, override

from pydantic import ConfigDict

from flext_core import (
    FlextConstants,
    FlextLogger,
    FlextResult,
    FlextService,
)
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.entry import FlextLdifEntryBuilder
from flext_ldif.management import FlextLdifManagement
from flext_ldif.models import FlextLdifModels
from flext_ldif.parser import FlextLdifParser
from flext_ldif.quirks import FlextLdifQuirksManager
from flext_ldif.schema import (
    FlextLdifObjectClassManager,
    FlextLdifSchemaBuilder,
    FlextLdifSchemaExtractor,
    FlextLdifSchemaValidator,
)
from flext_ldif.utilities import FlextLdifUtilities

__all__ = ["FlextLdifProcessor"]


class FlextLdifProcessor(FlextService[dict[str, object]]):
    """Unified LDIF processor for all LDIF operations.

    Provides comprehensive LDIF processing capabilities including parsing,
    validation, writing, transformation, and analytics. Implements FLEXT
    architectural patterns with FlextResult error handling.

    Follows the unified class pattern with nested helper classes for
    organization while maintaining single responsibility.

    Implements FlextLdifProtocols through structural subtyping:
    - LdifProcessorProtocol: parse, validate_entries, write, transform_entries, analyze_entries methods
    - LdifValidatorProtocol: validate_entries method
    - LdifWriterProtocol: write_entries_to_string, write_entries_to_file methods
    - LdifAnalyticsProtocol: analyze_entries, get_statistics, detect_patterns methods
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    # Constants for magic values - use FlextConstants for standardization
    DEFAULT_MAX_ENTRIES: ClassVar[int] = FlextConstants.Performance.MAX_BATCH_OPERATIONS
    QUALITY_THRESHOLD_HIGH: ClassVar[float] = (
        FlextConstants.Performance.CRITICAL_USAGE_PERCENT / 100.0
    )
    QUALITY_THRESHOLD_MEDIUM: ClassVar[float] = (
        FlextLdifConstants.QualityAnalysis.QUALITY_THRESHOLD_MEDIUM
    )
    MIN_ENTRY_COUNT_FOR_ANALYTICS: ClassVar[int] = (
        FlextConstants.Performance.PARALLEL_THRESHOLD // 2
    )
    MIN_ATTRIBUTE_COUNT_THRESHOLD: ClassVar[int] = (
        FlextConstants.Validation.MIN_NAME_LENGTH
    )

    def __init__(
        self,
        config: FlextLdifConfig | None = None,
        *,
        _explicit_none: bool = False,
    ) -> None:
        """Initialize LDIF processor with configuration."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        if config is None and not _explicit_none:
            # Create "default" config when no config is provided
            self._config: FlextLdifConfig | None = FlextLdifConfig()
        else:
            # Use provided config (including None if explicitly passed)
            self._config: FlextLdifConfig | None = config

        # Initialize advanced components
        parser_config: dict[str, object] = {
            "encoding": getattr(
                self._config,
                "ldif_encoding",
                FlextLdifConstants.Encoding.DEFAULT_ENCODING,
            ),
            "strict_mode": getattr(self._config, "strict_validation", True),
            "detect_server": True,
            "compliance_level": "strict",
        }
        self._parser = FlextLdifParser(parser_config)

        # Initialize unified management layer (lazy import to avoid circular dependency)
        self._management: FlextLdifManagement | None = None
        self._quirks = FlextLdifQuirksManager()

        # Initialize schema and entry components
        self._schema_extractor = FlextLdifSchemaExtractor()
        self._schema_validator = FlextLdifSchemaValidator()
        self._schema_builder = FlextLdifSchemaBuilder()
        self._objectclass_manager = FlextLdifObjectClassManager()
        self._entry_builder = FlextLdifEntryBuilder()

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check operation - required by FlextService.

        Returns:
            FlextResult containing health status dictionary with processor metrics.

        """
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "processor": FlextLdifProcessor,
            "config": self._get_config_summary(),
        })

    async def execute_async(self) -> FlextResult[dict[str, object]]:
        """Execute health check operation asynchronously - required by FlextService.

        Returns:
            FlextResult containing health status dictionary with processor metrics.

        """
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "processor": FlextLdifProcessor,
            "config": self._get_config_summary(),
        })

    def _get_config_summary(self) -> dict[str, object]:
        """Get configuration summary."""
        if self._config is None:
            return {"config": "default"}
        return {
            "encoding": getattr(
                self._config,
                "ldif_encoding",
                FlextLdifConstants.Encoding.DEFAULT_ENCODING,
            ),
            "strict_validation": getattr(self._config, "strict_validation", True),
        }

    # =============================================================================
    # NESTED HELPER CLASSES - Organization following FLEXT patterns
    # =============================================================================

    class _ParseHelper:
        """Helper class for parsing operations."""

        @staticmethod
        def process_entry_block(block: str) -> FlextResult[FlextLdifModels.Entry]:
            """Process a single LDIF entry block.

            Returns:
                FlextResult containing parsed Entry model or error message.

            """
            lines: list[str] = [
                line.strip() for line in block.strip().split("\n") if line.strip()
            ]
            if not lines:
                return FlextResult[FlextLdifModels.Entry].fail("Empty entry block")

            # First line must be DN
            first_line = lines[0]
            if not first_line.startswith("dn: "):
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Entry must start with 'dn: ', got: {first_line}",
                )

            dn_value = first_line[3:].strip()
            if not dn_value:
                return FlextResult[FlextLdifModels.Entry].fail(
                    FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR
                )

            # Process attributes
            attributes_data: dict[str, list[str]] = {}
            for line in lines[1:]:
                if ": " not in line:
                    continue

                attr_name, attr_value = line.split(": ", 1)
                attr_value = attr_value.strip()

                if attr_name not in attributes_data:
                    attributes_data[attr_name] = []
                attributes_data[attr_name].append(attr_value)

            # Create entry directly with dict

            entry_result = FlextLdifModels.Entry.create(
                data={"dn": dn_value, "attributes": attributes_data},
            )
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    entry_result.error or "Failed to create entry",
                )

            return FlextResult[FlextLdifModels.Entry].ok(entry_result.value)

        @staticmethod
        def process_line_continuation(content: str) -> str:
            """Process LDIF line continuations while preserving entry separators.

            Returns:
                Processed content with line continuations resolved but blank
                lines preserved.

            """
            lines = content.split("\n")
            processed_lines: list[str] = []
            current_line = ""

            for line in lines:
                if line.startswith((" ", "\t")):
                    # Continuation line
                    current_line += line[1:]  # Remove leading space/tab
                else:
                    # New line or empty line
                    if current_line:
                        processed_lines.append(current_line)
                        current_line = ""

                    # Always append the new line (including empty lines for
                    # entry separation)
                    processed_lines.append(line)

                    # If this is not an empty line, start building current_line
                    if line.strip():
                        current_line = (
                            processed_lines.pop()
                        )  # Remove it from processed and use as current

            # Handle any remaining current_line (shouldn't happen with proper LDIF)
            if current_line:
                processed_lines.append(current_line)

            return "\n".join(processed_lines)

    class _LdifValidationHelper:
        """Helper class for validation operations."""

        @staticmethod
        def validate_dn_structure(
            dn: FlextLdifModels.DistinguishedName,
        ) -> FlextResult[None]:
            """Validate DN structure.

            Returns:
                FlextResult[None]: Success if DN is valid, failure with error
                message if invalid.

            """
            if not dn.value:  # pragma: no cover
                return FlextResult[None].fail(
                    FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR
                )

            # Basic DN format validation
            if "=" not in dn.value:  # pragma: no cover
                return FlextResult[None].fail(
                    "DN must contain at least one attribute=value pair",
                )

            # Check for valid characters (basic validation)
            if any(char in dn.value for char in ["\n", "\r", "\0"]):
                return FlextResult[None].fail("DN contains invalid characters")

            return FlextResult[None].ok(None)

        @staticmethod
        def validate_required_attributes(
            entry: FlextLdifModels.Entry,
            required_attrs: list[str],
        ) -> FlextResult[None]:
            """Validate required attributes are present.

            Returns:
                FlextResult[None]: Success if all required attributes are
                present, failure with error message if missing.

            """
            for attr in required_attrs:
                if not entry.attributes.get_attribute(attr):
                    return FlextResult[None].fail(
                        f"Required attribute '{attr}' is missing",
                    )

            return FlextResult[None].ok(None)

        @staticmethod
        def validate_object_classes(
            entry: FlextLdifModels.Entry,
            required_classes: list[str],
        ) -> FlextResult[None]:
            """Validate required object classes are present.

            Returns:
                FlextResult[None]: Success if all required object classes are
                present, failure with error message if missing.

            """
            object_classes: list[str] = entry.get_attribute_values("objectClass")

            for required_class in required_classes:
                if required_class not in object_classes:
                    return FlextResult[None].fail(
                        f"Required object class '{required_class}' is missing",
                    )

            return FlextResult[None].ok(None)

    class _WriterHelper:
        """Helper class for writing operations."""

        @staticmethod
        def format_entry_as_ldif(entry: FlextLdifModels.Entry) -> str:
            """Format entry as LDIF string."""
            lines: list[str] = [f"dn: {entry.dn.value}"]

            # Sort attributes for consistent output
            for attr_name in sorted(entry.attributes.data.keys()):
                attr_values = entry.attributes.data[attr_name]
                lines.extend(f"{attr_name}: {value}" for value in attr_values)

            return "\n".join(lines)

        @staticmethod
        def apply_line_wrapping(
            content: str,
            max_line_length: int = FlextLdifConstants.Format.MAX_LINE_LENGTH,
        ) -> str:
            """Apply LDIF line wrapping rules."""
            lines = content.split("\n")
            wrapped_lines: list[str] = []

            for line in lines:
                if len(line) <= max_line_length:
                    wrapped_lines.append(line)
                else:
                    # Wrap long lines
                    wrapped_lines.append(line[:max_line_length])
                    remaining = line[max_line_length:]
                    while remaining:
                        chunk = remaining[: max_line_length - 1]  # -1 for leading space
                        wrapped_lines.append(" " + chunk)
                        remaining = remaining[len(chunk) :]

            return "\n".join(wrapped_lines)

    class _AnalyticsHelper:
        """Helper class for analytics operations."""

        @staticmethod
        def calculate_entry_statistics(
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, object]:
            """Calculate basic entry statistics."""
            if not entries:
                return {
                    "total_entries": 0,
                    "unique_dns": 0,
                    "attribute_diversity": 0,
                    "average_attributes_per_entry": 0,
                }

            total_entries = len(entries)
            unique_dns = len({entry.dn.value for entry in entries})
            all_attributes: set[str] = set()
            total_attributes = 0

            for entry in entries:
                if hasattr(entry, "to_ldif_string"):
                    entry_attrs = set(entry.attributes.data.keys())
                    all_attributes.update(entry_attrs)
                    total_attributes += len(entry_attrs)

            return {
                "total_entries": total_entries,
                "unique_dns": unique_dns,
                "attribute_diversity": len(all_attributes),
                "average_attributes_per_entry": total_attributes / total_entries
                if total_entries > 0
                else 0,
            }

        @staticmethod
        def analyze_dn_patterns(
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, object]:
            """Analyze DN patterns in entries."""
            min_dn_components_for_base_pattern = (
                FlextLdifConstants.QualityAnalysis.MIN_DN_COMPONENTS_FOR_BASE_PATTERN
            )
            dn_patterns: dict[str, int] = {}
            base_patterns: dict[str, int] = {}

            for entry in entries:
                if hasattr(entry, "to_ldif_string"):
                    # Full DN pattern
                    dn_patterns[entry.dn.value] = dn_patterns.get(entry.dn.value, 0) + 1

                    # Base pattern (last two components)
                    components = entry.dn.components
                    if len(components) >= min_dn_components_for_base_pattern:
                        base_pattern = ",".join(
                            components[-min_dn_components_for_base_pattern:],
                        )
                        base_patterns[base_pattern] = (
                            base_patterns.get(base_pattern, 0) + 1
                        )

            return {
                "dn_patterns": dn_patterns,
                "base_patterns": base_patterns,
                "unique_dn_count": len(dn_patterns),
                "unique_base_count": len(base_patterns),
            }

        @staticmethod
        def calculate_quality_metrics(
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, object]:
            """Calculate quality metrics for entries."""
            if not entries:
                return {"quality_score": 0.0, "issues": ["No entries to analyze"]}

            issues: list[str] = []
            quality_factors: list[float] = []

            # Check for duplicate DNs
            dns = [entry.dn.value for entry in entries]
            if len(dns) != len(set(dns)):
                issues.append("Duplicate DNs detected")
                quality_factors.append(0.5)
            else:
                quality_factors.append(1.0)

            # Check for entries with objectClass
            entries_with_object_class = sum(
                1 for entry in entries if entry.attributes.get_attribute("objectClass")
            )
            object_class_ratio = entries_with_object_class / len(entries)
            quality_factors.append(object_class_ratio)

            if object_class_ratio < FlextLdifProcessor.QUALITY_THRESHOLD_MEDIUM:
                issues.append("Many entries missing objectClass")

            # Check for minimal attributes
            avg_attrs = sum(len(entry.attributes.data) for entry in entries) / len(
                entries,
            )
            if avg_attrs < FlextLdifProcessor.MIN_ATTRIBUTE_COUNT_THRESHOLD:
                issues.append("Entries have very few attributes")
                quality_factors.append(0.6)
            else:
                quality_factors.append(1.0)

            quality_score = (
                sum(quality_factors) / len(quality_factors) if quality_factors else 0.0
            )

            return {
                "quality_score": quality_score,
                "issues": issues,
                "entries_with_object_class": entries_with_object_class,
                "average_attributes_per_entry": avg_attrs,
            }

    # =============================================================================
    # PROTOCOL IMPLEMENTATION METHODS - FlextLdifProtocols compliance
    # =============================================================================

    def parse(self, content: str) -> FlextResult[list[object]]:
        """Parse LDIF content string into entries - implements LdifProcessorProtocol.

        Args:
            content: LDIF content string to parse

        Returns:
            FlextResult[list[object]]: Parsed entries as objects

        """
        # Delegate to existing parse_string method and cast result
        result = self.parse_string(content)
        return result.map(lambda entries: cast("list[object]", entries))

    def write(self, entries: list[object]) -> FlextResult[str]:
        """Write entries to LDIF string - implements LdifProcessorProtocol.

        Args:
            entries: List of entries to write

        Returns:
            FlextResult[str]: LDIF formatted string

        """
        # Cast entries to the correct type and delegate to existing write_string method
        typed_entries = cast("list[FlextLdifModels.Entry]", entries)
        return self.write_string(typed_entries)

    # =============================================================================
    # CORE API METHODS - Main functionality
    # =============================================================================

    def parse_string(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string into entries."""
        if not content.strip():
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        # Process line continuations
        processed_content = self._ParseHelper.process_line_continuation(content)

        # Split into entry blocks
        entry_blocks: list[str] = [
            block.strip() for block in processed_content.split("\n\n") if block.strip()
        ]

        entries: list[FlextLdifModels.Entry] = []
        for i, block in enumerate(entry_blocks):
            entry_result: FlextResult[FlextLdifModels.Entry] = (
                self._ParseHelper.process_entry_block(block)
            )
            if entry_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to parse entry {i + 1}: {entry_result.error}",
                    error_code="PARSE_ERROR",
                )
            entries.append(entry_result.value)

        self._logger.info(f"Successfully parsed {len(entries)} entries from string")
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def parse_string_advanced(
        self,
        content: str,
    ) -> FlextResult[list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]]:
        """Parse LDIF content string with full RFC 2849 compliance.

        Args:
            content: LDIF content string

        Returns:
            FlextResult containing list of parsed entries and change records

        """
        parse_result = self._parser.parse_string(content)
        if parse_result.is_failure:
            return FlextResult[
                list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
            ].fail(parse_result.error or "Parse failed")
        return parse_result

    def parse_file_advanced(
        self,
        file_path: Path,
    ) -> FlextResult[list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]]:
        """Parse LDIF file with advanced RFC 2849 compliance and encoding detection.

        Args:
            file_path: Path to LDIF file

        Returns:
            FlextResult containing list of parsed entries and change records

        """
        # Use modern Pydantic approach
        try:
            content = file_path.read_text(
                encoding=FlextLdifConstants.Encoding.DEFAULT_ENCODING
            )
            return self._parser.parse_string(content)
        except Exception as e:
            return FlextResult[
                list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
            ].fail(f"Failed to read file {file_path}: {e}")

    def detect_server_type(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[str]:
        """Detect LDAP server type from entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing detected server type

        """
        return self._quirks.detect_server_type(entries)

    def adapt_entries_for_server(
        self,
        entries: list[FlextLdifModels.Entry],
        target_server: str | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Adapt entries for specific LDAP server type.

        Args:
            entries: List of entries to adapt
            target_server: Target server type, or None for auto-detection

        Returns:
            FlextResult containing adapted entries

        """
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        # Initialize management if not already done
        if self._management is None:
            self._management = FlextLdifManagement()

        adapted_result = self._management.adapt_entries_for_server(
            entries,
            target_server or "",
        )
        if adapted_result.is_failure:
            self._logger.warning(f"Failed to adapt entries: {adapted_result.error}")
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        adapted_entries = adapted_result.value
        self._logger.info(f"Adapted {len(adapted_entries)} entries for server type")
        return FlextResult[list[FlextLdifModels.Entry]].ok(adapted_entries)

    def validate_rfc_compliance(
        self,
        entries: list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord],
    ) -> FlextResult[dict[str, object]]:
        """Validate RFC 2849 compliance of entries.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing compliance report

        """
        return self._parser.validate_rfc_compliance(entries)

    def validate_server_compliance(
        self,
        entries: list[FlextLdifModels.Entry],
        server_type: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Validate entries against server-specific rules.

        Args:
            entries: List of entries to validate
            server_type: Server type to validate against, or None for auto-detection

        Returns:
            FlextResult containing validation report

        """
        if not entries:
            return FlextResult[dict[str, object]].ok({
                "server_type": server_type or "unknown",
                "compliant": True,
                "issues": [],
                "warnings": [],
                "recommendations": [],
            })

        # Validate each entry
        all_issues: list[str] = []
        all_warnings: list[str] = []
        all_recommendations: list[str] = []
        compliant_count = 0

        # Initialize management if not already done
        if self._management is None:
            self._management = FlextLdifManagement()

        validation_result = self._management.validate_entries_for_server(
            entries,
            server_type,
        )
        if validation_result.is_success:
            validation_data = validation_result.value
            for val_report in cast(
                "list[dict[str, object]]",
                validation_data.get("validation_reports", []),
            ):
                all_issues.extend(cast("list[str]", val_report.get("issues", [])))
                all_warnings.extend(cast("list[str]", val_report.get("warnings", [])))
                all_recommendations.extend(
                    cast("list[str]", validation_data.get("recommendations", [])),
                )

                if cast("bool", val_report.get("compliant", False)):
                    compliant_count += 1

        overall_compliant = len(all_issues) == 0
        compliance_percentage = (
            (compliant_count / len(entries)) * 100 if entries else 100
        )

        report: dict[str, object] = {
            "server_type": server_type or "auto-detected",
            "total_entries": len(entries),
            "compliant_entries": compliant_count,
            "compliance_percentage": compliance_percentage,
            "overall_compliant": overall_compliant,
            "issues": all_issues,
            "warnings": all_warnings,
            "recommendations": all_recommendations,
        }

        return FlextResult[dict[str, object]].ok(report)

    def get_server_info(
        self,
        server_type: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Get information about LDAP server type and its quirks.

        Args:
            server_type: Server type to get info for, or None for current

        Returns:
            FlextResult containing server information

        """
        # Use the quirks manager's server type if not provided
        if server_type is None:
            server_type = self._quirks.server_type

        quirks_result: FlextResult[dict[str, object]] = self._quirks.get_server_quirks(
            server_type,
        )
        if quirks_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                quirks_result.error or "Failed to get server info",
            )

        return FlextResult[dict[str, object]].ok({
            "server_type": server_type,
            "quirks": quirks_result.value,
        })

    def parse_ldif_file(
        self,
        file_path: Path,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file into entries."""
        validation_result: FlextResult[None] = self._validate_file_path(file_path)
        if validation_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                validation_result.error or "File path validation failed",
            )

        try:
            content = file_path.read_text(
                encoding=getattr(
                    self._config,
                    "ldif_encoding",
                    FlextLdifConstants.Encoding.DEFAULT_ENCODING,
                ),
            )
            self._logger.info(
                f"Read LDIF file: {file_path} ({len(content)} characters)",
            )
            return self.parse_string(content)
        except UnicodeDecodeError as e:
            # Create error message with safe serializable information
            error_msg = f"Failed to decode file {file_path}: {e}"
            # Log as error with serializable context (not exception to avoid
            # bytes serialization)
            self._logger.exception(
                error_msg,
                extra={
                    "file_path": str(file_path),
                    "error_type": UnicodeDecodeError,
                    "error_reason": getattr(e, "reason", "unknown"),
                    "error_start": getattr(e, "start", -1),
                    "error_end": getattr(e, "end", -1),
                },
            )
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)
        except OSError as e:
            error_msg = f"Failed to read file {file_path}: {e}"
            self._logger.exception(error_msg)
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    def filter_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        filters: dict[str, object],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries based on criteria."""
        try:
            filtered_entries = []
            for entry in entries:
                if hasattr(entry, "to_ldif_string"):
                    # Simple filtering logic - can be extended
                    if "dn_pattern" in filters:
                        pattern = str(filters["dn_pattern"])
                        if pattern.lower() not in entry.dn.value.lower():
                            continue
                    if "object_class" in filters:
                        obj_class = str(filters["object_class"])
                        if not entry.has_object_class(obj_class):
                            continue
                    filtered_entries.append(entry)

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)
        except Exception as e:
            error_msg = f"Failed to filter entries: {e}"
            self._logger.exception(error_msg)
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    def get_statistics(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, object]]:
        """Get statistics about entries."""
        try:
            stats: dict[str, object] = {
                "total_entries": len(entries),
                "object_class_counts": {},
                "attribute_counts": {},
                "average_dn_depth": 0,
                "max_dn_depth": 0,
            }

            # Type the nested dictionaries properly
            object_class_counts: dict[str, int] = {}
            attribute_counts: dict[str, int] = {}

            if entries:
                dn_depths = [entry.dn.depth for entry in entries]
                stats["average_dn_depth"] = sum(dn_depths) / len(dn_depths)
                stats["max_dn_depth"] = max(dn_depths)

                # Count object classes and attributes
                for entry in entries:
                    if hasattr(entry, "attributes") and entry.attributes:
                        for attr_name, attr_values in entry.attributes.data.items():
                            if attr_name.lower() == "objectclass":
                                for obj_class in attr_values:
                                    object_class_counts[str(obj_class)] = (
                                        object_class_counts.get(str(obj_class), 0) + 1
                                    )
                            attribute_counts[attr_name] = attribute_counts.get(
                                attr_name,
                                0,
                            ) + len(attr_values.values)

            # Update stats with the properly typed dictionaries
            stats["object_class_counts"] = object_class_counts
            stats["attribute_counts"] = attribute_counts

            return FlextResult[dict[str, object]].ok(stats)
        except Exception as e:
            error_msg = f"Failed to get statistics: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict[str, object]].fail(error_msg)

    def write_entries_to_string(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[str]:
        """Convert entries to LDIF string format."""
        try:
            ldif_lines: list[str] = []
            for entry in entries:
                # Add DN line
                ldif_lines.append(f"dn: {entry.dn.value}")
                # Add attributes
                for attr_name, attr_values in entry.attributes.attributes.items():
                    ldif_lines.extend(
                        f"{attr_name}: {value}" for value in attr_values.values
                    )
                # Add empty line between entries
                ldif_lines.append("")
            return FlextResult[str].ok("\n".join(ldif_lines))
        except Exception as e:
            error_msg = f"Failed to convert entries to string: {e}"
            self._logger.exception(error_msg)
            return FlextResult[str].fail(error_msg)

    def write_entries_to_file(
        self,
        entries: list[FlextLdifModels.Entry],
        output_file: Path,
    ) -> FlextResult[None]:
        """Write entries to LDIF file."""
        try:
            write_result = self.write_entries_to_string(entries)
            if write_result.is_failure:
                return FlextResult[None].fail(
                    write_result.error or "Failed to generate LDIF content",
                )

            output_file.write_text(
                write_result.value,
                encoding=FlextLdifConstants.Encoding.DEFAULT_ENCODING,
            )
            return FlextResult[None].ok(None)
        except Exception as e:
            error_msg = f"Failed to write entries to file: {e}"
            self._logger.exception(error_msg)
            return FlextResult[None].fail(error_msg)

    def validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate a list of LDIF entries.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with validated
            entries, failure with error message

        """
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "No entries to validate",
            )

        for i, entry in enumerate(entries):
            # Validate DN structure
            dn_validation = self._LdifValidationHelper.validate_dn_structure(entry.dn)
            if dn_validation.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Entry {i} DN validation failed: {dn_validation.error}",
                )

            # Validate required attributes (basic validation)
            required_attrs = self._get_required_attributes_for_classes(
                entry.get_attribute_values("objectClass"),
            )
            attr_validation = self._LdifValidationHelper.validate_required_attributes(
                entry,
                required_attrs,
            )
            if attr_validation.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Entry {i} attribute validation failed: {attr_validation.error}",
                )

        self._logger.info(f"Successfully validated {len(entries)} entries")
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def write_string(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write entries to LDIF format string."""
        if not entries:
            return FlextResult[str].ok("")

        entry_strings: list[str] = []
        for entry in entries:
            entry_ldif = self._WriterHelper.format_entry_as_ldif(entry)
            entry_strings.append(entry_ldif)

        # Join entries with double newline
        content = "\n\n".join(entry_strings) + "\n"

        # Apply line wrapping if configured
        if getattr(self._config, "wrap_lines", False):  # pragma: no cover
            content = self._WriterHelper.apply_line_wrapping(content)

        self._logger.info(
            f"Generated LDIF content for {len(entries)} entries "
            f"({len(content)} characters)",
        )
        return FlextResult[str].ok(content)

    def write_file(
        self,
        entries: list[FlextLdifModels.Entry],
        file_path: str,
    ) -> FlextResult[None]:
        """Write entries to LDIF file.

        Args:
            entries: List of entries to write
            file_path: Path to output file

        Returns:
            FlextResult[None]: Success if written successfully, failure with
            error message

        """
        content_result: FlextResult[str] = self.write_string(entries)
        if content_result.is_failure:  # pragma: no cover
            return FlextResult[None].fail(
                content_result.error or "Failed to generate LDIF content",
            )

        try:
            output_path = Path(file_path)

            # Validate file path for write operations
            path_validation = self._validate_file_path(output_path, check_writable=True)
            if path_validation.is_failure:
                return FlextResult[None].fail(
                    path_validation.error or "File path validation failed",
                )

            output_path.write_text(
                content_result.value,
                encoding=getattr(
                    self._config,
                    "ldif_encoding",
                    FlextLdifConstants.Encoding.DEFAULT_ENCODING,
                ),
            )
            self._logger.info(
                f"Successfully wrote {len(entries)} entries to {file_path}",
            )
            return FlextResult[None].ok(None)
        except OSError as e:
            error_msg = f"Failed to write file {file_path}: {e}"
            self._logger.exception(error_msg)
            return FlextResult[None].fail(error_msg)

    def transform_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        transformer: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform entries using provided transformer function."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        transformed_entries: list[FlextLdifModels.Entry] = []
        for i, entry in enumerate(entries):
            try:
                transformed = transformer(entry)
                transformed_entries.append(transformed)
            except Exception as e:
                error_msg = f"Transformation failed for entry {i + 1}: {e}"
                self._logger.exception(error_msg)
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    error_msg,
                    error_code="TRANSFORM_ERROR",
                )

        self._logger.info(f"Successfully transformed {len(entries)} entries")
        return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)

    def analyze_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, object]]:
        """Analyze entries and return comprehensive statistics."""
        if not entries:
            return FlextResult[dict[str, object]].ok({
                "message": "No entries to analyze",
                "entry_count": 0,
            })

        # Only perform detailed analytics for reasonable entry counts
        if len(entries) < self.MIN_ENTRY_COUNT_FOR_ANALYTICS:
            basic_stats = self._AnalyticsHelper.calculate_entry_statistics(entries)
            basic_stats["note"] = (
                f"Basic analysis only (< {self.MIN_ENTRY_COUNT_FOR_ANALYTICS} entries)"
            )
            return FlextResult[dict[str, object]].ok(basic_stats)

        # Comprehensive analytics
        try:
            statistics = self._AnalyticsHelper.calculate_entry_statistics(entries)
            dn_analysis = self._AnalyticsHelper.analyze_dn_patterns(entries)
            quality_metrics = self._AnalyticsHelper.calculate_quality_metrics(entries)

            combined_analysis: dict[str, object] = {
                "basic_statistics": statistics,
                "dn_analysis": dn_analysis,
                "quality_metrics": quality_metrics,
                "analysis_timestamp": datetime.now(UTC).isoformat(),
            }

            self._logger.info(
                f"Completed comprehensive analysis of {len(entries)} entries",
            )
            return FlextResult[dict[str, object]].ok(combined_analysis)

        except Exception as e:  # pragma: no cover
            error_msg = f"Analysis failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict[str, object]].fail(error_msg)

    def filter_entries_by_dn_pattern(
        self,
        entries: list[FlextLdifModels.Entry],
        pattern: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern using regex."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            filtered_entries: list[FlextLdifModels.Entry] = [
                entry for entry in entries if compiled_pattern.search(entry.dn.value)
            ]

            self._logger.info(
                f"Filtered {len(entries)} entries to {len(filtered_entries)} "
                f"using pattern: {pattern}",
            )
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

        except re.error as e:
            error_msg = f"Invalid regex pattern '{pattern}': {e}"
            self._logger.exception(error_msg)
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    def filter_entries_by_object_class(
        self,
        entries: list[FlextLdifModels.Entry],
        object_class: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by object class."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        filtered_entries: list[FlextLdifModels.Entry] = []
        for entry in entries:
            object_classes_raw = entry.get_attribute_values("objectClass")
            # Ensure object_classes is a list of strings
            object_classes: list[str] = [
                str(oc) for oc in object_classes_raw if oc is not None
            ]
            if any(oc.lower() == object_class.lower() for oc in object_classes):
                filtered_entries.append(entry)

        self._logger.info(
            f"Filtered {len(entries)} entries to {len(filtered_entries)} "
            f"with objectClass: {object_class}",
        )
        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

    def get_entry_by_dn(
        self,
        entries: list[FlextLdifModels.Entry],
        dn: str,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Get entry by DN from provided entries."""
        for entry in entries:
            if (
                hasattr(entry, "to_ldif_string")
                and entry.dn.value.lower() == dn.lower()
            ):
                return FlextResult[FlextLdifModels.Entry | None].ok(entry)

        return FlextResult[FlextLdifModels.Entry | None].ok(None)

    def get_entries_by_attribute(
        self,
        entries: list[FlextLdifModels.Entry],
        attr_name: str,
        attr_value: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Get entries that have specific attribute value."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        matching_entries: list[FlextLdifModels.Entry] = []
        for entry in entries:
            if hasattr(entry, "to_ldif_string"):
                attr_values_raw = entry.attributes.get_attribute(attr_name) or []
                # Ensure attr_values is a list of strings
                attr_values: list[str] = [
                    str(value) for value in attr_values_raw if value is not None
                ]
                if any(value.lower() == attr_value.lower() for value in attr_values):
                    matching_entries.append(entry)

                self._logger.info(
                    f"Found {len(matching_entries)} entries with "
                    f"{attr_name}={attr_value}",
                )
        return FlextResult[list[FlextLdifModels.Entry]].ok(matching_entries)

    def validate_schema_compliance(
        self,
        entries: list[FlextLdifModels.Entry],
        schema_rules: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Validate entries against schema rules."""
        if not entries:
            return FlextResult[dict[str, object]].ok({"status": "no_entries"})

        # Extract schema rules with proper typing
        required_attrs_raw: object = schema_rules.get("required_attributes", [])
        required_attrs: list[str] = cast(
            "list[str]",
            required_attrs_raw if isinstance(required_attrs_raw, list) else [],
        )

        required_classes_raw: object = schema_rules.get("required_object_classes", [])
        required_classes: list[str] = cast(
            "list[str]",
            required_classes_raw if isinstance(required_classes_raw, list) else [],
        )

        compliance_results: list[dict[str, object]] = []
        for i, entry in enumerate(entries):
            entry_compliance: dict[str, object] = {
                "entry_index": i,
                "dn": entry.dn.value,
                "issues": [],
            }
            issues_list: list[str] = []

            # Check required attributes
            if required_attrs:
                attrs_result = self._LdifValidationHelper.validate_required_attributes(
                    entry,
                    required_attrs,
                )
                if attrs_result.is_failure:
                    error_msg = attrs_result.error or "Unknown error"
                    issues_list.append(error_msg)

            # Check required object classes
            if required_classes:
                classes_result = self._LdifValidationHelper.validate_object_classes(
                    entry,
                    required_classes,
                )
                if classes_result.is_failure:
                    error_msg = classes_result.error or "Unknown error"
                    issues_list.append(error_msg)

            # Update entry compliance with issues
            entry_compliance["issues"] = issues_list

            compliance_results.append(entry_compliance)

        # Calculate overall compliance
        compliant_entries = sum(
            1 for result in compliance_results if not result["issues"]
        )
        compliance_percentage = (
            (compliant_entries / len(entries)) * 100 if entries else 0
        )

        report: dict[str, object] = {
            "total_entries": len(entries),
            "compliant_entries": compliant_entries,
            "compliance_percentage": compliance_percentage,
            "detailed_results": compliance_results,
            "schema_rules_applied": schema_rules,
        }

        self._logger.info(
            f"Schema compliance: {compliance_percentage:.1f}% "
            f"({compliant_entries}/{len(entries)})",
        )
        return FlextResult[dict[str, object]].ok(report)

    def merge_entries(
        self,
        entries1: list[FlextLdifModels.Entry],
        entries2: list[FlextLdifModels.Entry],
        *,
        overwrite_duplicates: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Merge two lists of entries, handling duplicates."""
        if not entries1:
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries2)
        if not entries2:
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries1)

        # Build DN index for first set
        dn_index: dict[str, FlextLdifModels.Entry] = {
            entry.dn.value.lower(): entry for entry in entries1
        }
        # Start with copy of all from first set
        merged_entries: list[FlextLdifModels.Entry] = []
        merged_entries.extend(entries1)

        duplicates_count = 0
        for entry in entries2:
            dn_key = entry.dn.value.lower()
            if dn_key in dn_index:
                duplicates_count += 1
                if overwrite_duplicates:
                    # Replace existing entry
                    for i, existing in enumerate(merged_entries):
                        if existing.dn.value.lower() == dn_key:
                            # Type check to help type checker
                            if not isinstance(merged_entries, list):
                                error_msg = "merged_entries must be a list"
                                raise TypeError(error_msg)
                            merged_entries[i] = entry
                            break
                # If not overwriting, skip the duplicate
            else:
                # Add new entry
                # Type check to help type checker
                if not isinstance(merged_entries, list):
                    error_msg = "merged_entries must be a list"
                    raise TypeError(error_msg)
                merged_entries.append(entry)
                dn_index[dn_key] = entry

        self._logger.info(
            f"Merged entries: {len(entries1)} + {len(entries2)} = "
            f"{len(merged_entries)} ({duplicates_count} duplicates handled)",
        )
        # Type check to help type checker
        if not isinstance(merged_entries, list):
            error_msg = "merged_entries must be a list"
            raise TypeError(error_msg)
        return FlextResult[list[FlextLdifModels.Entry]].ok(merged_entries)

    def detect_patterns(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, object]]:
        """Detect patterns in LDIF entries."""
        if not entries:
            return FlextResult[dict[str, object]].ok({
                "patterns": [],
                "summary": "No entries to analyze",
            })

        patterns: dict[str, object] = {}

        # Detect object class patterns
        class_combinations: dict[str, int] = {}
        for entry in entries:
            if hasattr(entry, "to_ldif_string"):
                object_classes_raw = entry.get_attribute_values("objectClass")
                # Ensure object_classes is a list of strings
                object_classes: list[str] = [
                    str(oc) for oc in object_classes_raw if oc is not None
                ]
                if object_classes:
                    class_key = ",".join(sorted(object_classes))
                    class_combinations[class_key] = (
                        class_combinations.get(class_key, 0) + 1
                    )

        patterns["object_class_patterns"] = class_combinations

        # Detect attribute patterns
        attribute_frequency: dict[str, int] = {}
        for entry in entries:
            if hasattr(entry, "to_ldif_string"):
                for attr_name in entry.attributes.data:
                    attribute_frequency[attr_name] = (
                        attribute_frequency.get(attr_name, 0) + 1
                    )

        patterns["attribute_frequency"] = attribute_frequency

        # Detect DN structure patterns
        dn_structures: dict[str, int] = {}
        for entry in entries:
            if hasattr(entry, "to_ldif_string"):
                components = entry.dn.components
                if components:
                    # Create pattern from component types (e.g., "cn,ou,dc,dc")
                    structure = ",".join(comp.split("=")[0] for comp in components)
                    dn_structures[structure] = dn_structures.get(structure, 0) + 1

        patterns["dn_structures"] = dn_structures

        # Summary statistics
        summary: dict[str, object] = {
            "total_entries": len(entries),
            "unique_object_class_combinations": len(class_combinations),
            "unique_attributes": len(attribute_frequency),
            "unique_dn_structures": len(dn_structures),
        }

        patterns["summary"] = summary

        self._logger.info(f"Pattern detection completed for {len(entries)} entries")
        return FlextResult[dict[str, object]].ok(patterns)

    def generate_quality_report(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, object]]:
        """Generate comprehensive quality report for entries."""
        if not entries:
            return FlextResult[dict[str, object]].ok({
                "status": "no_entries",
                "message": "No entries provided for quality analysis",
            })

        try:
            # Basic quality metrics
            quality_metrics = self._AnalyticsHelper.calculate_quality_metrics(entries)

            # Additional quality checks
            quality_checks = {
                "empty_attributes": self._count_empty_attributes(entries),
                "missing_object_classes": self._count_missing_object_classes(entries),
                "duplicate_dns": self._count_duplicate_dns(entries),
                "invalid_dn_format": self._count_invalid_dns(entries),
            }

            # Calculate overall quality score
            base_score = quality_metrics.get("quality_score", 0.0)
            if isinstance(base_score, (int, float)):
                quality_score = float(base_score)
            else:
                quality_score = 0.0

            # Adjust score based on additional checks
            penalty_factors: list[float] = []
            empty_attrs = quality_checks.get("empty_attributes", 0)
            if empty_attrs > 0:
                penalty_factors.append(0.9)

            missing_oc = quality_checks.get("missing_object_classes", 0)
            if missing_oc > 0:
                penalty_factors.append(0.8)

            duplicate_dns = quality_checks.get("duplicate_dns", 0)
            if duplicate_dns > 0:
                penalty_factors.append(0.7)

            # Apply penalties
            for penalty in penalty_factors:
                quality_score *= penalty

            # Determine quality level
            if quality_score >= self.QUALITY_THRESHOLD_HIGH:
                quality_level = "excellent"
            elif quality_score >= self.QUALITY_THRESHOLD_MEDIUM:
                quality_level = "good"
            else:
                quality_level = "needs_improvement"

            # Compile recommendations
            recommendations: list[str] = []
            if quality_checks.get("empty_attributes", 0) > 0:
                recommendations.append("Remove or populate empty attributes")
            if quality_checks.get("missing_object_classes", 0) > 0:
                recommendations.append("Add objectClass to entries missing them")
            if quality_checks.get("duplicate_dns", 0) > 0:
                recommendations.append("Resolve duplicate DN entries")

            quality_report: dict[str, object] = {
                "overall_score": quality_score,
                "quality_level": quality_level,
                "total_entries": len(entries),
                "quality_metrics": quality_metrics,
                "quality_checks": quality_checks,
                "recommendations": recommendations,
                "analysis_timestamp": datetime.now(UTC).isoformat(),
            }

            self._logger.info(
                f"Quality report generated: {quality_level} ({quality_score:.2f})",
            )
            return FlextResult[dict[str, object]].ok(quality_report)

        except Exception as e:
            error_msg = f"Quality report generation failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict[str, object]].fail(error_msg)

    def get_processor_health(self) -> FlextResult[dict[str, object]]:
        """Get processor health status."""
        try:
            health_info: dict[str, object] = {
                "status": "healthy",
                "timestamp": datetime.now(UTC).isoformat(),
                "config": {
                    "encoding": getattr(
                        self._config,
                        "ldif_encoding",
                        FlextLdifConstants.Encoding.DEFAULT_ENCODING,
                    ),
                    "max_entries": getattr(
                        self._config,
                        "max_entries",
                        self.DEFAULT_MAX_ENTRIES,
                    ),
                    "strict_validation": getattr(
                        self._config,
                        "strict_validation",
                        True,
                    ),
                },
                "capabilities": [
                    "parse_string",
                    "parse_ldif_file",
                    "validate_entries",
                    "write_string",
                    "write_file",
                    "transform_entries",
                    "analyze_entries",
                    "filter_operations",
                    "quality_analysis",
                    "pattern_detection",
                    "schema_validation",
                    "entry_merging",
                ],
            }

            return FlextResult[dict[str, object]].ok(health_info)

        except Exception as e:
            error_msg = f"Health check failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict[str, object]].fail(error_msg)

    def get_config_info(self) -> dict[str, object]:
        """Get configuration information."""
        return {
            "encoding": getattr(
                self._config,
                "ldif_encoding",
                FlextLdifConstants.Encoding.DEFAULT_ENCODING,
            ),
            "max_entries": getattr(
                self._config,
                "max_entries",
                self.DEFAULT_MAX_ENTRIES,
            ),
            "strict_validation": getattr(self._config, "strict_validation", True),
            "wrap_lines": getattr(self._config, "wrap_lines", True),
        }

    # =============================================================================
    # HELPER METHODS - Private utilities
    # =============================================================================

    @staticmethod
    def _validate_file_path(
        file_path: Path,
        *,
        check_writable: bool = False,
    ) -> FlextResult[None]:
        """Validate file path for write operations.

        Args:
            file_path: Path to validate
            check_writable: If True, check if parent directory is writable for new files

        Returns:
            FlextResult[None]: Success if path is valid, failure with error message

        """
        validation_result = FlextLdifUtilities.FileUtilities.validate_file_path(
            file_path,
            check_writable=check_writable,
        )
        if validation_result.is_failure:
            return FlextResult[None].fail(
                validation_result.error or "File path validation failed",
            )
        return FlextResult[None].ok(None)

    def _get_required_attributes_for_classes(
        self,
        object_classes: list[str],
    ) -> list[str]:
        """Get required attributes for given object classes."""
        # Basic LDAP object class requirements
        required_attrs: list[str] = []

        for oc in object_classes:
            oc_lower = oc.lower()
            if oc_lower in {"person", "organizationalperson", "inetorgperson"}:
                required_attrs.extend(["cn", "sn"])
            elif oc_lower == "organizationalunit":
                required_attrs.append("ou")
            elif oc_lower == "groupofnames":
                required_attrs.extend(["cn", "member"])

        return list(set(required_attrs))  # Remove duplicates

    def _count_empty_attributes(self, entries: list[FlextLdifModels.Entry]) -> int:
        """Count entries with empty attributes."""
        count = 0
        for entry in entries:
            if hasattr(entry, "to_ldif_string"):
                for attr_values in entry.attributes.data.values():
                    if not attr_values or (
                        len(attr_values.values) == 1
                        and not str(attr_values.values[0]).strip()
                    ):
                        count += 1
                        break
        return count

    def _count_missing_object_classes(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> int:
        """Count entries missing objectClass."""
        return sum(
            1 for entry in entries if not entry.attributes.get_attribute("objectClass")
        )

    def _count_duplicate_dns(self, entries: list[FlextLdifModels.Entry]) -> int:
        """Count duplicate DN entries."""
        dns: list[str] = [entry.dn.value.lower() for entry in entries]
        return len(dns) - len(set(dns))

    def _count_invalid_dns(self, entries: list[FlextLdifModels.Entry]) -> int:
        """Count entries with invalid DN format."""
        count = 0
        for entry in entries:
            if hasattr(entry, "to_ldif_string"):
                result: FlextResult[None] = (
                    self._LdifValidationHelper.validate_dn_structure(entry.dn)
                )
                if result.is_failure:
                    count += 1
        return count

    def extract_schema_from_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Extract schema information from LDIF entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing schema discovery results

        """
        return self._schema_extractor.extract_from_entries(entries)

    def extract_attribute_usage(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, dict[str, object]]]:
        """Extract attribute usage statistics from LDIF entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing attribute usage statistics

        """
        return self._schema_extractor.extract_attribute_usage(entries)

    def validate_entry_against_schema(
        self,
        entry: FlextLdifModels.Entry,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[dict[str, object]]:
        """Validate an entry against a schema.

        Args:
            entry: LDIF entry to validate
            schema: Schema to validate against

        Returns:
            FlextResult containing validation results

        """
        return self._schema_validator.validate_entry_against_schema(entry, schema)

    def validate_objectclass_requirements(
        self,
        entry: FlextLdifModels.Entry,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[dict[str, object]]:
        """Validate objectClass requirements for an entry.

        Args:
            entry: LDIF entry to validate
            schema: Schema containing objectClass definitions

        Returns:
            FlextResult containing validation results

        """
        return self._schema_validator.validate_objectclass_requirements(entry, schema)

    def build_standard_person_schema(
        self,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Build a standard person schema.

        Returns:
            FlextResult containing standard person schema

        """
        return self._schema_builder.build_standard_person_schema()

    def build_standard_group_schema(
        self,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Build a standard group schema.

        Returns:
            FlextResult containing standard group schema

        """
        return self._schema_builder.build_standard_group_schema()

    def get_objectclass_definition(
        self,
        objectclass_name: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Get objectClass definition (not implemented in current version)."""
        _ = objectclass_name  # Suppress unused argument warning
        return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
            "get_objectclass_definition not available in current version",
        )

    def get_required_attributes_for_objectclasses(
        self,
        objectclasses: list[str],
    ) -> FlextResult[list[str]]:
        """Get required attributes for objectClasses (requires schema context)."""
        _ = objectclasses  # Suppress unused argument warning
        return FlextResult[list[str]].fail(
            "get_required_attributes_for_objectclasses requires schema context",
        )

    def validate_objectclass_combination(
        self,
        objectclasses: list[str],
    ) -> FlextResult[dict[str, object]]:
        """Validate objectClass combination (requires schema context)."""
        _ = objectclasses  # Suppress unused argument warning
        return FlextResult[dict[str, object]].fail(
            "validate_objectclass_combination requires schema context",
        )

    def build_person_entry(
        self,
        cn: str,
        sn: str,
        base_dn: str,
        uid: str | None = None,
        mail: str | None = None,
        given_name: str | None = None,
        additional_attrs: dict[str, list[str]] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a person entry with standard attributes.

        Args:
            cn: Common name
            sn: Surname
            base_dn: Base DN for the entry
            uid: User ID (optional)
            mail: Email address (optional)
            given_name: Given name (optional)
            additional_attrs: Additional attributes (optional)

        Returns:
            FlextResult containing the created person entry

        """
        return self._entry_builder.build_person_entry(
            cn,
            sn,
            base_dn,
            uid,
            mail,
            given_name,
            additional_attrs,
        )

    def build_group_entry(
        self,
        cn: str,
        base_dn: str,
        members: list[str] | None = None,
        description: str | None = None,
        additional_attrs: dict[str, list[str]] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a group entry with standard attributes.

        Args:
            cn: Common name
            base_dn: Base DN for the entry
            members: List of member DNs (optional)
            description: Group description (optional)
            additional_attrs: Additional attributes (optional)

        Returns:
            FlextResult containing the created group entry

        """
        return self._entry_builder.build_group_entry(
            cn,
            base_dn,
            members,
            description,
            additional_attrs,
        )

    def build_organizational_unit_entry(
        self,
        ou: str,
        base_dn: str,
        description: str | None = None,
        additional_attrs: dict[str, list[str]] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build an organizational unit entry.

        Args:
            ou: Organizational unit name
            base_dn: Base DN for the entry
            description: OU description (optional)
            additional_attrs: Additional attributes (optional)

        Returns:
            FlextResult containing the created OU entry

        """
        return self._entry_builder.build_organizational_unit_entry(
            ou,
            base_dn,
            description,
            additional_attrs,
        )

    def build_entries_from_json(
        self,
        json_data: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Build LDIF entries from JSON data.

        Args:
            json_data: JSON string containing entry data

        Returns:
            FlextResult containing list of created entries

        """
        return self._entry_builder.build_entries_from_json(json_data)

    def convert_entries_to_json(
        self,
        entries: list[FlextLdifModels.Entry],
        indent: int = 2,
    ) -> FlextResult[str]:
        """Convert LDIF entries to JSON format."""
        return self._entry_builder.convert_entries_to_json(entries, indent)

    def parse_ldif_content(
        self,
        content: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content from a string."""
        try:
            # Use advanced parser for full RFC 2849 compliance including comments
            parse_result = self.parse_string_advanced(content)
            if parse_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    parse_result.error or "Parse failed",
                )

            # Filter to only return Entry objects (not ChangeRecord objects)
            entries = [
                item
                for item in parse_result.value
                if isinstance(item, FlextLdifModels.Entry)
            ]
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to parse LDIF content: {e}",
            )

    def write_ldif_content(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[str]:
        """Write entries to LDIF string content."""
        try:
            content = ""
            for entry in entries:
                content += f"dn: {entry.dn.value}\n"
                for attr_name, attr_values in entry.attributes.data.items():
                    for value in attr_values:
                        content += f"{attr_name}: {value}\n"
                content += "\n"
            return FlextResult[str].ok(content)
        except Exception as e:
            return FlextResult[str].fail(f"Failed to write LDIF content: {e}")

    def get_configuration(self) -> FlextResult[FlextLdifConfig | None]:
        """Get the current configuration."""
        if hasattr(self, "_config") and self._config is not None:
            return FlextResult[FlextLdifConfig | None].ok(self._config)
        return FlextResult[FlextLdifConfig | None].ok(None)

    def validate_ldif_content(self, content: str) -> FlextResult[dict[str, object]]:
        """Validate LDIF content and return validation results."""
        try:
            # Parse the content to validate it
            parse_result = self.parse_string(content)
            if parse_result.is_failure:
                return FlextResult[dict[str, object]].ok({
                    "valid": False,
                    "error": parse_result.error,
                    "entry_count": 0,
                })

            # Validate the parsed entries
            validation_result = self.validate_entries(parse_result.value)
            if validation_result.is_failure:
                return FlextResult[dict[str, object]].ok({
                    "valid": False,
                    "error": validation_result.error,
                    "entry_count": len(parse_result.value),
                })

            return FlextResult[dict[str, object]].ok({
                "valid": True,
                "entry_count": len(parse_result.value),
                "message": "LDIF content is valid",
            })
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Validation failed: {e}")

    def transform_ldif_content(
        self,
        content: str,
        transformation_rules: dict[str, object],
    ) -> FlextResult[str]:
        """Transform LDIF content using transformation rules."""
        try:
            # Parse the content
            parse_result = self.parse_string(content)
            if parse_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to parse content: {parse_result.error}",
                )

            # Apply transformation rules (simplified implementation)
            transformed_entries: list[FlextLdifModels.Entry] = []
            for entry in parse_result.value:
                # Simple transformation: add a comment attribute if specified in rules
                if "add_comment" in transformation_rules:
                    comment = transformation_rules.get("add_comment", "Transformed")
                    if isinstance(comment, str):
                        # Create a new entry with the comment attribute
                        new_attrs = dict(entry.attributes.data)
                        new_attrs["comment"] = FlextLdifModels.AttributeValues(
                            values=[comment],
                        )

                        # Create new entry with transformed attributes
                        new_entry = FlextLdifModels.Entry(
                            dn=entry.dn,
                            attributes=FlextLdifModels.LdifAttributes(
                                attributes=new_attrs,
                            ),
                        )
                        transformed_entries.append(new_entry)
                    else:
                        transformed_entries.append(entry)
                else:
                    transformed_entries.append(entry)

            # Convert back to LDIF string
            write_result = self.write_ldif_content(transformed_entries)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write transformed content: {write_result.error}",
                )

            return FlextResult[str].ok(write_result.value)
        except Exception as e:
            return FlextResult[str].fail(f"Transformation failed: {e}")

    def get_status(self) -> FlextResult[dict[str, object]]:
        """Get processor status information."""
        try:
            status: dict[str, object] = {
                "processor_type": FlextLdifProcessor,
                "config_loaded": self._config is not None,
                "parser_initialized": hasattr(self, "_parser")
                and self._parser is not None,
                "logger_initialized": hasattr(self, "_logger")
                and self._logger is not None,
                "timestamp": datetime.now(UTC).isoformat(),
            }
            return FlextResult[dict[str, object]].ok(status)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Failed to get status: {e}")

    def filter_ldif_content(
        self,
        content: str,
        filters: dict[str, str],
    ) -> FlextResult[str]:
        """Filter LDIF content based on provided filters."""
        try:
            # Parse the content first
            parse_result = self.parse_string(content)
            if parse_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to parse LDIF content: {parse_result.error}",
                )

            entries = parse_result.value
            filtered_entries = []

            # Apply filters
            for entry in entries:
                include_entry = True
                for filter_key, filter_value in filters.items():
                    if filter_key in entry.attributes:
                        if filter_value not in str(entry.attributes[filter_key]):
                            include_entry = False
                            break
                    else:
                        # If filter key doesn't exist in entry, exclude it
                        include_entry = False
                        break

                if include_entry:
                    filtered_entries.append(entry)

            # Convert back to LDIF string
            result_content = self.write_string(filtered_entries)
            if result_content.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write filtered content: {result_content.error}",
                )

            return FlextResult[str].ok(result_content.value)
        except Exception as e:
            return FlextResult[str].fail(f"Failed to filter LDIF content: {e}")

    def analyze_ldif_content(self, content: str) -> FlextResult[dict[str, object]]:
        """Analyze LDIF content and return statistics."""
        try:
            # Parse the content
            parse_result = self.parse_string(content)
            if parse_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Failed to parse LDIF content: {parse_result.error}",
                )

            entries = parse_result.value

            # Calculate statistics
            stats: dict[str, object] = {
                "total_entries": len(entries),
                "object_classes": {},
                "attributes": {},
                "dn_patterns": {},
            }

            for entry in entries:
                # Count object classes
                object_classes = entry.get_attribute("objectClass") or []
                object_classes_dict = stats["object_classes"]
                if isinstance(object_classes_dict, dict):
                    # Cast to proper type for type checker
                    typed_dict = object_classes_dict
                    for obj_class in object_classes:
                        typed_dict[obj_class] = typed_dict.get(obj_class, 0) + 1

                # Count attributes
                attributes_dict = stats["attributes"]
                if isinstance(attributes_dict, dict):
                    # Cast to proper type for type checker
                    typed_attr_dict = attributes_dict
                    for attr_name in entry.attributes.attributes:
                        typed_attr_dict[attr_name] = (
                            typed_attr_dict.get(attr_name, 0) + 1
                        )

                # Analyze DN patterns
                dn_parts = entry.dn.value.split(",")
                if dn_parts:
                    pattern = (
                        dn_parts[0].split("=")[0] if "=" in dn_parts[0] else dn_parts[0]
                    )
                    dn_patterns_dict = stats["dn_patterns"]
                    if isinstance(dn_patterns_dict, dict):
                        # Cast to proper type for type checker
                        typed_dn_dict = dn_patterns_dict
                        typed_dn_dict[pattern] = typed_dn_dict.get(pattern, 0) + 1

            return FlextResult[dict[str, object]].ok(stats)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to analyze LDIF content: {e}",
            )
