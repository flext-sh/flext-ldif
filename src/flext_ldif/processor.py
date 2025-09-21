"""Unified LDIF Processor - Main entry point for all LDIF operations.

This module provides the unified FlextLdifProcessor class that consolidates
functionality from multiple overlapping modules into a single, coherent API
following FLEXT unified class patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from pydantic import ConfigDict

from flext_core import (
    FlextDomainService,
    FlextLogger,
    FlextResult,
)

from .config import FlextLdifConfig
from .models import FlextLdifModels

__all__ = ["FlextLdifProcessor"]


class FlextLdifProcessor(FlextDomainService[dict[str, object]]):
    """Unified LDIF processor for all LDIF operations.

    Provides comprehensive LDIF processing capabilities including parsing,
    validation, writing, transformation, and analytics. Implements FLEXT
    architectural patterns with FlextResult error handling.

    Follows the unified class pattern with nested helper classes for
    organization while maintaining single responsibility.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    # Constants for magic values
    DEFAULT_MAX_ENTRIES: ClassVar[int] = 10000
    QUALITY_THRESHOLD_HIGH: ClassVar[float] = 0.9
    QUALITY_THRESHOLD_MEDIUM: ClassVar[float] = 0.8
    MIN_ENTRY_COUNT_FOR_ANALYTICS: ClassVar[int] = 50
    MIN_ATTRIBUTE_COUNT_THRESHOLD: ClassVar[int] = 3

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF processor with configuration."""
        super().__init__()
        # Explicitly type _config as FlextLdifConfig for MyPy
        self._config: FlextLdifConfig = config or FlextLdifConfig()
        self._logger = FlextLogger(__name__)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check operation - required by FlextDomainService.

        Returns:
            FlextResult containing health status dictionary with processor metrics.

        """
        return self.get_processor_health()

    # =============================================================================
    # NESTED HELPER CLASSES - Organization following FLEXT patterns
    # =============================================================================

    class _ParseHelper:
        """Helper class for parsing operations."""

        @staticmethod
        def _process_entry_block(block: str) -> FlextResult[FlextLdifModels.Entry]:
            """Process a single LDIF entry block.

            Returns:
                FlextResult containing parsed Entry model or error message.

            """
            lines = [line.strip() for line in block.strip().split("\n") if line.strip()]
            if not lines:
                return FlextResult[FlextLdifModels.Entry].fail("Empty entry block")

            # First line must be DN
            first_line = lines[0]
            if not first_line.startswith("dn:"):
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Entry must start with 'dn:', got: {first_line}"
                )

            dn_value = first_line[3:].strip()
            if not dn_value:
                return FlextResult[FlextLdifModels.Entry].fail("DN cannot be empty")

            # Create DN object
            dn_result = FlextLdifModels.create_dn(dn_value)
            if dn_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    dn_result.error or "Failed to create DN"
                )

            # Process attributes
            attributes_data: dict[str, list[str]] = {}
            for line in lines[1:]:
                if ":" not in line:
                    continue

                attr_name, attr_value = line.split(":", 1)
                attr_value = attr_value.strip()

                if attr_name not in attributes_data:
                    attributes_data[attr_name] = []
                attributes_data[attr_name].append(attr_value)

            # Create attributes object
            attrs_result = FlextLdifModels.create_attributes(attributes_data)
            if attrs_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    attrs_result.error or "Failed to create attributes"
                )

            # Create entry
            entry_data: dict[str, object] = {
                "dn": dn_result.value,
                "attributes": attrs_result.value,
            }

            entry_result = FlextLdifModels.create_entry(entry_data)
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    entry_result.error or "Failed to create entry"
                )

            return FlextResult[FlextLdifModels.Entry].ok(entry_result.value)

        @staticmethod
        def _process_line_continuation(content: str) -> str:
            """Process LDIF line continuations.

            Returns:
                Processed content with line continuations resolved.

            """
            lines = content.split("\n")
            processed_lines = []
            current_line = ""

            for line in lines:
                if line.startswith((" ", "\t")):
                    # Continuation line
                    current_line += line[1:]  # Remove leading space/tab
                else:
                    # New line
                    if current_line:
                        processed_lines.append(current_line)
                    current_line = line

            if current_line:
                processed_lines.append(current_line)

            return "\n".join(processed_lines)

    class _ValidationHelper:
        """Helper class for validation operations."""

        @staticmethod
        def _validate_dn_structure(
            dn: FlextLdifModels.DistinguishedName,
        ) -> FlextResult[None]:
            """Validate DN structure."""
            if not dn.value:
                return FlextResult[None].fail("DN cannot be empty")

            # Basic DN format validation
            if "=" not in dn.value:
                return FlextResult[None].fail(
                    "DN must contain at least one attribute=value pair"
                )

            # Check for valid characters (basic validation)
            if any(char in dn.value for char in ["\n", "\r", "\0"]):
                return FlextResult[None].fail("DN contains invalid characters")

            return FlextResult[None].ok(None)

        @staticmethod
        def _validate_required_attributes(
            entry: FlextLdifModels.Entry, required_attrs: list[str]
        ) -> FlextResult[None]:
            """Validate required attributes are present."""
            for attr in required_attrs:
                if not entry.get_attribute(attr):
                    return FlextResult[None].fail(
                        f"Required attribute '{attr}' is missing"
                    )

            return FlextResult[None].ok(None)

        @staticmethod
        def _validate_object_classes(
            entry: FlextLdifModels.Entry, required_classes: list[str]
        ) -> FlextResult[None]:
            """Validate required object classes are present."""
            object_classes = entry.get_attribute("objectClass") or []

            for required_class in required_classes:
                if required_class not in object_classes:
                    return FlextResult[None].fail(
                        f"Required object class '{required_class}' is missing"
                    )

            return FlextResult[None].ok(None)

    class _WriterHelper:
        """Helper class for writing operations."""

        @staticmethod
        def _format_entry_as_ldif(entry: FlextLdifModels.Entry) -> str:
            """Format entry as LDIF string."""
            lines = [f"dn: {entry.dn.value}"]

            # Sort attributes for consistent output
            for attr_name in sorted(entry.attributes.data.keys()):
                attr_values = entry.attributes.data[attr_name]
                lines.extend(f"{attr_name}: {value}" for value in attr_values)

            return "\n".join(lines)

        @staticmethod
        def _apply_line_wrapping(content: str, max_line_length: int = 78) -> str:
            """Apply LDIF line wrapping rules."""
            lines = content.split("\n")
            wrapped_lines = []

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
        def _calculate_entry_statistics(
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
        def _analyze_dn_patterns(
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, object]:
            """Analyze DN patterns in entries."""
            min_dn_components_for_base_pattern = 2
            dn_patterns: dict[str, int] = {}
            base_patterns: dict[str, int] = {}

            for entry in entries:
                # Full DN pattern
                dn_patterns[entry.dn.value] = dn_patterns.get(entry.dn.value, 0) + 1

                # Base pattern (last two components)
                components = entry.dn.components
                if len(components) >= min_dn_components_for_base_pattern:
                    base_pattern = ",".join(
                        components[-min_dn_components_for_base_pattern:]
                    )
                    base_patterns[base_pattern] = base_patterns.get(base_pattern, 0) + 1

            return {
                "dn_patterns": dn_patterns,
                "base_patterns": base_patterns,
                "unique_dn_count": len(dn_patterns),
                "unique_base_count": len(base_patterns),
            }

        @staticmethod
        def _calculate_quality_metrics(
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, object]:
            """Calculate quality metrics for entries."""
            if not entries:
                return {"quality_score": 0.0, "issues": ["No entries to analyze"]}

            issues = []
            quality_factors = []

            # Check for duplicate DNs
            dns = [entry.dn.value for entry in entries]
            if len(dns) != len(set(dns)):
                issues.append("Duplicate DNs detected")
                quality_factors.append(0.5)
            else:
                quality_factors.append(1.0)

            # Check for entries with objectClass
            entries_with_object_class = sum(
                1 for entry in entries if entry.get_attribute("objectClass")
            )
            object_class_ratio = entries_with_object_class / len(entries)
            quality_factors.append(object_class_ratio)

            if object_class_ratio < FlextLdifProcessor.QUALITY_THRESHOLD_MEDIUM:
                issues.append("Many entries missing objectClass")

            # Check for minimal attributes
            avg_attrs = sum(len(entry.attributes.data) for entry in entries) / len(
                entries
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
    # CORE API METHODS - Main functionality
    # =============================================================================

    def parse_string(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string into entries."""
        if not content.strip():
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        # Process line continuations
        processed_content = self._ParseHelper._process_line_continuation(content)

        # Split into entry blocks
        entry_blocks = [
            block.strip() for block in processed_content.split("\n\n") if block.strip()
        ]

        entries = []
        for i, block in enumerate(entry_blocks):
            entry_result = self._ParseHelper._process_entry_block(block)
            if entry_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to parse entry {i + 1}: {entry_result.error}"
                )
            entries.append(entry_result.value)

        self._logger.info(f"Successfully parsed {len(entries)} entries from string")
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def parse_ldif_file(
        self, file_path: Path
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file into entries."""
        validation_result = self._validate_file_path(file_path)
        if validation_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                validation_result.error or "File path validation failed"
            )

        try:
            content = file_path.read_text(encoding=self._config.ldif_encoding)
            self._logger.info(
                f"Read LDIF file: {file_path} ({len(content)} characters)"
            )
            return self.parse_string(content)
        except UnicodeDecodeError as e:
            error_msg = f"Failed to decode file {file_path}: {e}"
            self._logger.exception(error_msg)
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)
        except OSError as e:
            error_msg = f"Failed to read file {file_path}: {e}"
            self._logger.exception(error_msg)
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[None]:
        """Validate a list of LDIF entries.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult[None]: Success if all entries are valid, failure with error message

        """
        if not entries:
            return FlextResult[None].fail("No entries to validate")

        for i, entry in enumerate(entries):
            # Validate DN structure
            dn_validation = self._ValidationHelper._validate_dn_structure(entry.dn)
            if dn_validation.is_failure:
                return FlextResult[None].fail(
                    f"Entry {i} DN validation failed: {dn_validation.error}"
                )

            # Validate required attributes (basic validation)
            required_attrs = self._get_required_attributes_for_classes(
                entry.get_attribute("objectClass") or []
            )
            attr_validation = self._ValidationHelper._validate_required_attributes(
                entry, required_attrs
            )
            if attr_validation.is_failure:
                return FlextResult[None].fail(
                    f"Entry {i} attribute validation failed: {attr_validation.error}"
                )

        self._logger.info(f"Successfully validated {len(entries)} entries")
        return FlextResult[None].ok(None)

    def write_string(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write entries to LDIF format string."""
        if not entries:
            return FlextResult[str].ok("")

        entry_strings = []
        for entry in entries:
            entry_ldif = self._WriterHelper._format_entry_as_ldif(entry)
            entry_strings.append(entry_ldif)

        # Join entries with double newline
        content = "\n\n".join(entry_strings) + "\n"

        # Apply line wrapping if configured
        if hasattr(self._config, "wrap_lines") and self._config.wrap_lines:
            content = self._WriterHelper._apply_line_wrapping(content)

        self._logger.info(
            f"Generated LDIF content for {len(entries)} entries ({len(content)} characters)"
        )
        return FlextResult[str].ok(content)

    def write_file(
        self, entries: list[FlextLdifModels.Entry], file_path: str
    ) -> FlextResult[None]:
        """Write entries to LDIF file.

        Args:
            entries: List of entries to write
            file_path: Path to output file

        Returns:
            FlextResult[None]: Success if written successfully, failure with error message

        """
        content_result = self.write_string(entries)
        if content_result.is_failure:
            return FlextResult[None].fail(
                content_result.error or "Failed to generate LDIF content"
            )

        try:
            output_path = Path(file_path)

            # Validate file path
            path_validation = self._validate_file_path(output_path)
            if path_validation.is_failure:
                return FlextResult[None].fail(
                    path_validation.error or "File path validation failed"
                )

            output_path.write_text(
                content_result.value, encoding=self._config.ldif_encoding
            )
            self._logger.info(
                f"Successfully wrote {len(entries)} entries to {file_path}"
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

        transformed_entries = []
        for i, entry in enumerate(entries):
            try:
                transformed = transformer(entry)
                transformed_entries.append(transformed)
            except Exception as e:
                error_msg = f"Transformation failed for entry {i + 1}: {e}"
                self._logger.exception(error_msg)
                return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

        self._logger.info(f"Successfully transformed {len(entries)} entries")
        return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)

    def analyze_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Analyze entries and return comprehensive statistics."""
        if not entries:
            return FlextResult[dict[str, object]].ok({
                "message": "No entries to analyze",
                "entry_count": 0,
            })

        # Only perform detailed analytics for reasonable entry counts
        if len(entries) < self.MIN_ENTRY_COUNT_FOR_ANALYTICS:
            basic_stats = self._AnalyticsHelper._calculate_entry_statistics(entries)
            basic_stats["note"] = (
                f"Basic analysis only (< {self.MIN_ENTRY_COUNT_FOR_ANALYTICS} entries)"
            )
            return FlextResult[dict[str, object]].ok(basic_stats)

        # Comprehensive analytics
        try:
            statistics = self._AnalyticsHelper._calculate_entry_statistics(entries)
            dn_analysis = self._AnalyticsHelper._analyze_dn_patterns(entries)
            quality_metrics = self._AnalyticsHelper._calculate_quality_metrics(entries)

            combined_analysis: dict[str, object] = {
                "basic_statistics": statistics,
                "dn_analysis": dn_analysis,
                "quality_metrics": quality_metrics,
                "analysis_timestamp": datetime.now(UTC).isoformat(),
            }

            self._logger.info(
                f"Completed comprehensive analysis of {len(entries)} entries"
            )
            return FlextResult[dict[str, object]].ok(combined_analysis)

        except Exception as e:
            error_msg = f"Analysis failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict[str, object]].fail(error_msg)

    def filter_entries_by_dn_pattern(
        self, entries: list[FlextLdifModels.Entry], pattern: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern using regex."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            filtered_entries = [
                entry for entry in entries if compiled_pattern.search(entry.dn.value)
            ]

            self._logger.info(
                f"Filtered {len(entries)} entries to {len(filtered_entries)} using pattern: {pattern}"
            )
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

        except re.error as e:
            error_msg = f"Invalid regex pattern '{pattern}': {e}"
            self._logger.exception(error_msg)
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    def filter_entries_by_object_class(
        self, entries: list[FlextLdifModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by object class."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        filtered_entries = []
        for entry in entries:
            object_classes = entry.get_attribute("objectClass") or []
            if any(oc.lower() == object_class.lower() for oc in object_classes):
                filtered_entries.append(entry)

        self._logger.info(
            f"Filtered {len(entries)} entries to {len(filtered_entries)} with objectClass: {object_class}"
        )
        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

    def get_entry_by_dn(
        self, entries: list[FlextLdifModels.Entry], dn: str
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Get entry by DN from provided entries."""
        for entry in entries:
            if entry.dn.value.lower() == dn.lower():
                return FlextResult[FlextLdifModels.Entry | None].ok(entry)

        return FlextResult[FlextLdifModels.Entry | None].ok(None)

    def get_entries_by_attribute(
        self, entries: list[FlextLdifModels.Entry], attr_name: str, attr_value: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Get entries that have specific attribute value."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        matching_entries = []
        for entry in entries:
            attr_values = entry.get_attribute(attr_name) or []
            if any(value.lower() == attr_value.lower() for value in attr_values):
                matching_entries.append(entry)

        self._logger.info(
            f"Found {len(matching_entries)} entries with {attr_name}={attr_value}"
        )
        return FlextResult[list[FlextLdifModels.Entry]].ok(matching_entries)

    def validate_schema_compliance(
        self, entries: list[FlextLdifModels.Entry], schema_rules: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Validate entries against schema rules."""
        if not entries:
            return FlextResult[dict[str, object]].ok({"status": "no_entries"})

        # Extract schema rules with proper typing
        required_attrs_raw = schema_rules.get("required_attributes", [])
        required_attrs: list[str] = (
            required_attrs_raw if isinstance(required_attrs_raw, list) else []
        )

        required_classes_raw = schema_rules.get("required_object_classes", [])
        required_classes: list[str] = (
            required_classes_raw if isinstance(required_classes_raw, list) else []
        )

        compliance_results = []
        for i, entry in enumerate(entries):
            entry_compliance: dict[str, object] = {
                "entry_index": i,
                "dn": entry.dn.value,
                "issues": [],
            }

            # Check required attributes
            if required_attrs:
                attrs_result = self._ValidationHelper._validate_required_attributes(
                    entry, required_attrs
                )
                if attrs_result.is_failure:
                    issues_list = entry_compliance["issues"]
                    if isinstance(issues_list, list):
                        issues_list.append(attrs_result.error)

            # Check required object classes
            if required_classes:
                classes_result = self._ValidationHelper._validate_object_classes(
                    entry, required_classes
                )
                if classes_result.is_failure:
                    issues_list = entry_compliance["issues"]
                    if isinstance(issues_list, list):
                        issues_list.append(classes_result.error)

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
            f"Schema compliance: {compliance_percentage:.1f}% ({compliant_entries}/{len(entries)})"
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
        dn_index = {entry.dn.value.lower(): entry for entry in entries1}
        merged_entries = list(entries1)  # Start with all from first set

        duplicates_count = 0
        for entry in entries2:
            dn_key = entry.dn.value.lower()
            if dn_key in dn_index:
                duplicates_count += 1
                if overwrite_duplicates:
                    # Replace existing entry
                    for i, existing in enumerate(merged_entries):
                        if existing.dn.value.lower() == dn_key:
                            merged_entries[i] = entry
                            break
                # If not overwriting, skip the duplicate
            else:
                # Add new entry
                merged_entries.append(entry)
                dn_index[dn_key] = entry

        self._logger.info(
            f"Merged entries: {len(entries1)} + {len(entries2)} = {len(merged_entries)} "
            f"({duplicates_count} duplicates handled)"
        )
        return FlextResult[list[FlextLdifModels.Entry]].ok(merged_entries)

    def detect_patterns(
        self, entries: list[FlextLdifModels.Entry]
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
            object_classes = entry.get_attribute("objectClass") or []
            if object_classes:
                class_key = ",".join(sorted(object_classes))
                class_combinations[class_key] = class_combinations.get(class_key, 0) + 1

        patterns["object_class_patterns"] = class_combinations

        # Detect attribute patterns
        attribute_frequency: dict[str, int] = {}
        for entry in entries:
            for attr_name in entry.attributes.data:
                attribute_frequency[attr_name] = (
                    attribute_frequency.get(attr_name, 0) + 1
                )

        patterns["attribute_frequency"] = attribute_frequency

        # Detect DN structure patterns
        dn_structures: dict[str, int] = {}
        for entry in entries:
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
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Generate comprehensive quality report for entries."""
        if not entries:
            return FlextResult[dict[str, object]].ok({
                "status": "no_entries",
                "message": "No entries provided for quality analysis",
            })

        try:
            # Basic quality metrics
            quality_metrics = self._AnalyticsHelper._calculate_quality_metrics(entries)

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
            penalty_factors = []
            empty_attrs = quality_checks.get("empty_attributes", 0)
            if isinstance(empty_attrs, (int, float)) and empty_attrs > 0:
                penalty_factors.append(0.9)

            missing_oc = quality_checks.get("missing_object_classes", 0)
            if isinstance(missing_oc, (int, float)) and missing_oc > 0:
                penalty_factors.append(0.8)

            duplicate_dns = quality_checks.get("duplicate_dns", 0)
            if isinstance(duplicate_dns, (int, float)) and duplicate_dns > 0:
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
            recommendations = []
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
                f"Quality report generated: {quality_level} ({quality_score:.2f})"
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
                    "encoding": self._config.ldif_encoding,
                    "max_entries": getattr(
                        self._config, "max_entries", self.DEFAULT_MAX_ENTRIES
                    ),
                    "strict_validation": getattr(
                        self._config, "strict_validation", True
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
            "encoding": self._config.ldif_encoding,
            "max_entries": getattr(
                self._config, "max_entries", self.DEFAULT_MAX_ENTRIES
            ),
            "strict_validation": getattr(self._config, "strict_validation", True),
            "wrap_lines": getattr(self._config, "wrap_lines", True),
        }

    # =============================================================================
    # HELPER METHODS - Private utilities
    # =============================================================================

    @staticmethod
    def _validate_file_path(file_path: Path) -> FlextResult[None]:
        """Validate file path for write operations.

        Args:
            file_path: Path to validate

        Returns:
            FlextResult[None]: Success if path is valid, failure with error message

        """
        try:
            # Check if parent directory exists or can be created
            parent_dir = file_path.parent
            if not parent_dir.exists():
                try:
                    parent_dir.mkdir(parents=True, exist_ok=True)
                except OSError as e:
                    return FlextResult[None].fail(
                        f"Cannot create directory {parent_dir}: {e}"
                    )

            # Check write permissions
            if file_path.exists():
                if not os.access(file_path, os.W_OK):
                    return FlextResult[None].fail(
                        f"No write permission for file: {file_path}"
                    )
            # Check parent directory write permission
            elif not os.access(parent_dir, os.W_OK):
                return FlextResult[None].fail(
                    f"No write permission for directory: {parent_dir}"
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"File path validation failed: {e}")

    def _get_required_attributes_for_classes(
        self, object_classes: list[str]
    ) -> list[str]:
        """Get required attributes for given object classes."""
        # Basic LDAP object class requirements
        required_attrs = []

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
            for attr_values in entry.attributes.data.values():
                if not attr_values or (
                    len(attr_values) == 1 and not attr_values[0].strip()
                ):
                    count += 1
                    break
        return count

    def _count_missing_object_classes(
        self, entries: list[FlextLdifModels.Entry]
    ) -> int:
        """Count entries missing objectClass."""
        return sum(1 for entry in entries if not entry.get_attribute("objectClass"))

    def _count_duplicate_dns(self, entries: list[FlextLdifModels.Entry]) -> int:
        """Count duplicate DN entries."""
        dns = [entry.dn.value.lower() for entry in entries]
        return len(dns) - len(set(dns))

    def _count_invalid_dns(self, entries: list[FlextLdifModels.Entry]) -> int:
        """Count entries with invalid DN format."""
        count = 0
        for entry in entries:
            result = self._ValidationHelper._validate_dn_structure(entry.dn)
            if result.is_failure:
                count += 1
        return count
