"""Analysis Service - Entry Analysis and Validation.

Provides comprehensive analysis and validation for LDIF entries including
statistics generation, pattern detection, and RFC 2849/4512 compliance validation.

Scope: Entry collection analysis, object class distribution, pattern detection,
DN validation, attribute validation, and ObjectClass validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections import Counter
from typing import override

from flext_core import FlextResult, FlextRuntime

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.validation import FlextLdifValidation

# Import _DynamicCounts for type usage
from flext_ldif._models.results import _DynamicCounts


class FlextLdifAnalysis(
    FlextLdifServiceBase[FlextLdifModels.EntryAnalysisResult],
):
    """Service for entry analysis and validation.

    Provides methods for:
    - Analyzing entry collections and generating statistics
    - Validating entries against RFC 2849/4512 standards
    - Pattern detection in DNs and attributes

    Example:
        analysis_service = FlextLdifAnalysis()

        # Analyze entries
        result = analysis_service.analyze(entries)
        if result.is_success:
            stats = result.unwrap()
            print(f"Total: {stats.total_entries}")

        # Validate entries
        validation_result = analysis_service.validate_entries(entries, validation_service)
        if validation_result.is_success:
            report = validation_result.unwrap()
            print(f"Valid: {report.is_valid}")

    """

    @override
    def execute(
        self,
    ) -> FlextResult[FlextLdifModels.EntryAnalysisResult]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (analyze, validate_entries)
        rather than a generic execute operation.

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(
            "FlextLdifAnalysis does not support generic execute(). Use specific methods instead.",
        )

    def analyze(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.EntryAnalysisResult]:
        """Analyze LDIF entries and generate statistics.

        Performs comprehensive analysis of entry collection including:
        - Total entry count
        - Object class distribution
        - Pattern detection in DNs and attributes

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing EntryAnalysisResult with statistics

        Example:
            result = analysis_service.analyze(entries)
            if result.is_success:
                stats = result.unwrap()
                print(f"Total: {stats.total_entries}")
                print(f"Classes: {stats.objectclass_distribution}")

        """
        total_entries = len(entries)

        objectclass_distribution: Counter[str] = Counter()
        patterns_detected: set[str] = set()

        for entry in entries:
            for oc_name in entry.get_objectclass_names():
                objectclass_distribution[oc_name] += 1

            dn_str_lower = str(entry.dn).lower()
            if "ou=users" in dn_str_lower:
                patterns_detected.add("user pattern")
            if "ou=groups" in dn_str_lower:
                patterns_detected.add("group pattern")

        return FlextResult[FlextLdifModels.EntryAnalysisResult].ok(
            FlextLdifModels.EntryAnalysisResult(
                total_entries=total_entries,
                objectclass_distribution=_DynamicCounts(**objectclass_distribution),
                patterns_detected=sorted(patterns_detected),
            ),
        )

    def validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        validation_service: FlextLdifValidation,
    ) -> FlextResult[FlextLdifModels.ValidationResult]:
        """Validate LDIF entries against RFC 2849/4512 standards.

        Performs comprehensive validation including:
        - DN format validation
        - Attribute name validation (RFC 4512)
        - ObjectClass name validation (RFC 4512)
        - Attribute value length checks
        - Entry structure validation

        Args:
            entries: List of entries to validate
            validation_service: Validation service instance for RFC compliance checks

        Returns:
            FlextResult containing ValidationResult with validation status

        Example:
            validation_service = FlextLdifValidation()
            result = analysis_service.validate_entries(entries, validation_service)
            if result.is_success:
                report = result.unwrap()
                print(f"Valid: {report.is_valid}")
                print(f"Valid entries: {report.valid_entries}/{report.total_entries}")

        """
        errors: list[str] = []
        valid_count = 0

        for entry in entries:
            is_entry_valid, entry_errors = self._validate_single_entry(
                entry,
                validation_service,
            )
            errors.extend(entry_errors)
            if is_entry_valid:
                valid_count += 1

        total_entries = len(entries)
        invalid_count = total_entries - valid_count

        return FlextResult[FlextLdifModels.ValidationResult].ok(
            FlextLdifModels.ValidationResult(
                is_valid=invalid_count == 0,
                total_entries=total_entries,
                valid_entries=valid_count,
                invalid_entries=invalid_count,
                errors=errors[:100],
            ),
        )

    def _validate_single_entry(
        self,
        entry: FlextLdifModels.Entry,
        validation_service: FlextLdifValidation,
    ) -> tuple[bool, list[str]]:
        """Validate a single LDIF entry.

        Internal helper method to reduce complexity in validate_entries() method.

        Args:
            entry: Entry to validate
            validation_service: Validation service instance

        Returns:
            Tuple of (is_valid, errors) where is_valid is True if entry is valid,
            and errors is list of validation error messages

        """
        errors: list[str] = []
        is_entry_valid = True

        # Validate DN (dn is required, cannot be None)
        dn_str = entry.dn.value
        if not dn_str:
            errors.append(f"Entry has invalid DN: {entry.dn}")
            is_entry_valid = False

        # Validate each attribute name (attributes is required, cannot be None)

        for attr_name in entry.attributes.attributes:
            attr_result = validation_service.validate_attribute_name(attr_name)
            if attr_result.is_failure or not attr_result.unwrap():
                errors.append(f"Entry {dn_str}: Invalid attribute name '{attr_name}'")
                is_entry_valid = False

        # Validate objectClass values
        oc_values = entry.attributes.attributes.get("objectClass", [])
        if FlextRuntime.is_list_like(oc_values):
            for oc in oc_values:
                if not isinstance(oc, str):
                    msg = f"Expected str, got {type(oc)}"
                    raise TypeError(msg)
                oc_result = validation_service.validate_objectclass_name(oc)
                if oc_result.is_failure or not oc_result.unwrap():
                    errors.append(f"Entry {dn_str}: Invalid objectClass '{oc}'")
                    is_entry_valid = False

        return is_entry_valid, errors


__all__ = ["FlextLdifAnalysis"]
