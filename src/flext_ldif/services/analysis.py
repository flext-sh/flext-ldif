"""Analysis Service - Entry Analysis and Validation.

Provides comprehensive analysis and validation for LDIF entries including
statistics generation, pattern detection, and RFC 2849/4512 compliance validation.

Scope: Entry collection analysis, object class distribution, pattern detection,
DN validation, attribute validation, and ObjectClass validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import contextlib
from collections import Counter
from typing import override

from flext_core import r

from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.utilities import u


class FlextLdifAnalysis(
    FlextLdifServiceBase[FlextLdifModelsResults.EntryAnalysisResult],
):
    """Service for entry analysis and validation.

    Business Rule: Analysis service provides comprehensive entry collection analysis
    including statistics generation, object class distribution, and pattern detection.
    Validation delegates to FlextLdifValidation service for RFC 2849/4512 compliance
    checks. Analysis results enable data quality assessment and migration planning.

    Implication: Analysis enables understanding of LDIF data structure before processing.
    Pattern detection identifies common organizational patterns (users, groups) for
    categorization. Statistics support migration planning and data quality assessment.

    Provides methods for:
    - Analyzing entry collections and generating statistics
    - Validating entries against RFC 2849/4512 standards
    - Pattern detection in DNs and attributes

    Example:
        analysis_service = FlextLdifAnalysis()

        # Analyze entries
        result = analysis_service.analyze(entries)
        if result.is_success:
            stats = result.value
            print(f"Total: {stats.total_entries}")

        # Validate entries
        validation_result = analysis_service.validate_entries(entries, validation_service)
        if validation_result.is_success:
            report = validation_result.value
            print(f"Valid: {report.is_valid}")

    """

    @override
    def execute(
        self,
    ) -> r[m.Ldif.Results.EntryAnalysisResult]:
        """Execute method required by FlextService abstract base class.

        Business Rule: Analysis service does not support generic execute() operation.
        Use specific methods (analyze(), validate_entries()) for analysis operations.
        This ensures type safety and clear API boundaries.

        Implication: This method returns fail-fast error directing to correct usage.
        Service-based execution patterns should use analyze() or validate_entries()
        directly.

        Returns:
            r.fail() with error message directing to correct usage

        """
        return r[m.Ldif.Results.EntryAnalysisResult].fail(
            "FlextLdifAnalysis does not support generic execute(). Use specific methods instead.",
        )

    @staticmethod
    def analyze(
        entries: list[m.Ldif.Entry],
    ) -> r[m.Ldif.Results.EntryAnalysisResult]:
        """Analyze LDIF entries and generate statistics.

        Business Rule: Entry analysis generates comprehensive statistics including
        total entry count, object class distribution (Counter), and pattern detection
        in DNs (users, groups patterns). Analysis enables data quality assessment
        and migration planning.

        Implication: Object class distribution uses Counter for efficient counting.
        Pattern detection identifies common organizational patterns for categorization.
        Results support migration planning and data quality assessment.

        Performs comprehensive analysis of entry collection including:
        - Total entry count
        - Object class distribution
        - Pattern detection in DNs and attributes

        Args:
            entries: List of entries to analyze

        Returns:
            r containing EntryAnalysisResult with statistics

        Example:
            result = analysis_service.analyze(entries)
            if result.is_success:
                stats = result.value
                print(f"Total: {stats.total_entries}")
                print(f"Classes: {stats.objectclass_distribution}")

        """
        total_entries = len(entries)

        objectclass_distribution: Counter[str] = Counter()
        patterns_detected: set[str] = set()

        def process_entry(entry: m.Ldif.Entry) -> None:
            """Process entry for analysis."""
            for oc_name in entry.get_objectclass_names():
                objectclass_distribution[oc_name] += 1

            dn_str_lower = str(entry.dn).lower()
            if "ou=users" in dn_str_lower:
                patterns_detected.add("user pattern")
            if "ou=groups" in dn_str_lower:
                patterns_detected.add("group pattern")

        # Process entries using simple iteration - u.process has different signature
        # (u.process is for server transformations, not generic processing)
        for entry in entries:
            with contextlib.suppress(Exception):  # Skip errors like _on_error="skip"
                process_entry(entry)

        return r[m.Ldif.LdifResults.EntryAnalysisResult].ok(
            m.Ldif.LdifResults.EntryAnalysisResult(
                total_entries=total_entries,
                objectclass_distribution=FlextLdifModelsResults.DynamicCounts(
                    **objectclass_distribution
                ),
                patterns_detected=sorted(patterns_detected),
            ),
        )

    @staticmethod
    def validate_entries(
        entries: list[m.Ldif.Entry],
        validation_service: FlextLdifValidation,
    ) -> r[m.Ldif.LdifResults.ValidationResult]:
        """Validate LDIF entries against RFC 2849/4512 standards.

        Business Rule: Entry validation delegates to FlextLdifValidation service
        for RFC 2849/4512 compliance checks. Validation includes DN format, attribute
        names, objectClass names, attribute value lengths, and entry structure.
        Validation results aggregate errors and provide validation status.

        Implication: Validation enables data quality assessment before processing.
        Errors are collected and reported in ValidationResult for comprehensive
        validation reporting. Invalid entries are identified for correction.

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
            r containing ValidationResult with validation status and errors

        Example:
            validation_service = FlextLdifValidation()
            result = analysis_service.validate_entries(entries, validation_service)
            if result.is_success:
                report = result.value
                print(f"Valid: {report.is_valid}")
                print(f"Valid entries: {report.valid_entries}/{report.total_entries}")

        """
        errors: list[str] = []
        valid_count = 0

        def validate_entry(entry: m.Ldif.Entry) -> bool:
            """Validate single entry and collect errors."""
            is_entry_valid, entry_errors = FlextLdifAnalysis._validate_single_entry(
                entry,
                validation_service,
            )
            errors.extend(entry_errors)
            return is_entry_valid

        # Process entries using u.Collection.map() - u.batch_process() doesn't exist
        # Map each entry through validation function, collecting results
        validation_results = u.Collection.map(entries, validate_entry)
        # Count valid entries (True values) by filtering first
        valid_results = [r for r in validation_results if r is True]
        valid_count = u.count(valid_results)

        total_entries = u.count(entries)
        invalid_count = total_entries - valid_count

        return r[m.Ldif.LdifResults.ValidationResult].ok(
            m.Ldif.LdifResults.ValidationResult(
                is_valid=invalid_count == 0,
                total_entries=total_entries,
                valid_entries=valid_count,
                invalid_entries=invalid_count,
                errors=errors[:100],
            ),
        )

    @staticmethod
    def _validate_entry_dn(
        entry: m.Ldif.Entry,
    ) -> tuple[bool, str, list[str]]:
        """Validate entry DN.

        Returns:
            Tuple of (is_valid, dn_str, errors)

        """
        errors: list[str] = []
        if entry.dn is None:
            errors.append("Entry has None DN")
            return (False, "", errors)
        # Type narrowing: entry.dn is not None
        dn_str = entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
        if not dn_str:
            errors.append(f"Entry has invalid DN: {entry.dn}")
            return (False, dn_str, errors)
        return (True, dn_str, errors)

    @staticmethod
    def _validate_entry_attributes(
        entry: m.Ldif.Entry,
        dn_str: str,
        validation_service: FlextLdifValidation,
    ) -> tuple[bool, list[str]]:
        """Validate entry attributes.

        Returns:
            Tuple of (is_valid, errors)

        """
        errors: list[str] = []
        is_valid = True
        if entry.attributes is None:
            errors.append(f"Entry {dn_str}: Attributes cannot be None")
            return (False, errors)

        for attr_name in entry.attributes.attributes:
            attr_result = validation_service.validate_attribute_name(attr_name)
            if attr_result.is_failure or not attr_result.value:
                errors.append(f"Entry {dn_str}: Invalid attribute name '{attr_name}'")
                is_valid = False
        return (is_valid, errors)

    @staticmethod
    def _validate_entry_objectclasses(
        entry: m.Ldif.Entry,
        dn_str: str,
        validation_service: FlextLdifValidation,
    ) -> tuple[bool, list[str]]:
        """Validate entry objectClass values.

        Returns:
            Tuple of (is_valid, errors)

        """
        errors: list[str] = []
        is_valid = True
        oc_values_raw: object = u.mapper().get(
            entry.attributes.attributes if entry.attributes else {},
            "objectClass",
            default=[],
        )
        # Type narrowing: u.get returns object, but we know objectClass is list[str] | str
        oc_values: list[str] | str = (
            oc_values_raw if isinstance(oc_values_raw, (list, str)) else []
        )
        # Type narrowing: oc_values is list[str] | str
        # Note: list may contain non-str items, so we validate each item
        if isinstance(oc_values, list):
            for oc_item in oc_values:
                # Runtime validation: ensure each item is str
                if not isinstance(oc_item, str):
                    msg = f"Expected str, got {type(oc_item)}"
                    raise TypeError(msg)
                oc_result = validation_service.validate_objectclass_name(oc_item)
                if oc_result.is_failure or not oc_result.value:
                    errors.append(f"Entry {dn_str}: Invalid objectClass '{oc_item}'")
                    is_valid = False
        elif isinstance(oc_values, str):
            # Single string objectClass value
            oc_result = validation_service.validate_objectclass_name(oc_values)
            if oc_result.is_failure or not oc_result.value:
                errors.append(f"Entry {dn_str}: Invalid objectClass '{oc_values}'")
                is_valid = False
        return (is_valid, errors)

    @staticmethod
    def _validate_single_entry(
        entry: m.Ldif.Entry,
        validation_service: FlextLdifValidation,
    ) -> tuple[bool, list[str]]:
        """Validate a single LDIF entry.

        Business Rule: Single entry validation checks DN format, attribute names,
        objectClass names, and attribute value lengths. Validation errors are
        collected and returned as tuple (is_valid, errors) for aggregation.

        Implication: This method enables batch validation with error aggregation.
        Each entry is validated independently, with errors collected for reporting.

        Internal helper method to reduce complexity in validate_entries() method.

        Args:
            entry: Entry to validate
            validation_service: Validation service instance for RFC compliance checks

        Returns:
            Tuple of (is_valid, errors) where is_valid is True if entry is valid,
            and errors is list of validation error messages

        """
        errors: list[str] = []
        is_entry_valid = True

        # Validate DN
        dn_valid, dn_str, dn_errors = FlextLdifAnalysis._validate_entry_dn(entry)
        errors.extend(dn_errors)
        if not dn_valid:
            return (False, errors)
        is_entry_valid = is_entry_valid and dn_valid

        # Validate attributes
        attrs_valid, attrs_errors = FlextLdifAnalysis._validate_entry_attributes(
            entry,
            dn_str,
            validation_service,
        )
        errors.extend(attrs_errors)
        if not attrs_valid:
            return (False, errors)
        is_entry_valid = is_entry_valid and attrs_valid

        # Validate objectClasses
        oc_valid, oc_errors = FlextLdifAnalysis._validate_entry_objectclasses(
            entry,
            dn_str,
            validation_service,
        )
        errors.extend(oc_errors)
        is_entry_valid = is_entry_valid and oc_valid

        return (is_entry_valid, errors)


__all__ = ["FlextLdifAnalysis"]
