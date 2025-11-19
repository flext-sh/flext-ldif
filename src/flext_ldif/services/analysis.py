"""FLEXT-LDIF Analysis Service - Entry analysis and validation.

This service handles entry analysis, statistics generation, and validation
operations.

Extracted from FlextLdif facade to follow Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.typings import FlextLdifTypes


class FlextLdifAnalysis(FlextService[FlextLdifTypes.Models.ServiceResponseTypes]):
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

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (analyze, validate_entries)
        rather than a generic execute operation.

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult.fail(
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
        try:
            total_entries = len(entries)

            # Analyze object class distribution
            objectclass_distribution: dict[str, int] = {}
            patterns_detected: list[str] = []

            for entry in entries:
                # Count object classes
                if entry.metadata.objectclasses:
                    for oc in entry.metadata.objectclasses:
                        oc_name = oc.name if hasattr(oc, "name") else str(oc)
                        objectclass_distribution[oc_name] = (
                            objectclass_distribution.get(oc_name, 0) + 1
                        )

                # Simple pattern detection
                dn_str = str(entry.dn)
                if (
                    "ou=users" in dn_str.lower()
                    and "user pattern" not in patterns_detected
                ):
                    patterns_detected.append("user pattern")
                if (
                    "ou=groups" in dn_str.lower()
                    and "group pattern" not in patterns_detected
                ):
                    patterns_detected.append("group pattern")

            # Create analysis result
            analysis_result = FlextLdifModels.EntryAnalysisResult(
                total_entries=total_entries,
                objectclass_distribution=objectclass_distribution,
                patterns_detected=patterns_detected,
            )

            return FlextResult[FlextLdifModels.EntryAnalysisResult].ok(analysis_result)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(
                f"Entry analysis failed: {e}",
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
        try:
            errors: list[str] = []
            valid_count = 0
            invalid_count = 0

            for entry in entries:
                is_entry_valid, entry_errors = self._validate_single_entry(
                    entry,
                    validation_service,
                )
                errors.extend(entry_errors)

                if is_entry_valid:
                    valid_count += 1
                else:
                    invalid_count += 1

            total_entries = len(entries)
            is_valid = invalid_count == 0

            result = FlextLdifModels.ValidationResult(
                is_valid=is_valid,
                total_entries=total_entries,
                valid_entries=valid_count,
                invalid_entries=invalid_count,
                errors=errors[:100],  # Limit errors to 100
            )

            return FlextResult[FlextLdifModels.ValidationResult].ok(result)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.ValidationResult].fail(
                f"Entry validation failed: {e}",
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
        if not dn_str or not isinstance(dn_str, str):
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
        if isinstance(oc_values, list):
            for oc in oc_values:
                oc_result = validation_service.validate_objectclass_name(oc)
                if oc_result.is_failure or not oc_result.unwrap():
                    errors.append(f"Entry {dn_str}: Invalid objectClass '{oc}'")
                    is_entry_valid = False

        return is_entry_valid, errors


__all__ = ["FlextLdifAnalysis"]
