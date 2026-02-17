"""Analysis Service - Entry Analysis and Validation."""

from __future__ import annotations

import contextlib
from collections import Counter
from typing import override

from flext_core import r

from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.typings import t
from flext_ldif.utilities import u


class FlextLdifAnalysis(
    s[m.Ldif.LdifResults.EntryAnalysisResult],
):
    """Service for entry analysis and validation."""

    @override
    def execute(
        self,
    ) -> r[m.Ldif.Results.EntryAnalysisResult]:
        """Execute method required by FlextService abstract base class."""
        return r[m.Ldif.Results.EntryAnalysisResult].fail(
            "FlextLdifAnalysis does not support generic execute(). Use specific methods instead.",
        )

    @staticmethod
    def analyze(
        entries: list[m.Ldif.Entry],
    ) -> r[m.Ldif.Results.EntryAnalysisResult]:
        """Analyze LDIF entries and generate statistics."""
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

        for entry in entries:
            with contextlib.suppress(Exception):
                process_entry(entry)

        return r[m.Ldif.LdifResults.EntryAnalysisResult].ok(
            m.Ldif.LdifResults.EntryAnalysisResult(
                total_entries=total_entries,
                objectclass_distribution=m.Ldif.LdifResults.DynamicCounts(
                    **objectclass_distribution,
                ),
                patterns_detected=sorted(patterns_detected),
            ),
        )

    @staticmethod
    def validate_entries(
        entries: list[m.Ldif.Entry],
        validation_service: FlextLdifValidation,
    ) -> r[m.Ldif.LdifResults.ValidationResult]:
        """Validate LDIF entries against RFC 2849/4512 standards."""
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

        validation_results = u.Collection.map(entries, validate_entry)

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
        """Validate entry DN."""
        errors: list[str] = []
        if entry.dn is None:
            errors.append("Entry has None DN")
            return (False, "", errors)

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
        """Validate entry attributes."""
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
        """Validate entry objectClass values."""
        errors: list[str] = []
        is_valid = True
        oc_values_raw: t.GeneralValueType = u.mapper().get(
            entry.attributes.attributes if entry.attributes else {},
            "objectClass",
            default=[],
        )

        if isinstance(oc_values_raw, str):
            oc_values: list[str] | str = oc_values_raw
        elif isinstance(oc_values_raw, list):
            oc_values = [str(oc) for oc in oc_values_raw]
        else:
            oc_values = []

        if isinstance(oc_values, list):
            for oc_item in oc_values:
                if not isinstance(oc_item, str):
                    msg = f"Expected str, got {type(oc_item)}"
                    raise TypeError(msg)
                oc_result = validation_service.validate_objectclass_name(oc_item)
                if oc_result.is_failure or not oc_result.value:
                    errors.append(f"Entry {dn_str}: Invalid objectClass '{oc_item}'")
                    is_valid = False
        elif isinstance(oc_values, str):
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
        """Validate a single LDIF entry."""
        errors: list[str] = []
        is_entry_valid = True

        dn_valid, dn_str, dn_errors = FlextLdifAnalysis._validate_entry_dn(entry)
        errors.extend(dn_errors)
        if not dn_valid:
            return (False, errors)
        is_entry_valid = is_entry_valid and dn_valid

        attrs_valid, attrs_errors = FlextLdifAnalysis._validate_entry_attributes(
            entry,
            dn_str,
            validation_service,
        )
        errors.extend(attrs_errors)
        if not attrs_valid:
            return (False, errors)
        is_entry_valid = is_entry_valid and attrs_valid

        oc_valid, oc_errors = FlextLdifAnalysis._validate_entry_objectclasses(
            entry,
            dn_str,
            validation_service,
        )
        errors.extend(oc_errors)
        is_entry_valid = is_entry_valid and oc_valid

        return (is_entry_valid, errors)


__all__ = ["FlextLdifAnalysis"]
