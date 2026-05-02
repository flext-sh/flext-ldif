"""Analysis Service - Entry Analysis and Validation."""

from __future__ import annotations

from flext_ldif import (
    FlextLdifValidation,
    m,
    p,
    r,
    s,
    t,
    u,
)


class FlextLdifAnalysis(s):
    """Service for entry analysis and validation."""

    @staticmethod
    def _validate_entry_attributes(
        entry: m.Ldif.Entry,
        dn_str: str,
        validation_service: p.Ldif.ValidationService,
    ) -> tuple[bool, t.MutableSequenceOf[str]]:
        """Validate entry attributes."""
        errors: t.MutableSequenceOf[str] = []
        valid = True
        if entry.attributes is None:
            errors.append(f"Entry {dn_str}: Attributes cannot be None")
            return (False, errors)
        for attr_name in entry.attributes.attributes:
            attr_result = validation_service.validate_attribute_name(attr_name)
            if attr_result.failure or not attr_result.value:
                errors.append(f"Entry {dn_str}: Invalid attribute name '{attr_name}'")
                valid = False
        return (valid, errors)

    @staticmethod
    def _validate_entry_dn(
        entry: m.Ldif.Entry,
    ) -> tuple[bool, str, t.MutableSequenceOf[str]]:
        """Validate entry DN."""
        errors: t.MutableSequenceOf[str] = []
        if entry.dn is None:
            errors.append("Entry has None DN")
            return (False, "", errors)
        dn_str = (
            entry.dn.value
            if getattr(entry.dn, "value", None) is not None
            else str(entry.dn)
        )
        if not dn_str:
            errors.append(f"Entry has invalid DN: {entry.dn}")
            return (False, dn_str, errors)
        return (True, dn_str, errors)

    @staticmethod
    def _validate_entry_objectclasses(
        entry: m.Ldif.Entry,
        dn_str: str,
        validation_service: p.Ldif.ValidationService,
    ) -> tuple[bool, t.MutableSequenceOf[str]]:
        """Validate entry objectClass values."""
        errors: t.MutableSequenceOf[str] = []
        valid = True
        oc_values_raw = (
            entry.attributes.attributes.get("objectClass")
            if entry.attributes is not None
            else None
        )
        if isinstance(oc_values_raw, list):
            oc_values: t.MutableSequenceOf[str] = list(oc_values_raw)
        else:
            oc_values = []
        for oc_item in oc_values:
            oc_result = validation_service.validate_objectclass_name(oc_item)
            if oc_result.failure or not oc_result.value:
                errors.append(f"Entry {dn_str}: Invalid objectClass '{oc_item}'")
                valid = False
        return (valid, errors)

    @staticmethod
    def _validate_single_entry(
        entry: m.Ldif.Entry,
        validation_service: p.Ldif.ValidationService,
    ) -> tuple[bool, t.MutableSequenceOf[str]]:
        """Validate a single LDIF entry."""
        errors: t.MutableSequenceOf[str] = []
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

    def validate_entries(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        validation_service: p.Ldif.ValidationService | None = None,
    ) -> r[m.Ldif.ValidationResult]:
        """Validate LDIF entries against RFC 2849/4512 standards."""
        normalized_entries = (
            entries.entries if isinstance(entries, m.Ldif.ParseResponse) else entries
        )
        errors: t.MutableSequenceOf[str] = []
        valid_count = 0
        svc: p.Ldif.ValidationService = (
            validation_service
            if validation_service is not None
            else FlextLdifValidation()
        )

        def validate_entry(entry: m.Ldif.Entry) -> bool:
            """Validate single entry and collect errors."""
            is_entry_valid, entry_errors = FlextLdifAnalysis._validate_single_entry(
                entry,
                svc,
            )
            errors.extend(entry_errors)
            return is_entry_valid

        validation_results = u.map(normalized_entries, validate_entry)
        valid_results = [r for r in validation_results if r is True]
        valid_count = u.count(valid_results)
        total_entries = u.count(normalized_entries)
        invalid_count = total_entries - valid_count
        return r[m.Ldif.ValidationResult].ok(
            m.Ldif.ValidationResult.model_validate({
                "valid": invalid_count == 0,
                "total_entries": total_entries,
                "valid_entries": valid_count,
                "invalid_entries": invalid_count,
                "errors": errors[:100],
            }),
        )


__all__: list[str] = ["FlextLdifAnalysis"]
