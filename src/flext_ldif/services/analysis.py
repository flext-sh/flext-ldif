"""Analysis Service - Entry Analysis and Validation."""

from __future__ import annotations

from flext_ldif import m, p, r, s, t, u
from flext_ldif.services.validation import FlextLdifValidation


class FlextLdifAnalysis(s):
    """Service for entry analysis and validation."""

    @staticmethod
    def _validate_entry_attributes(
        entry: p.Ldif.Entry,
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
        entry: p.Ldif.Entry,
    ) -> tuple[bool, str, t.MutableSequenceOf[str]]:
        """Validate entry DN."""
        errors: t.MutableSequenceOf[str] = []
        if entry.dn is None:
            errors.append("Entry has None DN")
            return (False, "", errors)
        dn_str = str(entry.dn)
        if not dn_str:
            errors.append(f"Entry has invalid DN: {entry.dn}")
            return (False, dn_str, errors)
        return (True, dn_str, errors)

    @staticmethod
    def _validate_entry_objectclasses(
        entry: p.Ldif.Entry,
        dn_str: str,
        validation_service: p.Ldif.ValidationService,
    ) -> tuple[bool, t.MutableSequenceOf[str]]:
        """Validate entry objectClass values."""
        errors: t.MutableSequenceOf[str] = []
        valid = True
        oc_values: t.MutableSequenceOf[str] = u.Ldif.get_objectclass_names(entry)
        for oc_item in oc_values:
            oc_result = validation_service.validate_objectclass_name(oc_item)
            if oc_result.failure or not oc_result.value:
                errors.append(f"Entry {dn_str}: Invalid objectClass '{oc_item}'")
                valid = False
        return (valid, errors)

    @staticmethod
    def _validate_single_entry(
        entry: p.Ldif.Entry,
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
        entries: t.MutableSequenceOf[p.Ldif.Entry] | m.Ldif.ParseResponse,
        validation_service: p.Ldif.ValidationService | None = None,
    ) -> p.Result[p.Ldif.ValidationResult]:
        """Validate LDIF entries against RFC 2849/4512 standards."""
        normalized_entries = u.Ldif.as_entries(entries)
        errors: t.MutableSequenceOf[str] = []
        valid_count = 0
        svc: p.Ldif.ValidationService = (
            validation_service
            if validation_service is not None
            else FlextLdifValidation()
        )

        def validate_entry(entry: p.Ldif.Entry) -> bool:
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
        return r[p.Ldif.ValidationResult].ok(
            m.Ldif.ValidationResult.model_validate({
                "valid": invalid_count == 0,
                "total_entries": total_entries,
                "valid_entries": valid_count,
                "invalid_entries": invalid_count,
                "errors": errors[:100],
            }),
        )


__all__: list[str] = ["FlextLdifAnalysis"]
