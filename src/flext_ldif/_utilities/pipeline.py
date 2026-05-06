"""Validation pipeline utilities for LDIF entries."""

from __future__ import annotations

from typing import override

from flext_ldif import m, p, r, t


class FlextLdifUtilitiesPipeline:
    """Validation pipeline utilities for LDIF entries."""

    class ValidationResult:
        """Result of entry validation."""

        __slots__ = ("_errors", "_is_valid", "_warnings")

        def __init__(
            self,
            *,
            valid: bool,
            errors: t.MutableSequenceOf[str] | None = None,
            warnings: t.MutableSequenceOf[str] | None = None,
        ) -> None:
            """Initialize validation result."""
            super().__init__()
            self._is_valid = valid
            self._errors = errors or []
            self._warnings = warnings or []

        @override
        def __repr__(self) -> str:
            """Return string representation."""
            status = "valid" if self._is_valid else "invalid"
            return f"ValidationResult({status}, errors={len(self._errors)}, warnings={len(self._warnings)})"

        @property
        def errors(self) -> t.MutableSequenceOf[str]:
            """Get list of error messages."""
            return self._errors

        @property
        def valid(self) -> bool:
            """Check if validation passed."""
            return self._is_valid

        @property
        def warnings(self) -> t.MutableSequenceOf[str]:
            """Get list of warning messages."""
            return self._warnings

    class ValidationPipeline:
        """Pipeline for validating entries."""

        __slots__ = ("_collect_all", "_max_errors", "_strict")

        def __init__(
            self,
            *,
            strict: bool = True,
            collect_all: bool = True,
            max_errors: int = 0,
        ) -> None:
            """Initialize validation pipeline."""
            super().__init__()
            self._strict = strict
            self._collect_all = collect_all
            self._max_errors = max_errors

        def validate(
            self,
            entries: t.SequenceOf[m.Ldif.Entry],
        ) -> p.Result[t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]]:
            """Validate a sequence of entries."""
            results: t.MutableSequenceOf[
                FlextLdifUtilitiesPipeline.ValidationResult
            ] = []
            total_errors = 0
            for entry in entries:
                validation_result = self.validate_one(entry)
                if validation_result.failure:
                    return r[
                        t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]
                    ].fail(validation_result.error)
                validation = validation_result.value
                results.append(validation)
                total_errors += len(validation.errors)
                if self._max_errors > 0 and total_errors >= self._max_errors:
                    break
                if not self._collect_all and (not validation.valid):
                    break
            return r[
                t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]
            ].ok(
                results,
            )

        def validate_one(
            self,
            entry: m.Ldif.Entry,
        ) -> p.Result[FlextLdifUtilitiesPipeline.ValidationResult]:
            """Validate a single entry."""
            errors: t.MutableSequenceOf[str] = []
            warnings: t.MutableSequenceOf[str] = []
            if entry.dn is None:
                errors.append("Entry has no DN (RFC 2849 violation)")
            else:
                dn_str = (
                    entry.dn.value
                    if getattr(entry.dn, "value", None) is not None
                    else str(entry.dn)
                )
                components = dn_str.split(",")
                for comp in components:
                    comp_stripped = comp.strip()
                    if "=" not in comp_stripped:
                        errors.append(f"Invalid RDN (missing '='): {comp_stripped}")
                        continue
                    _, _, value = comp_stripped.partition("=")
                    if not value.strip():
                        errors.append(f"Invalid RDN (missing value): {comp_stripped}")
            if entry.attributes is None:
                errors.append("Entry has no attributes (RFC 2849 violation)")
            else:
                attrs: t.MutableStrSequenceMapping = (
                    entry.attributes.attributes
                    if getattr(entry.attributes, "attributes", None) is not None
                    else {}
                )
                has_objectclass = any(k.lower() == "objectclass" for k in attrs)
                if not has_objectclass:
                    if self._strict:
                        errors.append("Entry has no objectClass attribute")
                    else:
                        warnings.append("Entry has no objectClass attribute")
            return r[FlextLdifUtilitiesPipeline.ValidationResult].ok(
                FlextLdifUtilitiesPipeline.ValidationResult(
                    valid=not errors,
                    errors=errors,
                    warnings=warnings,
                ),
            )


__all__: list[str] = [
    "FlextLdifUtilitiesPipeline",
]
