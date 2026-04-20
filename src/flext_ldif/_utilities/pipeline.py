"""Power Method Pipeline - Pipeline orchestration for entry processing."""

from __future__ import annotations

from collections.abc import (
    Callable,
    MutableSequence,
    Sequence,
)
from typing import ClassVar, Self, override

from flext_ldif import r
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.typings import t


class FlextLdifUtilitiesPipeline:
    """Pipeline orchestration utilities for LDIF entry processing."""

    class _Filtered:
        """Sentinel class to signal that an entry was filtered out."""

        __slots__: ClassVar[tuple[str, ...]] = ()

    FILTERED = _Filtered()

    class Pipeline:
        """Pipeline for executing a sequence of transformations."""

        __slots__ = ("_fail_fast", "_steps")

        def __init__(self, *, fail_fast: bool = True) -> None:
            """Initialize pipeline."""
            super().__init__()
            self._steps: MutableSequence[
                tuple[
                    str,
                    Callable[
                        [m.Ldif.Entry],
                        r[m.Ldif.Entry | FlextLdifUtilitiesPipeline._Filtered],
                    ],
                ]
            ] = []
            self._fail_fast = fail_fast

        def add(
            self,
            transformer: p.Ldif.EntryTransformer,
            *,
            name: str | None = None,
        ) -> Self:
            """Add a transformer to the pipeline."""
            step_name = name or transformer.__class__.__name__

            def wrapped_transformer(
                entry: m.Ldif.Entry,
            ) -> r[m.Ldif.Entry | FlextLdifUtilitiesPipeline._Filtered]:
                """Wrap transformer to match pipeline filter signature."""
                transformed_result = transformer.apply(entry).map_error(
                    lambda error: error or "Transformer failed",
                )
                if transformed_result.failure:
                    return r[m.Ldif.Entry | FlextLdifUtilitiesPipeline._Filtered].fail(
                        transformed_result.error,
                    )
                return r[m.Ldif.Entry | FlextLdifUtilitiesPipeline._Filtered].ok(
                    transformed_result.value,
                )

            self._steps.append((step_name, wrapped_transformer))
            return self

        def execute(
            self,
            entries: Sequence[m.Ldif.Entry],
        ) -> r[MutableSequence[m.Ldif.Entry]]:
            """Execute pipeline on a sequence of entries."""
            results: MutableSequence[m.Ldif.Entry] = []
            for entry in entries:
                result = self.execute_one(entry).map_error(
                    lambda error: error or "Processing failed",
                )
                if result.failure:
                    if self._fail_fast:
                        return r[MutableSequence[m.Ldif.Entry]].fail(
                            result.error or "Pipeline execution failed",
                        )
                    continue
                processed = result.value
                if isinstance(processed, FlextLdifUtilitiesPipeline._Filtered):
                    continue
                results.append(processed)
            return r[MutableSequence[m.Ldif.Entry]].ok(results)

        def execute_one(
            self,
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry | FlextLdifUtilitiesPipeline._Filtered]:
            """Execute pipeline on a single entry."""
            current: m.Ldif.Entry | FlextLdifUtilitiesPipeline._Filtered = entry
            for step_name, step_func in self._steps:
                if isinstance(current, FlextLdifUtilitiesPipeline._Filtered):
                    return r[m.Ldif.Entry | FlextLdifUtilitiesPipeline._Filtered].ok(
                        FlextLdifUtilitiesPipeline.FILTERED,
                    )
                failure_prefix = f"Step '{step_name}' failed: "
                result = step_func(current).map_error(
                    lambda error, prefix=failure_prefix: (
                        f"{prefix}{error or 'Transformer failed'}"
                    ),
                )
                if result.failure:
                    return result
                current = result.value
            return r[m.Ldif.Entry | FlextLdifUtilitiesPipeline._Filtered].ok(current)

    class ValidationResult:
        """Result of entry validation."""

        _flext_enforcement_exempt: ClassVar[bool] = True

        __slots__ = ("_errors", "_is_valid", "_warnings")

        def __init__(
            self,
            *,
            valid: bool,
            errors: MutableSequence[str] | None = None,
            warnings: MutableSequence[str] | None = None,
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
        def errors(self) -> MutableSequence[str]:
            """Get list of error messages."""
            return self._errors

        @property
        def valid(self) -> bool:
            """Check if validation passed."""
            return self._is_valid

        @property
        def warnings(self) -> MutableSequence[str]:
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
            entries: Sequence[m.Ldif.Entry],
        ) -> r[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]:
            """Validate a sequence of entries."""
            results: MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult] = []
            total_errors = 0
            for entry in entries:
                validation_result = self.validate_one(entry)
                if validation_result.failure:
                    return r[
                        MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]
                    ].fail(validation_result.error)
                validation = validation_result.value
                results.append(validation)
                total_errors += len(validation.errors)
                if self._max_errors > 0 and total_errors >= self._max_errors:
                    break
                if not self._collect_all and (not validation.valid):
                    break
            return r[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]].ok(
                results,
            )

        def validate_one(
            self,
            entry: m.Ldif.Entry,
        ) -> r[FlextLdifUtilitiesPipeline.ValidationResult]:
            """Validate a single entry."""
            errors: MutableSequence[str] = []
            warnings: MutableSequence[str] = []
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
