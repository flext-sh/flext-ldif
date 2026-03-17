"""Power Method Pipeline - Pipeline orchestration for entry processing."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Self, override

from flext_core import r

from flext_ldif import m
from flext_ldif._utilities.filters import FlextLdifUtilitiesFilters
from flext_ldif._utilities.transformers import FlextLdifUtilitiesTransformer


class _Filtered:
    """Sentinel class to signal that an entry was filtered out."""

    __slots__ = ()


FILTERED = _Filtered()


class PipelineStep[TIn, TOut]:
    """A single step in a pipeline."""

    __slots__ = ("_func", "_name")

    def __init__(self, name: str, func: Callable[[TIn], r[TOut]]) -> None:
        """Initialize pipeline step."""
        super().__init__()
        self._name = name
        self._func = func

    @property
    def name(self) -> str:
        """Get step name."""
        return self._name

    def execute(self, input_data: TIn) -> r[TOut]:
        """Execute this step."""
        return self._func(input_data)


class Pipeline:
    """Pipeline for executing a sequence of transformations."""

    __slots__ = ("_fail_fast", "_steps")

    def __init__(self, *, fail_fast: bool = True) -> None:
        """Initialize pipeline."""
        super().__init__()
        self._steps: list[
            tuple[str, Callable[[m.Ldif.Entry], r[m.Ldif.Entry | _Filtered]]]
        ] = []
        self._fail_fast = fail_fast

    def add(
        self,
        transformer: FlextLdifUtilitiesTransformer[m.Ldif.Entry],
        *,
        name: str | None = None,
    ) -> Self:
        """Add a transformer to the pipeline."""
        step_name = name or transformer.__class__.__name__

        def wrapped_transformer(entry: m.Ldif.Entry) -> r[m.Ldif.Entry | _Filtered]:
            """Wrap transformer to match pipeline filter signature."""
            return transformer.apply(entry).fold(
                on_failure=lambda e: r[m.Ldif.Entry | _Filtered].fail(e),
                on_success=lambda v: r[m.Ldif.Entry | _Filtered].ok(v),
            )

        self._steps.append((step_name, wrapped_transformer))
        return self

    def custom(
        self,
        func: Callable[[m.Ldif.Entry], m.Ldif.Entry | r[m.Ldif.Entry] | None],
        *,
        name: str = "custom",
    ) -> Self:
        """Add a custom function to the pipeline."""

        def wrapped_func(entry: m.Ldif.Entry) -> r[m.Ldif.Entry | _Filtered]:
            """Wrap function to match pipeline filter signature."""
            func_result = func(entry)
            if func_result is None:
                return r[m.Ldif.Entry | _Filtered].ok(FILTERED)
            if isinstance(func_result, r):
                if func_result.is_success:
                    entry_value = func_result.value
                    return r[m.Ldif.Entry | _Filtered].ok(entry_value)
                return r[m.Ldif.Entry | _Filtered].fail(func_result.error)
            return r[m.Ldif.Entry | _Filtered].ok(func_result)

        self._steps.append((name, wrapped_func))
        return self

    def execute(self, entries: Sequence[m.Ldif.Entry]) -> r[list[m.Ldif.Entry]]:
        """Execute pipeline on a sequence of entries."""

        def process_entry(entry: m.Ldif.Entry) -> r[m.Ldif.Entry] | None:
            """Process single entry through pipeline."""
            result = self.execute_one(entry)
            if result.is_failure:
                return r[m.Ldif.Entry].fail(result.error or "Processing failed")
            processed = result.value
            if isinstance(processed, _Filtered):
                return None
            return r[m.Ldif.Entry].ok(processed)

        results: list[m.Ldif.Entry] = []
        for entry in entries:
            process_result = process_entry(entry)
            if process_result is None:
                continue
            if process_result.is_failure:
                if self._fail_fast:
                    return r[list[m.Ldif.Entry]].fail(
                        process_result.error or "Pipeline execution failed"
                    )
                continue
            results.append(process_result.value)
        return r[list[m.Ldif.Entry]].ok(results)

    def execute_one(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry | _Filtered]:
        """Execute pipeline on a single entry."""
        current: m.Ldif.Entry | _Filtered = entry
        for step_name, step_func in self._steps:
            if isinstance(current, _Filtered):
                return r[m.Ldif.Entry | _Filtered].ok(FILTERED)
            result = step_func(current)
            if result.is_failure:
                return r[m.Ldif.Entry | _Filtered].fail(
                    f"Step '{step_name}' failed: {result.error}"
                )
            unwrapped = result.value
            current = unwrapped
        return r[m.Ldif.Entry | _Filtered].ok(current)

    def filter(
        self,
        entry_filter: FlextLdifUtilitiesFilters[m.Ldif.Entry],
        *,
        name: str | None = None,
    ) -> Self:
        """Add a filter to the pipeline."""
        step_name = name or entry_filter.__class__.__name__

        def filter_func(entry: m.Ldif.Entry) -> r[m.Ldif.Entry | _Filtered]:
            if entry_filter.matches(entry):
                return r[m.Ldif.Entry | _Filtered].ok(entry)
            return r[m.Ldif.Entry | _Filtered].ok(FILTERED)

        self._steps.append((step_name, filter_func))
        return self


class ValidationPipeline:
    """Pipeline for validating entries."""

    __slots__ = ("_collect_all", "_max_errors", "_strict")

    def __init__(
        self, *, strict: bool = True, collect_all: bool = True, max_errors: int = 0
    ) -> None:
        """Initialize validation pipeline."""
        super().__init__()
        self._strict = strict
        self._collect_all = collect_all
        self._max_errors = max_errors

    def validate(self, entries: Sequence[m.Ldif.Entry]) -> r[list[ValidationResult]]:
        """Validate a sequence of entries."""
        results: list[ValidationResult] = []
        total_errors = 0
        for entry in entries:
            validation_result = self.validate_one(entry)
            if validation_result.is_failure:
                return r[list[ValidationResult]].fail(validation_result.error)
            validation = validation_result.value
            results.append(validation)
            total_errors += len(validation.errors)
            if self._max_errors > 0 and total_errors >= self._max_errors:
                break
            if not self._collect_all and (not validation.is_valid):
                break
        return r[list[ValidationResult]].ok(results)

    def validate_one(self, entry: m.Ldif.Entry) -> r[ValidationResult]:
        """Validate a single entry."""
        errors: list[str] = []
        warnings: list[str] = []
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
            attrs: dict[str, list[str]] = (
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
        return r[str].ok(
            ValidationResult(
                is_valid=len(errors) == 0, errors=errors, warnings=warnings
            )
        )


class ValidationResult:
    """Result of entry validation."""

    __slots__ = ("_errors", "_is_valid", "_warnings")

    def __init__(
        self,
        *,
        is_valid: bool,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        """Initialize validation result."""
        super().__init__()
        self._is_valid = is_valid
        self._errors = errors or []
        self._warnings = warnings or []

    @override
    def __repr__(self) -> str:
        """Return string representation."""
        status = "valid" if self._is_valid else "invalid"
        return f"ValidationResult({status}, errors={len(self._errors)}, warnings={len(self._warnings)})"

    @property
    def errors(self) -> list[str]:
        """Get list of error messages."""
        return self._errors

    @property
    def is_valid(self) -> bool:
        """Check if validation passed."""
        return self._is_valid

    @property
    def warnings(self) -> list[str]:
        """Get list of warning messages."""
        return self._warnings


__all__ = ["Pipeline", "PipelineStep", "ValidationPipeline", "ValidationResult"]
