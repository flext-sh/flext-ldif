"""Power Method Pipeline - Pipeline orchestration for entry processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides pipeline classes for orchestrating entry transformations:
    - Pipeline: Executes a sequence of transformers
    - ProcessingPipeline: Full processing pipeline with config
    - ValidationPipeline: Entry validation pipeline

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - Generic classes with type bounds
    - Self type for method chaining

Usage:
    from flext_ldif._utilities.pipeline import Pipeline

    # Create pipeline
    pipeline = (
        Pipeline()
        .add(Normalize.dn())
        .add(Transform.replace_base("dc=old", "dc=new"))
        .add(Filter.by_objectclass("person"))
    )

    # Execute
    result = pipeline.execute(entries)
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Self

from flext_core import r

from flext_ldif._utilities.configs import TransformConfig
from flext_ldif._utilities.filters import EntryFilter
from flext_ldif._utilities.transformers import EntryTransformer, Normalize
from flext_ldif.constants import c
from flext_ldif.models import m


# Sentinel for filtered out entries (since r.ok(None) is not allowed)
class _Filtered:
    """Sentinel class to signal that an entry was filtered out."""

    __slots__ = ()


FILTERED = _Filtered()


# =========================================================================
# PIPELINE STEP PROTOCOL
# =========================================================================


class PipelineStep[TIn, TOut]:
    """A single step in a pipeline.

    Wraps a transformer or filter with metadata for logging and debugging.
    """

    __slots__ = ("_func", "_name")

    def __init__(
        self,
        name: str,
        func: Callable[[TIn], r[TOut]],
    ) -> None:
        """Initialize pipeline step.

        Args:
            name: Step name for logging
            func: Function to execute

        """
        self._name = name
        self._func = func

    @property
    def name(self) -> str:
        """Get step name."""
        return self._name

    def execute(self, input_data: TIn) -> r[TOut]:
        """Execute this step.

        Args:
            input_data: Input data

        Returns:
            r containing output or error

        """
        return self._func(input_data)


# =========================================================================
# TRANSFORMATION PIPELINE
# =========================================================================


class Pipeline:
    """Pipeline for executing a sequence of transformations.

    Supports adding transformers, filters, and custom functions.
    All steps are executed in sequence, with early exit on failure.

    Examples:
        >>> pipeline = (
        ...     Pipeline()
        ...     .add(Normalize.dn())
        ...     .add(Transform.replace_base("dc=old", "dc=new"))
        ...     .filter(Filter.by_objectclass("person"))
        ... )
        >>> result = pipeline.execute(entries)

    """

    __slots__ = ("_fail_fast", "_steps")

    def __init__(self, *, fail_fast: bool = True) -> None:
        """Initialize pipeline.

        Args:
            fail_fast: Stop on first error (default True)

        """
        self._steps: list[
            tuple[
                str,
                Callable[
                    [m.Ldif.Entry],
                    r[m.Ldif.Entry | _Filtered],
                ],
            ]
        ] = []
        self._fail_fast = fail_fast

    def add(
        self,
        transformer: EntryTransformer[m.Ldif.Entry],
        *,
        name: str | None = None,
    ) -> Self:
        """Add a transformer to the pipeline.

        Args:
            transformer: Transformer to add
            name: Optional step name for logging

        Returns:
            Self for chaining

        """
        # Business Rule: Add transformer step to pipeline
        # Transformers return r[Entry], but pipeline filters can return None
        # Wrap transformer.apply to match pipeline signature r[Entry | None]
        step_name = name or transformer.__class__.__name__

        def wrapped_transformer(
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry | _Filtered]:
            """Wrap transformer to match pipeline filter signature.

            Business Rule:
            - Transformers return r[Entry] (never None)
            - Pipeline filters can return Entry | FILTERED (FILTERED = filter out)
            - Wrap transformer result to match pipeline signature
            """
            transformer_result = transformer.apply(entry)
            if transformer_result.is_failure:
                # Convert r[Entry] failure to r[Entry | FILTERED] failure
                return r[m.Ldif.Entry | _Filtered].fail(transformer_result.error)
            # Transformers always return Entry (never FILTERED)
            entry_value = transformer_result.value
            return r[m.Ldif.Entry | _Filtered].ok(entry_value)

        self._steps.append((step_name, wrapped_transformer))
        return self

    def filter(
        self,
        entry_filter: EntryFilter[m.Ldif.Entry],
        *,
        name: str | None = None,
    ) -> Self:
        """Add a filter to the pipeline.

        Entries not matching the filter are removed (return None).

        Args:
            entry_filter: Filter to add
            name: Optional step name for logging

        Returns:
            Self for chaining

        """
        step_name = name or entry_filter.__class__.__name__

        def filter_func(
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry | _Filtered]:
            if entry_filter.matches(entry):
                return r[m.Ldif.Entry | _Filtered].ok(entry)
            # Use FILTERED sentinel instead of None (r.ok(None) is not allowed)
            return r[m.Ldif.Entry | _Filtered].ok(FILTERED)

        self._steps.append((step_name, filter_func))
        return self

    def custom(
        self,
        func: Callable[
            [m.Ldif.Entry],
            m.Ldif.Entry | r[m.Ldif.Entry] | None,
        ],
        *,
        name: str = "custom",
    ) -> Self:
        """Add a custom function to the pipeline.

        Args:
            func: Custom function (returns Entry, r[Entry], or None to filter)
            name: Step name for logging

        Returns:
            Self for chaining

        """

        def wrapped_func(
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry | _Filtered]:
            """Wrap function to match pipeline filter signature.

            Business Rule:
            - Pipeline filters can return Entry (keep), None (filter out), or r
            - Wraps all return types to consistent r[Entry | FILTERED] format
            - None values are converted to FILTERED sentinel (r.ok(None) is not allowed)
            """
            func_result = func(entry)
            if func_result is None:
                # Use FILTERED sentinel instead of None (r.ok(None) is not allowed)
                return r[m.Ldif.Entry | _Filtered].ok(FILTERED)
            if isinstance(func_result, r):
                # If result is Entry, wrap in Entry | FILTERED union
                if func_result.is_success:
                    entry_value = func_result.value
                    # Type narrowing: entry_value is Entry when success
                    return r[m.Ldif.Entry | _Filtered].ok(entry_value)
                # Convert r[Entry] failure to r[Entry | FILTERED] failure
                return r[m.Ldif.Entry | _Filtered].fail(func_result.error)
            # func_result is Entry (not None, not r)
            # Type narrowing: func_result is Entry
            return r[m.Ldif.Entry | _Filtered].ok(func_result)

        self._steps.append((name, wrapped_func))
        return self

    def execute_one(
        self,
        entry: m.Ldif.Entry,
    ) -> r[m.Ldif.Entry | _Filtered]:
        """Execute pipeline on a single entry.

        Args:
            entry: Entry to process

        Returns:
            r containing processed entry, FILTERED if filtered, or error

        """
        current: m.Ldif.Entry | _Filtered = entry

        for step_name, step_func in self._steps:
            if isinstance(current, _Filtered):
                # Entry was filtered out in previous step
                return r[m.Ldif.Entry | _Filtered].ok(FILTERED)

            # Type narrowing: current is Entry when not _Filtered
            result = step_func(current)
            if result.is_failure:
                return r[m.Ldif.Entry | _Filtered].fail(
                    f"Step '{step_name}' failed: {result.error}"
                )

            unwrapped = result.value
            # Business Rule: FILTERED sentinel indicates entry was filtered out
            # Type narrowing: unwrapped is Entry | FILTERED
            current = unwrapped

        return r[m.Ldif.Entry | _Filtered].ok(current)

    def execute(
        self,
        entries: Sequence[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Execute pipeline on a sequence of entries.

        Args:
            entries: Entries to process

        Returns:
            r containing list of processed entries or error

        """

        def process_entry(
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry] | None:
            """Process single entry through pipeline.

            Returns:
                r[Entry] on success, None if filtered (not an error)

            """
            result = self.execute_one(entry)
            if result.is_failure:
                # For fail_fast, batch will stop on first error
                # For collect mode, fail result signals skip
                return r[m.Ldif.Entry].fail(result.error or "Processing failed")
            processed = result.value
            # Type narrowing: processed is Entry | _Filtered
            if isinstance(processed, _Filtered):
                # Filtered entries return None (not an error, just skipped)
                return None
            # Type narrowing: processed is Entry when not _Filtered
            return r[m.Ldif.Entry].ok(processed)

        # Process entries: filtered entries return None (not an error)
        results: list[m.Ldif.Entry] = []
        for entry in entries:
            process_result = process_entry(entry)
            if process_result is None:
                # Filtered entry - skip (not an error)
                continue
            if process_result.is_failure:
                # Real error - handle based on fail_fast setting
                if self._fail_fast:
                    return r[list[m.Ldif.Entry]].fail(
                        process_result.error or "Pipeline execution failed",
                    )
                # Collect mode: skip error and continue
                continue
            # Success: add to results
            results.append(process_result.value)
        return r[list[m.Ldif.Entry]].ok(results)

    @property
    def step_count(self) -> int:
        """Get number of steps in pipeline."""
        return len(self._steps)

    @property
    def step_names(self) -> list[str]:
        """Get names of all steps."""
        return [name for name, _ in self._steps]


# =========================================================================
# PROCESSING PIPELINE - Full processing with config
# =========================================================================


class ProcessingPipeline:
    """Full processing pipeline with configuration.

    Combines loading, transformation, validation, and output based on
    ProcessConfig configuration.

    Examples:
        >>> config = TransformConfig(
        ...     source_server="oid",
        ...     target_server="oud",
        ...     normalize_dns=True,
        ... )
        >>> pipeline = ProcessingPipeline(config)
        >>> result = pipeline.execute(entries)

    """

    __slots__ = ("_config", "_pipeline")

    def __init__(self, config: TransformConfig | None = None) -> None:
        """Initialize processing pipeline.

        Args:
            config: Processing configuration (uses defaults if None)

        """
        self._config = config or TransformConfig()
        self._pipeline = self._build_pipeline()

    def _build_pipeline(self) -> Pipeline:
        """Build the internal pipeline based on configuration.

        Returns:
            Configured Pipeline instance

        """
        pipeline = Pipeline()

        # Add DN normalization if enabled
        if self._config.normalize_dns and self._config.process_config is not None:
            # Convert Literal to StrEnum for type compatibility
            dn_config = (
                self._config.process_config.dn_config or m.Ldif.DnNormalizationConfig()
            )
            case_fold_value = dn_config.case_fold or "none"
            space_handling_value = dn_config.space_handling or "preserve"

            case_enum = c.Ldif.CaseFoldOption(case_fold_value)
            spaces_enum = m.Ldif.SpaceHandlingOption(space_handling_value)

            pipeline.add(
                Normalize.dn(
                    case=case_enum,
                    spaces=spaces_enum,
                    validate=dn_config.validate_before,
                ),
                name="normalize_dn",
            )

        # Add attribute normalization if enabled
        if self._config.normalize_attrs and self._config.process_config is not None:
            attr_config = (
                self._config.process_config.attr_config
                or m.Ldif.AttrNormalizationConfig()
            )
            pipeline.add(
                Normalize.attrs(
                    case_fold_names=attr_config.case_fold_names,
                    trim_values=attr_config.trim_values,
                    remove_empty=attr_config.remove_empty,
                ),
                name="normalize_attrs",
            )

        return pipeline

    def execute(
        self,
        entries: Sequence[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Execute the processing pipeline.

        Args:
            entries: Entries to process (must be Entry instances)

        Returns:
            r containing processed entries or error

        """
        # No cast needed - entries parameter is properly typed as Sequence[m.Ldif.Entry]
        return self._pipeline.execute(entries)

    @property
    def config(self) -> TransformConfig:
        """Get the processing configuration."""
        return self._config


# =========================================================================
# VALIDATION PIPELINE
# =========================================================================


class ValidationPipeline:
    """Pipeline for validating entries.

    Validates entries against configured rules and returns a validation
    report with errors and warnings.

    Examples:
        >>> pipeline = ValidationPipeline(strict=True)
        >>> report = pipeline.validate(entries)

    """

    __slots__ = ("_collect_all", "_max_errors", "_strict")

    def __init__(
        self,
        *,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> None:
        """Initialize validation pipeline.

        Args:
            strict: Use strict RFC validation
            collect_all: Collect all errors vs fail on first
            max_errors: Maximum errors to collect (0 = unlimited)

        """
        self._strict = strict
        self._collect_all = collect_all
        self._max_errors = max_errors

    def validate_one(
        self,
        entry: m.Ldif.Entry,
    ) -> r[ValidationResult]:
        """Validate a single entry.

        Args:
            entry: Entry to validate

        Returns:
            r containing ValidationResult

        """
        errors: list[str] = []
        warnings: list[str] = []

        # Check DN exists
        if entry.dn is None:
            errors.append("Entry has no DN (RFC 2849 violation)")
        else:
            # Validate DN format - basic RFC 2253 compliance check
            # Each RDN component must have at least one '=' separator
            dn_str = entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)

            # Split by comma to get RDN components
            components = dn_str.split(",")
            for comp in components:
                comp_stripped = comp.strip()
                if "=" not in comp_stripped:
                    errors.append(f"Invalid RDN (missing '='): {comp_stripped}")
                    continue
                # Basic validation: RDN has attribute type and value
                _, _, value = comp_stripped.partition("=")
                if not value.strip():
                    errors.append(f"Invalid RDN (missing value): {comp_stripped}")

        # Check attributes exist
        if entry.attributes is None:
            errors.append("Entry has no attributes (RFC 2849 violation)")
        else:
            attrs = (
                entry.attributes.attributes
                if hasattr(entry.attributes, "attributes")
                else {}
            )

            # Check for objectClass
            has_objectclass = any(k.lower() == "objectclass" for k in attrs)
            if not has_objectclass:
                if self._strict:
                    errors.append("Entry has no objectClass attribute")
                else:
                    warnings.append("Entry has no objectClass attribute")

        return r[str].ok(
            ValidationResult(
                is_valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
            ),
        )

    def validate(
        self,
        entries: Sequence[m.Ldif.Entry],
    ) -> r[list[ValidationResult]]:
        """Validate a sequence of entries.

        Args:
            entries: Entries to validate

        Returns:
            r containing list of ValidationResults

        """
        results: list[ValidationResult] = []
        total_errors = 0

        # Business Rule: Validate multiple entries and collect all validation results
        # Returns list of ValidationResult objects, one per entry
        # Stops early if max_errors threshold is reached (fail-fast pattern)
        for entry in entries:
            validation_result = self.validate_one(entry)
            if validation_result.is_failure:
                # Convert r[ValidationResult] failure to r[list[ValidationResult]] failure
                return r[list[ValidationResult]].fail(validation_result.error)

            validation = validation_result.value
            results.append(validation)

            total_errors += len(validation.errors)
            if self._max_errors > 0 and total_errors >= self._max_errors:
                break

            if not self._collect_all and not validation.is_valid:
                break

        return r[list[ValidationResult]].ok(results)


# =========================================================================
# VALIDATION RESULT
# =========================================================================


class ValidationResult:
    """Result of entry validation.

    Contains validation status, errors, and warnings.
    """

    __slots__ = ("_errors", "_is_valid", "_warnings")

    def __init__(
        self,
        *,
        is_valid: bool,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        """Initialize validation result.

        Args:
            is_valid: Whether validation passed
            errors: List of error messages
            warnings: List of warning messages

        """
        self._is_valid = is_valid
        self._errors = errors or []
        self._warnings = warnings or []

    @property
    def is_valid(self) -> bool:
        """Check if validation passed."""
        return self._is_valid

    @property
    def errors(self) -> list[str]:
        """Get list of error messages."""
        return self._errors

    @property
    def warnings(self) -> list[str]:
        """Get list of warning messages."""
        return self._warnings

    def __repr__(self) -> str:
        """Return string representation."""
        status = "valid" if self._is_valid else "invalid"
        return f"ValidationResult({status}, errors={len(self._errors)}, warnings={len(self._warnings)})"


__all__ = [
    "Pipeline",
    "PipelineStep",
    "ProcessingPipeline",
    "ValidationPipeline",
    "ValidationResult",
]
