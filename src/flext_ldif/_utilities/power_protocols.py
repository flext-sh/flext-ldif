"""Power Method Protocols - Protocol definitions for FlextLdifUtilities power methods.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines protocols for the power method infrastructure:
    - TransformerProtocol: For entry transformations in pipelines
    - FilterProtocol: For entry filtering with operators
    - ValidatorProtocol: For entry/schema validation
    - PipelineStepProtocol: For pipeline step execution

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - runtime_checkable protocols for isinstance checks
    - Protocol inheritance for composable interfaces

Usage:
    from flext_ldif._utilities.power_protocols import TransformerProtocol

    class MyTransformer(TransformerProtocol[Entry]):
        def apply(self, item: Entry) -> FlextResult[Entry]:
            # Transform the entry
            return FlextResult.ok(transformed_entry)
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, runtime_checkable

from flext_core import FlextResult

# =========================================================================
# TRANSFORMER PROTOCOL - For entry transformations
# =========================================================================


@runtime_checkable
class TransformerProtocol[T](Protocol):
    """Protocol for transformers that can be used in pipelines.

    Transformers are applied via the `|` (pipe) operator on FlextLdifResult:

        result = FlextLdifResult.ok(entries) | MyTransformer()

    The apply method receives the value and returns a FlextResult containing
    the transformed value or an error.

    Type Parameters:
        T: The type being transformed (typically Entry or list[Entry])

    Examples:
        >>> class NormalizeDn(TransformerProtocol[Entry]):
        ...     def apply(self, item: Entry) -> FlextResult[Entry]:
        ...         item.dn = item.dn.lower()
        ...         return FlextResult.ok(item)

    """

    def apply(self, item: T) -> FlextResult[T]:
        """Apply the transformation to an item.

        Args:
            item: The item to transform

        Returns:
            FlextResult containing transformed item or error

        """
        ...


@runtime_checkable
class BatchTransformerProtocol[T](Protocol):
    """Protocol for transformers that operate on sequences.

    Batch transformers process multiple items at once, which can be
    more efficient than transforming items one by one.

    Type Parameters:
        T: The type of items in the sequence (typically Entry)
    """

    def apply_batch(self, items: Sequence[T]) -> FlextResult[list[T]]:
        """Apply the transformation to a batch of items.

        Args:
            items: Sequence of items to transform

        Returns:
            FlextResult containing list of transformed items or error

        """
        ...


# =========================================================================
# FILTER PROTOCOL - For entry filtering
# =========================================================================


@runtime_checkable
class FilterProtocol[T](Protocol):
    """Protocol for filters that can be used in pipelines.

    Filters are used to select entries matching certain criteria.
    They support operator composition:

        - filter1 & filter2 - AND combination
        - filter1 | filter2 - OR combination
        - ~filter - NOT (negation)

    Type Parameters:
        T: The type being filtered (typically Entry)

    Examples:
        >>> class ByObjectClass(FilterProtocol[Entry]):
        ...     def __init__(self, *classes: str):
        ...         self.classes = classes
        ...
        ...     def matches(self, item: Entry) -> bool:
        ...         return any(c in item.objectClasses for c in self.classes)

    """

    def matches(self, item: T) -> bool:
        """Check if an item matches the filter criteria.

        Args:
            item: The item to check

        Returns:
            True if the item matches, False otherwise

        """
        ...

    def __and__(self, other: FilterProtocol[T]) -> FilterProtocol[T]:
        """AND combination: filter1 & filter2."""
        ...

    def __or__(self, other: FilterProtocol[T]) -> FilterProtocol[T]:
        """OR combination: filter1 | filter2."""
        ...

    def __invert__(self) -> FilterProtocol[T]:
        """NOT negation: ~filter."""
        ...


# =========================================================================
# VALIDATOR PROTOCOL - For validation rules
# =========================================================================


@runtime_checkable
class ValidationReportProtocol(Protocol):
    """Protocol for validation reports returned by validators."""

    @property
    def is_valid(self) -> bool:
        """Check if validation passed."""
        ...

    @property
    def errors(self) -> list[str]:
        """Get list of error messages."""
        ...

    @property
    def warnings(self) -> list[str]:
        """Get list of warning messages."""
        ...


@runtime_checkable
class ValidatorProtocol[T](Protocol):
    """Protocol for validators that check entries or schemas.

    Validators are used in the validate() power method to check
    entries against rules (RFC compliance, schema, custom).

    Type Parameters:
        T: The type being validated (Entry, SchemaAttribute, etc.)

    Examples:
        >>> class RfcCompliance(ValidatorProtocol[Entry]):
        ...     def validate(self, item: Entry) -> FlextResult[ValidationReport]:
        ...         errors = []
        ...         if not item.dn:
        ...             errors.append("Entry must have a DN")
        ...         return FlextResult.ok(ValidationReport(errors=errors))

    """

    def validate(self, item: T) -> FlextResult[ValidationReportProtocol]:
        """Validate an item.

        Args:
            item: The item to validate

        Returns:
            FlextResult containing ValidationReport or error

        """
        ...


@runtime_checkable
class ValidationRuleProtocol[T](Protocol):
    """Protocol for individual validation rules.

    Rules are composable units that check specific aspects of an item.
    Multiple rules can be combined into a validator.

    Type Parameters:
        T: The type being validated
    """

    @property
    def name(self) -> str:
        """Get the rule name for error messages."""
        ...

    def check(self, item: T) -> tuple[bool, str | None]:
        """Check an item against this rule.

        Args:
            item: The item to check

        Returns:
            Tuple of (passed, error_message). error_message is None if passed.

        """
        ...


# =========================================================================
# PIPELINE STEP PROTOCOL - For pipeline orchestration
# =========================================================================


@runtime_checkable
class PipelineStepProtocol[TIn, TOut](Protocol):
    """Protocol for pipeline steps that transform data.

    Pipeline steps are the building blocks of the process() and
    transform() power methods. Each step receives input and produces
    output, which becomes the input for the next step.

    Type Parameters:
        TIn: Input type for this step
        TOut: Output type for this step
    """

    @property
    def name(self) -> str:
        """Get step name for logging/debugging."""
        ...

    def execute(self, input_data: TIn) -> FlextResult[TOut]:
        """Execute this pipeline step.

        Args:
            input_data: Input data from previous step

        Returns:
            FlextResult containing output data or error

        """
        ...


# =========================================================================
# FLUENT BUILDER PROTOCOL - For builder pattern
# =========================================================================


@runtime_checkable
class FluentBuilderProtocol[TConfig](Protocol):
    """Protocol for fluent builders that construct configuration objects.

    Builders provide a fluent interface for constructing complex
    configuration objects with method chaining.

    Type Parameters:
        TConfig: The configuration type being built
    """

    def build(self) -> TConfig:
        """Build the final configuration object.

        Returns:
            The constructed configuration object

        """
        ...


# =========================================================================
# FLUENT OPS PROTOCOL - For fluent operation chains
# =========================================================================


@runtime_checkable
class FluentOpsProtocol[T](Protocol):
    """Protocol for fluent operation chains (DnOps, EntryOps).

    Fluent ops provide method chaining for common operations,
    with a terminal build() method that returns the result.

    Type Parameters:
        T: The type being operated on (str for DN, Entry for entries)
    """

    def build(self) -> FlextResult[T]:
        """Build/finalize and return the result.

        Returns:
            FlextResult containing the final value or error

        """
        ...


# =========================================================================
# LOADABLE PROTOCOL - For data sources
# =========================================================================


@runtime_checkable
class LoadableProtocol[T](Protocol):
    """Protocol for loadable data sources.

    Represents anything that can be loaded as LDIF data:
    - File paths (str, Path)
    - Raw LDIF content (bytes)
    - Pre-parsed entries (Sequence[Entry])
    """

    def load(self) -> FlextResult[T]:
        """Load and return the data.

        Returns:
            FlextResult containing loaded data or error

        """
        ...


# =========================================================================
# WRITABLE PROTOCOL - For output targets
# =========================================================================


@runtime_checkable
class WritableProtocol(Protocol):
    """Protocol for writable output targets.

    Represents anything that can receive LDIF output:
    - File paths
    - File-like objects
    - String builders
    """

    def write(self, content: str) -> FlextResult[str]:
        """Write content to the target.

        Args:
            content: The content to write

        Returns:
            FlextResult containing written content or error

        """
        ...


# =========================================================================
# TYPE ALIASES - Convenience types for common patterns
# =========================================================================

# Transformer that takes and returns the same type
type SimpleTransformer[T] = Callable[[T], T]

# Transformer that may fail
type FailableTransformer[T] = Callable[[T], FlextResult[T]]

# Filter predicate
type FilterPredicate[T] = Callable[[T], bool]

# Validation result tuple
type ValidationResult = tuple[bool, list[str]]


__all__ = [
    "BatchTransformerProtocol",
    "FailableTransformer",
    "FilterPredicate",
    "FilterProtocol",
    "FluentBuilderProtocol",
    "FluentOpsProtocol",
    "LoadableProtocol",
    "PipelineStepProtocol",
    # Type aliases
    "SimpleTransformer",
    # Protocols
    "TransformerProtocol",
    "ValidationReportProtocol",
    "ValidationResult",
    "ValidationRuleProtocol",
    "ValidatorProtocol",
    "WritableProtocol",
]
