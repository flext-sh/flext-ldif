"""FlextLdifResult - Extended FlextResult with LDIF-specific DSL operators.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides FlextLdifResult[T] class that extends FlextResult[T] with
LDIF-specific operators for fluent pipeline operations:

    - `|` (pipe) - Chain transformations
    - `>>` (rshift) - Write to output
    - `@` (matmul) - Attach metadata
    - `&` (and) - Combine results

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - Generic class with type bounds
    - Self type for method chaining

Usage:
    from flext_ldif._utilities.result import FlextLdifResult

    # Pipe operator for transformations
    result = FlextLdifResult.ok(entries) | Normalize.dn() | Filter.by_objectclass("person")

    # Write operator for output
    result >> Path("output.ldif")

    # Metadata attachment
    result = result @ {"source": "oid", "version": "1.0"}

    # Combine results
    combined = users_result & groups_result
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, Self, overload

from flext_core import FlextResult
from flext_core.runtime import FlextRuntime

from flext_ldif.protocols import p

r = FlextResult

# Type variable for the result value type
type ResultValue[T] = T


class FlextLdifResult[T]:
    """Extended FlextResult with LDIF-specific DSL operators.

    Provides a fluent interface for LDIF operations through operator overloading:

    Operators:
        - `|` (pipe): Chain transformations - result | transform
        - `>>` (rshift): Write to output - result >> path
        - `@` (matmul): Attach metadata - result @ metadata
        - `&` (and): Combine results - result1 & result2
        - `~` (invert): Negate filter - ~filter

    This class wraps FlextResult[T] and delegates all core operations to it,
    adding operator support for LDIF-specific DSL patterns.

    Type Parameters:
        T: The type of the success value

    Examples:
        >>> # Create result
        >>> result = FlextLdifResult.ok([entry1, entry2])

        >>> # Pipe transformations
        >>> result = (
        ...     result | Normalize.dn(case="lower") | Filter.by_objectclass("person")
        ... )

        >>> # Write to file
        >>> result >> Path("output.ldif")

        >>> # Attach metadata
        >>> result = result @ {"source": "oid"}

        >>> # Combine multiple results
        >>> combined = users_result & groups_result

    """

    __slots__ = ("_inner",)

    def __hash__(self) -> int:
        """Hash implementation for FlextLdifResult.

        Returns hash of inner FlextResult for use in sets and dict keys.
        """
        return hash(self._inner)

    def __init__(self, inner: FlextResult[T] | FlextRuntime.RuntimeResult[T]) -> None:
        """Initialize FlextLdifResult wrapping a FlextResult or RuntimeResult.

        Args:
            inner: The underlying FlextResult or RuntimeResult to wrap

        """
        # Convert RuntimeResult to FlextResult if needed
        inner_result: FlextResult[T]
        if isinstance(inner, FlextRuntime.RuntimeResult):
            # RuntimeResult is compatible with FlextResult interface
            # Convert by creating new FlextResult with same value/error
            if inner.is_success:
                inner_result = r[T].ok(inner.value)
            else:
                error_msg = inner.error if hasattr(inner, "error") else str(inner)
                inner_result = r[T].fail(error_msg)
        else:
            inner_result = inner
        self._inner = inner_result

    # =========================================================================
    # FACTORY METHODS - Create new results
    # =========================================================================

    @classmethod
    def ok(cls, value: T) -> FlextLdifResult[T]:
        """Create a successful result with the given value.

        Args:
            value: The success value

        Returns:
            FlextLdifResult containing the success value

        """
        return cls(r[T].ok(value))

    @classmethod
    def fail(cls, error: str | Exception) -> FlextLdifResult[T]:
        """Create a failed result with the given error.

        Args:
            error: The error message or exception

        Returns:
            FlextLdifResult containing the error

        """
        error_msg = str(error) if isinstance(error, Exception) else error
        return cls(r.fail(error_msg))

    @classmethod
    def from_result(cls, result: FlextResult[T]) -> FlextLdifResult[T]:
        """Wrap an existing FlextResult in FlextLdifResult.

        Args:
            result: The FlextResult to wrap

        Returns:
            FlextLdifResult wrapping the given result

        """
        return cls(result)

    # =========================================================================
    # PROPERTIES - Delegate to inner FlextResult
    # =========================================================================

    @property
    def is_success(self) -> bool:
        """Check if the result is a success."""
        return self._inner.is_success

    @property
    def is_failure(self) -> bool:
        """Check if the result is a failure."""
        return self._inner.is_failure

    @property
    def value(self) -> T:
        """Get the success value. Raises if result is a failure."""
        return self._inner.value

    @property
    def error(self) -> str:
        """Get the error message. Raises if result is a success.

        Business Rule:
        - Returns error message string from inner FlextResult
        - Error is always non-empty string when result is failure
        - Raises ValueError if result is success (per FlextResult contract)

        Returns:
            Error message string (never None)

        """
        error_msg = self._inner.error
        # Ensure we return str, not str | None
        return error_msg if error_msg is not None else "Unknown error"

    # =========================================================================
    # CORE METHODS - Delegate to inner FlextResult
    # =========================================================================

    def unwrap(self) -> T:
        """Unwrap the success value or raise an exception.

        Returns:
            The success value

        Raises:
            ValueError: If the result is a failure

        """
        return self._inner.value

    def unwrap_or(self, default: T) -> T:
        """Unwrap the success value or return a default.

        Args:
            default: The default value to return on failure

        Returns:
            The success value or the default

        """
        return self._inner.unwrap_or(default)

    def unwrap_or_else(self, func: Callable[[], T]) -> T:
        """Unwrap the success value or compute from error.

        Business Rule:
        - If result is success, return the value
        - If result is failure, call func() to compute default value
        - Uses FlextResult.unwrap_or pattern for error handling

        Args:
            func: Function to compute default value (no arguments)

        Returns:
            The success value or computed default

        """
        if self.is_failure:
            return func()
        return self._inner.value

    def map[U](self, func: Callable[[T], U]) -> FlextLdifResult[U]:
        """Map a function over the success value.

        Args:
            func: Function to apply to the success value

        Returns:
            New FlextLdifResult with mapped value or propagated error

        """
        # map may return RuntimeResult, convert to FlextResult
        mapped_result = self._inner.map(func)
        return FlextLdifResult(mapped_result)

    def flat_map[U](self, func: Callable[[T], FlextResult[U]]) -> FlextLdifResult[U]:
        """Flat map a function that returns FlextResult.

        Args:
            func: Function returning FlextResult to apply

        Returns:
            New FlextLdifResult with flat-mapped value or propagated error

        """
        # flat_map may return RuntimeResult, convert to FlextResult
        mapped_result = self._inner.flat_map(func)
        return FlextLdifResult(mapped_result)

    def map_error(self, func: Callable[[str], str]) -> FlextLdifResult[T]:
        """Map a function over the error message.

        Args:
            func: Function to transform error message

        Returns:
            New FlextLdifResult with mapped error or unchanged success

        """
        # map_error may return RuntimeResult, convert to FlextResult
        mapped_result = self._inner.map_error(func)
        return FlextLdifResult(mapped_result)

    def to_inner(self) -> FlextResult[T]:
        """Get the underlying FlextResult.

        Returns:
            The wrapped FlextResult

        """
        return self._inner

    # =========================================================================
    # DSL OPERATORS - LDIF-specific pipeline operations
    # =========================================================================

    @overload
    def __or__(
        self,
        transformer: p.Ldif.TransformerProtocol[T],
    ) -> FlextLdifResult[T]: ...

    @overload
    def __or__(self, transformer: Callable[[T], T]) -> FlextLdifResult[T]: ...

    @overload
    def __or__(
        self,
        transformer: Callable[[T], FlextResult[T]],
    ) -> FlextLdifResult[T]: ...

    def __or__(
        self,
        transformer: (
            p.Ldif.TransformerProtocol[T]
            | Callable[[T], T]
            | Callable[[T], FlextResult[T]]
        ),
    ) -> FlextLdifResult[T]:
        """Pipe operator: result | transformer.

        Applies a transformer to the success value. If this result is a failure,
        the error is propagated without calling the transformer.

        The transformer can be:
        - A TransformerProtocol with apply() method
        - A callable that transforms T -> T
        - A callable that transforms T -> FlextResult[T]

        Args:
            transformer: The transformation to apply

        Returns:
            New FlextLdifResult with transformed value or propagated error

        Examples:
            >>> result = FlextLdifResult.ok(entries)
            >>> result = result | Normalize.dn(case="lower")
            >>> result = result | Filter.by_objectclass("person")

        """
        if self.is_failure:
            return FlextLdifResult.fail(self.error)

        # Business Rule: Apply transformer to success value
        # Transformer can be p.Ldif.TransformerProtocol (has apply method) or callable
        # p.Ldif.TransformerProtocol.apply() returns FlextResult[T] or T
        # Callable transforms T -> T or T -> FlextResult[T]
        # Check if it has apply method (TransformerProtocol)
        # Business Rule: Access apply method via getattr for type safety
        # Implication: Type checker cannot infer that transformer.apply exists even after
        # hasattr check, so we use getattr to satisfy pyright strict mode.
        if hasattr(transformer, "apply"):
            apply_method = getattr(transformer, "apply", None)
            if apply_method is not None and callable(apply_method):
                transform_result = apply_method(self.value)
                if isinstance(transform_result, FlextResult):
                    return FlextLdifResult.from_result(transform_result)
                return FlextLdifResult.ok(transform_result)

        # It's a callable (function or lambda)
        if callable(transformer):
            result = transformer(self.value)
            if isinstance(result, FlextResult):
                return FlextLdifResult.from_result(result)
            return FlextLdifResult.ok(result)

        # Invalid transformer type
        return FlextLdifResult.fail(f"Invalid transformer type: {type(transformer)}")

    def __rshift__(self, output: Path | str | IO[str]) -> FlextLdifResult[str]:
        """Write operator: result >> output.

        Writes the result value to the specified output. If this result is a
        failure, the error is propagated without writing.

        Args:
            output: Path, string path, or file-like object to write to

        Returns:
            FlextLdifResult containing the written content as string,
            or propagated error

        Examples:
            >>> result = FlextLdifResult.ok(entries)
            >>> result >> Path("output.ldif")
            >>> result >> "output.ldif"

        """
        if self.is_failure:
            return FlextLdifResult.fail(self.error)

        # Get the value and write it

        # Handle different output types
        if isinstance(output, str):
            output = Path(output)

        if isinstance(output, Path):
            # Business Rule: Write entries to LDIF file format
            # Note: write_entries_to_file method needs implementation in FlextLdifUtilitiesWriter
            # For now, convert entries to LDIF string format and write using write_file
            # This requires serialization of entries to LDIF format
            return FlextLdifResult.fail(
                "write_entries_to_file not yet implemented - entries serialization required",
            )

        # Write to file-like object
        # Business Rule: Write entries to LDIF string format for file-like objects
        # Note: write_entries_to_string method needs implementation in FlextLdifUtilitiesWriter
        # This requires serialization of entries to LDIF format
        return FlextLdifResult.fail(
            "write_entries_to_string not yet implemented - entries serialization required",
        )

    def __matmul__(
        self,
        metadata: Mapping[str, str | int | float | bool | list[str] | None],
    ) -> FlextLdifResult[T]:
        """Metadata operator: result @ metadata.

        Attaches metadata to all entries in the result value. If this result
        is a failure, the error is propagated without attaching metadata.

        Args:
            metadata: Dictionary of metadata to attach

        Returns:
            New FlextLdifResult with metadata attached to entries,
            or propagated error

        Examples:
            >>> result = FlextLdifResult.ok(entries)
            >>> result = result @ {"source": "oid", "version": "1.0"}

        """
        if self.is_failure:
            return FlextLdifResult.fail(self.error)

        # Import here to avoid circular dependency

        value = self.value

        # Business Rule: Attach metadata to entries for audit trail and transformation tracking
        # Metadata is stored in entry.metadata field for round-trip conversions
        # Note: attach_metadata method needs implementation in FlextLdifUtilitiesMetadata
        # For now, return error indicating method needs implementation
        # Handle sequence of entries
        if isinstance(value, Sequence) and not isinstance(value, str):
            # Note: Metadata attachment for sequence of entries needs implementation
            return FlextLdifResult.fail(
                "attach_metadata not yet implemented for sequences",
            )

        # Handle single entry
        # Note: Metadata attachment for single entry needs implementation
        return FlextLdifResult.fail(
            "attach_metadata not yet implemented for single entry",
        )

    def __and__(self, other: FlextLdifResult[T]) -> FlextLdifResult[list[T]]:
        """Combine operator: result1 & result2.

        Combines two results into a single result containing both values.
        If either result is a failure, the first error is propagated.

        Args:
            other: Another FlextLdifResult to combine with

        Returns:
            FlextLdifResult containing list of both values,
            or propagated error from first failure

        Examples:
            >>> users = FlextLdifResult.ok(user_entries)
            >>> groups = FlextLdifResult.ok(group_entries)
            >>> combined = users & groups
            >>> # combined.value == [user_entries, group_entries]

        """
        if self.is_failure:
            return FlextLdifResult.fail(self.error)
        if other.is_failure:
            return FlextLdifResult.fail(other.error)

        return FlextLdifResult.ok([self.value, other.value])

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def filter(
        self,
        predicate: p.Ldif.FilterProtocol | Callable,
    ) -> FlextLdifResult:
        """Filter the result value using a predicate.

        For sequence values, filters elements matching the predicate and returns
        a new sequence of the same type T. For single values, returns the value
        if it matches, or a failure if it doesn't match.

        Business Rule: The filter method preserves the type T. When T is list[Entry],
        filtering returns FlextLdifResult[list[Entry]] with matching entries.

        Args:
            predicate: Filter predicate (p.Ldif.FilterProtocol or callable)

        Returns:
            FlextLdifResult with filtered value or propagated error

        """
        if self.is_failure:
            return FlextLdifResult.fail(self.error)

        value = self.value

        # Get matches function from predicate - check for matches method first
        matches_func = None
        predicate_matches = getattr(predicate, "matches", None)
        if predicate_matches is not None and callable(predicate_matches):
            # FilterProtocol with matches method - wrap as callable
            def wrapped_matches(item: object) -> bool:
                return bool(predicate_matches(item))

            matches_func = wrapped_matches
        elif callable(predicate):
            matches_func = predicate

        if matches_func is None:
            return FlextLdifResult.fail("Invalid predicate type")

        # Handle sequence of entries - filter elements and preserve type
        if isinstance(value, Sequence) and not isinstance(value, str):
            # Filter elements - result is always a list for type consistency
            filtered_elements = [item for item in value if matches_func(item)]
            return FlextLdifResult.ok(filtered_elements)

        # Handle single value - return if matches, fail otherwise
        if matches_func(value):
            return FlextLdifResult.ok(value)

        return FlextLdifResult.fail("Value did not match filter predicate")

    def on_success(self, func: Callable[[T], None]) -> Self:
        """Execute a function on success value without changing result.

        Args:
            func: Function to call with success value

        Returns:
            Self (unchanged result for chaining)

        """
        if self.is_success:
            func(self.value)
        return self

    def on_failure(self, func: Callable[[str], None]) -> Self:
        """Execute a function on error without changing result.

        Args:
            func: Function to call with error message

        Returns:
            Self (unchanged result for chaining)

        """
        if self.is_failure:
            func(self.error)
        return self

    # =========================================================================
    # SPECIAL METHODS
    # =========================================================================

    def __repr__(self) -> str:
        """Return string representation."""
        if self.is_success:
            return f"FlextLdifResult.ok({self.value!r})"
        return f"FlextLdifResult.fail({self.error!r})"

    def __bool__(self) -> bool:
        """Return True if result is success."""
        return self.is_success

    def __eq__(self, other: object) -> bool:
        """Check equality with another FlextLdifResult."""
        if not isinstance(other, FlextLdifResult):
            return NotImplemented
        if self.is_success != other.is_success:
            return False
        if self.is_success:
            return bool(self.value == other.value)
        return self.error == other.error


__all__ = ["FlextLdifResult"]
