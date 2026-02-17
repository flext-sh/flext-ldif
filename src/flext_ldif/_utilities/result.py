"""FlextLdifResult - Extended FlextResult with LDIF-specific DSL operators."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, Self, overload

from flext_core import FlextResult
from flext_core.runtime import FlextRuntime
from flext_core.utilities import FlextUtilities

from flext_ldif.protocols import p

r = FlextResult
u_core = FlextUtilities

# Type variable for the result value type
type ResultValue[T] = T


class FlextLdifResult[T]:
    """Extended FlextResult with LDIF-specific DSL operators."""

    __slots__ = ("_inner",)

    def __hash__(self) -> int:
        """Hash implementation for FlextLdifResult."""
        return hash(self._inner)

    def __init__(self, inner: FlextResult[T] | FlextRuntime.RuntimeResult[T]) -> None:
        """Initialize FlextLdifResult wrapping a FlextResult or RuntimeResult."""
        # FlextResult extends RuntimeResult, so check FlextResult first (more specific)
        inner_result: FlextResult[T]
        if isinstance(inner, FlextResult):
            # Already a FlextResult, use directly
            inner_result = inner
        # RuntimeResult (not FlextResult) - convert by creating new FlextResult
        elif inner.is_success:
            inner_result = r[T].ok(inner.value)
        else:
            error_msg = inner.error if hasattr(inner, "error") else str(inner)
            inner_result = r[T].fail(error_msg)
        self._inner = inner_result

    # FACTORY METHODS - Create new results

    @classmethod
    def ok(cls, value: T) -> FlextLdifResult[T]:
        """Create a successful result with the given value."""
        return cls(r[T].ok(value))

    @classmethod
    def fail(cls, error: str | Exception) -> FlextLdifResult[T]:
        """Create a failed result with the given error."""
        error_msg = str(error) if isinstance(error, Exception) else error
        return cls(r.fail(error_msg))

    @classmethod
    def from_result(cls, result: FlextResult[T]) -> FlextLdifResult[T]:
        """Wrap an existing FlextResult in FlextLdifResult."""
        return cls(result)

    # PROPERTIES - Delegate to inner FlextResult

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
        """Get the error message."""
        error_msg = self._inner.error
        # Ensure we return str, not str | None
        return error_msg if error_msg is not None else "Unknown error"

    # CORE METHODS - Delegate to inner FlextResult

    def unwrap(self) -> T:
        """Unwrap the success value or raise an exception."""
        return self._inner.value

    def unwrap_or(self, default: T) -> T:
        """Unwrap the success value or return a default."""
        return self._inner.unwrap_or(default)

    def unwrap_or_else(self, func: Callable[[], T]) -> T:
        """Unwrap the success value or compute from error."""
        if self.is_failure:
            return func()
        return self._inner.value

    def map[U](self, func: Callable[[T], U]) -> FlextLdifResult[U]:
        """Map a function over the success value."""
        # map may return RuntimeResult, convert to FlextResult
        mapped_result = self._inner.map(func)
        return FlextLdifResult(mapped_result)

    def flat_map[U](self, func: Callable[[T], FlextResult[U]]) -> FlextLdifResult[U]:
        """Flat map a function that returns FlextResult."""
        # flat_map may return RuntimeResult, convert to FlextResult
        mapped_result = self._inner.flat_map(func)
        return FlextLdifResult(mapped_result)

    def map_error(self, func: Callable[[str], str]) -> FlextLdifResult[T]:
        """Map a function over the error message."""
        # map_error may return RuntimeResult, convert to FlextResult
        mapped_result = self._inner.map_error(func)
        return FlextLdifResult(mapped_result)

    def to_inner(self) -> FlextResult[T]:
        """Get the underlying FlextResult."""
        return self._inner

    # DSL OPERATORS - LDIF-specific pipeline operations

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
        """Pipe operator: result | transformer."""
        if self.is_failure:
            return FlextLdifResult.fail(self.error)

        # Business Rule: Apply transformer to success value
        # Transformer can be p.Ldif.TransformerProtocol (has apply method) or callable
        # p.Ldif.TransformerProtocol.apply() returns FlextResult[T] or T
        # Callable transforms T -> T or T -> FlextResult[T]
        # Check if transformer implements TransformerProtocol (runtime_checkable)
        if isinstance(transformer, p.Ldif.TransformerProtocol):
            transform_result = transformer.apply(self.value)
            if isinstance(transform_result, FlextResult):
                return FlextLdifResult.from_result(transform_result)
            # After isinstance check, transform_result is T (not FlextResult)
            return FlextLdifResult.ok(transform_result)

        # It's a callable (function or lambda) - type system guarantees this
        result = transformer(self.value)
        if isinstance(result, FlextResult):
            return FlextLdifResult.from_result(result)
        return FlextLdifResult.ok(result)

    def __rshift__(self, output: Path | str | IO[str]) -> FlextLdifResult[str]:
        """Write operator: result >> output."""
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
        """Metadata operator: result @ metadata."""
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
        """Combine operator: result1 & result2."""
        if self.is_failure:
            return FlextLdifResult.fail(self.error)
        if other.is_failure:
            return FlextLdifResult.fail(other.error)

        return FlextLdifResult.ok([self.value, other.value])

    # UTILITY METHODS

    def filter(
        self,
        predicate: p.Ldif.FilterProtocol[T] | Callable[[T], bool],
    ) -> FlextLdifResult[T]:
        """Filter the result value using a predicate."""
        if self.is_failure:
            return FlextLdifResult.fail(self.error)

        value = self.value

        # Use Protocol isinstance check for FilterProtocol (runtime_checkable)
        matches_func: Callable[[T], bool]
        if isinstance(predicate, p.Ldif.FilterProtocol):
            # FilterProtocol - wrap matches method with proper typing
            filter_protocol = predicate

            def wrapped_matches(item: T) -> bool:
                return filter_protocol.matches(item)

            matches_func = wrapped_matches
        elif callable(predicate):
            # Direct callable - already properly typed as Callable[[T], bool]
            matches_func = predicate
        else:
            return FlextLdifResult.fail("Invalid predicate type")

        # Check if value matches predicate
        if matches_func(value):
            return FlextLdifResult.ok(value)

        return FlextLdifResult.fail("Value did not match filter predicate")

    def on_success(self, func: Callable[[T], None]) -> Self:
        """Execute a function on success value without changing result."""
        if self.is_success:
            func(self.value)
        return self

    def on_failure(self, func: Callable[[str], None]) -> Self:
        """Execute a function on error without changing result."""
        if self.is_failure:
            func(self.error)
        return self

    # SPECIAL METHODS

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
