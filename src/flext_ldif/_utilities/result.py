"""FlextLdifResult - Extended FlextResult with LDIF-specific DSL operators."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, Self, overload

from flext_core import FlextResult
from flext_core.runtime import FlextRuntime

from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif.models import m
from flext_ldif.protocols import p

r = FlextResult

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
        super().__init__()
        # FlextResult extends RuntimeResult, so check FlextResult first (more specific)
        inner_result: FlextResult[T]
        if isinstance(inner, FlextResult):
            # Already a FlextResult, use directly
            inner_result = inner
        # RuntimeResult (not FlextResult) - convert by creating new FlextResult
        elif inner.is_success:
            inner_result = r[T].ok(inner.value)
        else:
            error_msg = (
                inner.error if getattr(inner, "error", None) is not None else str(inner)
            )
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

        serialized = FlextLdifResult._serialize_entries_to_ldif(self.value)
        if serialized.is_failure:
            serialized_error = serialized.error
            if serialized_error is None:
                return FlextLdifResult.fail("Entry serialization failed")
            return FlextLdifResult.fail(serialized_error)

        ldif_content = serialized.value

        # Handle different output types
        if isinstance(output, str):
            output = Path(output)

        if isinstance(output, Path):
            write_result = FlextLdifUtilitiesWriter.write_file(ldif_content, output)
            if write_result.is_failure:
                write_error = write_result.error
                if write_error is None:
                    return FlextLdifResult.fail("write_entries_to_file failed")
                return FlextLdifResult.fail(write_error)
            return FlextLdifResult.ok(ldif_content)

        # Write to file-like object
        try:
            _ = output.write(ldif_content)
        except (ValueError, AttributeError, OSError, TypeError) as exc:
            return FlextLdifResult.fail(f"write_entries_to_string failed: {exc}")

        return FlextLdifResult.ok(ldif_content)

    @staticmethod
    def _encode_dn_line(dn_value: str) -> str:
        if FlextLdifUtilitiesWriter.needs_base64_encoding(dn_value):
            encoded_dn = base64.b64encode(dn_value.encode("utf-8")).decode("ascii")
            return f"dn:: {encoded_dn}"
        return f"dn: {dn_value}"

    @staticmethod
    def _serialize_single_entry(entry: m.Ldif.Entry) -> FlextResult[list[str]]:
        if entry.dn is None:
            return r[list[str]].fail("Entry serialization failed: missing DN")

        dn_value = entry.dn.value
        if not dn_value:
            return r[list[str]].fail("Entry serialization failed: empty DN")

        lines: list[str] = [FlextLdifResult._encode_dn_line(dn_value)]

        entry_attributes = entry.attributes.attributes if entry.attributes else {}
        for attr_name, values in entry_attributes.items():
            for value in values:
                attr_line = FlextLdifUtilitiesWriter.encode_attribute_value(
                    attr_name, value
                )
                lines.extend(FlextLdifUtilitiesWriter.fold(attr_line))

        lines.append("")
        return r[list[str]].ok(lines)

    @staticmethod
    def _serialize_entries_to_ldif(
        value: Sequence[m.Ldif.Entry] | m.Ldif.Entry,
    ) -> FlextResult[str]:
        entries: list[m.Ldif.Entry] = []

        if isinstance(value, m.Ldif.Entry):
            entries = [value]
        elif isinstance(value, Sequence) and not isinstance(value, str):
            for item in value:
                if not isinstance(item, m.Ldif.Entry):
                    return r[str].fail(
                        "Entry serialization failed: sequence contains non-entry value",
                    )
                entries.append(item)
        else:
            return r[str].fail(
                "Entry serialization failed: value must be Entry or sequence of Entry",
            )

        all_lines: list[str] = []
        for entry in entries:
            entry_lines_result = FlextLdifResult._serialize_single_entry(entry)
            if entry_lines_result.is_failure:
                entry_error = entry_lines_result.error
                if entry_error is None:
                    return r[str].fail("Entry serialization failed")
                return r[str].fail(entry_error)
            all_lines.extend(entry_lines_result.value)

        ldif_text = "\n".join(all_lines)
        if ldif_text and not ldif_text.endswith("\n"):
            ldif_text += "\n"
        return r[str].ok(ldif_text)

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
