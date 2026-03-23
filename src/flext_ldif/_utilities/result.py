"""FlextLdifUtilitiesResult - Extended r with LDIF-specific DSL operators."""

from __future__ import annotations

import base64
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import IO, Self, overload, override

from flext_core import FlextRuntime, r

from flext_ldif import FlextLdifUtilitiesWriter, m, t


class FlextLdifUtilitiesResult[T: t.NormalizedValue]:
    """Extended r with LDIF-specific DSL operators."""

    __slots__ = ("_inner",)
    _inner: r[T]

    def __init__(self, inner: r[T] | FlextRuntime.RuntimeResult[T]) -> None:
        """Initialize FlextLdifUtilitiesResult wrapping r[T] or RuntimeResult."""
        super().__init__()
        inner_result: r[T]
        if isinstance(inner, r):
            inner_result = inner
        elif inner.is_success:
            inner_result = r[T].ok(inner.value)
        else:
            error_msg = (
                inner.error if getattr(inner, "error", None) is not None else str(inner)
            )
            inner_result = r[T].fail(error_msg)
        self._inner = inner_result

    @override
    def __repr__(self) -> str:
        """Return string representation."""
        if self.is_success:
            return f"FlextLdifUtilitiesResult.ok({self.value!r})"
        return f"FlextLdifUtilitiesResult.fail({self.error!r})"

    def __hash__(self) -> int:
        """Hash implementation for FlextLdifUtilitiesResult."""
        return hash(self._inner)

    def __bool__(self) -> bool:
        """Return True if result is success."""
        return self.is_success

    def __and__(
        self,
        other: FlextLdifUtilitiesResult[T],
    ) -> FlextLdifUtilitiesResult[list[T]]:
        """Combine operator: result1 & result2."""
        if self.is_failure:
            return FlextLdifUtilitiesResult[list[T]].fail(self.error)
        if other.is_failure:
            return FlextLdifUtilitiesResult[list[T]].fail(other.error)
        return FlextLdifUtilitiesResult.ok([self.value, other.value])

    def __matmul__(
        self,
        metadata: dict[str, t.Scalar | list[str] | None],
    ) -> FlextLdifUtilitiesResult[T]:
        """Metadata operator: result @ metadata."""
        if self.is_failure:
            return FlextLdifUtilitiesResult[T].fail(self.error)
        value = self.value
        if isinstance(value, Sequence) and (not isinstance(value, str)):
            return FlextLdifUtilitiesResult[T].fail(
                "attach_metadata not yet implemented for sequences",
            )
        return FlextLdifUtilitiesResult[T].fail(
            "attach_metadata not yet implemented for single entry",
        )

    @overload
    def __or__(self, transformer: Callable[[T], T]) -> FlextLdifUtilitiesResult[T]: ...

    @overload
    def __or__(
        self,
        transformer: Callable[[T], r[T]],
    ) -> FlextLdifUtilitiesResult[T]: ...

    def __or__(
        self,
        transformer: Callable[[T], T] | Callable[[T], r[T]],
    ) -> FlextLdifUtilitiesResult[T]:
        """Pipe operator: result | transformer."""
        if self.is_failure:
            return FlextLdifUtilitiesResult[T].fail(self.error)
        result = transformer(self.value)
        if isinstance(result, r):
            return FlextLdifUtilitiesResult.from_result(result)
        return FlextLdifUtilitiesResult.ok(result)

    def __rshift__(self, output: Path | str | IO[str]) -> FlextLdifUtilitiesResult[str]:
        """Write operator: result >> output."""
        if self.is_failure:
            return FlextLdifUtilitiesResult[str].fail(self.error)
        raw_value = self.value
        entry_payload: m.Ldif.Entry | list[m.Ldif.Entry]
        if isinstance(raw_value, m.Ldif.Entry):
            entry_payload = raw_value
        elif isinstance(raw_value, Sequence) and (not isinstance(raw_value, str)):
            entries: list[m.Ldif.Entry] = []
            for item in raw_value:
                if not isinstance(item, m.Ldif.Entry):
                    return FlextLdifUtilitiesResult[str].fail(
                        "Entry serialization failed: sequence contains non-entry value",
                    )
                entries.append(item)
            entry_payload = entries
        else:
            return FlextLdifUtilitiesResult[str].fail(
                "Entry serialization failed: value must be Entry or sequence of Entry",
            )
        serialized = FlextLdifUtilitiesResult._serialize_entries_to_ldif(entry_payload)
        if serialized.is_failure:
            serialized_error = serialized.error
            if serialized_error is None:
                return FlextLdifUtilitiesResult[str].fail("Entry serialization failed")
            return FlextLdifUtilitiesResult[str].fail(serialized_error)
        ldif_content = serialized.value
        if isinstance(output, str):
            output = Path(output)
        if isinstance(output, Path):
            write_result = FlextLdifUtilitiesWriter.write_file(ldif_content, output)
            if write_result.is_failure:
                write_error = write_result.error
                if write_error is None:
                    return FlextLdifUtilitiesResult[str].fail(
                        "write_entries_to_file failed",
                    )
                return FlextLdifUtilitiesResult[str].fail(write_error)
            return FlextLdifUtilitiesResult.ok(ldif_content)
        try:
            _ = output.write(ldif_content)
        except (ValueError, AttributeError, OSError, TypeError) as exc:
            return FlextLdifUtilitiesResult[str].fail(
                f"write_entries_to_string failed: {exc}",
            )
        return FlextLdifUtilitiesResult.ok(ldif_content)

    @property
    def error(self) -> str:
        """Get the error message."""
        error_msg = self._inner.error
        return error_msg if error_msg is not None else "Unknown error"

    @property
    def is_failure(self) -> bool:
        """Check if the result is a failure."""
        return self._inner.is_failure

    @property
    def is_success(self) -> bool:
        """Check if the result is a success."""
        return self._inner.is_success

    @property
    def value(self) -> T:
        """Get the success value. Raises if result is a failure."""
        return self._inner.value

    @classmethod
    def fail(
        cls: type[FlextLdifUtilitiesResult[T]],
        error: str | Exception,
    ) -> FlextLdifUtilitiesResult[T]:
        """Create a failed result with the given error."""
        error_msg = str(error) if isinstance(error, Exception) else error
        return cls(r[T].fail(error_msg))

    @staticmethod
    def from_result[TResult: t.NormalizedValue](
        result: r[TResult],
    ) -> FlextLdifUtilitiesResult[TResult]:
        """Wrap an existing r[T] in FlextLdifUtilitiesResult."""
        return FlextLdifUtilitiesResult(result)

    @staticmethod
    def ok[TResult: t.NormalizedValue](
        value: TResult,
    ) -> FlextLdifUtilitiesResult[TResult]:
        """Create a successful result with the given value."""
        return FlextLdifUtilitiesResult(r[TResult].ok(value))

    @staticmethod
    def _encode_dn_line(dn_value: str) -> str:
        if FlextLdifUtilitiesWriter.needs_base64_encoding(dn_value):
            encoded_dn = base64.b64encode(dn_value.encode("utf-8")).decode("ascii")
            return f"dn:: {encoded_dn}"
        return f"dn: {dn_value}"

    @staticmethod
    def _serialize_entries_to_ldif(
        value: list[m.Ldif.Entry] | m.Ldif.Entry,
    ) -> r[str]:
        entries: list[m.Ldif.Entry] = (
            [value] if isinstance(value, m.Ldif.Entry) else list(value)
        )
        all_lines: list[str] = []
        for entry in entries:
            entry_lines_result = FlextLdifUtilitiesResult._serialize_single_entry(entry)
            if entry_lines_result.is_failure:
                entry_error = entry_lines_result.error
                if entry_error is None:
                    return r[str].fail("Entry serialization failed")
                return r[str].fail(entry_error)
            all_lines.extend(entry_lines_result.value)
        ldif_text = "\n".join(all_lines)
        if ldif_text and (not ldif_text.endswith("\n")):
            ldif_text += "\n"
        return r[str].ok(ldif_text)

    @staticmethod
    def _serialize_single_entry(entry: m.Ldif.Entry) -> r[list[str]]:
        if entry.dn is None:
            return r[list[str]].fail("Entry serialization failed: missing DN")
        dn_value = entry.dn.value
        if not dn_value:
            return r[list[str]].fail("Entry serialization failed: empty DN")
        lines: list[str] = [FlextLdifUtilitiesResult._encode_dn_line(dn_value)]
        entry_attributes: dict[str, list[str]] = (
            entry.attributes.attributes if entry.attributes else {}
        )
        for attr_name, values in entry_attributes.items():
            for value in values:
                attr_line = FlextLdifUtilitiesWriter.encode_attribute_value(
                    attr_name,
                    value,
                )
                lines.extend(FlextLdifUtilitiesWriter.fold_line(attr_line))
        lines.append("")
        return r[list[str]].ok(lines)

    def filter(self, predicate: Callable[[T], bool]) -> FlextLdifUtilitiesResult[T]:
        """Filter the result value using a predicate."""
        if self.is_failure:
            return FlextLdifUtilitiesResult[T].fail(self.error)
        value = self.value
        if predicate(value):
            return FlextLdifUtilitiesResult.ok(value)
        return FlextLdifUtilitiesResult[T].fail("Value did not match filter predicate")

    def flat_map[U: t.NormalizedValue](
        self,
        func: Callable[[T], r[U]],
    ) -> FlextLdifUtilitiesResult[U]:
        """Flat map a function that returns r[U]."""
        mapped_result = self._inner.flat_map(func)
        return FlextLdifUtilitiesResult(mapped_result)

    def map[U: t.NormalizedValue](
        self,
        func: Callable[[T], U],
    ) -> FlextLdifUtilitiesResult[U]:
        """Map a function over the success value."""
        mapped_result = self._inner.map(func)
        return FlextLdifUtilitiesResult(mapped_result)

    def on_failure(self, func: Callable[[str], None]) -> Self:
        """Execute a function on error without changing result."""
        if self.is_failure:
            func(self.error)
        return self

    def on_success(self, func: Callable[[T], None]) -> Self:
        """Execute a function on success value without changing result."""
        if self.is_success:
            func(self.value)
        return self

    def unwrap(self) -> T:
        """Unwrap the success value or raise an exception."""
        return self._inner.value

    def unwrap_or(self, default: T) -> T:
        """Unwrap the success value or return a default."""
        return self._inner.unwrap_or(default)


__all__ = ["FlextLdifUtilitiesResult"]
