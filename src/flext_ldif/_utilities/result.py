"""FlextLdifUtilitiesResult - Extended r with LDIF-specific DSL operators."""

from __future__ import annotations

from typing import override

from flext_core import FlextModelsResult, r


class FlextLdifUtilitiesResult[T]:
    """Extended r with LDIF-specific DSL operators."""

    __slots__ = ("_inner",)
    _inner: r[T]

    def __init__(self, inner: r[T] | FlextModelsResult.RuntimeResult[T]) -> None:
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
    def from_result[TResult](
        result: r[TResult],
    ) -> FlextLdifUtilitiesResult[TResult]:
        """Wrap an existing r[T] in FlextLdifUtilitiesResult."""
        return FlextLdifUtilitiesResult(result)

    @staticmethod
    def ok[TResult](
        value: TResult,
    ) -> FlextLdifUtilitiesResult[TResult]:
        """Create a successful result with the given value."""
        return FlextLdifUtilitiesResult(r[TResult].ok(value))

    def unwrap_or(self, default: T) -> T:
        """Unwrap the success value or return a default."""
        return self._inner.unwrap_or(default)


__all__ = ["FlextLdifUtilitiesResult"]
