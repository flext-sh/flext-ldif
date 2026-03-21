"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

from collections.abc import Sequence

from flext_tests import FlextTestsDocker, u as _flext_tests_u

from flext_ldif import FlextLdifUtilities
from flext_ldif._utilities import FlextLdifUtilitiesOID

from .constants import TestsFlextLdifConstants

_SENTINEL = object()


class TestsFlextLdifUtilities(_flext_tests_u, FlextLdifUtilities):
    """Project test utility namespace extension."""

    OID = FlextLdifUtilitiesOID

    class TestCategorization:
        """Test categorization utilities."""

    class Tests(_flext_tests_u.Tests):
        """Test utilities with Matchers and Docker support."""

        Docker = FlextTestsDocker

        class Matchers:
            """Assertion matchers for test readability."""

            @staticmethod
            def that(
                value: object,
                *,
                eq: object = _SENTINEL,
                none: bool | object = _SENTINEL,
                is_: type | object = _SENTINEL,
                contains: object = _SENTINEL,
                attrs: Sequence[str] | object = _SENTINEL,
                keys: Sequence[str] | object = _SENTINEL,
                lacks_keys: Sequence[str] | object = _SENTINEL,
                kv: dict[str, object] | object = _SENTINEL,
                gte: float | object = _SENTINEL,
                lte: float | object = _SENTINEL,
                **kwargs: object,
            ) -> None:
                """Assert value matches expected conditions."""
                if eq is not _SENTINEL:
                    assert value == eq, f"Expected {eq!r}, got {value!r}"
                if none is not _SENTINEL:
                    if none is True:
                        assert value is None, f"Expected None, got {value!r}"
                    elif none is False:
                        assert value is not None, "Expected non-None value"
                if is_ is not _SENTINEL:
                    assert isinstance(
                        value,
                        is_,  # type: ignore[arg-type]
                    ), f"Expected instance of {is_!r}, got {type(value)!r}"
                if contains is not _SENTINEL:
                    assert contains in value, (  # type: ignore[operator]
                        f"Expected {value!r} to contain {contains!r}"
                    )
                if attrs is not _SENTINEL:
                    for attr_name in attrs:  # type: ignore[union-attr]
                        assert hasattr(value, attr_name), (
                            f"Missing attribute: {attr_name}"
                        )
                if keys is not _SENTINEL:
                    for key in keys:  # type: ignore[union-attr]
                        assert key in value, f"Missing key: {key}"  # type: ignore[operator]
                if lacks_keys is not _SENTINEL:
                    for key in lacks_keys:  # type: ignore[union-attr]
                        assert key not in value, f"Unexpected key: {key}"  # type: ignore[operator]
                if kv is not _SENTINEL:
                    for k, v in kv.items():  # type: ignore[union-attr]
                        actual = value[k]  # type: ignore[index]
                        assert actual == v, f"Key {k!r}: expected {v!r}, got {actual!r}"
                if gte is not _SENTINEL:
                    assert value >= gte, f"Expected >= {gte!r}, got {value!r}"  # type: ignore[operator]
                if lte is not _SENTINEL:
                    assert value <= lte, f"Expected <= {lte!r}, got {value!r}"  # type: ignore[operator]
                if "len" in kwargs:
                    expected_len = kwargs["len"]
                    actual_len = len(value)  # type: ignore[arg-type]
                    assert actual_len == expected_len, (
                        f"Expected length {expected_len}, got {actual_len}"
                    )

            @staticmethod
            def ok(result: object, **kwargs: object) -> object:
                """Assert result is success and return its value."""
                assert hasattr(result, "is_success"), "Expected a Result object"
                assert result.is_success, (  # type: ignore[union-attr]
                    f"Expected success, got failure: {getattr(result, 'error', 'unknown')}"
                )
                value = result.value  # type: ignore[union-attr]
                if kwargs:
                    TestsFlextLdifUtilities.Tests.Matchers.that(value, **kwargs)
                return value

            @staticmethod
            def fail(result: object, **kwargs: object) -> str:
                """Assert result is failure and return error string."""
                assert hasattr(result, "is_failure"), "Expected a Result object"
                assert result.is_failure, "Expected failure, got success"  # type: ignore[union-attr]
                error_str = str(result.error) if result.error else ""  # type: ignore[union-attr]
                has_value = kwargs.get("has")
                if has_value is not None:
                    assert has_value in error_str.lower(), (  # type: ignore[operator]
                        f"Expected error to contain {has_value!r}, got {error_str!r}"
                    )
                return error_str


__all__ = ["TestsFlextLdifUtilities", "u"]

u = TestsFlextLdifUtilities


# Lazy-load helpers to avoid circular imports
def __getattr__(name: str) -> type[object]:
    """Lazy-load test helpers from constants."""
    if name in {"TestDeduplicationHelpers", "RfcTestHelpers"}:
        return getattr(TestsFlextLdifConstants, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
