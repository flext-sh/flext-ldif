"""Pure functional utilities for FLEXT-LDIF."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping, MutableSequence


class FlextLdifUtilitiesFunctional:
    """Pure functional utilities without circular dependencies."""

    @staticmethod
    def map_filter[T](
        items: MutableSequence[T],
        mapper: Callable[[T], T] | None = None,
        predicate: Callable[[T], bool] = lambda x: x is not None,
    ) -> MutableSequence[T]:
        """Map then filter items (mnemonic: mf)."""
        result: MutableSequence[T] = []
        for item in items:
            mapped = mapper(item) if mapper is not None else item
            if predicate(mapped):
                result.append(mapped)
        return result

    mf = map_filter

    @staticmethod
    def merge[T](*dicts: MutableMapping[str, T]) -> MutableMapping[str, T]:
        """Merge multiple dicts (mnemonic: mg)."""
        result: MutableMapping[str, T] = {}
        for d in dicts:
            result.update(d)
        return result

    mg = merge

    @classmethod
    def switch[T, U](
        cls,
        value: T,
        cases: MutableMapping[T, U],
        default: U | None = None,
    ) -> U | None:
        """Switch using dict lookup (mnemonic: sw)."""
        return cases.get(value, default)

    sw = switch


f = FlextLdifUtilitiesFunctional
__all__ = ["FlextLdifUtilitiesFunctional", "f"]
