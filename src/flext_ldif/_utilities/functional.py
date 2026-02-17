"""Pure functional utilities for FLEXT-LDIF."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import ClassVar, Literal, Protocol, TypeVar, overload, runtime_checkable

from flext_core import FlextTypes as t, T, U
from flext_core.utilities import FlextUtilities as u

CallableType = TypeVar("CallableType", bound=type[t.GeneralValueType])
_TThunk_co = TypeVar("_TThunk_co", covariant=True)
_TUnaryIn_contra = TypeVar("_TUnaryIn_contra", contravariant=True)
_TUnaryOut_co = TypeVar("_TUnaryOut_co", covariant=True)


@runtime_checkable
class _Thunk(Protocol[_TThunk_co]):
    def __call__(self) -> _TThunk_co: ...


@runtime_checkable
class _UnaryCase(Protocol[_TUnaryIn_contra, _TUnaryOut_co]):
    def __call__(self, value: _TUnaryIn_contra) -> _TUnaryOut_co: ...


class FlextFunctional:
    """Pure functional utilities without circular dependencies."""

    @staticmethod
    def or_[T](
        *values: T | None,
        default: T | None = None,
    ) -> T | None:
        """Return first non-None value (mnemonic: oo)."""
        for v in values:
            if v is not None:
                return v
        return default

    oo = or_

    @staticmethod
    def maybe[T, U](
        value: T | None,
        *,
        default: T | U | None = None,
        mapper: Callable[[T], U] | None = None,
    ) -> T | U | None:
        """Maybe monad pattern (mnemonic: mb)."""
        if value is None:
            return default
        if mapper is not None:
            return mapper(value)
        return value

    mb = maybe

    @staticmethod
    def chain[T](
        value: T,
        *funcs: Callable[[T], T],
    ) -> T:
        """Chain function calls (DSL helper, mnemonic: ch)."""
        result: T = value
        for func in funcs:
            result = func(result)
        return result

    ch = chain

    @staticmethod
    def pick[T](
        data: dict[str, T],
        *keys: str,
        as_dict: bool = True,
    ) -> dict[str, T] | list[T]:
        """Pick keys from dict (DSL helper, mnemonic: pc)."""
        if as_dict:
            return {k: data[k] for k in keys if k in data}
        return [data[k] for k in keys if k in data]

    pc = pick

    @staticmethod
    def map_dict[T, U](
        data: dict[str, T],
        mapper: Callable[[str, T], tuple[str, U]],
    ) -> dict[str, U]:
        """Map dict with transformations (mnemonic: md)."""
        result: dict[str, U] = {}
        for key, value in data.items():
            new_key, new_value = mapper(key, value)
            result[new_key] = new_value
        return result

    md = map_dict

    @overload
    @staticmethod
    def reduce_dict[T](
        data: dict[str, T],
        *,
        processor: None = None,
        predicate: Callable[[str, T], bool] = lambda _k, _v: True,
        key_mapper: Callable[[str], str] = lambda k: k,
    ) -> dict[str, T]: ...

    @overload
    @staticmethod
    def reduce_dict[T, U](
        data: dict[str, T],
        *,
        processor: Callable[[str, T], U],
        predicate: Callable[[str, T], bool] = lambda _k, _v: True,
        key_mapper: Callable[[str], str] = lambda k: k,
    ) -> dict[str, U]: ...

    @staticmethod
    def reduce_dict[T, U](
        data: dict[str, T],
        *,
        processor: Callable[[str, T], U] | None = None,
        predicate: Callable[[str, T], bool] = lambda _k, _v: True,
        key_mapper: Callable[[str], str] = lambda k: k,
    ) -> dict[str, T] | dict[str, U]:
        """Reduce dicts with processor/predicate (mnemonic: rd)."""
        if processor is not None:
            result: dict[str, U] = {}
            for key, value in data.items():
                if predicate(key, value):
                    new_key = key_mapper(key)
                    result[new_key] = processor(key, value)
            return result
        result_no_proc: dict[str, T] = {}
        for key, value in data.items():
            if predicate(key, value):
                new_key = key_mapper(key)
                result_no_proc[new_key] = value
        return result_no_proc

    rd = reduce_dict

    @staticmethod
    def find_key[T](
        data: dict[str, T] | T,
        predicate: Callable[[str, T], bool],
        *,
        default: str | None = None,
    ) -> str | None:
        """Find first key matching predicate (mnemonic: fk)."""
        if not isinstance(data, dict):
            return default
        for key, value in data.items():
            if predicate(key, value):
                return key
        return default

    fk = find_key

    @staticmethod
    def find_val[T](
        data: dict[str, T] | T,
        predicate: Callable[[str, T], bool],
        *,
        default: T | None = None,
    ) -> T | None:
        """Find first value matching predicate (mnemonic: fv)."""
        if isinstance(data, dict):
            for key, value in data.items():
                if predicate(key, value):
                    return value
        return default

    fv = find_val

    @staticmethod
    def pairs[T](
        d: dict[str, T] | Mapping[str, T],
    ) -> list[tuple[str, T]]:
        """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr)."""
        return list(d.items())

    pr = pairs

    @staticmethod
    def fold[T, U](
        items: Sequence[T] | T,
        folder: Callable[[U, T], U],
        initial: U,
    ) -> U:
        """Fold items using folder function (mnemonic: fd)."""
        if not isinstance(items, (list, tuple)):
            return initial
        sequence: Sequence[T] = items
        result = initial
        for item in sequence:
            result = folder(result, item)
        return result

    fd = fold

    @staticmethod
    def map_filter[T](
        items: Sequence[T] | T,
        mapper: Callable[[T], T] | None = None,
        predicate: Callable[[T], bool] = lambda x: x is not None,
    ) -> list[T]:
        """Map then filter items (mnemonic: mf)."""
        if not isinstance(items, (list, tuple)):
            return []
        sequence: Sequence[T] = items
        result: list[T] = []
        for item in sequence:
            mapped = mapper(item) if mapper is not None else item
            if predicate(mapped):
                result.append(mapped)
        return result

    mf = map_filter

    @staticmethod
    def process_flatten[T, U](
        items: Sequence[T] | T,
        processor: Callable[[T], list[U] | tuple[U, ...] | U],
        *,
        predicate: Callable[[U], bool] = lambda x: x is not None,
        on_error: Literal["skip", "stop", "collect"] = "skip",
    ) -> list[U]:
        """Process and flatten items (mnemonic: pf)."""
        if not isinstance(items, (list, tuple)):
            return []
        sequence: Sequence[T] = items
        result: list[U] = []
        for item in sequence:
            try:
                processed = processor(item)
                if isinstance(processed, (list, tuple)):
                    result.extend([
                        sub_item for sub_item in processed if predicate(sub_item)
                    ])
                elif predicate(processed):
                    result.append(processed)
            except Exception:
                if on_error == "stop":
                    raise
        return result

    pf = process_flatten

    @staticmethod
    def build[T](
        value: T,
        ops: dict[str, Callable[[T], T]],
    ) -> T:
        """Build value using operations dict."""
        result = value
        for op in ops.values():
            result = op(result)
        return result

    @classmethod
    def normalize_list[T](
        cls,
        value: T | list[T] | tuple[T, ...] | None,
        *,
        mapper: Callable[[T], T] | None = None,
        predicate: Callable[[T], bool] | None = None,
        default: list[T] | None = None,
    ) -> list[T]:
        """Normalize to list (mnemonic: nl)."""
        items: list[T]
        if value is None:
            if default is not None:
                return list(default)
            return []

        if isinstance(value, (str, bytes)):
            items = [value]  # Single item of type T
        elif isinstance(value, list):
            items = value
        elif isinstance(value, tuple):
            items = list(value)
        else:
            items = [value]

        if mapper is not None:
            items_mapped: list[T] = [mapper(item) for item in items]
            if predicate is not None:
                return [item for item in items_mapped if predicate(item)]
            return items_mapped

        if predicate is not None:
            return [item for item in items if predicate(item)]
        return items

    nl = normalize_list

    @staticmethod
    def get[T](
        data: dict[str, T] | T,
        key: str,
        default: T | None = None,
    ) -> T | None:
        """Get value from dict with default (mnemonic: gt)."""
        if isinstance(data, dict):
            return data.get(key, default)
        return default

    gt = get

    @staticmethod
    def merge[T](
        *dicts: dict[str, T],
    ) -> dict[str, T]:
        """Merge multiple dicts (mnemonic: mg)."""
        result: dict[str, T] = {}
        for d in dicts:
            result.update(d)
        return result

    mg = merge

    @staticmethod
    def evolve[T](
        data: dict[str, T],
        updates: dict[str, T],
    ) -> dict[str, T]:
        """Update dict with changes (mnemonic: ev)."""
        return {**data, **updates}

    ev = evolve

    @staticmethod
    def when[T](
        *,
        condition: bool = False,
        then: T | _Thunk[T] | None = None,
        else_: T | None = None,
    ) -> T | None:
        """Functional conditional (DSL pattern, mnemonic: wh)."""
        if condition:
            if isinstance(then, _Thunk):
                return then()
            if then is not None:
                return then
        return else_

    wh = when

    @staticmethod
    def cond[T, U](
        *cases: tuple[Callable[[T], bool], Callable[[T], U]],
        default: U | None = None,
    ) -> Callable[[T], U | None]:
        """Conditional expression returning curried function (mnemonic: cd)."""

        def evaluator(value: T) -> U | None:
            for condition_fn, result_fn in cases:
                if condition_fn(value):
                    return result_fn(value)
            return default

        return evaluator

    cd = cond

    @staticmethod
    def pipe[T](
        initial: T,
        *transforms: Callable[[T], T],
    ) -> T:
        """Pipe value through transformation functions (mnemonic: pp)."""
        result = initial
        for transform in transforms:
            result = transform(result)
        return result

    pp = pipe

    @classmethod
    def match[T, U](
        cls,
        value: T,
        *cases: tuple[
            type[T] | T | Callable[[T], bool],
            U,
        ],
        default: U | None = None,
    ) -> U | None:
        """Pattern match (mnemonic: mt)."""
        for pattern, result in cases:
            if isinstance(pattern, type) and isinstance(value, pattern):
                return result
            if callable(pattern) and not isinstance(pattern, type):
                try:
                    if pattern(value):
                        return result
                except (TypeError, ValueError):
                    continue
            if value == pattern:
                return result
        return default

    mt = match

    @classmethod
    def switch[T, U](
        cls,
        value: T,
        cases: dict[T, U | _UnaryCase[T, U]],
        default: U | None = None,
    ) -> U | None:
        """Switch using dict lookup (mnemonic: sw)."""
        result = cases.get(value, default)
        if isinstance(result, _UnaryCase):
            return result(value)
        return result

    sw = switch

    @classmethod
    def is_type[T](
        cls,
        value: T,
        *types: type[T] | str,
    ) -> bool:
        """Type check (mnemonic: it)."""
        type_map: dict[str, type] = {
            "list": list,
            "dict": dict,
            "str": str,
            "int": int,
            "bool": bool,
            "tuple": tuple,
            "float": float,
            "set": set,
        }
        for t_val in types:
            # Resolve type: if string, look up in map; if type, use directly
            resolved_type: type | None = (
                type_map.get(t_val) if isinstance(t_val, str) else t_val
            )
            if resolved_type is not None and isinstance(value, resolved_type):
                return True
        return False

    it = is_type

    _ConvertibleType = (
        str
        | int
        | float
        | bool
        | list[t.GeneralValueType]
        | tuple[t.GeneralValueType, ...]
        | set[t.GeneralValueType]
        | dict[str, t.GeneralValueType]
    )

    _TYPE_MAP: ClassVar[dict[str, type]] = {
        "list": list,
        "dict": dict,
        "str": str,
        "int": int,
        "bool": bool,
        "tuple": tuple,
        "float": float,
    }

    @staticmethod
    def _convert_with_target(
        value: t.GeneralValueType,
        target_type: type,
        default: t.GeneralValueType | None,
    ) -> t.GeneralValueType | None:
        if target_type is str:
            return str(value)
        if target_type is int:
            if isinstance(value, (str, bytes, bytearray, int, float)):
                return int(value)
            try:
                return int(str(value))
            except (TypeError, ValueError):
                return default
        if target_type is float:
            if isinstance(value, (str, bytes, bytearray, int, float)):
                return float(value)
            try:
                return float(str(value))
            except (TypeError, ValueError):
                return default
        if target_type is bool:
            if isinstance(value, str):
                return value.lower() in {"true", "1", "yes", "on"}
            return bool(value)
        if target_type is list:
            if isinstance(value, (list, tuple, set)):
                return list(value)
            return [value]
        if target_type is tuple:
            if isinstance(value, (list, tuple)):
                return tuple(value)
            return (value,)
        if target_type is dict:
            if isinstance(value, dict):
                return value
            return default
        return default

    @overload
    @classmethod
    def as_type(
        cls,
        value: t.GeneralValueType,
        *,
        target: type[str] | Literal["str"],
        default: str | None = None,
    ) -> str | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: t.GeneralValueType,
        *,
        target: type[bool] | Literal["bool"],
        default: bool | None = None,
    ) -> bool | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: t.GeneralValueType,
        *,
        target: type[int] | Literal["int"],
        default: int | None = None,
    ) -> int | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: t.GeneralValueType,
        *,
        target: type[float] | Literal["float"],
        default: float | None = None,
    ) -> float | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: t.GeneralValueType,
        *,
        target: type[list[t.GeneralValueType]] | Literal["list"],
        default: list[t.GeneralValueType] | None = None,
    ) -> list[t.GeneralValueType] | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: t.GeneralValueType,
        *,
        target: type[tuple[t.GeneralValueType, ...]] | Literal["tuple"],
        default: tuple[t.GeneralValueType, ...] | None = None,
    ) -> tuple[t.GeneralValueType, ...] | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: t.GeneralValueType,
        *,
        target: type[dict[str, t.GeneralValueType]] | Literal["dict"],
        default: dict[str, t.GeneralValueType] | None = None,
    ) -> dict[str, t.GeneralValueType] | None: ...

    @classmethod
    def as_type(
        cls,
        value: t.GeneralValueType,
        *,
        target: type | str,
        default: t.GeneralValueType | None = None,
    ) -> t.GeneralValueType | None:
        """Safe cast (mnemonic: at)."""
        target_type: type | None = (
            cls._TYPE_MAP.get(target) if isinstance(target, str) else target
        )

        if target_type is None:
            return default

        if isinstance(target_type, type) and isinstance(value, target_type):
            return value

        try:
            return cls._convert_with_target(value, target_type, default)
        except (TypeError, ValueError):
            return default

    at = as_type

    @classmethod
    def prop(
        cls,
        key: str,
    ) -> Callable[[t.GeneralValueType], t.GeneralValueType]:
        """Property accessor (mnemonic: pp)."""

        def getter(obj: t.GeneralValueType) -> t.GeneralValueType:
            """Get value from object by key."""
            if isinstance(obj, Mapping):
                value: t.GeneralValueType = obj.get(key)
                return value
            if hasattr(obj, key):
                attr_val: t.GeneralValueType = getattr(obj, key, None)
                return attr_val
            return None

        return getter

    prop_get = prop

    @classmethod
    def props(
        cls,
        *keys: str,
    ) -> Callable[[t.GeneralValueType], dict[str, t.GeneralValueType]]:
        """Multiple property accessor (mnemonic: ps)."""

        def accessor(obj: t.GeneralValueType) -> dict[str, t.GeneralValueType]:
            """Get multiple values from object by keys."""
            result_dict: dict[str, t.GeneralValueType] = {}
            for k in keys:
                if isinstance(obj, Mapping):
                    value: t.GeneralValueType | None = u.mapper().get(obj, k)
                    result_dict[k] = value
                elif hasattr(obj, k):
                    attr_value: t.GeneralValueType = getattr(obj, k, None)
                    result_dict[k] = attr_value
                else:
                    result_dict[k] = None
            return result_dict

        return accessor

    ps = props

    @classmethod
    def path(
        cls,
        *keys: str,
    ) -> Callable[[t.GeneralValueType], t.GeneralValueType]:
        """Path accessor using chain() DSL (mnemonic: ph)."""

        def make_getter(
            key: str,
        ) -> Callable[[t.GeneralValueType], t.GeneralValueType]:
            """Create a single-key getter."""

            def getter_fn(obj: t.GeneralValueType) -> t.GeneralValueType:
                """Get value from object by key."""
                if obj is None:
                    return None
                if isinstance(obj, Mapping):
                    map_result = u.mapper().get(obj, key)
                    if map_result == key and isinstance(key, str):
                        return None
                    return map_result
                if hasattr(obj, key):
                    return getattr(obj, key, None)
                return None

            return getter_fn

        getters: list[Callable[[t.GeneralValueType], t.GeneralValueType]] = [
            make_getter(k) for k in keys
        ]

        def path_getter(obj: t.GeneralValueType) -> t.GeneralValueType:
            """Get value at path."""
            if obj is None:
                return None
            result: t.GeneralValueType = obj
            for getter in getters:
                if result is None:
                    return None
                result = getter(result)
            return result

        return path_getter

    ph = path


f = FlextFunctional


__all__ = [
    "FlextFunctional",
    "f",
]
