"""Pure functional utilities for FLEXT-LDIF."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Literal, Protocol, TypeVar, overload, runtime_checkable

from flext_core import T, U, t, x
from flext_core.utilities import u
from pydantic import BaseModel

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
    def _to_general(value: object) -> t.GeneralValueType:
        """Normalize arbitrary values into GeneralValueType-compatible shape."""
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, BaseModel):
            return FlextFunctional._to_general(value.model_dump())
        if isinstance(value, Mapping):
            normalized_mapping: dict[str, t.GeneralValueType] = {}
            for key, item in value.items():
                if isinstance(key, str):
                    normalized_mapping[key] = FlextFunctional._to_general(item)
            return normalized_mapping
        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            return [FlextFunctional._to_general(item) for item in value]
        return str(value)

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
        data: Mapping[str, T],
        *keys: str,
        as_dict: bool = True,
    ) -> Mapping[str, T] | list[T]:
        """Pick keys from dict (DSL helper, mnemonic: pc)."""
        if as_dict:
            return {k: data[k] for k in keys if k in data}
        return [data[k] for k in keys if k in data]

    pc = pick

    @staticmethod
    def map_dict[T, U](
        data: Mapping[str, T],
        mapper: Callable[[str, T], tuple[str, U]],
    ) -> Mapping[str, U]:
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
        data: Mapping[str, T],
        *,
        processor: None = None,
        predicate: Callable[[str, T], bool] = lambda _k, _v: True,
        key_mapper: Callable[[str], str] = lambda k: k,
    ) -> Mapping[str, T]: ...

    @overload
    @staticmethod
    def reduce_dict[T, U](
        data: Mapping[str, T],
        *,
        processor: Callable[[str, T], U],
        predicate: Callable[[str, T], bool] = lambda _k, _v: True,
        key_mapper: Callable[[str], str] = lambda k: k,
    ) -> Mapping[str, U]: ...

    @staticmethod
    def reduce_dict[T, U](
        data: Mapping[str, T],
        *,
        processor: Callable[[str, T], U] | None = None,
        predicate: Callable[[str, T], bool] = lambda _k, _v: True,
        key_mapper: Callable[[str], str] = lambda k: k,
    ) -> Mapping[str, T] | Mapping[str, U]:
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
        data: Mapping[str, T],
        predicate: Callable[[str, T], bool],
        *,
        default: str | None = None,
    ) -> str | None:
        """Find first key matching predicate (mnemonic: fk)."""
        for key, value in data.items():
            if predicate(key, value):
                return key
        return default

    fk = find_key

    @staticmethod
    def find_val[T](
        data: Mapping[str, T],
        predicate: Callable[[str, T], bool],
        *,
        default: T | None = None,
    ) -> T | None:
        """Find first value matching predicate (mnemonic: fv)."""
        for key, value in data.items():
            if predicate(key, value):
                return value
        return default

    fv = find_val

    @staticmethod
    def pairs[T](
        d: Mapping[str, T],
    ) -> list[tuple[str, T]]:
        """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr)."""
        return list(d.items())

    pr = pairs

    @staticmethod
    def fold[T, U](
        items: Sequence[T],
        folder: Callable[[U, T], U],
        initial: U,
    ) -> U:
        """Fold items using folder function (mnemonic: fd)."""
        result = initial
        for item in items:
            result = folder(result, item)
        return result

    fd = fold

    @staticmethod
    def map_filter[T](
        items: Sequence[T],
        mapper: Callable[[T], T] | None = None,
        predicate: Callable[[T], bool] = lambda x: x is not None,
    ) -> list[T]:
        """Map then filter items (mnemonic: mf)."""
        result: list[T] = []
        for item in items:
            mapped = mapper(item) if mapper is not None else item
            if predicate(mapped):
                result.append(mapped)
        return result

    mf = map_filter

    @staticmethod
    def process_flatten[T, U](
        items: Sequence[T],
        processor: Callable[[T], list[U] | tuple[U, ...] | U],
        *,
        predicate: Callable[[U], bool] = lambda x: x is not None,
        on_error: Literal["skip", "stop", "collect"] = "skip",
    ) -> list[U]:
        """Process and flatten items (mnemonic: pf)."""
        result: list[U] = []
        for item in items:
            try:
                processed = processor(item)
                if isinstance(processed, list | tuple):
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
        ops: Mapping[str, Callable[[T], T]],
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
        if value is None:
            if default is not None:
                return list(default)
            return []

        items: list[T] = list(value) if isinstance(value, list | tuple) else [value]

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
        data: Mapping[str, T],
        key: str,
        default: T | None = None,
    ) -> T | None:
        """Get value from dict with default (mnemonic: gt)."""
        return data.get(key, default)

    gt = get

    @staticmethod
    def merge[T](
        *dicts: Mapping[str, T],
    ) -> Mapping[str, T]:
        """Merge multiple dicts (mnemonic: mg)."""
        result: dict[str, T] = {}
        for d in dicts:
            result.update(d)
        return result

    mg = merge

    @staticmethod
    def evolve[T](
        data: Mapping[str, T],
        updates: Mapping[str, T],
    ) -> Mapping[str, T]:
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
            if callable(then):
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
            if isinstance(pattern, type):
                if isinstance(value, pattern):
                    return result
            elif callable(pattern):
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
        cases: Mapping[T, U | _UnaryCase[T, U]],
        default: U | None = None,
    ) -> U | None:
        """Switch using dict lookup (mnemonic: sw)."""
        result = cases.get(value, default)
        if callable(result):
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

    _TYPE_MAP: ClassVar[Mapping[str, type]] = {
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
        """Execute type conversion using centralized Pydantic v2 models.

        Dispatches to the appropriate ConversionRequest model based on target_type
        using a discriminated union for type safety and centralized validation.

        Args:
            value: Value to convert
            target_type: Target type (str, int, float, bool, list, tuple, dict)
            default: Default value if conversion fails

        Returns:
            Converted value or default if conversion fails

        """
        from flext_ldif._models.conversion import (  # noqa: PLC0415
            ConvertToBool,
            ConvertToDict,
            ConvertToFloat,
            ConvertToInt,
            ConvertToList,
            ConvertToStr,
            ConvertToTuple,
        )

        conversion_model: (
            ConvertToStr
            | ConvertToInt
            | ConvertToFloat
            | ConvertToBool
            | ConvertToList
            | ConvertToTuple
            | ConvertToDict
            | None
        ) = None

        if target_type is str:
            conversion_model = ConvertToStr(value=value, default=default)
        elif target_type is int:
            conversion_model = ConvertToInt(value=value, default=default)
        elif target_type is float:
            conversion_model = ConvertToFloat(value=value, default=default)
        elif target_type is bool:
            conversion_model = ConvertToBool(value=value, default=default)
        elif target_type is list:
            conversion_model = ConvertToList(value=value, default=default)
        elif target_type is tuple:
            conversion_model = ConvertToTuple(value=value, default=default)
        elif target_type is dict:
            conversion_model = ConvertToDict(value=value, default=default)

        if conversion_model is None:
            return default

        try:
            converted = conversion_model.convert()
            return FlextFunctional._to_general(converted)
        except (TypeError, ValueError):
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
        target: type[Mapping[str, t.GeneralValueType]] | Literal["dict"],
        default: Mapping[str, t.GeneralValueType] | None = None,
    ) -> Mapping[str, t.GeneralValueType] | None: ...

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
            return FlextFunctional._to_general(value)

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
                return FlextFunctional._to_general(obj.get(key))
            if x.is_base_model(obj):
                dumped = obj.model_dump()
                return dumped.get(key)
            return None

        return getter

    prop_get = prop

    @classmethod
    def props(
        cls,
        *keys: str,
    ) -> Callable[[t.GeneralValueType], Mapping[str, t.GeneralValueType]]:
        """Multiple property accessor (mnemonic: ps)."""

        def accessor(obj: t.GeneralValueType) -> Mapping[str, t.GeneralValueType]:
            """Get multiple values from object by keys."""
            result_dict: dict[str, t.GeneralValueType] = {}
            for k in keys:
                if isinstance(obj, Mapping):
                    result_dict[k] = FlextFunctional._to_general(obj.get(k))
                elif x.is_base_model(obj):
                    dumped = obj.model_dump()
                    result_dict[k] = dumped.get(k)
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
                    return FlextFunctional._to_general(obj.get(key))
                if x.is_base_model(obj):
                    dumped = obj.model_dump()
                    return dumped.get(key)
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
