"""Pure functional utilities for FLEXT-LDIF."""

from __future__ import annotations

import builtins
import struct
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Literal, overload

from pydantic import BaseModel

from flext_ldif._models._models import (
    ConvertToBool,
    ConvertToDict,
    ConvertToFloat,
    ConvertToInt,
    ConvertToList,
    ConvertToStr,
    ConvertToTuple,
)
from flext_ldif.typings import t


class FlextFunctional:
    """Pure functional utilities without circular dependencies."""

    @staticmethod
    def _to_general(value: builtins.object) -> builtins.object:
        """Normalize arbitrary values into object-compatible shape."""
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, BaseModel):
            model_mapping: dict[str, builtins.object] = {
                key: FlextFunctional._to_general(getattr(value, key))
                for key in type(value).model_fields
            }
            extra = value.__pydantic_extra__
            if extra:
                for key, item in extra.items():
                    model_mapping[key] = FlextFunctional._to_general(item)
            return model_mapping
        if isinstance(value, Mapping):
            normalized_mapping: dict[str, builtins.object] = {}
            for key, item in value.items():
                normalized_mapping[key] = FlextFunctional._to_general(item)
            return normalized_mapping
        if isinstance(value, Iterable):
            return [FlextFunctional._to_general(item) for item in value]
        return value

    @staticmethod
    def or_[T](*values: T | None, default: T | None = None) -> T | None:
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
    def chain[T](value: T, *funcs: Callable[[T], T]) -> T:
        """Chain function calls (DSL helper, mnemonic: ch)."""
        result: T = value
        for func in funcs:
            result = func(result)
        return result

    ch = chain

    @staticmethod
    def pick[T](
        data: Mapping[str, T], *keys: str, as_dict: bool = True
    ) -> Mapping[str, T] | list[T]:
        """Pick keys from dict (DSL helper, mnemonic: pc)."""
        if as_dict:
            return {k: data[k] for k in keys if k in data}
        return [data[k] for k in keys if k in data]

    pc = pick

    @staticmethod
    def map_dict[T, U](
        data: Mapping[str, T], mapper: Callable[[str, T], tuple[str, U]]
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
    def pairs[T](d: Mapping[str, T]) -> list[tuple[str, T]]:
        """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr)."""
        return list(d.items())

    pr = pairs

    @staticmethod
    def fold[T, U](items: Sequence[T], folder: Callable[[U, T], U], initial: U) -> U:
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
    def process_flatten(
        items: Sequence[builtins.object],
        processor: Callable[
            ...,
            list[builtins.object] | tuple[builtins.object, ...] | object,
        ],
        *,
        predicate: Callable[..., bool] = lambda x: x is not None,
        on_error: Literal["skip", "stop", "collect"] = "skip",
    ) -> list[builtins.object]:
        """Process and flatten items (mnemonic: pf)."""
        result: list[builtins.object] = []
        for item in items:
            try:
                processed = processor(item)
                if isinstance(processed, list):
                    processed_values: list[builtins.object] = processed
                    result.extend(
                        sub_item for sub_item in processed_values if predicate(sub_item)
                    )
                elif isinstance(processed, tuple):
                    processed_tuple_values: list[builtins.object] = list(processed)
                    result.extend(
                        sub_item
                        for sub_item in processed_tuple_values
                        if predicate(sub_item)
                    )
                elif predicate(processed):
                    result.append(processed)
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                if on_error == "stop":
                    raise
        return result

    pf = process_flatten

    @classmethod
    def normalize_list(
        cls,
        value: builtins.object | Sequence[builtins.object] | None,
        *,
        mapper: Callable[..., object] | None = None,
        predicate: Callable[..., bool] | None = None,
        default: list[builtins.object] | None = None,
    ) -> list[builtins.object]:
        """Normalize to list (mnemonic: nl)."""
        if value is None:
            if default is not None:
                return list(default)
            return []
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            items: list[builtins.object] = list(value)
        else:
            items = [value]
        if mapper is not None:
            items_mapped: list[builtins.object] = [mapper(item) for item in items]
            if predicate is not None:
                return [item for item in items_mapped if predicate(item)]
            return items_mapped
        if predicate is not None:
            return [item for item in items if predicate(item)]
        return items

    @staticmethod
    def build[T](value: T, ops: Mapping[str, Callable[[T], T]]) -> T:
        """Build value using operations dict."""
        result = value
        for op in ops.values():
            result = op(result)
        return result

    nl = normalize_list

    @staticmethod
    def get[T](data: Mapping[str, T], key: str, default: T | None = None) -> T | None:
        """Get value from dict with default (mnemonic: gt)."""
        return data.get(key, default)

    gt = get

    @staticmethod
    def merge[T](*dicts: Mapping[str, T]) -> Mapping[str, T]:
        """Merge multiple dicts (mnemonic: mg)."""
        result: dict[str, T] = {}
        for d in dicts:
            result.update(d)
        return result

    mg = merge

    @staticmethod
    def evolve[T](data: Mapping[str, T], updates: Mapping[str, T]) -> Mapping[str, T]:
        """Update dict with changes (mnemonic: ev)."""
        return {**data, **updates}

    ev = evolve

    @staticmethod
    def when[T](
        *, condition: bool = False, then: T | None = None, else_: T | None = None
    ) -> T | None:
        """Functional conditional (DSL pattern, mnemonic: wh)."""
        if not condition:
            return else_
        return then if then is not None else else_

    wh = when

    @staticmethod
    def cond[T, U](
        *cases: tuple[Callable[[T], bool], Callable[[T], U]], default: U | None = None
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
    def pipe[T](initial: T, *transforms: Callable[[T], T]) -> T:
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
        *cases: tuple[type[T] | T | Callable[[T], bool], U],
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
        cls, value: T, cases: Mapping[T, U], default: U | None = None
    ) -> U | None:
        """Switch using dict lookup (mnemonic: sw)."""
        return cases.get(value, default)

    sw = switch

    @classmethod
    def is_type[T](cls, value: T, *types: type[T] | str) -> bool:
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
            resolved_type: type | None = (
                type_map.get(t_val) if isinstance(t_val, str) else t_val
            )
            if resolved_type is not None and isinstance(value, resolved_type):
                return True
        return False

    it = is_type
    _ConvertibleType = (
        t.Scalar
        | list[builtins.object]
        | tuple[builtins.object, ...]
        | set[builtins.object]
        | object
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

    @overload
    @classmethod
    def as_type(
        cls,
        value: builtins.object,
        *,
        target: type[str] | Literal["str"],
        default: str | None = None,
    ) -> str | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: builtins.object,
        *,
        target: type[bool] | Literal["bool"],
        default: bool | None = None,
    ) -> bool | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: builtins.object,
        *,
        target: type[int] | Literal["int"],
        default: int | None = None,
    ) -> int | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: builtins.object,
        *,
        target: type[float] | Literal["float"],
        default: float | None = None,
    ) -> float | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: builtins.object,
        *,
        target: type[list[builtins.object]] | Literal["list"],
        default: list[builtins.object] | None = None,
    ) -> list[builtins.object] | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: builtins.object,
        *,
        target: type[tuple[builtins.object, ...]] | Literal["tuple"],
        default: tuple[builtins.object, ...] | None = None,
    ) -> tuple[builtins.object, ...] | None: ...

    @overload
    @classmethod
    def as_type(
        cls,
        value: builtins.object,
        *,
        target: type[Mapping[str, builtins.object]] | Literal["dict"],
        default: Mapping[str, builtins.object] | None = None,
    ) -> Mapping[str, builtins.object] | None: ...

    @classmethod
    def as_type(
        cls,
        value: builtins.object,
        *,
        target: type | str,
        default: builtins.object | None = None,
    ) -> builtins.object | None:
        """Safe cast (mnemonic: at)."""
        target_type: type | None = (
            cls._TYPE_MAP.get(target) if isinstance(target, str) else target
        )
        if target_type is None:
            return default
        if target_type is str and isinstance(value, str):
            return value
        if target_type is bool and isinstance(value, bool):
            return value
        if target_type is int and isinstance(value, int):
            return value
        if target_type is float and isinstance(value, float):
            return value
        if target_type is list and isinstance(value, list):
            return value
        if target_type is tuple and isinstance(value, tuple):
            return value
        if target_type is dict and isinstance(value, dict):
            return value
        try:
            return cls._convert_with_target(value, target_type, default)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _convert_with_target(
        value: builtins.object, target_type: type, default: builtins.object | None
    ) -> builtins.object | None:
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
        normalized_value: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container]
        )
        if isinstance(value, t.CONTAINER_TYPES):
            normalized_value = value
        elif isinstance(value, Mapping):
            normalized_value = {
                str(key): item if isinstance(item, t.CONTAINER_TYPES) else str(item)
                for key, item in value.items()
            }
        elif isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            normalized_value = [
                item if isinstance(item, t.CONTAINER_TYPES) else str(item)
                for item in value
            ]
        else:
            normalized_value = str(value)
        normalized_default: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None
        )
        if default is None:
            normalized_default = None
        elif isinstance(default, t.CONTAINER_TYPES):
            normalized_default = default
        elif isinstance(default, Mapping):
            normalized_default = {
                str(key): item if isinstance(item, t.CONTAINER_TYPES) else str(item)
                for key, item in default.items()
            }
        elif isinstance(default, Sequence) and not isinstance(
            default, (str, bytes, bytearray)
        ):
            normalized_default = [
                item if isinstance(item, t.CONTAINER_TYPES) else str(item)
                for item in default
            ]
        else:
            normalized_default = str(default)

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
            conversion_model = ConvertToStr(
                value=normalized_value, default=normalized_default
            )
        elif target_type is int:
            conversion_model = ConvertToInt(
                value=normalized_value, default=normalized_default
            )
        elif target_type is float:
            conversion_model = ConvertToFloat(
                value=normalized_value, default=normalized_default
            )
        elif target_type is bool:
            conversion_model = ConvertToBool(
                value=normalized_value, default=normalized_default
            )
        elif target_type is list:
            conversion_model = ConvertToList(
                value=normalized_value, default=normalized_default
            )
        elif target_type is tuple:
            conversion_model = ConvertToTuple(
                value=normalized_value, default=normalized_default
            )
        elif target_type is dict:
            conversion_model = ConvertToDict(
                value=normalized_value, default=normalized_default
            )
        if conversion_model is None:
            return default
        try:
            converted = conversion_model.convert()
            return FlextFunctional._to_general(converted)
        except (TypeError, ValueError):
            return default

    at = as_type

    @classmethod
    def prop(cls, key: str) -> Callable[..., object]:
        """Property accessor (mnemonic: pp)."""

        def getter(obj: builtins.object) -> builtins.object:
            """Get value from object by key."""
            normalized_obj: builtins.object = FlextFunctional._to_general(obj)
            if isinstance(normalized_obj, dict):
                return FlextFunctional._to_general(normalized_obj.get(key))
            return None

        return getter

    prop_get = prop

    @classmethod
    def props(cls, *keys: str) -> Callable[..., Mapping[str, builtins.object]]:
        """Multiple property accessor (mnemonic: ps)."""

        def accessor(obj: builtins.object) -> Mapping[str, builtins.object]:
            """Get multiple values from object by keys."""
            result_dict: dict[str, builtins.object] = {}
            normalized_obj: builtins.object = FlextFunctional._to_general(obj)
            for k in keys:
                if isinstance(normalized_obj, dict):
                    val: builtins.object | None = normalized_obj.get(k)
                    result_dict[k] = FlextFunctional._to_general(val)
                else:
                    result_dict[k] = None
            return result_dict

        return accessor

    ps = props

    @classmethod
    def path(cls, *keys: str) -> Callable[..., object]:
        """Path accessor using chain() DSL (mnemonic: ph)."""

        def make_getter(key: str) -> Callable[..., object]:
            """Create a single-key getter."""

            def getter_fn(obj: builtins.object) -> builtins.object:
                """Get value from object by key."""
                if obj is None:
                    return None
                normalized_obj: builtins.object = FlextFunctional._to_general(obj)
                if isinstance(normalized_obj, dict):
                    return FlextFunctional._to_general(normalized_obj.get(key))
                return None

            return getter_fn

        getters: list[Callable[..., object]] = [make_getter(k) for k in keys]

        def path_getter(obj: builtins.object) -> builtins.object:
            """Get value at path."""
            if obj is None:
                return None
            result: builtins.object = obj
            for getter in getters:
                if result is None:
                    return None
                result = getter(result)
            return result

        return path_getter

    ph = path


f = FlextFunctional
__all__ = ["FlextFunctional", "f"]
