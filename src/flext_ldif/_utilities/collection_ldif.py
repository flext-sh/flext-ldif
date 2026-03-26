"""LDIF-specific collection/merge/DSL utilities for FLEXT-LDIF."""

from __future__ import annotations

import contextlib
import inspect
import struct
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from typing import overload

from flext_core import FlextUtilities, r

from flext_ldif import t


class FlextLdifUtilitiesCollectionLdif:
    """LDIF-specific collection, merge, and DSL methods."""

    type VariadicCallable[T] = Callable[..., T]

    @classmethod
    def update_inplace(
        cls,
        obj: t.MutableContainerMapping,
        *updates: t.MutableContainerMapping | None,
    ) -> t.MutableContainerMapping:
        """Update in-place using FlextUtilities.flow() pattern (mnemonic: ui)."""
        for update in updates:
            if update is not None:
                obj.update(update)
        return obj

    ui = update_inplace

    @classmethod
    def get_ldif[T](
        cls,
        data: t.NormalizedValue,
        key: str,
        *,
        default: t.NormalizedValue | T | None = None,
    ) -> t.NormalizedValue | T | None:
        """Safe get with optional mapping (DSL pattern)."""
        match data:
            case Mapping() as data_mapping:
                return data_mapping.get(key, default)
            case _:
                pass
        return default

    @staticmethod
    def find(
        items: t.ContainerList,
        *,
        predicate: Callable[..., bool],
    ) -> t.NormalizedValue | None:
        """Find first item matching predicate."""
        for elem in items:
            if predicate(elem):
                return elem
        return None

    @staticmethod
    def unwrap_or[T](result: r[T], *, default: T | None = None) -> T | None:
        """Unwrap r with default value."""
        if result.is_success:
            return result.value
        return default

    @staticmethod
    def empty(items: t.NormalizedValue) -> bool:
        """Check if value is empty."""
        if items is None:
            return True
        if isinstance(items, (str, bytes)):
            return not items
        if isinstance(items, Mapping):
            return not items
        if isinstance(items, Sequence):
            return not items
        return False

    @classmethod
    def zip_with(
        cls,
        *sequences: t.MutableContainerList,
        combiner: FlextLdifUtilitiesCollectionLdif.VariadicCallable[
            tuple[t.NormalizedValue, ...]
        ]
        | None = None,
    ) -> t.MutableContainerList:
        """Zip with combiner (generalized: uses zip from base, mnemonic: zw)."""
        if not sequences:
            return []
        zipped = zip(*sequences, strict=False)
        if combiner is None:
            return [tuple(items) for items in zipped]
        result: t.MutableContainerList = []
        for items_tuple in zipped:
            items_list = list(items_tuple)
            combined = combiner(*items_list)
            result.append(combined)
        return result

    zw = zip_with

    @staticmethod
    def is_empty_value(value: t.NormalizedValue) -> bool:
        """Check if value is empty (empty string, list, or dict)."""
        match value:
            case str() as value_str if not value_str:
                return True
            case list() as value_list if not value_list:
                return True
            case dict() as value_dict:
                return not value_dict
            case _:
                return False

    @classmethod
    def keys[T](
        cls,
        items: MutableMapping[str, T] | r[MutableMapping[str, T]],
        *,
        default: MutableSequence[str] | None = None,
    ) -> MutableSequence[str]:
        """Get keys from dict (mnemonic: ky)."""
        match items:
            case r() as result_items:
                if result_items.is_success:
                    return list(result_items.value.keys())
                return default or []
            case _:
                return list(items.keys())

    ky = keys

    @classmethod
    def dict_vals[T](
        cls,
        items: MutableMapping[str, T] | r[MutableMapping[str, T]],
        *,
        default: MutableSequence[T] | None = None,
    ) -> MutableSequence[T]:
        """Get values from dict (mnemonic: vl)."""
        match items:
            case r() as result_items:
                if result_items.is_success:
                    return list(result_items.value.values())
                return default or []
            case _:
                return list(items.values())

    vl = dict_vals

    @classmethod
    def invert(cls, obj: t.MutableContainerMapping) -> MutableMapping[str, str]:
        """Invert dict using FlextUtilities.map_dict() pattern (mnemonic: iv)."""
        str_dict: MutableMapping[str, str] = {k: str(v) for k, v in obj.items()}
        inverted = FlextUtilities.invert_dict(str_dict)
        return dict(inverted)

    iv = invert

    @classmethod
    def where(
        cls,
        obj: t.MutableContainerMapping,
        *,
        predicate: Callable[[str, t.NormalizedValue], bool] | None = None,
    ) -> t.MutableContainerMapping:
        """Where using FlextUtilities.filter() (mnemonic: wh)."""
        if predicate is None:
            return dict(obj)
        return {k: v for k, v in obj.items() if predicate(k, v)}

    wh = where

    @staticmethod
    def all_(*args: t.NormalizedValue) -> bool:
        """Check if all values are truthy."""
        return all(args)

    @staticmethod
    def any_(*args: t.NormalizedValue) -> bool:
        """Check if any value is truthy."""
        return any(args)

    @staticmethod
    def sum(
        items: t.MutableContainerList | t.MutableContainerMapping,
    ) -> t.Numeric:
        """Sum of numeric items."""
        if isinstance(items, Mapping):
            total_dict: t.Numeric = 0
            for v in items.values():
                match v:
                    case int() | float():
                        total_dict += v
                    case _:
                        pass
            return total_dict
        if not items:
            return 0
        has_float = any(isinstance(v, float) for v in items)
        total_seq: t.Numeric = 0.0 if has_float else 0
        for v in items:
            match v:
                case int() | float():
                    total_seq += v
                case _:
                    pass
        return total_seq

    @staticmethod
    @overload
    def result_val_opt[T](result: r[T], default: T) -> T: ...

    @staticmethod
    @overload
    def result_val_opt[T](result: r[T], default: None = None) -> T | None: ...

    @staticmethod
    def result_val_opt[T](result: r[T], default: T | None = None) -> T | None:
        """Extract value from r with optional default (DSL helper)."""
        if result.is_success:
            return result.value
        return default

    @classmethod
    def _detect_predicate_type(
        cls,
        pairs: tuple[
            tuple[
                Callable[[], bool] | Callable[..., bool] | bool,
                t.NormalizedValue,
            ],
            ...,
        ],
    ) -> bool:
        """Detect if predicates are no-arg (True) or value-arg (False)."""
        if not pairs:
            return False
        first_pred = pairs[0][0]
        if not callable(first_pred):
            return False
        try:
            sig = inspect.signature(first_pred)
            return not sig.parameters
        except (ValueError, TypeError):
            return False

    @classmethod
    def _evaluate_no_arg_result(
        cls,
        result_val: t.NormalizedValue,
    ) -> t.NormalizedValue:
        """Evaluate a no-arg result value."""
        return result_val

    @classmethod
    def _evaluate_value_arg_predicate(
        cls,
        *,
        pred: Callable[[], bool] | Callable[..., bool] | bool,
        value: t.NormalizedValue,
    ) -> bool:
        """Evaluate a value-arg predicate."""
        if callable(pred):
            if FlextLdifUtilitiesCollectionLdif.is_no_arg_callable(pred):
                no_arg_pred: Callable[[], bool] = pred
                return no_arg_pred()
            if FlextLdifUtilitiesCollectionLdif.is_object_arg_callable(pred):
                value_pred: Callable[..., bool] = pred
                return value_pred(value)
            return bool(pred)
        return bool(pred)

    @classmethod
    def _evaluate_value_arg_result(
        cls,
        result_val: t.NormalizedValue,
        value: t.NormalizedValue,
    ) -> t.NormalizedValue:
        """Evaluate a value-arg result value."""
        _ = value
        return result_val

    @classmethod
    def cond(
        cls,
        *pairs: tuple[
            Callable[[], bool] | Callable[..., bool] | bool,
            t.NormalizedValue,
        ],
        default: t.NormalizedValue | None = None,
    ) -> Callable[[], t.NormalizedValue] | Callable[..., t.NormalizedValue]:
        """Cond pattern (mnemonic: cd)."""
        is_no_arg = cls._detect_predicate_type(pairs)
        if is_no_arg:

            def conditional_no_arg() -> t.NormalizedValue:
                for pred, result_val in pairs:
                    evaluated = False
                    if callable(
                        pred,
                    ) and FlextLdifUtilitiesCollectionLdif.is_no_arg_callable(pred):
                        with contextlib.suppress(TypeError):
                            call_result = pred()
                            evaluated = bool(call_result)
                    elif not callable(pred):
                        evaluated = bool(pred)
                    if evaluated:
                        return cls._evaluate_no_arg_result(result_val)
                return default

            return conditional_no_arg

        def conditional(value: t.NormalizedValue) -> t.NormalizedValue:
            for pred, result_val in pairs:
                if cls._evaluate_value_arg_predicate(pred=pred, value=value):
                    return cls._evaluate_value_arg_result(result_val, value)
            return default

        return conditional

    cd = cond

    @classmethod
    def switch(
        cls,
        value: t.NormalizedValue,
        cases: MutableMapping[t.NormalizedValue, t.NormalizedValue],
        default: t.NormalizedValue | None = None,
    ) -> t.NormalizedValue:
        """Switch using dict lookup (mnemonic: sw)."""
        return cases.get(value, default)

    sw = switch

    @classmethod
    def update(
        cls,
        data: t.MutableContainerMapping,
        updates: t.MutableContainerMapping,
    ) -> t.MutableContainerMapping:
        """Update dict using FlextUtilities.merge_mappings() (mnemonic: ud)."""
        updated = dict(data)
        updated.update(updates)
        return updated

    ud = update

    @staticmethod
    def or_[T: t.NormalizedValue](
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
    def reduce_dict(
        items: t.NormalizedValue,
        *,
        processor: Callable[[str, t.NormalizedValue], tuple[str, t.NormalizedValue]]
        | None = None,
        predicate: Callable[[str, t.NormalizedValue], bool] | None = None,
        default: t.MutableContainerMapping | None = None,
    ) -> t.MutableContainerMapping:
        """Reduce dicts (mnemonic: rd)."""
        if not items:
            return default or {}
        items_list: MutableSequence[t.MutableContainerMapping] = []
        if isinstance(items, Mapping):
            items_list = [
                {
                    str(key): FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                        value,
                    )
                    for key, value in items.items()
                },
            ]
        elif isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
            for item in items:
                if isinstance(item, Mapping):
                    items_list.append({
                        str(key): FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                            value,
                        )
                        for key, value in item.items()
                    })
        result: t.MutableContainerMapping = dict(default) if default else {}
        for d_item in items_list:
            for key, val in d_item.items():
                if predicate and (not predicate(key, val)):
                    continue
                if processor:
                    processed_key, processed_val = processor(key, val)
                    result[processed_key] = processed_val
                else:
                    result[key] = val
        return result

    rd = reduce_dict

    @staticmethod
    def map_filter(
        items: t.NormalizedValue,
        *,
        mapper: Callable[..., t.NormalizedValue] | None = None,
        predicate: Callable[..., bool] | None = None,
    ) -> t.MutableContainerList:
        """Map then filter items (mnemonic: mf)."""
        items_list: t.MutableContainerList
        if isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
            items_list = [
                FlextLdifUtilitiesCollectionLdif.to_config_map_value(item)
                for item in items
            ]
        else:
            items_list = [FlextLdifUtilitiesCollectionLdif.to_config_map_value(items)]
        if mapper:
            items_list = [mapper(item) for item in items_list]
        if predicate:
            items_list = [item for item in items_list if predicate(item)]
        return items_list

    mf = map_filter

    @staticmethod
    def process_flatten(
        items: t.NormalizedValue,
        *,
        processor: Callable[..., t.NormalizedValue] | None = None,
        on_error: str = "skip",
    ) -> t.MutableContainerList:
        """Process and flatten items (mnemonic: pf)."""
        if isinstance(items, Mapping):
            items_list: t.MutableContainerList = list(
                FlextLdifUtilitiesCollectionLdif.normalize_mapping(items).values(),
            )
        elif isinstance(items, (list, tuple, set, frozenset)):
            items_list = [
                FlextLdifUtilitiesCollectionLdif.normalize_container(v) for v in items
            ]
        else:
            items_list = [FlextLdifUtilitiesCollectionLdif.normalize_container(items)]
        result: t.MutableContainerList = []
        for item in items_list:
            try:
                processed = processor(item) if processor else item
                if isinstance(processed, Sequence) and not isinstance(
                    processed,
                    (str, bytes),
                ):
                    result.extend(
                        FlextLdifUtilitiesCollectionLdif.normalize_container(v)
                        for v in processed
                    )
                else:
                    result.append(
                        FlextLdifUtilitiesCollectionLdif.to_config_map_value(processed),
                    )
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                if on_error == "fail":
                    raise
                if on_error == "return":
                    return result
        return result

    pf = process_flatten

    @staticmethod
    def find_key(
        obj: t.MutableContainerMapping,
        *,
        predicate: Callable[[str, t.NormalizedValue], bool] | None = None,
    ) -> str | None:
        """Find first key matching predicate (mnemonic: fk)."""
        if not predicate:
            return next(iter(obj), None)
        for k, v in obj.items():
            if predicate(k, v):
                return k
        return None

    fk = find_key

    @staticmethod
    def find_val(
        obj: t.MutableContainerMapping,
        *,
        predicate: Callable[[str, t.NormalizedValue], bool] | None = None,
    ) -> t.NormalizedValue | None:
        """Find first value matching predicate (mnemonic: fv)."""
        if not predicate:
            return next(iter(obj.values()), None)
        for k, v in obj.items():
            if predicate(k, v):
                return v
        return None

    fv = find_val

    @classmethod
    def pairs(
        cls,
        d: t.MutableContainerMapping,
    ) -> MutableSequence[tuple[str, t.NormalizedValue]]:
        """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr)."""
        return list(d.items())

    pr = pairs

    @classmethod
    def props(cls, *keys: str) -> Callable[..., t.MutableContainerMapping]:
        """Props accessor using FlextUtilities.pick() directly (mnemonic: ps)."""

        def accessor(obj: t.NormalizedValue) -> t.MutableContainerMapping:
            match obj:
                case Mapping() as obj_mapping:
                    return {
                        key: FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                            obj_mapping.get(key, None),
                        )
                        for key in keys
                    }
                case _:
                    pass
            result_dict: t.MutableContainerMapping = {}
            for k in keys:
                if getattr(obj, k, None) is not None:
                    result_dict[k] = (
                        FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                            getattr(obj, k),
                        )
                    )
                else:
                    result_dict[k] = ""
            return result_dict

        return accessor

    ps = props

    @classmethod
    def path(cls, *keys: str) -> Callable[..., t.NormalizedValue]:
        """Path accessor using chain DSL (mnemonic: ph)."""

        def make_getter(
            key: str,
        ) -> Callable[..., t.NormalizedValue]:

            def getter_fn(obj: t.NormalizedValue) -> t.NormalizedValue:
                """Get value from t.NormalizedValue by key."""
                match obj:
                    case Mapping() as obj_mapping:
                        return FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                            obj_mapping.get(key, ""),
                        )
                    case _:
                        pass
                if getattr(obj, key, None) is not None:
                    return FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                        getattr(obj, key),
                    )
                return ""

            return getter_fn

        getters: MutableSequence[Callable[..., t.NormalizedValue]] = [
            make_getter(k) for k in keys
        ]

        def _path_getter(obj: t.NormalizedValue) -> t.NormalizedValue:
            return cls.chain(obj, *getters)

        return _path_getter

    ph = path

    @staticmethod
    def chain(
        value: t.NormalizedValue,
        *funcs: Callable[..., t.NormalizedValue],
    ) -> t.NormalizedValue:
        """Chain function calls (DSL helper, mnemonic: ch)."""
        result = value
        for func in funcs:
            result = func(result)
        return result

    ch = chain

    @classmethod
    def normalize_ldif(
        cls,
        value: str | MutableSequence[str] | tuple[str, ...] | set[str] | frozenset[str],
        other: str
        | MutableSequence[str]
        | tuple[str, ...]
        | set[str]
        | frozenset[str]
        | None = None,
        *,
        case: str = "lower",
    ) -> str | MutableSequence[str] | set[str] | bool:
        """Normalize for LDIF comparison (mnemonic: nz)."""

        def normalize_single(v: str) -> str:
            if case == "lower":
                return v.lower()
            if case == "upper":
                return v.upper()
            return v

        if other is not None:
            match (value, other):
                case [str() as value_str, str() as other_str]:
                    return normalize_single(value_str) == normalize_single(
                        other_str,
                    )
                case _:
                    pass
        match value:
            case str() as value_str:
                return normalize_single(value_str)
            case list() | tuple() as seq_value:
                return [normalize_single(str(v)) for v in seq_value]
            case set() | frozenset() as set_value:
                return {normalize_single(str(v)) for v in set_value}
            case _:
                return [normalize_single(str(v)) for v in value]

    nz = normalize_ldif

    @staticmethod
    def to_config_map_value(value: t.NormalizedValue) -> t.NormalizedValue:
        """Convert value to t.NormalizedValue (general value or str)."""
        if FlextUtilities.is_general_value_type(value):
            return value
        return str(value)

    @staticmethod
    def normalize_container(value: t.NormalizedValue) -> t.NormalizedValue:
        """Normalize a t.NormalizedValue to a canonical form."""
        if FlextUtilities.is_general_value_type(value):
            return value
        return str(value)

    @staticmethod
    def normalize_mapping(
        mapping: Mapping[str, t.NormalizedValue],
    ) -> t.MutableContainerMapping:
        """Normalize a mapping of objects to a standard dict form."""
        normalized: t.MutableContainerMapping = {}
        for key, value in mapping.items():
            normalized[str(key)] = FlextLdifUtilitiesCollectionLdif.normalize_container(
                value,
            )
        return normalized

    @staticmethod
    def is_no_arg_callable[R](
        func: Callable[..., R] | t.NormalizedValue,
    ) -> bool:
        """Check if callable accepts 0 arguments."""
        if not callable(func):
            return False
        try:
            sig = inspect.signature(func)
            return not sig.parameters
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_object_arg_callable[R](
        func: Callable[..., R] | t.NormalizedValue,
    ) -> bool:
        """Check if callable accepts 1 t.NormalizedValue argument."""
        if not callable(func):
            return False
        try:
            sig = inspect.signature(func)
            return len(sig.parameters) == 1
        except (ValueError, TypeError):
            return False


__all__ = ["FlextLdifUtilitiesCollectionLdif"]
