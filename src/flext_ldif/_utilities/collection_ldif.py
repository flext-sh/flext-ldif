"""LDIF-specific collection/merge/DSL utilities for FLEXT-LDIF."""

from __future__ import annotations

import contextlib
import inspect
import struct
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from typing import overload, override

from flext_core import FlextUtilities, r

from flext_ldif import t


class FlextLdifUtilitiesCollectionLdif:
    """LDIF-specific collection, merge, and DSL methods."""

    type VariadicCallable[T] = Callable[..., T]

    @classmethod
    def defaults(
        cls,
        *dicts: t.MutableContainerMapping | None,
    ) -> t.MutableContainerMapping:
        """Defaults merge - first wins using FlextUtilities.flow() DSL (mnemonic: df)."""
        if not dicts:
            return {}

        def apply_defaults(
            acc: t.NormalizedValue,
            d: t.NormalizedValue,
        ) -> t.NormalizedValue:
            """Apply defaults using fold() pattern: first wins, later fill missing/None."""
            match (acc, d):
                case [dict() as acc_dict, dict() as d_dict]:
                    pass
                case _:
                    return acc
            filtered = cls.map_dict(
                d_dict,
                predicate=lambda k, _v: k not in acc_dict or acc_dict.get(k) is None,
            )
            acc_dict.update(filtered)
            return acc_dict

        dict_list = [dict_item for dict_item in dicts if isinstance(dict_item, dict)]
        if dict_list:
            result = cls.fold(dict_list, folder=apply_defaults, initial={})
            return result if isinstance(result, dict) else {}
        return {}

    d = defaults

    @classmethod
    def deep_merge(
        cls,
        *dicts: t.MutableContainerMapping | None,
    ) -> t.MutableContainerMapping:
        """Deep merge using FlextUtilities.merge() with deep strategy (mnemonic: dm)."""
        if not dicts:
            return {}
        mapping_list: MutableSequence[t.MutableContainerMapping] = [
            dict_item for dict_item in dicts if isinstance(dict_item, dict)
        ]
        if not mapping_list:
            return {}
        merged: t.MutableContainerMapping = {
            key: FlextLdifUtilitiesCollectionLdif.to_config_map_value(value)
            for key, value in dict(mapping_list[0]).items()
        }
        for mapping in mapping_list[1:]:
            mapping_dict: t.MutableContainerMapping = {
                key: FlextLdifUtilitiesCollectionLdif.to_config_map_value(value)
                for key, value in dict(mapping).items()
            }
            merge_result = FlextUtilities.merge(
                merged,
                mapping_dict,
                strategy="deep",
            )
            if merge_result.is_success:
                merged = merge_result.value
        return merged

    dm = deep_merge

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
    def _apply_deep_defaults_recursive(
        cls,
        acc: t.NormalizedValue,
        d: t.NormalizedValue,
    ) -> t.NormalizedValue:
        """Apply deep defaults recursively: first wins, recurse nested."""
        match (acc, d):
            case [dict() as acc_dict, dict() as d_dict]:
                pass
            case _:
                return acc
        for k, v in d_dict.items():
            if k not in acc_dict:
                acc_dict[k] = v
            else:
                current = acc_dict[k]
                match (current, v):
                    case [dict() as current_dict, dict() as v_dict]:
                        acc_dict[k] = cls.defaults_deep(current_dict, v_dict)
                    case _:
                        pass
        return acc_dict

    @classmethod
    def defaults_deep(
        cls,
        *dicts: t.MutableContainerMapping | None,
    ) -> t.MutableContainerMapping:
        """Deep defaults using FlextUtilities.merge() deep strategy + first wins (mnemonic: dd)."""
        if not dicts:
            return {}
        dict_list = [
            dict_item for dict_item in reversed(dicts) if isinstance(dict_item, dict)
        ]
        if not dict_list:
            return {}
        result = FlextLdifUtilitiesCollectionLdif.fold(
            dict_list,
            folder=cls._apply_deep_defaults_recursive,
            initial={},
        )
        return result if isinstance(result, dict) else {}

    dd = defaults_deep

    @staticmethod
    def merge_dicts(
        *dicts: t.MutableContainerMapping,
        strategy: str = "deep",
        filter_none: bool = False,
        filter_empty: bool = False,
    ) -> r[t.MutableContainerMapping]:
        """Merge multiple dicts with filtering options (mnemonic: mg)."""
        dicts_typed: tuple[t.MutableContainerMapping, ...] = dicts
        if not dicts_typed:
            return r[t.MutableContainerMapping].ok({})
        merged: t.MutableContainerMapping = {}
        for dict_item in dicts_typed:
            dict_item_dict: t.MutableContainerMapping = dict(dict_item)
            merge_result = FlextUtilities.merge(
                merged,
                dict_item_dict,
                strategy=strategy,
            )
            if merge_result.is_failure:
                return r[t.MutableContainerMapping].fail(
                    merge_result.error or "Merge failed",
                )
            merged = merge_result.value
        if filter_none or filter_empty:
            filtered: t.MutableContainerMapping = {}
            for key, value in merged.items():
                if filter_empty and FlextLdifUtilitiesCollectionLdif.is_empty_value(
                    value
                ):
                    continue
                filtered[key] = value
            merged = filtered
        return r[t.MutableContainerMapping].ok(merged)

    mg = merge_dicts

    @classmethod
    @override
    def group_by(
        cls,
        items: t.MutableContainerList,
        *,
        key: Callable[..., t.NormalizedValue],
    ) -> MutableMapping[t.NormalizedValue, t.MutableContainerList]:
        """Group by key function (generalized, mnemonic: gb)."""
        items_list = list(items)
        result: MutableMapping[t.NormalizedValue, t.MutableContainerList] = {}
        for item in items_list:
            k = key(item)
            if k not in result:
                result[k] = []
            result[k].append(item)
        return result

    gb = group_by

    @classmethod
    @override
    def partition(
        cls,
        items: t.MutableContainerList,
        *,
        predicate: Callable[..., bool],
    ) -> tuple[t.MutableContainerList, t.MutableContainerList]:
        """Partition items by predicate into (matches, non-matches) (mnemonic: pt)."""
        matches: t.MutableContainerList = []
        non_matches: t.MutableContainerList = []
        for item in items:
            if predicate(item):
                matches.append(item)
            else:
                non_matches.append(item)
        return (matches, non_matches)

    pt = partition

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

    @classmethod
    @override
    def pluck(
        cls,
        items: t.MutableContainerList,
        *,
        key: str | int | Callable[..., t.NormalizedValue],
    ) -> t.MutableContainerList:
        """Extract values from sequence by key/index/function (mnemonic: pk)."""
        result: t.MutableContainerList = []
        for item in items:
            if callable(key):
                result.append(key(item))
            elif isinstance(key, str):
                match item:
                    case Mapping() as item_mapping:
                        result.append(item_mapping.get(key))
                    case _:
                        if getattr(item, str(key), None) is not None:
                            result.append(getattr(item, str(key)))
                        else:
                            result.append(None)
            else:
                match item:
                    case Sequence() as item_sequence:
                        result.append(
                            item_sequence[key] if len(item_sequence) > key else None,
                        )
                    case _:
                        if getattr(item, str(key), None) is not None:
                            result.append(getattr(item, str(key)))
                        else:
                            result.append(None)
        return result

    pk = pluck

    @staticmethod
    @override
    def count[T](
        items: MutableSequence[T] | tuple[T, ...],
        predicate: Callable[[T], bool] | None = None,
    ) -> int:
        """Count items (generalized: uses count from base, mnemonic: ct)."""
        if predicate is not None:
            filtered_items = [item for item in items if predicate(item)]
            return FlextUtilities.count(filtered_items)
        return FlextUtilities.count(items)

    ct = count

    @classmethod
    @override
    def omit(
        cls,
        data: t.MutableContainerMapping,
        *keys: str,
    ) -> t.MutableContainerMapping:
        """Omit keys using FlextUtilities.map_dict() DSL (mnemonic: om)."""
        if not data or not keys:
            return dict(data) if data else {}
        keys_set = set(keys)
        return cls.map_dict(data, predicate=lambda k, _: k not in keys_set)

    om = omit

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

    @staticmethod
    @override
    def take(
        data_or_items: t.NormalizedValue,
        key_or_n: str | int,
        *,
        as_type: type | None = None,
        default: t.NormalizedValue | None = None,
        from_start: bool = True,
    ) -> t.MutableContainerMapping | t.MutableContainerList | t.NormalizedValue | None:
        """Take value from data with type guard (mnemonic: tk)."""
        if isinstance(key_or_n, str):
            value: t.NormalizedValue = None
            match data_or_items:
                case Mapping() as mapping_items:
                    raw_value = mapping_items.get(key_or_n, default)
                    value = FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                        raw_value
                    )
                case _ if getattr(data_or_items, key_or_n, None) is not None:
                    raw_attr = getattr(data_or_items, key_or_n, default)
                    value = FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                        raw_attr
                    )
                case _:
                    value = default
            if as_type is not None and value is not None:
                if FlextUtilities.is_type(value, as_type):
                    return value
                return default
            return value
        n: int = key_or_n
        match data_or_items:
            case dict() as dict_items:
                items = list(dict_items.items())
                sliced = items[:n] if from_start else items[-n:]
                sliced_dict: t.MutableContainerMapping = {
                    key: FlextLdifUtilitiesCollectionLdif.to_config_map_value(value)
                    for key, value in sliced
                }
                return sliced_dict
            case list() | tuple() as seq_items:
                if from_start:
                    return list(seq_items[:n])
                return list(seq_items[-n:])
            case _:
                pass
        return default

    tk = take

    @classmethod
    @override
    def try_[T](
        cls,
        func: Callable[[], T],
        *,
        default: T | None = None,
        catch: type[Exception] | tuple[type[Exception], ...] = Exception,
    ) -> T | None:
        """Try executing function, return default on exception (mnemonic: tr)."""
        try:
            return func()
        except Exception as exc:
            if isinstance(exc, catch):
                return default
            raise

    tr = try_

    @staticmethod
    @override
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
    @override
    def unwrap_or[T](result: r[T], *, default: T | None = None) -> T | None:
        """Unwrap r with default value."""
        if result.is_success:
            return result.value
        return default

    @staticmethod
    @override
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
    def pipe_ldif(
        value: t.NormalizedValue,
        *ops: t.MutableContainerMapping | Callable[..., t.NormalizedValue],
    ) -> t.NormalizedValue:
        """LDIF-specific pipe - supports dict operations via flow()."""
        result: t.NormalizedValue = value
        for op in ops:
            match op:
                case dict() as op_dict:
                    current: t.NormalizedValue = result
                    match current:
                        case dict() as current_dict:
                            result = {**current_dict, **op_dict}
                        case _:
                            result = op_dict
                case _ if callable(op):
                    result = op(result)
                case _:
                    pass
        return result

    @staticmethod
    def pp(
        value: t.NormalizedValue,
        *ops: t.MutableContainerMapping | Callable[..., t.NormalizedValue],
    ) -> t.NormalizedValue:
        """Alias for pipe_ldif (mnemonic: pp)."""
        return FlextLdifUtilitiesCollectionLdif.pipe_ldif(value, *ops)

    @classmethod
    def guard_simple[T](
        cls,
        value: T,
        *,
        check: Callable[[T], bool] | bool,
        default: T | None = None,
    ) -> T | None:
        """Simple guard using check pattern (mnemonic: gd)."""
        check_result = check(value) if callable(check) else bool(check)
        return value if check_result else default

    gd = guard_simple

    @classmethod
    def let(
        cls,
        value: t.NormalizedValue,
        *,
        fn: Callable[..., t.NormalizedValue],
    ) -> t.NormalizedValue:
        """Let using chain() (mnemonic: lt)."""
        return FlextLdifUtilitiesCollectionLdif.chain(value, fn)

    lt = let

    @classmethod
    @override
    def apply(
        cls,
        fn: FlextLdifUtilitiesCollectionLdif.VariadicCallable[t.NormalizedValue]
        | t.NormalizedValue,
        *args: t.NormalizedValue,
        **kwargs: t.Scalar,
    ) -> t.NormalizedValue:
        """Apply function (mnemonic: ap)."""
        if callable(fn):
            return fn(*args, **kwargs)
        return fn

    ap = apply

    @classmethod
    def bind(
        cls,
        value: t.NormalizedValue,
        *fns: Callable[..., t.NormalizedValue],
    ) -> t.NormalizedValue:
        """Bind using chain() (mnemonic: bd)."""
        return FlextLdifUtilitiesCollectionLdif.chain(value, *fns)

    bd = bind

    @classmethod
    def lift(
        cls,
        fn: Callable[..., t.NormalizedValue],
    ) -> Callable[..., t.NormalizedValue | None]:
        """Lift function for optionals (mnemonic: lf)."""

        def lifted_fn(v: t.NormalizedValue) -> t.NormalizedValue | None:
            """Lifted function with safe None handling using DSL."""
            return FlextLdifUtilitiesCollectionLdif.maybe(
                cls.tr(lambda: fn(v), default=None),
                default=None,
            )

        return lifted_fn

    lf = lift

    @classmethod
    def seq(cls, *values: t.NormalizedValue) -> t.MutableContainerList:
        """Sequence constructor (mnemonic: sq)."""
        return list(values)

    sq = seq

    @classmethod
    def assoc(
        cls,
        data: t.MutableContainerMapping,
        key: str,
        value: t.NormalizedValue,
    ) -> t.MutableContainerMapping:
        """Associate key-value using FlextUtilities.merge() DSL (mnemonic: ac)."""
        updated = dict(data)
        updated[key] = value
        return updated

    ac = assoc

    @classmethod
    def dissoc(
        cls,
        data: t.MutableContainerMapping,
        *keys: str,
    ) -> t.MutableContainerMapping:
        """Dissociate keys using omit DSL (mnemonic: ds)."""
        return {k: v for k, v in data.items() if k not in keys}

    ds = dissoc

    @classmethod
    @override
    def update(
        cls,
        data: t.MutableContainerMapping,
        updates: t.MutableContainerMapping,
    ) -> t.MutableContainerMapping:
        """Update dict using FlextUtilities.merge() (mnemonic: ud)."""
        updated = dict(data)
        updated.update(updates)
        return updated

    ud = update

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
    @override
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
                        pred
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
    def when[T](
        cls,
        *,
        condition: bool = False,
        then_value: T | None = None,
        else_value: T | None = None,
    ) -> T | None:
        """Functional conditional (DSL pattern)."""
        return then_value if condition else else_value

    @classmethod
    def thru(
        cls,
        value: t.NormalizedValue,
        *,
        fn: Callable[..., t.NormalizedValue],
    ) -> t.NormalizedValue:
        """Thru using direct call (mnemonic: th)."""
        return fn(value)

    th = thru

    @classmethod
    def comp(
        cls, *fns: Callable[..., t.NormalizedValue]
    ) -> Callable[..., t.NormalizedValue]:
        """Compose using FlextUtilities.chain() (mnemonic: cp)."""
        if not fns:
            return lambda x: x
        return lambda value: cls.chain(value, *fns)

    cp = comp

    @classmethod
    def juxt(
        cls,
        *fns: Callable[..., t.NormalizedValue],
    ) -> Callable[..., tuple[t.NormalizedValue, ...]]:
        """Juxtapose functions (mnemonic: jx)."""
        if not fns:
            return lambda _x: ()
        return lambda value: tuple(fn(value) for fn in fns)

    jx = juxt

    @classmethod
    def curry(
        cls,
        fn: Callable[..., t.NormalizedValue],
        *args: t.NormalizedValue,
    ) -> Callable[..., t.NormalizedValue]:
        """Curry function (mnemonic: cy)."""

        def curried(
            *more_args: t.NormalizedValue,
            **_kwargs: t.Scalar,
        ) -> t.NormalizedValue:
            combined_args: tuple[t.NormalizedValue, ...] = args + more_args
            converted_args: t.MutableContainerList = []
            for arg in combined_args:
                match arg:
                    case None:
                        converted_args.append(None)
                    case list() | tuple() | dict() | Mapping():
                        converted_args.append(arg)
                    case _:
                        converted_args.append(str(arg))
            if not converted_args:
                result = fn()
            elif len(converted_args) == 1:
                result = fn(converted_args[0])
            else:
                result = fn(*converted_args)
            return result

        return curried

    cy = curry

    @classmethod
    def evolve(
        cls,
        obj: t.MutableContainerMapping,
        *transforms: t.MutableContainerMapping
        | Callable[
            [t.MutableContainerMapping],
            t.MutableContainerMapping,
        ],
    ) -> t.MutableContainerMapping:
        """Evolve using FlextUtilities.flow() pattern (mnemonic: ev)."""
        result: t.MutableContainerMapping = dict(obj)
        for transform in transforms:
            if callable(transform) and (not isinstance(transform, Mapping)):
                transformed = transform(result)
                result = FlextLdifUtilitiesCollectionLdif.normalize_mapping(transformed)
            else:
                continue
        return result

    ev = evolve

    @staticmethod
    @override
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
    def maybe(
        value: t.NormalizedValue | None,
        *,
        default: t.NormalizedValue | None = None,
        mapper: Callable[..., t.NormalizedValue] | None = None,
    ) -> t.NormalizedValue | None:
        """Maybe monad pattern (mnemonic: mb)."""
        if value is None:
            return default
        if mapper:
            return mapper(value)
        return value

    mb = maybe

    @staticmethod
    @override
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

    @staticmethod
    @override
    def pick(
        data: t.NormalizedValue,
        *keys: str,
        as_dict: bool = True,
    ) -> t.MutableContainerMapping | t.MutableContainerList:
        """Pick keys from dict (DSL helper, mnemonic: pc)."""
        if not isinstance(data, Mapping):
            return {} if as_dict else []

        data_mapping: t.MutableContainerMapping = {
            str(key): FlextLdifUtilitiesCollectionLdif.to_config_map_value(value)
            for key, value in data.items()
        }
        if as_dict:
            return {k: data_mapping[k] for k in keys if k in data_mapping}
        return [data_mapping[k] for k in keys if k in data_mapping]

    pc = pick

    @staticmethod
    def map_dict(
        obj: t.MutableContainerMapping,
        *,
        mapper: Callable[[str, t.NormalizedValue], t.NormalizedValue] | None = None,
        key_mapper: Callable[[str], str] | None = None,
        predicate: Callable[[str, t.NormalizedValue], bool] | None = None,
    ) -> t.MutableContainerMapping:
        """Map dict with optional transformations (mnemonic: md)."""
        result: t.MutableContainerMapping = {}
        for k, v in obj.items():
            if predicate and (not predicate(k, v)):
                continue
            new_k = key_mapper(k) if key_mapper else k
            new_v: t.NormalizedValue = mapper(k, v) if mapper else v
            result[new_k] = new_v
        return result

    md = map_dict

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
                        value
                    )
                    for key, value in items.items()
                },
            ]
        elif isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
            for item in items:
                if isinstance(item, Mapping):
                    items_list.append({
                        str(key): FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                            value
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
    @override
    def fold(
        items: t.NormalizedValue,
        *,
        initial: t.NormalizedValue,
        folder: Callable[[t.NormalizedValue, t.NormalizedValue], t.NormalizedValue]
        | None = None,
        predicate: Callable[..., bool] | None = None,
    ) -> t.NormalizedValue:
        """Fold items using folder function (mnemonic: fd)."""
        if not folder:
            return initial
        items_list: t.MutableContainerList
        if isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
            items_list = [
                FlextLdifUtilitiesCollectionLdif.to_config_map_value(item)
                for item in items
            ]
        else:
            items_list = [FlextLdifUtilitiesCollectionLdif.to_config_map_value(items)]
        if predicate:
            items_list = [item for item in items_list if predicate(item)]
        result: t.NormalizedValue = initial
        for item in items_list:
            result = folder(result, item)
        return result

    fd = fold

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
        cls, d: t.MutableContainerMapping
    ) -> MutableSequence[tuple[str, t.NormalizedValue]]:
        """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr)."""
        return list(d.items())

    pr = pairs

    @staticmethod
    @override
    def is_type(
        value: t.NormalizedValue,
        type_spec: str | type | tuple[type, ...],
    ) -> bool:
        """Type check using FlextUtilities.build() DSL (mnemonic: it)."""
        types_tuple: tuple[str | type, ...] = (
            type_spec if isinstance(type_spec, tuple) else (type_spec,)
        )
        type_map = {
            "list": list,
            "dict": dict,
            "str": str,
            "int": int,
            "bool": bool,
            "tuple": tuple,
        }
        for tuple_ in types_tuple:
            resolved_type: type | None = (
                type_map.get(tuple_) if isinstance(tuple_, str) else tuple_
            )
            if resolved_type is not None and FlextUtilities.is_type(
                value,
                resolved_type,
            ):
                return True
        return False

    @classmethod
    @override
    def prop(cls, key: str) -> Callable[..., t.NormalizedValue]:
        """Property accessor using FlextUtilities.get() (mnemonic: pp)."""

        def getter(obj: t.NormalizedValue) -> t.NormalizedValue:
            """Get value from t.NormalizedValue by key."""
            match obj:
                case Mapping() as obj_mapping:
                    return FlextLdifUtilitiesCollectionLdif.to_config_map_value(
                        obj_mapping.get(key),
                    )
                case _:
                    pass
            if getattr(obj, key, None) is not None:
                return getattr(obj, key)
            return None

        return getter

    prop_get = prop

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
        """Path accessor using FlextUtilities.chain() DSL (mnemonic: ph)."""

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
        return lambda obj: cls.chain(obj, *getters)

    ph = path

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
