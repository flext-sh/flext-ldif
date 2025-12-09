"""Pure functional utilities for FLEXT-LDIF.

This module provides pure functional utilities that can be imported
without circular dependencies. These methods are extracted from
FlextLdifUtilities to break the circular import between utilities.py
and acl.py.

CRITICAL: This module MUST NOT import from:
- flext_ldif.utilities (circular)
- flext_ldif._utilities.acl (circular)

Only imports from flext_core and Python stdlib are allowed.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping, Sequence
from inspect import Parameter, signature
from typing import Literal, TypeVar, cast

from flext_core import FlextUtilities as u_core

# TypeVars for generic methods
T = TypeVar("T")
U = TypeVar("U")
V = TypeVar("V")


class FlextFunctional:
    """Pure functional utilities without circular dependencies.

    All methods are static or class methods that operate on pure data
    without requiring any LDIF-specific imports.

    Mnemonics:
        oo = or_         (first non-None)
        mb = maybe       (maybe monad)
        ch = chain       (chain functions)
        pc = pick        (pick keys)
        md = map_dict    (map dictionary)
        rd = reduce_dict (reduce dictionary)
        fd = fold        (fold items)
        mf = map_filter  (map then filter)
        pf = process_flatten (process and flatten)
        fk = find_key    (find key by predicate)
        fv = find_val    (find value by predicate)
        pr = pairs       (dict to pairs)
        mt = match       (pattern match)
        sw = switch      (dict-based switch)
        it = is_type     (type check)
        at = as_type     (safe cast)
        nl = normalize_list (normalize to list)
        wh = when        (conditional)
        pp = prop        (property accessor)
        ps = props       (multiple props)
        ph = path        (path accessor)
    """

    # -------------------------------------------------------------------------
    # Core Functional Combinators
    # -------------------------------------------------------------------------

    @staticmethod
    def or_[T](
        *values: T | None,
        default: T | None = None,
    ) -> T | None:
        """Return first non-None value (mnemonic: oo).

        Args:
            *values: Values to check for non-None
            default: Default value if all are None

        Returns:
            First non-None value or default

        Example:
            >>> FlextFunctional.or_(None, "a", "b")
            'a'
            >>> FlextFunctional.oo(None, None, default="x")
            'x'

        """
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
        """Maybe monad pattern (mnemonic: mb).

        Args:
            value: Value to process (may be None)
            default: Default value if value is None
            mapper: Optional function to apply if value is not None

        Returns:
            Mapped value, original value, or default

        Example:
            >>> FlextFunctional.maybe(None, default="none")
            'none'
            >>> FlextFunctional.mb("hello", mapper=str.upper)
            'HELLO'

        """
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
        """Chain function calls (DSL helper, mnemonic: ch).

        Args:
            value: Initial value to process
            *funcs: Functions to apply in sequence

        Returns:
            Result after applying all functions

        Example:
            >>> FlextFunctional.chain("hello", str.upper, lambda s: s + "!")
            'HELLO!'

        """
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
        """Pick keys from dict (DSL helper, mnemonic: pc).

        Args:
            data: Dictionary to pick from
            *keys: Keys to pick
            as_dict: If True, return dict; if False, return list of values

        Returns:
            Dictionary with picked keys or list of values

        Example:
            >>> FlextFunctional.pick({"a": 1, "b": 2, "c": 3}, "a", "c")
            {'a': 1, 'c': 3}
            >>> FlextFunctional.pc({"a": 1, "b": 2}, "a", "b", as_dict=False)
            [1, 2]

        """
        if as_dict:
            return {k: data[k] for k in keys if k in data}
        return [data[k] for k in keys if k in data]

    pc = pick

    # -------------------------------------------------------------------------
    # Dictionary Operations
    # -------------------------------------------------------------------------

    @staticmethod
    def map_dict[T, U](
        data: dict[str, T],
        mapper: Callable[[str, T], tuple[str, U]],
    ) -> dict[str, U]:
        """Map dict with transformations (mnemonic: md).

        Args:
            data: Dictionary to map
            mapper: Function (key, value) -> (new_key, new_value)

        Returns:
            New dictionary with transformed keys and values

        Example:
            >>> FlextFunctional.map_dict({"a": 1}, lambda k, v: (k.upper(), v * 2))
            {'A': 2}

        """
        result: dict[str, U] = {}
        for key, value in data.items():
            new_key, new_value = mapper(key, value)
            result[new_key] = new_value
        return result

    md = map_dict

    @staticmethod
    def reduce_dict[T, U](
        data: dict[str, T],
        *,
        processor: Callable[[str, T], U] | None = None,
        predicate: Callable[[str, T], bool] = lambda _k, _v: True,
        key_mapper: Callable[[str], str] = lambda k: k,
    ) -> dict[str, U]:
        """Reduce dicts with processor/predicate (mnemonic: rd).

        Args:
            data: Dictionary to reduce
            processor: Function to process each value (identity if None)
            predicate: Function to filter key-value pairs
            key_mapper: Function to transform keys

        Returns:
            Reduced dictionary

        Example:
            >>> FlextFunctional.reduce_dict(
            ...     {"a": 1, "b": 2, "c": 3},
            ...     predicate=lambda k, v: v > 1,
            ...     processor=lambda k, v: v * 10,
            ... )
            {'b': 20, 'c': 30}

        """
        result: dict[str, U] = {}
        for key, value in data.items():
            if predicate(key, value):
                new_key = key_mapper(key)
                if processor is not None:
                    result[new_key] = processor(key, value)
                else:
                    # When processor is None, T must be compatible with U
                    # Type narrowing: value is U when processor is None
                    # Runtime check ensures type compatibility
                    # For generic types, we rely on runtime validation
                    result[new_key] = cast("U", value)
        return result

    rd = reduce_dict

    @staticmethod
    def find_key[T](
        data: dict[str, T] | T,
        predicate: Callable[[str, T], bool],
        *,
        default: str | None = None,
    ) -> str | None:
        """Find first key matching predicate (mnemonic: fk).

        Args:
            data: Dictionary to search
            predicate: Function (key, value) -> bool
            default: Default key if not found

        Returns:
            First matching key or default

        Example:
            >>> FlextFunctional.find_key({"a": 1, "b": 2}, lambda k, v: v == 2)
            'b'

        """
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
        """Find first value matching predicate (mnemonic: fv).

        Args:
            data: Dictionary to search
            predicate: Function (key, value) -> bool
            default: Default value if not found

        Returns:
            First matching value or default

        Example:
            >>> FlextFunctional.find_val({"a": 1, "b": 2}, lambda k, v: k == "b")
            2

        """
        for key, value in data.items():
            if predicate(key, value):
                return value
        return default

    fv = find_val

    @staticmethod
    def pairs[T](
        d: dict[str, T] | Mapping[str, T],
    ) -> list[tuple[str, T]]:
        """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr).

        Args:
            d: Dictionary or mapping to convert

        Returns:
            List of (key, value) tuples

        Example:
            >>> FlextFunctional.pairs({"a": 1, "b": 2})
            [('a', 1), ('b', 2)]

        """
        return list(d.items())

    pr = pairs

    # -------------------------------------------------------------------------
    # Collection Operations
    # -------------------------------------------------------------------------

    @staticmethod
    def fold[T, U](
        items: Sequence[T] | T,
        folder: Callable[[U, T], U],
        initial: U,
    ) -> U:
        """Fold items using folder function (mnemonic: fd).

        Args:
            items: Sequence to fold
            folder: Function (accumulator, item) -> new_accumulator
            initial: Initial accumulator value

        Returns:
            Final accumulated value

        Example:
            >>> FlextFunctional.fold([1, 2, 3], lambda acc, x: acc + x, 0)
            6

        """
        if not isinstance(items, (list, tuple)):
            return initial
        result = initial
        # Type narrowing: items is Sequence[T] after isinstance check
        # isinstance narrows to list | tuple, both are Sequence[T]
        for item in items:
            result = folder(result, item)
        return result

    fd = fold

    @staticmethod
    def map_filter[T](
        items: Sequence[T] | T,
        mapper: Callable[[T], T] | None = None,
        predicate: Callable[[object], bool] = lambda x: x is not None,
    ) -> list[T]:
        """Map then filter items (mnemonic: mf).

        Args:
            items: Sequence to process
            mapper: Function to transform each item (identity if None)
            predicate: Function to filter results (default: non-None)

        Returns:
            List of mapped and filtered items

        Example:
            >>> FlextFunctional.map_filter(
            ...     [1, 2, 3], lambda x: x * 2 if x > 1 else None
            ... )
            [4, 6]

        """
        if not isinstance(items, (list, tuple)):
            return []
        result: list[T] = []
        # Type narrowing: items is Sequence[T] after isinstance check
        # isinstance narrows to list | tuple, both are Sequence[T]
        for item in items:
            if mapper is not None:
                mapped: T = mapper(item)
            else:
                # When no mapper provided, item is already T
                mapped: T = item
            if predicate(mapped):
                result.append(mapped)
        return result

    mf = map_filter

    @staticmethod
    def process_flatten[T, U](
        items: Sequence[T] | T,
        processor: Callable[[T], Sequence[U] | U],
        *,
        predicate: Callable[[object], bool] = lambda x: x is not None,
        on_error: Literal["skip", "stop", "collect"] = "skip",
    ) -> list[U]:
        """Process and flatten items (mnemonic: pf).

        Args:
            items: Sequence to process
            processor: Function that may return single value or sequence
            predicate: Function to filter results
            on_error: Error handling mode:
                - "skip": Continue processing, skip items that raise exceptions
                - "stop": Re-raise first exception encountered
                - "collect": Accumulate errors and return successfully-processed items

        Returns:
            Flattened list of processed items

        Example:
            >>> FlextFunctional.process_flatten([1, 2], lambda x: [x, x * 2])
            [1, 2, 2, 4]

        """
        if not isinstance(items, (list, tuple)):
            return []
        result: list[U] = []
        # Type narrowing: items is Sequence[T] after isinstance check
        # isinstance narrows to list | tuple, both are Sequence[T]
        for item in items:
            try:
                processed = processor(item)
                if isinstance(processed, (list, tuple)):
                    # Type narrowing: processed is Sequence[U] after isinstance check
                    # isinstance narrows to list | tuple, both are Sequence[U]
                    result.extend([
                        sub_item for sub_item in processed if predicate(sub_item)
                    ])
                # Single value (not list/tuple), predicate checks it
                # Type narrowing: isinstance(processed, (list, tuple)) is False
                # so processed is U in this branch
                elif predicate(processed):
                    # processed is U when not a sequence
                    # Runtime check ensures type compatibility
                    result.append(processed)
            except Exception:
                if on_error == "stop":
                    raise
                # "skip" and "collect" both continue processing
        return result

    pf = process_flatten

    @staticmethod
    def build[T](
        value: T,
        ops: dict[str, Callable[[T], T]],
    ) -> T:
        """Build value using operations dict.

        Args:
            value: Initial value
            ops: Dictionary of named operations to apply in sequence

        Returns:
            Result after applying all operations

        Example:
            >>> FlextFunctional.build(
            ...     "hello", {"upper": str.upper, "exclaim": lambda s: s + "!"}
            ... )
            'HELLO!'

        """
        result = value
        for op in ops.values():
            result = op(result)
        return result

    # -------------------------------------------------------------------------
    # List Normalization
    # -------------------------------------------------------------------------

    @classmethod
    def normalize_list[T, U](
        cls,
        value: T | Sequence[T] | None,
        *,
        mapper: Callable[[T], U] | None = None,
        predicate: Callable[[T | U], bool] | None = None,
        default: list[T] | None = None,
    ) -> list[T] | list[U]:
        """Normalize to list (mnemonic: nl).

        Converts any value to a list, with optional mapping and filtering.

        Args:
            value: Value to normalize (single item or sequence)
            mapper: Optional function to apply to each item
            predicate: Optional function to filter items
            default: Default list if value is None

        Returns:
            Normalized list

        Example:
            >>> FlextFunctional.normalize_list("hello")
            ['hello']
            >>> FlextFunctional.nl([1, 2, 3], mapper=lambda x: x * 2)
            [2, 4, 6]

        """
        default_list = default if default is not None else []

        # Normalize value to Sequence[T] | None for or_
        # isinstance narrows to list | tuple, both are Sequence[T]
        if isinstance(value, (list, tuple)):
            value_seq: Sequence[T] | None = value
        elif value is None:
            value_seq = None
        else:
            # Single value wrapped in list becomes Sequence[T]
            value_seq: Sequence[T] | None = [value]

        # Use or_ DSL for None handling
        extracted = cls.or_(value_seq, default=default_list)

        # Ensure list - extracted is always Sequence[T] from or_
        if isinstance(extracted, (list, tuple)):
            items_raw: list[T] = list(extracted)
        elif extracted is None:
            items_raw = []
        else:
            # extracted is Sequence[T] (e.g., from default), convert to list
            items_raw = list(extracted)

        # Apply mapper if provided
        items_result: list[T] | list[U]
        if mapper is not None:
            # Type narrowing: items is list[T] after normalization
            items_mapped: list[U] = [mapper(item) for item in items_raw]
            # After mapper, items becomes list[U], but return type is list[T] | list[U]
            items_result = items_mapped
        else:
            # Without mapper, items remains list[T]
            items_result = items_raw

        # Apply predicate if provided
        if predicate is not None:
            # Type narrowing: items is list[T] or list[U] after mapper
            # Filter items and maintain type
            if mapper is not None:
                # items_result is list[U] after mapper
                # Type narrowing: item is U in list[U]
                items_result = [
                    item
                    for item in items_result
                    if predicate(item)
                ]
            else:
                # items_result is list[T] without mapper
                # Type narrowing: item is T in list[T]
                items_result = [
                    item
                    for item in items_result
                    if predicate(item)
                ]

        return items_result

    nl = normalize_list

    # -------------------------------------------------------------------------
    # Dictionary Operations
    # -------------------------------------------------------------------------

    @staticmethod
    def get[T](
        data: dict[str, T] | T,
        key: str,
        default: T | None = None,
    ) -> T | None:
        """Get value from dict with default (mnemonic: gt).

        Args:
            data: Dictionary to get from
            key: Key to retrieve
            default: Default value if key not found

        Returns:
            Value at key, or default if not found

        Example:
            >>> FlextFunctional.get({"a": 1, "b": 2}, "a")
            1
            >>> FlextFunctional.gt({"a": 1}, "x", default=None)
            None

        """
        return u_core.mapper().get(data, key, default=default)

    gt = get

    @staticmethod
    def merge[T](
        *dicts: dict[str, T],
    ) -> dict[str, T]:
        """Merge multiple dicts (mnemonic: mg).

        Later dicts override earlier ones.

        Args:
            *dicts: Dictionaries to merge

        Returns:
            Merged dictionary

        Example:
            >>> FlextFunctional.merge({"a": 1}, {"b": 2})
            {'a': 1, 'b': 2}
            >>> FlextFunctional.mg({"a": 1}, {"a": 2})
            {'a': 2}

        """
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
        """Update dict with changes (mnemonic: ev).

        Creates a new dict with updates applied.

        Args:
            data: Original dictionary
            updates: Updates to apply

        Returns:
            New dictionary with updates applied

        Example:
            >>> FlextFunctional.evolve({"a": 1, "b": 2}, {"b": 3})
            {'a': 1, 'b': 3}

        """
        return {**data, **updates}

    ev = evolve

    # -------------------------------------------------------------------------
    # Conditional Operations
    # -------------------------------------------------------------------------

    @staticmethod
    def when[T](
        *,
        condition: bool = False,
        then: T | Callable[[], T] | None = None,
        else_: T | None = None,
    ) -> T | None:
        """Functional conditional (DSL pattern, mnemonic: wh).

        Args:
            condition: Boolean condition to check
            then: Value or callable to return if condition is True
            else_: Value to return if condition is False

        Returns:
            then (or its result if callable) if condition else else_

        Example:
            >>> FlextFunctional.when(condition=True, then="yes", else_="no")
            'yes'
            >>> FlextFunctional.when(condition=True, then=lambda: "computed")
            'computed'

        """
        if condition:
            # If then is callable, call it to get the value
            if callable(then):
                # Type narrowing: callable returns T
                return then()
            # Type narrowing: then is T | None
            return then
        # Type narrowing: else_ is T | None
        return else_

    wh = when

    @staticmethod
    def cond[T, U](
        *cases: tuple[
            Callable[[T], bool] | Callable[[], bool],
            Callable[[T], U] | Callable[[], U],
        ],
        default: U | None = None,
    ) -> Callable[[T], U | None]:
        """Conditional expression returning curried function (mnemonic: cd).

        Creates a function that evaluates conditions in order and returns
        the result of the first matching condition's result function.

        Args:
            *cases: Tuples of (condition_fn, result_fn)
                - condition_fn: Callable that takes 0 or 1 arg, returns bool
                - result_fn: Callable that takes 0 or 1 arg, returns value
            default: Default value if no condition matches

        Returns:
            Function that takes a value and evaluates conditions

        Example:
            >>> result = FlextFunctional.cond(
            ...     (lambda x: x > 10, lambda x: "large"),
            ...     (lambda x: x > 5, lambda x: "medium"),
            ...     default="small",
            ... )(7)
            'medium'

            >>> result = FlextFunctional.cond(
            ...     (lambda: True, lambda: "always"),
            ...     default="never",
            ... )()
            'always'

        """

        def _call_condition_fn(
            condition_fn: Callable[..., object], value: T | None
        ) -> bool:
            """Call condition function with appropriate signature."""
            try:
                sig = inspect.signature(condition_fn)
                param_count = len(sig.parameters)
                if param_count == 0:
                    result = condition_fn()
                    # Type narrowing: result is truthy/falsy, bool() converts to bool
                    return bool(result)
                if value is not None:
                    result = condition_fn(value)
                    # Type narrowing: result is truthy/falsy, bool() converts to bool
                    return bool(result)
            except (TypeError, ValueError):
                if value is not None:
                    try:
                        result = condition_fn(value)
                        # Type narrowing: result is truthy/falsy, bool() converts to bool
                        return bool(result)
                    except (TypeError, ValueError):
                        try:
                            result = condition_fn()
                            # Type narrowing: result is truthy/falsy, bool() converts to bool
                            return bool(result)
                        except (TypeError, ValueError):
                            pass
            return False

        def _call_result_fn(
            result_fn: Callable[..., U | None], value: T | None
        ) -> U | None:
            """Call result function with appropriate signature."""
            try:
                sig = inspect.signature(result_fn)
                param_count = len(sig.parameters)
                if param_count == 0:
                    return result_fn()
                if value is not None:
                    return result_fn(value)
            except (TypeError, ValueError):
                if value is not None:
                    try:
                        return result_fn(value)
                    except (TypeError, ValueError):
                        try:
                            return result_fn()
                        except (TypeError, ValueError):
                            pass
            return None

        def evaluator(value: T | None = None) -> U | None:
            for condition_fn, result_fn in cases:
                condition_result = _call_condition_fn(condition_fn, value)
                if condition_result:
                    result = _call_result_fn(result_fn, value)
                    if result is not None:
                        return result
            return default

        return evaluator

    cd = cond

    @staticmethod
    def pipe[T](
        initial: T,
        *transforms: Callable[[T], T],
    ) -> T:
        """Pipe value through transformation functions (mnemonic: pp).

        Threads a value through a sequence of transformation functions,
        where each function receives the result of the previous function.

        Args:
            initial: Starting value
            *transforms: Functions to apply in sequence

        Returns:
            Final transformed value

        Example:
            >>> FlextFunctional.pipe(
            ...     "  hello  ",
            ...     str.strip,
            ...     str.upper,
            ... )
            'HELLO'

            >>> FlextFunctional.pipe(
            ...     [1, 2, 3],
            ...     lambda x: [i * 2 for i in x],
            ...     sum,
            ... )
            12

        """
        result = initial
        for transform in transforms:
            result = transform(result)
        return result

    pp = pipe

    # -------------------------------------------------------------------------
    # Pattern Matching
    # -------------------------------------------------------------------------

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
        """Pattern match (mnemonic: mt).

        Matches value against cases. Each case is a tuple of (pattern, result).
        Pattern can be:
        - A type: matches if isinstance(value, type)
        - A value: matches if value == pattern
        - A callable: matches if callable(value) returns True

        Args:
            value: Value to match
            *cases: Tuples of (pattern, result)
            default: Default value if no match

        Returns:
            Result of first matching case or default

        Example:
            >>> FlextFunctional.match(
            ...     42, (str, "it's a string"), (int, "it's an int"), default="unknown"
            ... )
            "it's an int"

        """
        for pattern, result in cases:
            # Type matching
            if isinstance(pattern, type) and isinstance(value, pattern):
                return result
            # Predicate matching
            if callable(pattern) and not isinstance(pattern, type):
                try:
                    if pattern(value):
                        return result
                except (TypeError, ValueError):
                    continue
            # Value matching
            if value == pattern:
                return result
        return default

    mt = match

    @classmethod
    def switch[T, U](
        cls,
        value: T,
        cases: dict[T, U | Callable[[T], U]],
        default: U | None = None,
    ) -> U | None:
        """Switch using dict lookup (mnemonic: sw).

        Args:
            value: Value to switch on
            cases: Dictionary mapping values to results (or callables)
            default: Default value if not found

        Returns:
            Matched result or default

        Example:
            >>> FlextFunctional.switch("a", {"a": 1, "b": 2, "c": 3}, default=0)
            1

        """
        result = cases.get(value, default)
        # If result is callable, call it with value
        if callable(result):
            # Type narrowing: callable returns U or None
            return result(value)
        return result

    sw = switch

    # -------------------------------------------------------------------------
    # Type Checking and Casting
    # -------------------------------------------------------------------------

    @classmethod
    def is_type[T](
        cls,
        value: T,
        *types: type[T] | str,
    ) -> bool:
        """Type check (mnemonic: it).

        Args:
            value: Value to check
            *types: Types to check against (can be type objects or strings)

        Returns:
            True if value matches any of the types

        Example:
            >>> FlextFunctional.is_type("hello", str)
            True
            >>> FlextFunctional.it([1, 2], "list", "tuple")
            True

        """
        type_map: dict[str, type[object]] = {
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
            if isinstance(t_val, str):
                map_result = u_core.mapper().get(type_map, t_val)
                # Ensure map_result is a type, not a string
                resolved_type: type[object] | None = (
                    map_result if isinstance(map_result, type) else None
                )
            elif isinstance(t_val, type):
                resolved_type = t_val
            else:
                resolved_type = None
            if resolved_type is not None and isinstance(value, resolved_type):
                return True
        return False

    it = is_type

    @classmethod
    def as_type[T, U](
        cls,
        value: T,
        *,
        target: type[U] | str,
        default: U | None = None,
    ) -> U | None:
        """Safe cast (mnemonic: at).

        Args:
            value: Value to cast
            target: Target type (can be type object or string)
            default: Default value if cast fails

        Returns:
            Cast value or default

        Example:
            >>> FlextFunctional.as_type("42", target=int, default=0)
            42
            >>> FlextFunctional.at("hello", target="int", default=0)
            0

        """
        type_map: dict[str, type[object]] = {
            "list": list,
            "dict": dict,
            "str": str,
            "int": int,
            "bool": bool,
            "tuple": tuple,
            "float": float,
            "set": set,
        }

        # Resolve target type
        if isinstance(target, str):
            map_result = u_core.mapper().get(type_map, target)
            # Ensure map_result is a type, not a string
            target_type: type[object] | None = (
                map_result if isinstance(map_result, type) else None
            )
        elif isinstance(target, type):
            target_type = target
        else:
            target_type = None

        if target_type is None:
            return default

        # Already the right type
        if isinstance(value, target_type):
            # Value is T, but isinstance proves it matches target_type (which is U)
            # Type narrowing: value is U after isinstance check
            # Return directly - isinstance check ensures type compatibility
            return cast("U", value)

        # Try to cast - each branch returns U | None where U is the target type
        # mypy can't verify this at compile time since U is a generic type parameter

        try:  # noqa: PLR1702
            if target_type is str:
                # Type narrowing: str(value) returns str, which is U when target_type is str
                return cast("U", str(value))
            if target_type is int:
                # int() requires value to be convertible to int
                if isinstance(value, (str, bytes, bytearray)):
                    # Type narrowing: int(value) returns int, which is U when target_type is int
                    return cast("U", int(value))
                # For objects with __int__ or __index__
                # Runtime will raise TypeError if conversion fails
                try:
                    if hasattr(value, "__int__"):
                        # Type narrowing: value has __int__, int() will work
                        int_value = int(value)
                        return cast("U", int_value)
                    if hasattr(value, "__index__"):
                        # Type narrowing: value has __index__, int() will work
                        int_value = int(value)
                        return cast("U", int_value)
                except (TypeError, ValueError):
                    pass
                return default
            if target_type is float:
                # float() requires value to be convertible to float
                if isinstance(value, (str, bytes, bytearray)):
                    # Type narrowing: float(value) returns float, which is U when target_type is float
                    return cast("U", float(value))
                # For objects with __float__ or __index__
                # Runtime will raise TypeError if conversion fails
                try:
                    if hasattr(value, "__float__"):
                        # Type narrowing: value has __float__, float() will work
                        float_value = float(value)
                        return cast("U", float_value)
                    if hasattr(value, "__index__"):
                        # Type narrowing: value has __index__, float() will work
                        float_value = float(value)
                        return cast("U", float_value)
                except (TypeError, ValueError):
                    pass
                return default
            if target_type is bool:
                if isinstance(value, str):
                    # Type narrowing: bool expression returns bool, which is U when target_type is bool
                    return cast("U", value.lower() in {"true", "1", "yes", "on"})
                return cast("U", bool(value))
            if target_type is list:
                if isinstance(value, (list, tuple, set)):
                    # Type narrowing: list(value) returns list, which is U when target_type is list
                    return cast("U", list(value))
                return cast("U", [value])
            if target_type is tuple:
                if isinstance(value, (list, tuple, set)):
                    # Type narrowing: tuple(value) returns tuple, which is U when target_type is tuple
                    return cast("U", tuple(value))
                return cast("U", (value,))
            if target_type is set:
                if isinstance(value, (list, tuple, set)):
                    # Type narrowing: set(value) returns set, which is U when target_type is set
                    return cast("U", set(value))
                return cast("U", {value})
            if target_type is dict:
                if isinstance(value, dict):
                    # Type narrowing: value is dict, which is U when target_type is dict
                    return cast("U", value)
                return default
            # Generic type cast attempt - only if target_type is callable
            # object() doesn't accept arguments, so check if it's a proper type constructor
            if target_type is not object and callable(target_type):
                try:
                    # target_type is a callable constructor
                    constructor = target_type
                    # Constructor returns object, but we know it's U when target_type is U
                    # Skip object() as it doesn't accept arguments
                    if constructor is object:
                        return default
                    # Type check: ensure constructor can be called with value
                    if not callable(constructor):
                        return default
                    # Type assertion: constructor is callable, but object.__init__ takes no args
                    # Skip if constructor is object class itself
                    if constructor is type(object):
                        return default
                    try:
                        # Type narrowing: constructor is callable, try calling with value
                        # Check if constructor accepts arguments by trying to call it
                        # Some types like object() don't accept arguments
                        # Type narrowing: constructor is a type but not object
                        # Use explicit check to help type checker
                        if isinstance(constructor, type):
                            # Skip object() as it doesn't accept arguments
                            if constructor is object:
                                return default
                            # Try to instantiate with value if possible
                            try:
                                # Type narrowing: constructor is a type but not object
                                # Use cast to help type checker understand constructor accepts arguments
                                # Skip if constructor is type(object) as well
                                if constructor is type(object):
                                    return default
                                # Type narrowing: constructor is a type that accepts arguments
                                # Use cast to help type checker, but verify it's not object first
                                # Additional runtime check: object() doesn't accept arguments
                                # Mypy limitation: type[U] can be type[object], so we need explicit check
                                # Skip object() completely - it never accepts arguments
                                if constructor is object or constructor is type(object):
                                    return default
                                # Type narrowing: constructor is not object, safe to call with value
                                # Use cast to help mypy, but we've already verified it's not object
                                # Additional check: use inspect to verify constructor accepts arguments
                                try:
                                    sig = signature(constructor)
                                    # Check if constructor accepts at least one positional argument
                                    params = list(sig.parameters.values())
                                    if params and params[0].kind in {
                                        Parameter.POSITIONAL_ONLY,
                                        Parameter.POSITIONAL_OR_KEYWORD,
                                    }:
                                        constructor_type = cast("type[U]", constructor)
                                        # Additional runtime check: ensure constructor_type is not object
                                        # We've already checked constructor is not object above, but mypy needs this
                                        if (
                                            constructor_type is not object
                                            and constructor_type is not type(object)
                                        ):
                                            # Type narrowing: constructor_type is not object, safe to call
                                            constructor_callable = cast(
                                                "Callable[[object], U]",
                                                constructor_type,
                                            )
                                            converted_result: U = constructor_callable(
                                                value
                                            )
                                            if isinstance(
                                                converted_result, target_type
                                            ):
                                                return converted_result
                                            return default
                                        return default
                                    return default
                                except (ValueError, TypeError):
                                    # Constructor doesn't have inspectable signature, try calling it
                                    # We've already verified it's not object above, so it should be safe
                                    constructor_type = cast("type[U]", constructor)
                                    # Additional runtime check: ensure constructor_type is not object
                                    if (
                                        constructor_type is not object
                                        and constructor_type is not type(object)
                                    ):
                                        # Type narrowing: constructor_type is not object, safe to call
                                        constructor_callable = cast(
                                            "Callable[[object], U]", constructor_type
                                        )
                                        fallback_result: U = constructor_callable(value)
                                        if isinstance(fallback_result, target_type):
                                            return fallback_result
                                        return default
                                    return default
                            except TypeError:
                                # Constructor doesn't accept value argument
                                return default
                        elif constructor is object:
                            # object() doesn't accept arguments, return value as-is
                            return cast("U", value)
                        else:
                            # Not a type, treat as callable
                            # Type narrowing: constructor is not object (already checked above)
                            # Use cast to help type checker understand constructor is not object
                            constructor_callable = cast(
                                "Callable[[object], object]", constructor
                            )
                            result_raw = constructor_callable(value)
                            callable_result = cast("U", result_raw)
                            if isinstance(callable_result, target_type):
                                return cast("U", callable_result)
                            return default
                    except TypeError:
                        # Constructor doesn't accept value argument
                        return default
                    # If we reach here, all paths should have returned
                    return default
                except (TypeError, ValueError, AttributeError):
                    return default
            return default
        except (TypeError, ValueError):
            return default

    at = as_type

    # -------------------------------------------------------------------------
    # Property Accessors
    # -------------------------------------------------------------------------

    @classmethod
    def prop[T](
        cls,
        key: str,
    ) -> Callable[[T], T | None]:
        """Property accessor (mnemonic: pp).

        Args:
            key: Property key to access

        Returns:
            Callable that extracts the property from an object

        Example:
            >>> getter = FlextFunctional.prop("name")
            >>> getter({"name": "John"})
            'John'

        """

        def getter(obj: T) -> T | None:
            """Get value from object by key."""
            if isinstance(obj, Mapping):
                # Type narrowing: Mapping.get returns object, but we know it's T | None
                return obj.get(key)
            if hasattr(obj, key):
                # Type narrowing: getattr returns object, but we know it's T | None
                return getattr(obj, key)
            return None

        return getter

    prop_get = prop

    @classmethod
    def props(
        cls,
        *keys: str,
    ) -> Callable[[object], dict[str, object]]:
        """Multiple property accessor (mnemonic: ps).

        Args:
            *keys: Property keys to access

        Returns:
            Callable that extracts multiple properties as a dict

        Example:
            >>> getter = FlextFunctional.props("name", "age")
            >>> getter({"name": "John", "age": 30, "city": "NYC"})
            {'name': 'John', 'age': 30}

        """

        def accessor(obj: object) -> dict[str, object]:
            """Get multiple values from object by keys."""
            result_dict: dict[str, object] = {}
            for k in keys:
                if isinstance(obj, Mapping):
                    # Type assertion: obj is Mapping, get() returns value or None
                    value: object = u_core.mapper().get(obj, k)
                    result_dict[k] = value
                elif hasattr(obj, k):
                    attr_value: object = getattr(obj, k, None)
                    result_dict[k] = attr_value
                else:
                    result_dict[k] = None
            return result_dict

        return accessor

    ps = props

    @classmethod
    def path[T](
        cls,
        *keys: str,
    ) -> Callable[[T], object]:
        """Path accessor using chain() DSL (mnemonic: ph).

        Creates a getter that traverses a nested path.

        Args:
            *keys: Keys forming the path

        Returns:
            Callable that extracts value at nested path

        Example:
            >>> getter = FlextFunctional.path("user", "address", "city")
            >>> getter({"user": {"address": {"city": "NYC"}}})
            'NYC'

        """

        def make_getter(key: str) -> Callable[[object], object]:
            """Create a single-key getter."""

            def getter_fn(obj: object) -> object:
                """Get value from object by key."""
                if obj is None:
                    return None
                if isinstance(obj, Mapping):
                    # mapper().get() returns the value or None
                    map_result = u_core.mapper().get(obj, key)
                    # If result is the key itself (string), it means key not found, return None
                    if map_result == key and isinstance(key, str):
                        return None
                    return map_result
                if hasattr(obj, key):
                    return getattr(obj, key, None)
                return None

            return getter_fn

        # Create getters for each key in path
        getters: list[Callable[[object], object]] = [make_getter(k) for k in keys]

        def path_getter(obj: T) -> object:
            """Get value at path."""
            if obj is None:
                return None
            # Chain through all getters
            result: object = obj
            for getter in getters:
                if result is None:
                    return None
                result = getter(result)
            return result

        return path_getter

    ph = path


# Short alias for the class
f = FlextFunctional


__all__ = [
    "FlextFunctional",
    "f",
]
