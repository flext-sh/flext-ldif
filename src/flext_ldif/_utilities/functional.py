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

from collections.abc import Callable, Mapping, Sequence
from inspect import Parameter, signature
from typing import Literal, Protocol, TypeVar, overload, runtime_checkable

from flext_core import FlextTypes as t, T, U
from flext_core.utilities import FlextUtilities as u


@runtime_checkable
class ConditionFn[T_co](Protocol):
    """Protocol for condition functions in cond() pattern."""

    def __call__(self, value: T_co, /) -> bool:  # INTERFACE
        """Evaluate condition on value."""
        ...


@runtime_checkable
class ResultFn[T_contra, U_co](Protocol):
    """Protocol for result functions in cond() pattern."""

    def __call__(self, value: T_contra, /) -> U_co:  # INTERFACE
        """Transform value to result."""
        ...


@runtime_checkable
class Evaluator[T_contra, U_co](Protocol):
    """Protocol for evaluator returned by cond()."""

    def __call__(self, value: T_contra, /) -> U_co | None:  # INTERFACE
        """Evaluate value through conditions."""
        ...


# Type variable for callable types
CallableType = TypeVar("CallableType", bound=type[t.GeneralValueType])


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
        if processor is not None:
            result: dict[str, U] = {}
            for key, value in data.items():
                if predicate(key, value):
                    new_key = key_mapper(key)
                    result[new_key] = processor(key, value)
            return result
        # When processor is None, T must be compatible with U for the overload
        # but we return dict[str, T] which should be compatible
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
        # Type assertion: after isinstance check, items is Sequence[T]
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
        # Type assertion: after isinstance check, items is Sequence[T]
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
        """Process and flatten items (mnemonic: pf).

        Args:
            items: Sequence to process
            processor: Function that may return single value, list, or tuple
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
        # Type assertion: after isinstance check, items is Sequence[T]
        sequence: Sequence[T] = items
        result: list[U] = []
        for item in sequence:
            try:
                processed = processor(item)
                if isinstance(processed, list):
                    # processed is list[U] - extend with filtered items
                    result.extend([
                        sub_item for sub_item in processed if predicate(sub_item)
                    ])
                elif isinstance(processed, tuple):
                    # processed is tuple[U, ...] - extend with filtered items
                    result.extend([
                        sub_item for sub_item in processed if predicate(sub_item)
                    ])
                # Single value case - processed is U (not list or tuple)
                elif predicate(processed):
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
    def normalize_list[T](
        cls,
        value: T | list[T] | tuple[T, ...] | None,
        *,
        mapper: Callable[[T], T] | None = None,
        predicate: Callable[[T], bool] | None = None,
        default: list[T] | None = None,
    ) -> list[T]:
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
        # Build items from value
        if value is None:
            if default is not None:
                return list(default)
            return []

        # Handle different input types and normalize to list[T]
        items: list[T]
        if isinstance(value, list):
            items = value
        elif isinstance(value, tuple):
            items = list(value)
        else:
            # Single item (including str/bytes) - wrap in list
            # Type narrowing: value is T at this point
            items = [value]

        # Apply mapper if provided
        if mapper is not None:
            items_mapped: list[T] = [mapper(item) for item in items]
            # Apply predicate if provided
            if predicate is not None:
                return [item for item in items_mapped if predicate(item)]
            return items_mapped

        # No mapper - return items
        if predicate is not None:
            return [item for item in items if predicate(item)]
        return items

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
        # Implement directly to preserve generic T type
        if isinstance(data, dict):
            return data.get(key, default)
        return default

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
                # Type narrowing: callable() returns T
                # Callable validates signature, result is T
                return then()
            # Direct value
            if then is not None:
                return then
        # Return else_
        return else_

    wh = when

    @staticmethod
    def cond(
        *cases: tuple[
            ConditionFn[t.GeneralValueType],
            ResultFn[t.GeneralValueType, t.GeneralValueType],
        ],
        default: t.GeneralValueType | None = None,
    ) -> Evaluator[t.GeneralValueType, t.GeneralValueType]:
        """Conditional expression returning curried function (mnemonic: cd).

        Creates a function that evaluates conditions in order and returns
        the result of the first matching condition's result function.

        Args:
            *cases: Tuples of (condition_fn, result_fn)
                - condition_fn: Protocol that takes 1 arg, returns bool
                - result_fn: Protocol that takes 1 arg, returns value
            default: Default value if no condition matches

        Returns:
            Evaluator Protocol that takes a value and evaluates conditions

        Example:
            >>> result = FlextFunctional.cond(
            ...     (lambda x: x > 10, lambda x: "large"),
            ...     (lambda x: x > 5, lambda x: "medium"),
            ...     default="small",
            ... )(7)
            'medium'

        """
        stored_cases = cases
        stored_default = default

        def evaluator(value: t.GeneralValueType, /) -> t.GeneralValueType | None:
            for cond_fn, res_fn in stored_cases:
                if cond_fn(value):
                    return res_fn(value)
            return stored_default

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
            # Type narrowing: callable(value) returns U
            # Callable validates signature, result is U
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

    # Type alias for as_type return - union of all convertible types
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
        target: type[t.GeneralValueType] | str,
        default: t.GeneralValueType | None = None,
    ) -> t.GeneralValueType | None:
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
        type_map: dict[str, type] = {
            "list": list,
            "dict": dict,
            "str": str,
            "int": int,
            "bool": bool,
            "tuple": tuple,
            "float": float,
        }

        # Resolve target type: if string, look up in map; if type, use directly
        target_type: type[t.GeneralValueType] | None = (
            type_map.get(target) if isinstance(target, str) else target
        )

        if target_type is None:
            return default

        # Already the right type (only check for concrete types, not callables)
        if isinstance(target_type, type) and isinstance(value, target_type):
            return value

        # Try to convert
        try:
            if target_type is str:
                return str(value)
            if target_type is int:
                if isinstance(value, (str, bytes, bytearray, int, float)):
                    return int(value)
                # For objects with numeric protocol
                try:
                    # Use str(value) then int() for general conversion
                    return int(str(value))
                except (TypeError, ValueError):
                    pass
                return default
            if target_type is float:
                if isinstance(value, (str, bytes, bytearray, int, float)):
                    return float(value)
                # For objects with numeric protocol
                try:
                    # Use str(value) then float() for general conversion
                    return float(str(value))
                except (TypeError, ValueError):
                    pass
                return default
            if target_type is bool:
                if isinstance(value, str):
                    return value.lower() in {"true", "1", "yes", "on"}
                return bool(value)
            if target_type is list:
                if isinstance(value, (list, tuple)):
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
            # Generic type conversion - skip object since object() doesn't accept args
            if target_type is object:
                return default

            # Handle other callable types (excluding object)
            if callable(target_type):
                try:
                    try:
                        sig = signature(target_type)
                        params = list(sig.parameters.values())
                        accepts_args = params and params[0].kind in {
                            Parameter.POSITIONAL_ONLY,
                            Parameter.POSITIONAL_OR_KEYWORD,
                        }
                    except (ValueError, TypeError):
                        accepts_args = True

                    if accepts_args:
                        # Call target_type constructor with value
                        # We've already checked target_type is not object above
                        try:
                            # Explicitly handle each known type to satisfy mypy
                            converted: t.GeneralValueType | None = None
                            if target_type is str:
                                converted = str(value)
                            elif target_type is int:
                                # int() needs specific types, so check first
                                if isinstance(value, (int, float, str, bool)):
                                    converted = int(value)
                                else:
                                    return default
                            elif target_type is bool:
                                converted = bool(value)
                            elif target_type is float:
                                # float() needs specific types, so check first
                                if isinstance(value, (int, float, str, bool)):
                                    converted = float(value)
                                else:
                                    return default
                            elif target_type is list:
                                converted = (
                                    list(value)
                                    if isinstance(value, (list, tuple))
                                    else [value]
                                )
                            elif target_type is tuple:
                                converted = (
                                    tuple(value)
                                    if isinstance(value, (list, tuple))
                                    else (value,)
                                )
                            elif target_type is dict:
                                converted = (
                                    dict(value) if isinstance(value, dict) else default
                                )
                            else:
                                # For all other types (custom classes, BaseModel, etc.)
                                # We cannot safely construct these dynamically since they
                                # may require specific constructor arguments (e.g., datetime
                                # needs year/month/day, Pydantic models need validation)
                                # Return default for unhandled types
                                return default

                            if converted is None:
                                return default
                        except (TypeError, ValueError):
                            return default

                        if isinstance(converted, target_type):
                            return converted
                        return default
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
                # Mapping.get returns value or None - type annotation narrows
                value: T | None = obj.get(key)  # type narrowing via annotation
                return value
            if hasattr(obj, key):
                # getattr returns attribute value - type annotation narrows
                attr_val: T | None = getattr(obj, key)  # type narrowing via annotation
                return attr_val
            return None

        return getter

    prop_get = prop

    @classmethod
    def props(
        cls,
        *keys: str,
    ) -> Callable[[t.GeneralValueType], dict[str, t.GeneralValueType]]:
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

        def accessor(obj: t.GeneralValueType) -> dict[str, t.GeneralValueType]:
            """Get multiple values from object by keys."""
            result_dict: dict[str, t.GeneralValueType] = {}
            for k in keys:
                if isinstance(obj, Mapping):
                    # Type assertion: obj is Mapping, get() returns value or None
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

        def make_getter(
            key: str,
        ) -> Callable[[t.GeneralValueType], t.GeneralValueType]:
            """Create a single-key getter."""

            def getter_fn(obj: t.GeneralValueType) -> t.GeneralValueType:
                """Get value from object by key."""
                if obj is None:
                    return None
                if isinstance(obj, Mapping):
                    # mapper().get() returns the value or None
                    map_result = u.mapper().get(obj, key)
                    # If result is the key itself (string), it means key not found
                    if map_result == key and isinstance(key, str):
                        return None
                    return map_result
                if hasattr(obj, key):
                    return getattr(obj, key, None)
                return None

            return getter_fn

        # Create getters for each key in path
        getters: list[Callable[[t.GeneralValueType], t.GeneralValueType]] = [
            make_getter(k) for k in keys
        ]

        def path_getter(obj: t.GeneralValueType) -> t.GeneralValueType:
            """Get value at path."""
            if obj is None:
                return None
            # Chain through all getters
            result: t.GeneralValueType = obj
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
