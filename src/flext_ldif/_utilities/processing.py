"""Processing utilities for FLEXT-LDIF."""

from __future__ import annotations

import inspect
import struct
from collections.abc import Callable, Mapping, MutableSequence, Sequence
from typing import TypeIs, overload

from flext_core import FlextLogger, FlextUtilities, r

from flext_ldif import (
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesResult,
    c,
    m,
    t,
)

logger = FlextLogger(__name__)


class FlextLdifUtilitiesProcessing:
    """Processing/filtering/batch methods for LDIF utilities."""

    type VariadicCallable[T] = Callable[..., T]

    TWO_ARG_THRESHOLD: int = 2
    """Minimum parameter count for 2-argument functions."""

    @staticmethod
    def evaluate_predicate(
        predicate: Callable[..., bool],
        key: str,
        value: t.NormalizedValue,
    ) -> bool:
        """Evaluate predicate with automatic 1-arg or 2-arg detection."""
        if FlextLdifUtilitiesProcessing.is_two_arg_processor(predicate):
            try:
                return FlextLdifUtilitiesProcessing.call_processor(
                    predicate,
                    key,
                    value,
                )
            except (TypeError, ValueError):
                try:
                    if FlextLdifUtilitiesProcessing.is_object_arg_callable(predicate):
                        return predicate(value)
                except (TypeError, ValueError):
                    pass
        else:
            try:
                if FlextLdifUtilitiesProcessing.is_object_arg_callable(predicate):
                    return bool(predicate(value))
            except (TypeError, ValueError):
                pass
        return True

    @staticmethod
    def should_skip_key(
        key: str,
        filter_keys: set[str] | None,
        exclude_keys: set[str] | None,
    ) -> bool:
        """Check if key should be skipped based on filter/exclude rules."""
        if filter_keys and key not in filter_keys:
            return True
        return bool(exclude_keys and key in exclude_keys)

    @staticmethod
    def call_processor[T, R](
        processor_func: Callable[[str, T], R],
        key: str,
        value: T,
    ) -> R:
        """Call 2-arg processor function."""
        return processor_func(key, value)

    @staticmethod
    def is_object_arg_callable[R](
        func: Callable[..., R] | t.NormalizedValue,
    ) -> TypeIs[Callable[..., R]]:
        """Check if callable accepts 1 t.NormalizedValue argument."""
        if not callable(func):
            return False
        try:
            sig = inspect.signature(func)
            return len(sig.parameters) == 1
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_two_arg_processor[T, R](
        func: Callable[[str, T], R] | Callable[[T], R],
    ) -> TypeIs[Callable[[str, T], R]]:
        """Check if processor function accepts 2 arguments."""
        try:
            sig = inspect.signature(func)
            return len(sig.parameters) >= FlextLdifUtilitiesProcessing.TWO_ARG_THRESHOLD
        except (ValueError, TypeError):
            return False

    @staticmethod
    @overload
    def process(
        items_or_entries: t.NormalizedValue
        | t.MutableContainerList
        | tuple[t.NormalizedValue, ...]
        | t.MutableContainerMapping,
        processor_or_config: Callable[..., t.NormalizedValue]
        | Callable[[str, t.NormalizedValue], t.NormalizedValue]
        | None = None,
        *,
        processor: Callable[..., t.NormalizedValue]
        | Callable[[str, t.NormalizedValue], t.NormalizedValue]
        | None = None,
        on_error: str = "collect",
        predicate: Callable[..., bool]
        | Callable[[str, t.NormalizedValue], bool]
        | None = None,
        filter_keys: set[str] | None = None,
        exclude_keys: set[str] | None = None,
        config: m.Ldif.ProcessConfig | None = None,
        source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
        target_server: c.Ldif.ServerTypes | None = None,
        normalize_dns: bool = True,
        normalize_attrs: bool = True,
    ) -> r[t.MutableContainerList]: ...

    @staticmethod
    @overload
    def process(
        items_or_entries: MutableSequence[m.Ldif.Entry],
        processor_or_config: m.Ldif.ProcessConfig | None = None,
        *,
        processor: Callable[[m.Ldif.Entry], t.NormalizedValue] | None = None,
        on_error: str = "collect",
        predicate: Callable[[m.Ldif.Entry], bool] | None = None,
        filter_keys: set[str] | None = None,
        exclude_keys: set[str] | None = None,
        config: m.Ldif.ProcessConfig | None = None,
        source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
        target_server: c.Ldif.ServerTypes | None = None,
        normalize_dns: bool = True,
        normalize_attrs: bool = True,
    ) -> FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]]: ...

    @staticmethod
    def process(
        items_or_entries: t.NormalizedValue
        | t.MutableContainerList
        | tuple[t.NormalizedValue, ...]
        | t.MutableContainerMapping
        | MutableSequence[m.Ldif.Entry],
        processor_or_config: Callable[..., t.NormalizedValue]
        | Callable[[str, t.NormalizedValue], t.NormalizedValue]
        | m.Ldif.ProcessConfig
        | None = None,
        *,
        processor: Callable[..., t.NormalizedValue]
        | Callable[[str, t.NormalizedValue], t.NormalizedValue]
        | Callable[[m.Ldif.Entry], t.NormalizedValue]
        | None = None,
        on_error: str = "collect",
        predicate: Callable[..., bool]
        | Callable[[str, t.NormalizedValue], bool]
        | Callable[[m.Ldif.Entry], bool]
        | None = None,
        filter_keys: set[str] | None = None,
        exclude_keys: set[str] | None = None,
        config: m.Ldif.ProcessConfig | None = None,
        source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
        target_server: c.Ldif.ServerTypes | None = None,
        normalize_dns: bool = True,
        normalize_attrs: bool = True,
    ) -> (
        r[t.MutableContainerList]
        | FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]]
    ):
        """Universal entry processor."""
        processor_normalized = (
            processor_or_config if processor_or_config is not None else processor
        )
        _ = (config, source_server, target_server, normalize_dns, normalize_attrs)
        if (
            isinstance(processor_normalized, m.Ldif.ProcessConfig)
            or processor_normalized is None
        ):
            if (
                isinstance(items_or_entries, Sequence)
                and (not isinstance(items_or_entries, (str, bytes)))
                and all(isinstance(x, m.Ldif.Entry) for x in items_or_entries)
            ):
                entries: MutableSequence[m.Ldif.Entry] = [
                    x for x in items_or_entries if isinstance(x, m.Ldif.Entry)
                ]
                result = FlextLdifUtilitiesEntry.transform_batch(
                    entries,
                    normalize_dns=normalize_dns,
                    normalize_attrs=normalize_attrs,
                )
                return FlextLdifUtilitiesResult.from_result(result)
            if processor_normalized is None:
                msg = "processor is required for base class process"
                return FlextLdifUtilitiesResult.from_result(
                    r[MutableSequence[m.Ldif.Entry]].fail(msg),
                )
            msg = "ProcessConfig requires LDIF entry sequence"
            return FlextLdifUtilitiesResult.from_result(
                r[MutableSequence[m.Ldif.Entry]].fail(msg),
            )
        processor_func: Callable[..., t.NormalizedValue] = processor_normalized
        match items_or_entries:
            case dict() | Mapping():
                dict_items: t.MutableContainerMapping = {}
                for key, value in items_or_entries.items():
                    dict_items[str(key)] = (
                        FlextLdifUtilitiesProcessing.normalize_container(value)
                    )
                results = FlextLdifUtilitiesProcessing.process_dict_items(
                    dict_items,
                    processor_func,
                    predicate,
                    filter_keys,
                    exclude_keys,
                )
                return r[t.MutableContainerList].ok(results)
            case list() | tuple():
                items_list: t.MutableContainerList = [
                    FlextLdifUtilitiesProcessing.normalize_container(item)
                    if not isinstance(item, m.Ldif.Entry)
                    else str(item)
                    for item in items_or_entries
                ]
                return FlextLdifUtilitiesProcessing.process_list_items(
                    items_list,
                    processor_func,
                    predicate,
                    on_error,
                )
            case _:
                if isinstance(items_or_entries, Sequence) and (
                    not isinstance(items_or_entries, (str, bytes))
                ):
                    msg = "Unsupported non-list sequence for single-item processing"
                    return r[t.MutableContainerList].fail(msg)
                result_item = processor_func(items_or_entries)
                return r[t.MutableContainerList].ok([result_item])

    @staticmethod
    def process_dict_items[R](
        items: t.MutableContainerMapping,
        processor_func: Callable[..., R],
        predicate: Callable[..., bool] | None,
        filter_keys: set[str] | None,
        exclude_keys: set[str] | None,
    ) -> MutableSequence[R]:
        """Process dictionary items."""
        results: MutableSequence[R] = []
        for key, value in items.items():
            if FlextLdifUtilitiesProcessing.should_skip_key(
                key,
                filter_keys,
                exclude_keys,
            ):
                continue
            if predicate is not None and (
                not FlextLdifUtilitiesProcessing.evaluate_predicate(
                    predicate,
                    key,
                    value,
                )
            ):
                continue
            try:
                result_item: R = processor_func(key, value)
            except TypeError:
                result_item = processor_func(value)
            results.append(result_item)
        return results

    @staticmethod
    def process_list_items[R](
        items: t.MutableContainerList,
        processor_func: Callable[..., R],
        predicate: Callable[..., bool] | None,
        on_error: str,
    ) -> r[MutableSequence[R]]:
        """Process list/tuple items."""
        results: MutableSequence[R] = []
        errors: MutableSequence[str] = []
        for item in items:
            if predicate is not None:
                try:
                    if not predicate(item):
                        continue
                except TypeError:
                    continue
            try:
                result_item: R = processor_func(item)
                results.append(result_item)
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as e:
                if on_error == "fail":
                    return r[MutableSequence[R]].fail(f"Processing failed: {e}")
                if on_error == "skip":
                    continue
                errors.append(str(e))
        return r[MutableSequence[R]].ok(results)

    @staticmethod
    def is_entry_sequence(
        obj: object,
    ) -> TypeIs[MutableSequence[m.Ldif.Entry]]:
        """Check if value is a Sequence of Entry objects."""
        if isinstance(obj, (str, bytes)):
            return False
        if isinstance(obj, list):
            if not obj:
                return True
            return isinstance(obj[0], m.Ldif.Entry)
        if isinstance(obj, tuple):
            if not obj:
                return True
            return isinstance(obj[0], m.Ldif.Entry)
        return False

    @staticmethod
    def normalize_container(value: t.NormalizedValue) -> t.NormalizedValue:
        """Normalize a t.NormalizedValue to a canonical form."""
        if FlextUtilities.is_general_value_type(value):
            return value
        return str(value)


__all__ = ["FlextLdifUtilitiesProcessing"]
