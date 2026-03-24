"""Processing utilities for FLEXT-LDIF."""

from __future__ import annotations

import inspect
import struct
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from typing import Literal, TypeIs, overload, override

from flext_core import FlextLogger, FlextUtilities, r

from flext_ldif import (
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesFilters,
    FlextLdifUtilitiesResult,
    FlextLdifUtilitiesTransformer,
    Pipeline,
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
                    predicate, key, value
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
    def is_ldif_process_call(
        items: MutableSequence[m.Ldif.Entry]
        | t.MutableContainerMapping
        | str
        | bytes
        | None,
        processor_normalized: m.Ldif.ProcessConfig | None,
        processor: Callable[..., t.NormalizedValue] | None,
        config: m.Ldif.ProcessConfig | None,
        _source_server: c.Ldif.ServerTypes,
        target_server: c.Ldif.ServerTypes | None,
    ) -> bool:
        """Check if this is an LDIF-specific process call."""
        is_sequence_entry = bool(items)
        match items:
            case str() | bytes() | Mapping():
                is_sequence_entry = False
            case _:
                pass
        if is_sequence_entry and items:
            first_item = next(iter(items), None)
            if first_item is not None and (
                not getattr(first_item, "dn", None) is not None
            ):
                return False
        has_ldif_config = (
            (processor_normalized is None and processor is None)
            or config is not None
            or target_server is not None
        )
        return bool(is_sequence_entry and has_ldif_config)

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
    def call_single_item_processor[R](
        processor_func: Callable[..., R],
        item: t.NormalizedValue,
    ) -> r[MutableSequence[R]]:
        """Call processor with single item, handling signature detection."""
        try:
            sig = inspect.signature(processor_func)
            params = [
                p_
                for p_ in sig.parameters.values()
                if p_.default is inspect.Parameter.empty
                and p_.kind
                in {
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                }
            ]
            if len(params) == 1:
                result: R = processor_func(item)
                return r[MutableSequence[R]].ok([result])
            return r[MutableSequence[R]].fail(
                "Processor requires 2 arguments but single item provided",
            )
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            return r[MutableSequence[R]].fail(f"Processing failed: {e}")

    @staticmethod
    def is_no_arg_callable[R](
        func: Callable[..., R] | t.NormalizedValue,
    ) -> TypeIs[Callable[[], R]]:
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
    @override
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
    def transform_entries(
        entries: MutableSequence[m.Ldif.Entry],
        *transformers: FlextLdifUtilitiesTransformer[m.Ldif.Entry],
        fail_fast: bool = True,
    ) -> FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]]:
        """Apply entry transformers to LDIF entries using pipeline semantics."""
        pipeline = Pipeline(fail_fast=fail_fast)
        for transformer in transformers:
            _ = pipeline.add(transformer)
        return FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]].from_result(
            pipeline.execute(entries),
        )

    @staticmethod
    def batch_process[T, U](
        items: MutableSequence[T],
        func: Callable[[T], r[U]],
    ) -> r[MutableSequence[U]]:
        """Execute batch of operations with r (simplified)."""
        results: MutableSequence[U] = []
        for item in items:
            result = func(item)
            if result.is_failure:
                return r[MutableSequence[U]].fail(
                    result.error or "Batch operation failed"
                )
            results.append(result.value)
        return r[MutableSequence[U]].ok(results)

    @staticmethod
    @override
    def filter[T: t.NormalizedValue, R: t.NormalizedValue](
        items_or_entries: T
        | MutableSequence[T]
        | tuple[T, ...]
        | MutableMapping[str, T]
        | MutableSequence[m.Ldif.Entry],
        predicate_or_filter1: FlextLdifUtilitiesProcessing.VariadicCallable[bool]
        | FlextLdifUtilitiesFilters[m.Ldif.Entry],
        *filters: FlextLdifUtilitiesFilters[m.Ldif.Entry],
        _mapper: FlextLdifUtilitiesProcessing.VariadicCallable[R] | None = None,
        mode: Literal["all", "any"] = "all",
    ) -> (
        t.MutableContainerList
        | t.MutableContainerMapping
        | FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]]
    ):
        """Filter entries using composable filter predicates."""
        match predicate_or_filter1:
            case FlextLdifUtilitiesFilters():
                pass
            case _:
                predicate: FlextLdifUtilitiesProcessing.VariadicCallable[bool] = (
                    predicate_or_filter1
                )

                def predicate_callable(item: t.NormalizedValue) -> bool:
                    return predicate(item)

                return FlextLdifUtilitiesProcessing.filter_base_class(
                    items_or_entries,
                    predicate_callable,
                )
        if isinstance(items_or_entries, Sequence) and (
            not isinstance(items_or_entries, (str, bytes))
        ):
            seq_items = items_or_entries
            if seq_items and isinstance(seq_items[0], m.Ldif.Entry):
                entries_list: MutableSequence[m.Ldif.Entry] = [
                    e for e in seq_items if isinstance(e, m.Ldif.Entry)
                ]
                filter_entry = predicate_or_filter1
                return FlextLdifUtilitiesProcessing.filter_ldif_entries(
                    entries_list,
                    filter_entry,
                    filters,
                    mode,
                )

        if not isinstance(predicate_or_filter1, FlextLdifUtilitiesFilters):
            return []
        entry_filter: FlextLdifUtilitiesFilters[m.Ldif.Entry] = predicate_or_filter1

        def predicate_wrapper(item: t.Ldif.NormalizedValue) -> bool:
            """Wrap FlextLdifUtilitiesFilters as VariadicCallable for base class compatibility."""
            match item:
                case m.Ldif.Entry() as entry_item:
                    return entry_filter.matches(entry_item)
                case _:
                    return False

        return FlextLdifUtilitiesProcessing.filter_base_class(
            items_or_entries,
            predicate_wrapper,
        )

    @staticmethod
    def filter_base_class(
        items_or_entries: t.NormalizedValue,
        predicate: Callable[..., bool],
        _mapper: Callable[..., t.NormalizedValue] | None = None,
    ) -> t.MutableContainerList | t.MutableContainerMapping:
        """Filter using base class Collection.filter (internal helper)."""
        if isinstance(items_or_entries, (list, tuple)):
            items_list: t.MutableContainerList = list(items_or_entries)
            list_filter_result = FlextUtilities.filter(items_list, predicate)
            return list(list_filter_result) if list_filter_result else []
        if isinstance(items_or_entries, dict):
            items_dict: t.MutableContainerMapping = {}
            for k, v in items_or_entries.items():
                items_dict[k] = FlextLdifUtilitiesProcessing.to_config_map_value(v)
            dict_filter_result = FlextUtilities.filter(items_dict, predicate)
            return dict(dict_filter_result) if dict_filter_result else {}
        items_single_list: t.MutableContainerList = [items_or_entries]
        single_filter_result = FlextUtilities.filter(items_single_list, predicate)
        return list(single_filter_result) if single_filter_result else []

    @staticmethod
    def filter_ldif_entries(
        entries: MutableSequence[m.Ldif.Entry],
        predicate_or_filter1: FlextLdifUtilitiesFilters[m.Ldif.Entry],
        filters: tuple[FlextLdifUtilitiesFilters[m.Ldif.Entry], ...],
        mode: Literal["all", "any"],
    ) -> FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]]:
        """Filter LDIF entries using FlextLdifUtilitiesFilters (internal helper)."""
        filter_list: MutableSequence[FlextLdifUtilitiesFilters[m.Ldif.Entry]] = [
            predicate_or_filter1,
        ] + list(filters)
        if not filter_list:
            return FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]].ok(
                list(entries)
            )
        combined: FlextLdifUtilitiesFilters[m.Ldif.Entry] = filter_list[0]
        for f in filter_list[1:]:
            combined = combined & f if mode == "all" else combined | f
        filtered = [entry for entry in entries if combined.matches(entry)]
        return FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]].ok(filtered)

    @staticmethod
    @override
    def is_entry_sequence(
        obj: t.NormalizedValue,
    ) -> TypeIs[MutableSequence[m.Ldif.Entry]]:
        """Check if value is a Sequence of Entry objects."""
        match obj:
            case str() | bytes():
                return False
            case Sequence() as seq if seq:
                match seq[0]:
                    case m.Ldif.Entry():
                        return True
                    case _:
                        return False
            case Sequence():
                return True
            case _:
                return False

    @staticmethod
    def normalize_container(value: t.NormalizedValue) -> t.NormalizedValue:
        """Normalize a t.NormalizedValue to a canonical form."""
        if FlextUtilities.is_general_value_type(value):
            return value
        return str(value)

    @staticmethod
    def to_config_map_value(value: t.NormalizedValue) -> t.NormalizedValue:
        """Convert value to t.NormalizedValue (general value or str)."""
        if FlextUtilities.is_general_value_type(value):
            return value
        return str(value)


__all__ = ["FlextLdifUtilitiesProcessing"]
