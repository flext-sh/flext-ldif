"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations."""

from __future__ import annotations

import builtins
import contextlib
import inspect
import struct
from collections.abc import (
    Callable,
    Mapping,
    Sequence,
)
from enum import Enum
from typing import ClassVar, Literal, Self, TypeIs, overload

from flext_core import FlextLogger, FlextUtilities, r

from flext_ldif import c, m, p, t
from flext_ldif._utilities import (
    DnOps,
    EntryOps,
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesDecorators,
    FlextLdifUtilitiesDetection,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesEvents,
    FlextLdifUtilitiesFilters,
    FlextLdifUtilitiesMetadata,
    FlextLdifUtilitiesObjectClass,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesParsers,
    FlextLdifUtilitiesResult,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesTransformer,
    FlextLdifUtilitiesTypeGuards,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
    FlextLdifUtilitiesWriters,
    Pipeline,
    ValidationPipeline,
    ValidationResult,
)

logger = FlextLogger(__name__)


class FlextLdifUtilities(FlextUtilities):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations."""

    class Ldif(
        DnOps,
        EntryOps,
        FlextLdifUtilitiesACL,
        FlextLdifUtilitiesAttribute,
        FlextLdifUtilitiesDecorators,
        FlextLdifUtilitiesDetection,
        FlextLdifUtilitiesDN,
        FlextLdifUtilitiesEntry,
        FlextLdifUtilitiesEvents,
        FlextLdifUtilitiesFilters,
        FlextLdifUtilitiesMetadata,
        FlextLdifUtilitiesObjectClass,
        FlextLdifUtilitiesOID,
        FlextLdifUtilitiesParser,
        FlextLdifUtilitiesParsers,
        FlextLdifUtilitiesResult,
        FlextLdifUtilitiesSchema,
        FlextLdifUtilitiesServer,
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTypeGuards,
        FlextLdifUtilitiesValidation,
        FlextLdifUtilitiesWriter,
        FlextLdifUtilitiesWriters,
        Pipeline,
        ValidationPipeline,
        ValidationResult,
    ):
        """LDIF-specific utility namespace."""

        type VariadicCallable[T] = Callable[..., T]

        @staticmethod
        def to_config_map_value(value: builtins.object) -> builtins.object:
            """Convert value to object (general value or str)."""
            if FlextUtilities.is_general_value_type(value):
                return value
            return str(value)

        @staticmethod
        def normalize_container(value: builtins.object) -> builtins.object:
            """Normalize a object to a canonical form."""
            if FlextUtilities.is_general_value_type(value):
                return value
            return str(value)

        @staticmethod
        def normalize_mapping(
            mapping: Mapping[str, builtins.object],
        ) -> dict[str, builtins.object]:
            """Normalize a mapping of objects to a standard dict form."""
            normalized: dict[str, builtins.object] = {}
            for key, value in mapping.items():
                normalized[str(key)] = FlextLdifUtilities.Ldif.normalize_container(
                    value
                )
            return normalized

        class ConvBuilder:
            """Conversion builder for type-safe value conversion (DSL pattern)."""

            def __init__(self, *, value: builtins.object | None) -> None:
                """Initialize conversion builder with a value."""
                super().__init__()
                self._value: builtins.object | None = value
                self._default: builtins.object | None = None
                self._target_type: str | None = None
                self._safe_mode = False

            def build(self) -> builtins.object | None:
                """Build and return the converted value using parent utilities."""
                if self._value is None:
                    return self._default
                if self._target_type == "to_str":
                    str_default = ""
                    if self._default is not None:
                        with contextlib.suppress(TypeError, ValueError):
                            str_default = str(self._default)
                    value_str = str(self._value)
                    return value_str or str_default
                if self._target_type == "to_str_list":
                    list_default: list[str] = []
                    if self._default is not None:
                        if isinstance(self._default, list):
                            list_default = [str(x) for x in self._default]
                        else:
                            default_value = str(self._default)
                            list_default = [default_value] if default_value else []
                    match self._value:
                        case list() | tuple() as seq_values:
                            normalized = [str(item) for item in seq_values]
                            return normalized or list_default
                        case _:
                            single = str(self._value)
                            if single:
                                return [single]
                            return list_default
                if self._target_type == "to_int":
                    if self._safe_mode:
                        try:
                            return int(str(self._value))
                        except (ValueError, TypeError):
                            return self._default
                    return int(str(self._value))
                if self._target_type == "to_bool":
                    try:
                        str_val = str(self._value).lower()
                        return str_val in {"true", "1", "yes", "on"}
                    except (TypeError, ValueError):
                        return bool(self._value)
                return self._value

            def safe(self) -> Self:
                """Enable safe mode."""
                self._safe_mode = True
                return self

            def str_list(self, default: list[str] | None = None) -> Self:
                """Convert to string list using parent Conversion utilities."""
                self._default = default if default is not None else list[str]()
                self._target_type = "to_str_list"
                return self

            def to_bool(self, *, default: bool = False) -> Self:
                """Convert to bool."""
                self._default = default
                self._target_type = "to_bool"
                return self

            def to_int(self, default: int = 0) -> Self:
                """Convert to int."""
                self._default = default
                self._target_type = "to_int"
                return self

            def to_str(self, default: str = "") -> Self:
                """Convert to string using parent Conversion utilities."""
                self._default = default
                self._target_type = "to_str"
                return self

        @staticmethod
        def batch_process[T, U](
            items: Sequence[T], func: Callable[[T], r[U]]
        ) -> r[list[U]]:
            """Execute batch of operations with r (simplified)."""
            results: list[U] = []
            for item in items:
                result = func(item)
                if result.is_failure:
                    return r[list[U]].fail(result.error or "Batch operation failed")
                results.append(result.value)
            return r[list[U]].ok(results)

        @staticmethod
        def find(
            items: Sequence[builtins.object],
            *,
            predicate: Callable[..., bool],
        ) -> builtins.object | None:
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

        class Constants(c):
            """Constants for LDIF operations."""

            _CATEGORY_MAP: ClassVar[Mapping[str, type[Enum]]] = {
                "server_type": c.Ldif.ServerTypes,
                "encoding": c.Ldif.Encoding,
            }

            @classmethod
            def get_valid_values(cls, category: str) -> set[str]:
                """Get valid values for a category."""
                if category not in cls._CATEGORY_MAP:
                    msg = f"Unknown category: {category}"
                    raise KeyError(msg)
                enum_class = cls._CATEGORY_MAP[category]
                return {e.value for e in enum_class.__members__.values()}

            @classmethod
            def is_valid(cls, value: str, category: str) -> bool:
                """Check if value is valid for a category."""
                if category not in cls._CATEGORY_MAP:
                    return False
                valid_values = cls.get_valid_values(category)
                return value.lower() in {v.lower() for v in valid_values}

            @classmethod
            def validate_many(
                cls, values: set[str], category: str
            ) -> tuple[bool, set[str]]:
                """Validate multiple values for a category."""
                if category not in cls._CATEGORY_MAP:
                    msg = f"Unknown category: {category}"
                    raise KeyError(msg)
                valid_values = cls.get_valid_values(category)
                valid_lower = {v.lower() for v in valid_values}
                invalid = {v for v in values if v.lower() not in valid_lower}
                return (len(invalid) == 0, invalid)

        @staticmethod
        def evaluate_predicate(
            predicate: Callable[..., bool], key: str, value: builtins.object
        ) -> bool:
            """Evaluate predicate with automatic 1-arg or 2-arg detection."""
            if FlextLdifUtilities.Ldif.is_two_arg_processor(predicate):
                try:
                    return FlextLdifUtilities.Ldif.call_processor(predicate, key, value)
                except (TypeError, ValueError):
                    try:
                        if FlextLdifUtilities.Ldif.is_object_arg_callable(predicate):
                            return predicate(value)
                    except (TypeError, ValueError):
                        pass
            else:
                try:
                    if FlextLdifUtilities.Ldif.is_object_arg_callable(predicate):
                        return bool(predicate(value))
                except (TypeError, ValueError):
                    pass
            return True

        @staticmethod
        def is_ldif_process_call(
            items: Sequence[m.Ldif.Entry]
            | Mapping[str, builtins.object]
            | str
            | bytes
            | None,
            processor_normalized: m.Ldif.ProcessConfig | None,
            processor: Callable[..., object] | None,
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
            key: str, filter_keys: set[str] | None, exclude_keys: set[str] | None
        ) -> bool:
            """Check if key should be skipped based on filter/exclude rules."""
            if filter_keys and key not in filter_keys:
                return True
            return bool(exclude_keys and key in exclude_keys)

        TWO_ARG_THRESHOLD: int = 2
        "Minimum parameter count for 2-argument functions."

        @classmethod
        def dn(cls, dn: str) -> DnOps:
            """Create fluent DN operations."""
            return DnOps(dn)

        @classmethod
        def entry(cls, entry: m.Ldif.Entry) -> EntryOps:
            """Create fluent entry operations."""
            return EntryOps(entry)

        @classmethod
        def normalize_list(
            cls,
            value: builtins.object | r[builtins.object],
            *,
            default: list[builtins.object] | None = None,
        ) -> list[builtins.object]:
            """Normalize to list using FlextUtilities.build() DSL (mnemonic: nl)."""
            extracted_value: builtins.object | None
            match value:
                case r() as result_value:
                    extracted_value = (
                        result_value.value if not result_value.is_failure else None
                    )
                case _:
                    extracted_value = value
            default_list: list[builtins.object] = default if default is not None else []
            extracted: builtins.object = (
                extracted_value if extracted_value is not None else default_list
            )
            ops: dict[str, builtins.object] = {
                "ensure": "list",
                "ensure_default": default_list,
            }
            result = cls.build(
                extracted,
                ops=ops,
            )
            match result:
                case list() as result_list:
                    return [
                        FlextLdifUtilities.Ldif.to_config_map_value(item)
                        for item in result_list
                    ]
                case tuple() as result_tuple:
                    return [
                        FlextLdifUtilities.Ldif.to_config_map_value(item)
                        for item in result_tuple
                    ]
                case _:
                    pass
            result_typed = FlextLdifUtilities.Ldif.to_config_map_value(result)
            return [result_typed]

        @staticmethod
        def call_processor[T, R](
            processor_func: Callable[[str, T], R], key: str, value: T
        ) -> R:
            """Call 2-arg processor function."""
            return processor_func(key, value)

        @staticmethod
        def call_single_item_processor[R](
            processor_func: Callable[..., R], item: builtins.object
        ) -> r[list[R]]:
            """Call processor with single item, handling signature detection."""
            try:
                sig = inspect.signature(processor_func)
                params = [
                    p
                    for p in sig.parameters.values()
                    if p.default is inspect.Parameter.empty
                    and p.kind
                    in {
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    }
                ]
                if len(params) == 1:
                    result: R = processor_func(item)
                    return r[list[R]].ok([result])
                return r[list[R]].fail(
                    "Processor requires 2 arguments but single item provided"
                )
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as e:
                return r[list[R]].fail(f"Processing failed: {e}")

        @staticmethod
        def filter[T: builtins.object, R: builtins.object](
            items_or_entries: T
            | list[T]
            | tuple[T, ...]
            | Mapping[str, T]
            | Sequence[m.Ldif.Entry],
            predicate_or_filter1: FlextLdifUtilities.Ldif.VariadicCallable[bool]
            | FlextLdifUtilitiesFilters[m.Ldif.Entry],
            *filters: FlextLdifUtilitiesFilters[m.Ldif.Entry],
            _mapper: FlextLdifUtilities.Ldif.VariadicCallable[R] | None = None,
            mode: Literal["all", "any"] = "all",
        ) -> (
            list[builtins.object]
            | Mapping[str, builtins.object]
            | object
            | FlextLdifUtilitiesResult[list[m.Ldif.Entry]]
        ):
            """Filter entries using composable filter predicates."""
            match predicate_or_filter1:
                case FlextLdifUtilitiesFilters():
                    pass
                case _:
                    predicate: FlextLdifUtilities.Ldif.VariadicCallable[bool] = (
                        predicate_or_filter1
                    )

                    def predicate_callable(item: builtins.object) -> bool:
                        return predicate(item)

                    return FlextLdifUtilities.Ldif.filter_base_class(
                        items_or_entries,
                        predicate_callable,
                    )
            if isinstance(items_or_entries, Sequence) and (
                not isinstance(items_or_entries, (str, bytes))
            ):
                seq_items = items_or_entries
                if seq_items and isinstance(seq_items[0], m.Ldif.Entry):
                    entries_list: list[m.Ldif.Entry] = [
                        e for e in seq_items if isinstance(e, m.Ldif.Entry)
                    ]
                    filter_entry = predicate_or_filter1
                    return FlextLdifUtilities.Ldif.filter_ldif_entries(
                        entries_list, filter_entry, filters, mode
                    )

            entry_filter = predicate_or_filter1

            def predicate_wrapper(item: builtins.object) -> bool:
                """Wrap FlextLdifUtilitiesFilters as VariadicCallable for base class compatibility."""
                match item:
                    case m.Ldif.Entry() as entry_item:
                        return entry_filter.matches(entry_item)
                    case _:
                        return False

            return FlextLdifUtilities.Ldif.filter_base_class(
                items_or_entries,
                predicate_wrapper,
            )

        @staticmethod
        def filter_base_class(
            items_or_entries: Sequence[builtins.object]
            | Mapping[str, builtins.object]
            | object,
            predicate: Callable[..., bool],
            _mapper: Callable[..., object] | None = None,
        ) -> list[builtins.object] | Mapping[str, builtins.object]:
            """Filter using base class Collection.filter (internal helper)."""
            if isinstance(items_or_entries, (list, tuple)):
                items_list: list[builtins.object] = list(items_or_entries)
                list_filter_result = FlextUtilities.filter(items_list, predicate)
                return list(list_filter_result) if list_filter_result else []
            if isinstance(items_or_entries, dict):
                items_dict: dict[str, builtins.object] = {}
                for k, v in items_or_entries.items():
                    items_dict[k] = FlextLdifUtilities.Ldif.to_config_map_value(v)
                dict_filter_result = FlextUtilities.filter(items_dict, predicate)
                return dict_filter_result or {}
            items_single_list: list[builtins.object] = [items_or_entries]
            single_filter_result = FlextUtilities.filter(items_single_list, predicate)
            return list(single_filter_result) if single_filter_result else []

        @staticmethod
        def filter_ldif_entries(
            entries: Sequence[m.Ldif.Entry],
            predicate_or_filter1: FlextLdifUtilitiesFilters[m.Ldif.Entry],
            filters: tuple[FlextLdifUtilitiesFilters[m.Ldif.Entry], ...],
            mode: Literal["all", "any"],
        ) -> FlextLdifUtilitiesResult[list[m.Ldif.Entry]]:
            """Filter LDIF entries using FlextLdifUtilitiesFilters (internal helper)."""
            filter_list: list[FlextLdifUtilitiesFilters[m.Ldif.Entry]] = [
                predicate_or_filter1
            ] + list(filters)
            if not filter_list:
                return FlextLdifUtilitiesResult[list[m.Ldif.Entry]].ok(list(entries))
            combined: FlextLdifUtilitiesFilters[m.Ldif.Entry] = filter_list[0]
            for f in filter_list[1:]:
                combined = combined & f if mode == "all" else combined | f
            filtered = [entry for entry in entries if combined.matches(entry)]
            return FlextLdifUtilitiesResult[list[m.Ldif.Entry]].ok(filtered)

        @staticmethod
        def is_entry_sequence(
            value: builtins.object,
        ) -> TypeIs[Sequence[m.Ldif.Entry]]:
            """Check if value is a Sequence of Entry objects."""
            match value:
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
        def is_no_arg_callable[R](
            func: Callable[..., R] | object,
        ) -> TypeIs[Callable[[], R]]:
            """Check if callable accepts 0 arguments."""
            if not callable(func):
                return False
            try:
                sig = inspect.signature(func)
                return len(sig.parameters) == 0
            except (ValueError, TypeError):
                return False

        @staticmethod
        def is_object_arg_callable[R](
            func: Callable[..., R] | object,
        ) -> TypeIs[Callable[..., R]]:
            """Check if callable accepts 1 object argument."""
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
                return len(sig.parameters) >= FlextLdifUtilities.Ldif.TWO_ARG_THRESHOLD
            except (ValueError, TypeError):
                return False

        @staticmethod
        @overload
        def process(
            items_or_entries: builtins.object
            | list[builtins.object]
            | tuple[builtins.object, ...]
            | Mapping[str, builtins.object],
            processor_or_config: Callable[..., object]
            | Callable[[str, object], object]
            | None = None,
            *,
            processor: Callable[..., object]
            | Callable[[str, object], object]
            | None = None,
            on_error: str = "collect",
            predicate: Callable[..., bool]
            | Callable[[str, object], bool]
            | None = None,
            filter_keys: set[str] | None = None,
            exclude_keys: set[str] | None = None,
            config: m.Ldif.ProcessConfig | None = None,
            source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
            target_server: c.Ldif.ServerTypes | None = None,
            normalize_dns: bool = True,
            normalize_attrs: bool = True,
        ) -> r[list[builtins.object]]: ...

        @staticmethod
        @overload
        def process(
            items_or_entries: Sequence[m.Ldif.Entry],
            processor_or_config: m.Ldif.ProcessConfig | None = None,
            *,
            processor: Callable[[m.Ldif.Entry], object] | None = None,
            on_error: str = "collect",
            predicate: Callable[[m.Ldif.Entry], bool] | None = None,
            filter_keys: set[str] | None = None,
            exclude_keys: set[str] | None = None,
            config: m.Ldif.ProcessConfig | None = None,
            source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
            target_server: c.Ldif.ServerTypes | None = None,
            normalize_dns: bool = True,
            normalize_attrs: bool = True,
        ) -> FlextLdifUtilitiesResult[list[m.Ldif.Entry]]: ...

        @staticmethod
        def process(
            items_or_entries: builtins.object
            | list[builtins.object]
            | tuple[builtins.object, ...]
            | Mapping[str, builtins.object]
            | Sequence[m.Ldif.Entry],
            processor_or_config: Callable[..., object]
            | Callable[[str, object], object]
            | m.Ldif.ProcessConfig
            | None = None,
            *,
            processor: Callable[..., object]
            | Callable[[str, object], object]
            | Callable[[m.Ldif.Entry], object]
            | None = None,
            on_error: str = "collect",
            predicate: Callable[..., bool]
            | Callable[[str, object], bool]
            | Callable[[m.Ldif.Entry], bool]
            | None = None,
            filter_keys: set[str] | None = None,
            exclude_keys: set[str] | None = None,
            config: m.Ldif.ProcessConfig | None = None,
            source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
            target_server: c.Ldif.ServerTypes | None = None,
            normalize_dns: bool = True,
            normalize_attrs: bool = True,
        ) -> r[list[builtins.object]] | FlextLdifUtilitiesResult[list[m.Ldif.Entry]]:
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
                    entries: list[m.Ldif.Entry] = [
                        x for x in items_or_entries if isinstance(x, m.Ldif.Entry)
                    ]
                    result = FlextLdifUtilities.Ldif.transform_batch(
                        entries,
                        normalize_dns=normalize_dns,
                        normalize_attrs=normalize_attrs,
                    )
                    return FlextLdifUtilitiesResult.from_result(result)
                if processor_normalized is None:
                    msg = "processor is required for base class process"
                    return FlextLdifUtilitiesResult[list[m.Ldif.Entry]].fail(msg)
                msg = "ProcessConfig requires LDIF entry sequence"
                return FlextLdifUtilitiesResult[list[m.Ldif.Entry]].fail(msg)
            processor_func: Callable[..., object] = processor_normalized
            match items_or_entries:
                case dict() | Mapping():
                    dict_items: dict[str, builtins.object] = {}
                    for key, value in items_or_entries.items():
                        dict_items[str(key)] = (
                            FlextLdifUtilities.Ldif.normalize_container(value)
                        )
                    results = FlextLdifUtilities.Ldif.process_dict_items(
                        dict_items, processor_func, predicate, filter_keys, exclude_keys
                    )
                    return r[list[builtins.object]].ok(results)
                case list() | tuple():
                    items_list: list[builtins.object] = [
                        FlextLdifUtilities.Ldif.normalize_container(item)
                        for item in items_or_entries
                    ]
                    return FlextLdifUtilities.Ldif.process_list_items(
                        items_list, processor_func, predicate, on_error
                    )
                case _:
                    if isinstance(items_or_entries, Sequence) and (
                        not isinstance(items_or_entries, (str, bytes))
                    ):
                        msg = "Unsupported non-list sequence for single-item processing"
                        return r[list[builtins.object]].fail(msg)
                    result_item = processor_func(items_or_entries)
                    return r[list[builtins.object]].ok([result_item])

        @staticmethod
        def process_dict_items[R](
            items: Mapping[str, builtins.object],
            processor_func: Callable[..., R],
            predicate: Callable[..., bool] | None,
            filter_keys: set[str] | None,
            exclude_keys: set[str] | None,
        ) -> list[R]:
            """Process dictionary items."""
            results: list[R] = []
            for key, value in items.items():
                if FlextLdifUtilities.Ldif.should_skip_key(
                    key, filter_keys, exclude_keys
                ):
                    continue
                if predicate is not None and (
                    not FlextLdifUtilities.Ldif.evaluate_predicate(
                        predicate, key, value
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
            items: Sequence[builtins.object],
            processor_func: Callable[..., R],
            predicate: Callable[..., bool] | None,
            on_error: str,
        ) -> r[list[R]]:
            """Process list/tuple items."""
            results: list[R] = []
            errors: list[str] = []
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
                        return r[list[R]].fail(f"Processing failed: {e}")
                    if on_error == "skip":
                        continue
                    errors.append(str(e))
            return r[list[R]].ok(results)

        @staticmethod
        def transform_entries(
            entries: Sequence[m.Ldif.Entry],
            *transformers: FlextLdifUtilitiesTransformer[m.Ldif.Entry],
            fail_fast: bool = True,
        ) -> FlextLdifUtilitiesResult[list[m.Ldif.Entry]]:
            """Apply entry transformers to LDIF entries using pipeline semantics."""
            pipeline = Pipeline(fail_fast=fail_fast)
            for transformer in transformers:
                _ = pipeline.add(transformer)
            return FlextLdifUtilitiesResult[list[m.Ldif.Entry]].from_result(
                pipeline.execute(entries)
            )

        @staticmethod
        @overload
        def validate(
            value_or_entries: Sequence[m.Ldif.Entry],
            *,
            strict: bool = True,
            collect_all: bool = True,
            max_errors: int = 0,
        ) -> r[list[ValidationResult]]: ...

        @staticmethod
        @overload
        def validate(
            value_or_entries: t.Container,
            validator_first: p.ValidatorSpec,
            *validators_rest: p.ValidatorSpec,
            strict: bool = True,
            collect_all: bool = True,
            max_errors: int = 0,
        ) -> r[t.Container]: ...

        @staticmethod
        def validate(
            value_or_entries: Sequence[m.Ldif.Entry] | t.Container,
            validator_first: p.ValidatorSpec | None = None,
            *validators_rest: p.ValidatorSpec,
            strict: bool = True,
            collect_all: bool = True,
            max_errors: int = 0,
        ) -> r[list[ValidationResult]] | r[t.Container]:
            """Validate entries against rules."""
            if (
                FlextLdifUtilities.Ldif.is_entry_sequence(value_or_entries)
                and validator_first is None
            ):
                return FlextLdifUtilities.Ldif.validate_entries(
                    value_or_entries,
                    strict=strict,
                    collect_all=collect_all,
                    max_errors=max_errors,
                )
            validators: tuple[p.ValidatorSpec, ...] = (
                (validator_first, *validators_rest) if validator_first else ()
            )
            if isinstance(value_or_entries, Sequence) and (
                not isinstance(value_or_entries, (str, bytes))
            ):
                return r[t.Container].fail(
                    "validator call requires scalar, not entry sequence"
                )
            return FlextLdifUtilitiesValidation.validate(value_or_entries, *validators)

        @staticmethod
        def validate_entries(
            entries: Sequence[m.Ldif.Entry],
            *,
            strict: bool,
            collect_all: bool,
            max_errors: int,
        ) -> r[list[ValidationResult]]:
            """Internal: Validate LDIF entries."""
            pipeline = ValidationPipeline(
                strict=strict, collect_all=collect_all, max_errors=max_errors
            )
            return pipeline.validate(entries)

        nl = normalize_list

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
        def zip_with(
            cls,
            *sequences: Sequence[builtins.object],
            combiner: FlextLdifUtilities.Ldif.VariadicCallable[tuple[object, ...]]
            | None = None,
        ) -> list[builtins.object]:
            """Zip with combiner (generalized: uses zip from base, mnemonic: zw)."""
            if not sequences:
                return []
            zipped = zip(*sequences, strict=False)
            if combiner is None:
                return [tuple(items) for items in zipped]
            result: list[builtins.object] = []
            for items_tuple in zipped:
                items_list = list(items_tuple)
                combined = combiner(*items_list)
                result.append(combined)
            return result

        @staticmethod
        def pipe_ldif(
            value: builtins.object,
            *ops: Mapping[str, builtins.object] | Callable[..., object],
        ) -> builtins.object:
            """LDIF-specific pipe - supports dict operations via flow()."""
            result: builtins.object = value
            for op in ops:
                match op:
                    case dict() as op_dict:
                        current: builtins.object = result
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
            value: builtins.object,
            *ops: Mapping[str, builtins.object] | Callable[..., object],
        ) -> builtins.object:
            """Alias for pipe_ldif (mnemonic: pp)."""
            return FlextLdifUtilities.Ldif.pipe_ldif(value, *ops)

        zw = zip_with

        @classmethod
        def group_by(
            cls,
            items: Sequence[builtins.object],
            *,
            key: Callable[..., object],
        ) -> Mapping[object, list[builtins.object]]:
            """Group by key function (generalized, mnemonic: gb)."""
            items_list = list(items)
            result: dict[object, list[builtins.object]] = {}
            for item in items_list:
                k = key(item)
                if k not in result:
                    result[k] = []
                result[k].append(item)
            return result

        gb = group_by

        @classmethod
        def partition(
            cls,
            items: Sequence[builtins.object],
            *,
            predicate: Callable[..., bool],
        ) -> tuple[list[builtins.object], list[builtins.object]]:
            """Partition items by predicate into (matches, non-matches) (mnemonic: pt)."""
            matches: list[builtins.object] = []
            non_matches: list[builtins.object] = []
            for item in items:
                if predicate(item):
                    matches.append(item)
                else:
                    non_matches.append(item)
            return (matches, non_matches)

        pt = partition

        @classmethod
        @overload
        def get_ldif(
            cls, data: Mapping[str, builtins.object], key: str, *, default: str = ""
        ) -> str: ...

        @classmethod
        @overload
        def get_ldif[T](
            cls,
            data: Mapping[str, builtins.object] | object,
            key: str,
            *,
            default: list[T],
        ) -> list[T]: ...

        @classmethod
        @overload
        def get_ldif[T](
            cls,
            data: Mapping[str, builtins.object] | object,
            key: str,
            *,
            default: T | None = None,
        ) -> T | None: ...

        @classmethod
        def get_ldif[T](
            cls,
            data: Mapping[str, builtins.object] | object,
            key: str,
            *,
            default: builtins.object | T | None = None,
        ) -> builtins.object | T | None:
            """Safe get with optional mapping (DSL pattern)."""
            match data:
                case Mapping() as data_mapping:
                    return data_mapping.get(key, default)
                case _:
                    pass
            return default

        @classmethod
        def pluck(
            cls,
            items: Sequence[builtins.object],
            *,
            key: str | int | Callable[..., object],
        ) -> list[builtins.object]:
            """Extract values from sequence by key/index/function (mnemonic: pk)."""
            result: list[builtins.object] = []
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
                                item_sequence[key] if len(item_sequence) > key else None
                            )
                        case _:
                            if getattr(item, str(key), None) is not None:
                                result.append(getattr(item, str(key)))
                            else:
                                result.append(None)
            return result

        pk = pluck

        @classmethod
        def normalize_ldif(
            cls,
            value: str | list[str] | tuple[str, ...] | set[str] | frozenset[str],
            other: str
            | list[str]
            | tuple[str, ...]
            | set[str]
            | frozenset[str]
            | None = None,
            *,
            case: str = "lower",
        ) -> str | list[str] | set[str] | bool:
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
                            other_str
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
            return normalize_single(str(value))

        nz = normalize_ldif

        @classmethod
        def pairs(cls, d: Mapping[str, builtins.object]) -> list[tuple[str, object]]:
            """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr)."""
            return list(d.items())

        pr = pairs

        @staticmethod
        def count[T](
            items: list[T] | tuple[T, ...], predicate: Callable[[T], bool] | None = None
        ) -> int:
            """Count items (generalized: uses count from base, mnemonic: ct)."""
            if predicate is not None:
                filtered_items = [item for item in items if predicate(item)]
                return FlextUtilities.count(filtered_items)
            return FlextUtilities.count(items)

        ct = count

        @classmethod
        def omit(
            cls, obj: Mapping[str, builtins.object], *keys: str
        ) -> Mapping[str, builtins.object]:
            """Omit keys using FlextUtilities.map_dict() DSL (mnemonic: om)."""
            if not obj or not keys:
                return dict(obj) if obj else {}
            keys_set = set(keys)
            return cls.map_dict(obj, predicate=lambda k, _: k not in keys_set)

        om = omit

        @staticmethod
        def is_empty_value(value: builtins.object) -> bool:
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
        def merge_dicts(
            *dicts: Mapping[str, builtins.object],
            strategy: str = "deep",
            filter_none: bool = False,
            filter_empty: bool = False,
        ) -> r[Mapping[str, builtins.object]]:
            """Merge multiple dicts with filtering options (mnemonic: mg)."""
            dicts_typed: tuple[Mapping[str, builtins.object], ...] = dicts
            if not dicts_typed:
                return r[Mapping[str, builtins.object]].ok({})
            merged: dict[str, builtins.object] = {}
            for dict_item in dicts_typed:
                dict_item_dict: dict[str, builtins.object] = dict(dict_item)
                merge_result = FlextUtilities.merge(
                    merged,
                    dict_item_dict,
                    strategy=strategy,
                )
                if merge_result.is_failure:
                    return r[Mapping[str, builtins.object]].fail(
                        merge_result.error or "Merge failed"
                    )
                merged = merge_result.value
            if filter_none or filter_empty:
                filtered: dict[str, builtins.object] = {}
                for key, value in merged.items():
                    if filter_empty and FlextLdifUtilities.Ldif.is_empty_value(value):
                        continue
                    filtered[key] = value
                merged = filtered
            return r[Mapping[str, builtins.object]].ok(merged)

        mg = merge_dicts

        @classmethod
        def smart_convert(
            cls,
            value: builtins.object | r[builtins.object],
            *,
            target_type: str,
            predicate: Callable[..., bool] | None = None,
            default: builtins.object = None,
        ) -> builtins.object:
            """Smart convert using FlextUtilities.build() DSL (mnemonic: sc)."""
            match value:
                case r() as result_value:
                    extracted: builtins.object = (
                        result_value.value if not result_value.is_failure else default
                    )
                case _:
                    extracted = value
            if extracted is None:
                return default
            conv_builder = cls.conv(extracted)
            conv_result: builtins.object = None
            if target_type == "str":
                str_default = default if isinstance(default, str) else ""
                conv_result = conv_builder.to_str(default=str_default).build()
            elif target_type == "int":
                int_default = default if isinstance(default, int) else 0
                conv_result = conv_builder.to_int(default=int_default).build()
            elif target_type == "bool":
                bool_default = default if isinstance(default, bool) else False
                conv_result = conv_builder.to_bool(default=bool_default).build()
            elif target_type == "list":
                list_default: list[str] = []
                match default:
                    case list() | tuple() as default_seq:
                        list_default = [str(item) for item in default_seq]
                    case _:
                        pass
                conv_result = conv_builder.str_list(default=list_default).build()
                if predicate and isinstance(conv_result, list):
                    filtered = [item for item in conv_result if predicate(item)]
                    return filtered or conv_result
            else:
                ops: dict[str, builtins.object] = {
                    "ensure": target_type,
                    "ensure_default": default,
                }
                if predicate:
                    pass
                conv_result = cls.build(
                    extracted,
                    ops=ops,
                )
            return conv_result if conv_result is not None else default

        sc = smart_convert

        @classmethod
        def as_type(
            cls,
            value: builtins.object,
            *,
            target: type | str,
            default: builtins.object | None = None,
        ) -> builtins.object:
            """Safe cast using FlextUtilities.convert() or FlextUtilities.ensure() (mnemonic: at)."""
            type_map = {
                "list": list,
                "dict": dict,
                "str": str,
                "int": int,
                "bool": bool,
                "tuple": tuple,
            }
            target_type = type_map.get(target) if isinstance(target, str) else target
            if target_type is None:
                return default
            if target_type is str:
                str_default = default if isinstance(default, str) else ""
                return cls.conv(value).to_str(default=str_default).safe().build()
            if target_type is int:
                int_default = default if isinstance(default, int) else 0
                return cls.conv(value).to_int(default=int_default).safe().build()
            if target_type is bool:
                bool_default = default if isinstance(default, bool) else False
                return cls.conv(value).to_bool(default=bool_default).safe().build()
            if target_type is list:
                list_default: list[str] = []
                match default:
                    case list() | tuple() as default_seq:
                        list_default = [str(item) for item in default_seq]
                    case _:
                        pass
                return cls.conv(value).str_list(default=list_default).safe().build()
            ops: dict[str, builtins.object] = {}
            result = cls.build(
                value,
                ops=ops,
            )
            result_typed = FlextLdifUtilities.Ldif.to_config_map_value(result)
            return cls.or_(result_typed, default=default)

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

        @staticmethod
        def is_type(
            value: builtins.object, type_spec: str | type | tuple[type, ...]
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
            for t_val in types_tuple:
                resolved_type: type | None = (
                    type_map.get(t_val) if isinstance(t_val, str) else t_val
                )
                if resolved_type is not None and FlextUtilities.is_type(
                    value, resolved_type
                ):
                    return True
            return False

        gd = guard_simple

        @classmethod
        def thru(
            cls, value: builtins.object, *, fn: Callable[..., object]
        ) -> builtins.object:
            """Thru using direct call (mnemonic: th)."""
            return fn(value)

        th = thru

        @classmethod
        def comp(cls, *fns: Callable[..., object]) -> Callable[..., object]:
            """Compose using FlextUtilities.chain() (mnemonic: cp)."""
            if not fns:
                return lambda x: x
            return lambda value: cls.chain(value, *fns)

        cp = comp

        @classmethod
        def juxt(
            cls, *fns: Callable[..., object]
        ) -> Callable[..., tuple[builtins.object, ...]]:
            """Juxtapose functions (mnemonic: jx)."""
            if not fns:
                return lambda _x: ()
            return lambda value: tuple(fn(value) for fn in fns)

        jx = juxt

        @classmethod
        def curry(
            cls, fn: Callable[..., object], *args: builtins.object
        ) -> Callable[..., object]:
            """Curry function (mnemonic: cy)."""

            def curried(
                *more_args: builtins.object, **_kwargs: t.Scalar
            ) -> builtins.object:
                combined_args: tuple[builtins.object, ...] = args + more_args
                converted_args: list[builtins.object] = []
                for arg in combined_args:
                    match arg:
                        case None:
                            converted_args.append(None)
                        case list() | tuple() | dict() | Mapping():
                            converted_args.append(arg)
                        case _:
                            converted_args.append(str(arg))
                if len(converted_args) == 0:
                    result = fn()
                elif len(converted_args) == 1:
                    result = fn(converted_args[0])
                else:
                    result = fn(*converted_args)
                return result

            return curried

        cy = curry

        @classmethod
        def _detect_predicate_type(
            cls,
            pairs: tuple[
                tuple[
                    Callable[[], bool] | Callable[..., bool] | bool,
                    object,
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
                return len(sig.parameters) == 0
            except (ValueError, TypeError):
                return False

        @classmethod
        def _evaluate_no_arg_result(
            cls, result_val: builtins.object
        ) -> builtins.object:
            """Evaluate a no-arg result value."""
            return result_val

        @classmethod
        def _evaluate_value_arg_predicate(
            cls,
            *,
            pred: Callable[[], bool] | Callable[..., bool] | bool,
            value: builtins.object,
        ) -> bool:
            """Evaluate a value-arg predicate."""
            if callable(pred):
                if FlextLdifUtilities.Ldif.is_no_arg_callable(pred):
                    return pred()
                if FlextLdifUtilities.Ldif.is_object_arg_callable(pred):
                    return pred(value)
                return bool(pred)
            return bool(pred)

        @classmethod
        def _evaluate_value_arg_result(
            cls, result_val: builtins.object, value: builtins.object
        ) -> builtins.object:
            """Evaluate a value-arg result value."""
            _ = value
            return result_val

        @classmethod
        def cond(
            cls,
            *pairs: tuple[
                Callable[[], bool] | Callable[..., bool] | bool,
                object,
            ],
            default: builtins.object | None = None,
        ) -> Callable[[], object] | Callable[..., object]:
            """Cond pattern (mnemonic: cd)."""
            is_no_arg = cls._detect_predicate_type(pairs)
            if is_no_arg:

                def conditional_no_arg() -> builtins.object:
                    for pred, result_val in pairs:
                        evaluated = False
                        if FlextLdifUtilities.Ldif.is_no_arg_callable(pred):
                            with contextlib.suppress(TypeError):
                                evaluated = bool(pred())
                        elif not callable(pred):
                            evaluated = bool(pred)
                        if evaluated:
                            return cls._evaluate_no_arg_result(result_val)
                    return default

                return conditional_no_arg

            def conditional(value: builtins.object) -> builtins.object:
                for pred, result_val in pairs:
                    if cls._evaluate_value_arg_predicate(pred=pred, value=value):
                        return cls._evaluate_value_arg_result(result_val, value)
                return default

            return conditional

        cd = cond

        @classmethod
        def switch(
            cls,
            value: builtins.object,
            cases: Mapping[object, object],
            default: builtins.object | None = None,
        ) -> builtins.object:
            """Switch using dict lookup (mnemonic: sw)."""
            return cases.get(value, default)

        sw = switch

        @classmethod
        def defaults(
            cls, *dicts: Mapping[str, builtins.object] | None
        ) -> Mapping[str, builtins.object]:
            """Defaults merge - first wins using FlextUtilities.flow() DSL (mnemonic: df)."""
            if not dicts:
                return {}

            def apply_defaults(
                acc: builtins.object, d: builtins.object
            ) -> builtins.object:
                """Apply defaults using fold() pattern: first wins, later fill missing/None."""
                match (acc, d):
                    case [dict() as acc_dict, dict() as d_dict]:
                        pass
                    case _:
                        return acc
                filtered = cls.map_dict(
                    d_dict,
                    predicate=lambda k, _v: (
                        k not in acc_dict or acc_dict.get(k) is None
                    ),
                )
                acc_dict.update(filtered)
                return acc_dict

            dict_list = [
                dict_item for dict_item in dicts if isinstance(dict_item, dict)
            ]
            if dict_list:
                result = cls.fold(dict_list, folder=apply_defaults, initial={})
                return result if isinstance(result, dict) else {}
            return {}

        d = defaults

        @classmethod
        def deep_merge(
            cls, *dicts: Mapping[str, builtins.object] | None
        ) -> Mapping[str, builtins.object]:
            """Deep merge using FlextUtilities.merge() with deep strategy (mnemonic: dm)."""
            if not dicts:
                return {}
            mapping_list: list[dict[str, builtins.object]] = [
                dict_item for dict_item in dicts if isinstance(dict_item, dict)
            ]
            if not mapping_list:
                return {}
            merged: dict[str, builtins.object] = {
                key: FlextLdifUtilities.Ldif.to_config_map_value(value)
                for key, value in dict(mapping_list[0]).items()
            }
            for mapping in mapping_list[1:]:
                mapping_dict: dict[str, builtins.object] = {
                    key: FlextLdifUtilities.Ldif.to_config_map_value(value)
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
            obj: dict[str, builtins.object],
            *updates: Mapping[str, builtins.object] | None,
        ) -> dict[str, builtins.object]:
            """Update in-place using FlextUtilities.flow() pattern (mnemonic: ui)."""
            for update in updates:
                if update is not None:
                    obj.update(update)
            return obj

        ui = update_inplace

        @classmethod
        def _apply_deep_defaults_recursive(
            cls, acc: builtins.object, d: builtins.object
        ) -> builtins.object:
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
            cls, *dicts: Mapping[str, builtins.object] | None
        ) -> Mapping[str, builtins.object]:
            """Deep defaults using FlextUtilities.merge() deep strategy + first wins (mnemonic: dd)."""
            if not dicts:
                return {}
            dict_list = [
                dict_item
                for dict_item in reversed(dicts)
                if isinstance(dict_item, dict)
            ]
            if not dict_list:
                return {}
            result = FlextLdifUtilities.Ldif.fold(
                dict_list, folder=cls._apply_deep_defaults_recursive, initial={}
            )
            return result if isinstance(result, dict) else {}

        dd = defaults_deep

        @staticmethod
        def take(
            data_or_items: Mapping[str, builtins.object]
            | Sequence[builtins.object]
            | object,
            key_or_n: str | int,
            *,
            as_type: type | None = None,
            default: builtins.object | None = None,
            from_start: bool = True,
        ) -> (
            Mapping[str, builtins.object]
            | list[builtins.object]
            | builtins.object
            | None
        ):
            """Take value from data with type guard (mnemonic: tk)."""
            if isinstance(key_or_n, str):
                value: builtins.object = None
                match data_or_items:
                    case Mapping() as mapping_items:
                        raw_value = mapping_items.get(key_or_n, default)
                        value = FlextLdifUtilities.Ldif.to_config_map_value(raw_value)
                    case _ if getattr(data_or_items, key_or_n, None) is not None:
                        raw_attr = getattr(data_or_items, key_or_n, default)
                        value = FlextLdifUtilities.Ldif.to_config_map_value(raw_attr)
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
                    sliced_dict: dict[str, builtins.object] = {
                        key: FlextLdifUtilities.Ldif.to_config_map_value(value)
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

        @classmethod
        def let(
            cls, value: builtins.object, *, fn: Callable[..., object]
        ) -> builtins.object:
            """Let using chain() (mnemonic: lt)."""
            return FlextLdifUtilities.Ldif.chain(value, fn)

        lt = let

        @classmethod
        def apply(
            cls,
            fn: FlextLdifUtilities.Ldif.VariadicCallable[object] | object,
            *args: builtins.object,
            **kwargs: t.Scalar,
        ) -> builtins.object:
            """Apply function (mnemonic: ap)."""
            if callable(fn):
                return fn(*args, **kwargs)
            return fn

        ap = apply

        @classmethod
        def bind(
            cls, value: builtins.object, *fns: Callable[..., object]
        ) -> builtins.object:
            """Bind using chain() (mnemonic: bd)."""
            return FlextLdifUtilities.Ldif.chain(value, *fns)

        bd = bind

        @classmethod
        def lift(
            cls, fn: Callable[..., object]
        ) -> Callable[..., builtins.object | None]:
            """Lift function for optionals (mnemonic: lf)."""

            def lifted_fn(v: builtins.object) -> builtins.object | None:
                """Lifted function with safe None handling using DSL."""
                return FlextLdifUtilities.Ldif.maybe(
                    cls.tr(lambda: fn(v), default=None), default=None
                )

            return lifted_fn

        lf = lift

        @classmethod
        def seq(cls, *values: builtins.object) -> list[builtins.object]:
            """Sequence constructor (mnemonic: sq)."""
            return list(values)

        sq = seq

        @classmethod
        def assoc(
            cls, data: Mapping[str, builtins.object], key: str, value: builtins.object
        ) -> Mapping[str, builtins.object]:
            """Associate key-value using FlextUtilities.merge() DSL (mnemonic: ac)."""
            updated = dict(data)
            updated[key] = value
            return updated

        ac = assoc

        @classmethod
        def dissoc(
            cls, data: Mapping[str, builtins.object], *keys: str
        ) -> Mapping[str, builtins.object]:
            """Dissociate keys using omit DSL (mnemonic: ds)."""
            return {k: v for k, v in data.items() if k not in keys}

        ds = dissoc

        @classmethod
        def update(
            cls,
            data: Mapping[str, builtins.object],
            updates: Mapping[str, builtins.object],
        ) -> Mapping[str, builtins.object]:
            """Update dict using FlextUtilities.merge() (mnemonic: ud)."""
            updated = dict(data)
            updated.update(updates)
            return updated

        ud = update

        @classmethod
        def evolve(
            cls,
            obj: Mapping[str, builtins.object],
            *transforms: Mapping[str, builtins.object]
            | Callable[[dict[str, builtins.object]], Mapping[str, builtins.object]],
        ) -> Mapping[str, builtins.object]:
            """Evolve using FlextUtilities.flow() pattern (mnemonic: ev)."""
            result: dict[str, builtins.object] = dict(obj)
            for transform in transforms:
                if callable(transform) and (not isinstance(transform, Mapping)):
                    transformed = transform(result)
                    result = FlextLdifUtilities.Ldif.normalize_mapping(transformed)
                else:
                    continue
            return result

        ev = evolve

        @classmethod
        def keys[T](
            cls,
            items: Mapping[str, T] | r[Mapping[str, T]],
            *,
            default: list[str] | None = None,
        ) -> list[str]:
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
            items: Mapping[str, T] | r[Mapping[str, T]],
            *,
            default: list[T] | None = None,
        ) -> list[T]:
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
        def invert(cls, obj: Mapping[str, builtins.object]) -> Mapping[str, str]:
            """Invert dict using FlextUtilities.map_dict() pattern (mnemonic: iv)."""
            str_dict: Mapping[str, str] = {k: str(v) for k, v in obj.items()}
            inverted = FlextUtilities.invert_dict(str_dict)
            return dict(inverted)

        iv = invert

        @classmethod
        def where(
            cls,
            obj: Mapping[str, builtins.object],
            *,
            predicate: Callable[[str, object], bool] | None = None,
        ) -> Mapping[str, builtins.object]:
            """Where using FlextUtilities.filter() (mnemonic: wh)."""
            if predicate is None:
                return dict(obj)
            return {k: v for k, v in obj.items() if predicate(k, v)}

        wh = where

        @classmethod
        def prop(cls, key: str) -> Callable[..., object]:
            """Property accessor using FlextUtilities.get() (mnemonic: pp)."""

            def getter(obj: builtins.object) -> builtins.object:
                """Get value from object by key."""
                match obj:
                    case Mapping() as obj_mapping:
                        return FlextLdifUtilities.Ldif.to_config_map_value(
                            obj_mapping.get(key)
                        )
                    case _:
                        pass
                if getattr(obj, key, None) is not None:
                    return getattr(obj, key)
                return None

            return getter

        prop_get = prop

        @classmethod
        def props(cls, *keys: str) -> Callable[..., Mapping[str, builtins.object]]:
            """Props accessor using FlextUtilities.pick() directly (mnemonic: ps)."""

            def accessor(obj: builtins.object) -> Mapping[str, builtins.object]:
                match obj:
                    case Mapping() as obj_mapping:
                        return {
                            key: FlextLdifUtilities.Ldif.to_config_map_value(
                                obj_mapping.get(key, None)
                            )
                            for key in keys
                        }
                    case _:
                        pass
                result_dict: dict[str, builtins.object] = {}
                for k in keys:
                    if getattr(obj, k, None) is not None:
                        result_dict[k] = FlextLdifUtilities.Ldif.to_config_map_value(
                            getattr(obj, k)
                        )
                    else:
                        result_dict[k] = ""
                return result_dict

            return accessor

        ps = props

        @classmethod
        def path(cls, *keys: str) -> Callable[..., object]:
            """Path accessor using FlextUtilities.chain() DSL (mnemonic: ph)."""

            def make_getter(
                key: str,
            ) -> Callable[..., object]:

                def getter_fn(obj: builtins.object) -> builtins.object:
                    """Get value from object by key."""
                    match obj:
                        case Mapping() as obj_mapping:
                            return FlextLdifUtilities.Ldif.to_config_map_value(
                                obj_mapping.get(key, "")
                            )
                        case _:
                            pass
                    if getattr(obj, key, None) is not None:
                        return FlextLdifUtilities.Ldif.to_config_map_value(
                            getattr(obj, key)
                        )
                    return ""

                return getter_fn

            getters: list[Callable[..., object]] = [make_getter(k) for k in keys]
            return lambda obj: cls.chain(obj, *getters)

        ph = path

        @staticmethod
        def all_(*args: builtins.object) -> bool:
            """Check if all values are truthy."""
            return all(args)

        @staticmethod
        def any_(*args: builtins.object) -> bool:
            """Check if any value is truthy."""
            return any(args)

        @staticmethod
        def conv(value: builtins.object) -> FlextLdifUtilities.Ldif.ConvBuilder:
            """Create conversion builder (DSL entry point)."""
            return FlextLdifUtilities.Ldif.ConvBuilder(value=value)

        @staticmethod
        def empty(value: builtins.object) -> bool:
            """Check if value is empty."""
            if value is None:
                return True
            if isinstance(value, (str, bytes)):
                return len(value) == 0
            if isinstance(value, Mapping):
                return len(value) == 0
            if isinstance(value, Sequence):
                return len(value) == 0
            return False

        @staticmethod
        def or_[T: builtins.object](
            *values: T | None, default: T | None = None
        ) -> T | None:
            """Return first non-None value (mnemonic: oo)."""
            for v in values:
                if v is not None:
                    return v
            return default

        @staticmethod
        def sum(
            items: Sequence[int | float | object] | Mapping[str, int | float | object],
        ) -> int | float:
            """Sum of numeric items."""
            if isinstance(items, Mapping):
                total_dict: int | float = 0
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
            total_seq: int | float = 0.0 if has_float else 0
            for v in items:
                match v:
                    case int() | float():
                        total_seq += v
                    case _:
                        pass
            return total_seq

        oo = or_

        @staticmethod
        def maybe(
            value: builtins.object | None,
            *,
            default: builtins.object | None = None,
            mapper: Callable[..., object] | None = None,
        ) -> builtins.object | None:
            """Maybe monad pattern (mnemonic: mb)."""
            if value is None:
                return default
            if mapper:
                return mapper(value)
            return value

        mb = maybe

        @staticmethod
        def chain(
            value: builtins.object, *funcs: Callable[..., object]
        ) -> builtins.object:
            """Chain function calls (DSL helper, mnemonic: ch)."""
            result = value
            for func in funcs:
                result = func(result)
            return result

        ch = chain

        @staticmethod
        def pick(
            data: Mapping[str, builtins.object] | object,
            *keys: str,
            as_dict: bool = True,
        ) -> Mapping[str, builtins.object] | list[builtins.object]:
            """Pick keys from dict (DSL helper, mnemonic: pc)."""
            if not isinstance(data, Mapping):
                return {} if as_dict else []

            data_mapping: dict[str, builtins.object] = {
                str(key): FlextLdifUtilities.Ldif.to_config_map_value(value)
                for key, value in data.items()
            }
            if as_dict:
                return {k: data_mapping[k] for k in keys if k in data_mapping}
            return [data_mapping[k] for k in keys if k in data_mapping]

        pc = pick

        @staticmethod
        def map_dict(
            obj: Mapping[str, builtins.object],
            *,
            mapper: Callable[[str, object], object] | None = None,
            key_mapper: Callable[[str], str] | None = None,
            predicate: Callable[[str, object], bool] | None = None,
        ) -> Mapping[str, builtins.object]:
            """Map dict with optional transformations (mnemonic: md)."""
            result: dict[str, builtins.object] = {}
            for k, v in obj.items():
                if predicate and (not predicate(k, v)):
                    continue
                new_k = key_mapper(k) if key_mapper else k
                new_v: builtins.object = mapper(k, v) if mapper else v
                result[new_k] = new_v
            return result

        md = map_dict

        @staticmethod
        def reduce_dict(
            items: Sequence[Mapping[str, builtins.object]]
            | Mapping[str, builtins.object]
            | object,
            *,
            processor: Callable[[str, object], tuple[str, object]] | None = None,
            predicate: Callable[[str, object], bool] | None = None,
            default: Mapping[str, builtins.object] | None = None,
        ) -> Mapping[str, builtins.object]:
            """Reduce dicts (mnemonic: rd)."""
            if not items:
                return default or {}
            items_list: list[dict[str, builtins.object]] = []
            if isinstance(items, Mapping):
                items_list = [
                    {
                        str(key): FlextLdifUtilities.Ldif.to_config_map_value(value)
                        for key, value in items.items()
                    }
                ]
            elif isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
                for item in items:
                    if isinstance(item, Mapping):
                        items_list.append({
                            str(key): FlextLdifUtilities.Ldif.to_config_map_value(value)
                            for key, value in item.items()
                        })
            result: dict[str, builtins.object] = dict(default) if default else {}
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
        def fold(
            items: Sequence[builtins.object] | object,
            *,
            initial: builtins.object,
            folder: Callable[[object, object], object] | None = None,
            predicate: Callable[..., bool] | None = None,
        ) -> builtins.object:
            """Fold items using folder function (mnemonic: fd)."""
            if not folder:
                return initial
            items_list: list[builtins.object]
            if isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
                items_list = [
                    FlextLdifUtilities.Ldif.to_config_map_value(item) for item in items
                ]
            else:
                items_list = [FlextLdifUtilities.Ldif.to_config_map_value(items)]
            if predicate:
                items_list = [item for item in items_list if predicate(item)]
            result: builtins.object = initial
            for item in items_list:
                result = folder(result, item)
            return result

        fd = fold

        @staticmethod
        def map_filter(
            items: Sequence[builtins.object] | object,
            *,
            mapper: Callable[..., object] | None = None,
            predicate: Callable[..., bool] | None = None,
        ) -> list[builtins.object]:
            """Map then filter items (mnemonic: mf)."""
            items_list: list[builtins.object]
            if isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
                items_list = [
                    FlextLdifUtilities.Ldif.to_config_map_value(item) for item in items
                ]
            else:
                items_list = [FlextLdifUtilities.Ldif.to_config_map_value(items)]
            if mapper:
                items_list = [mapper(item) for item in items_list]
            if predicate:
                items_list = [item for item in items_list if predicate(item)]
            return items_list

        mf = map_filter

        @staticmethod
        def process_flatten(
            items: Mapping[str, builtins.object]
            | list[builtins.object]
            | tuple[builtins.object, ...]
            | set[builtins.object]
            | frozenset[object]
            | object,
            *,
            processor: Callable[..., object] | None = None,
            on_error: str = "skip",
        ) -> list[builtins.object]:
            """Process and flatten items (mnemonic: pf)."""
            if isinstance(items, Mapping):
                items_list: list[builtins.object] = list(
                    FlextLdifUtilities.Ldif.normalize_mapping(items).values()
                )
            elif isinstance(items, (list, tuple, set, frozenset)):
                items_list = [
                    FlextLdifUtilities.Ldif.normalize_container(v) for v in items
                ]
            else:
                items_list = [FlextLdifUtilities.Ldif.normalize_container(items)]
            result: list[builtins.object] = []
            for item in items_list:
                try:
                    processed = processor(item) if processor else item
                    if isinstance(processed, Sequence) and not isinstance(
                        processed, (str, bytes)
                    ):
                        result.extend(
                            FlextLdifUtilities.Ldif.normalize_container(v)
                            for v in processed
                        )
                    else:
                        result.append(
                            FlextLdifUtilities.Ldif.to_config_map_value(processed)
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
        def build(
            value: builtins.object, *, ops: Mapping[str, builtins.object] | None = None
        ) -> builtins.object:
            """Build value using operations dict (DSL helper)."""
            if ops is None:
                return value
            return value

        @staticmethod
        def find_key(
            obj: Mapping[str, builtins.object],
            *,
            predicate: Callable[[str, object], bool] | None = None,
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
            obj: Mapping[str, builtins.object],
            *,
            predicate: Callable[[str, object], bool] | None = None,
        ) -> builtins.object | None:
            """Find first value matching predicate (mnemonic: fv)."""
            if not predicate:
                return next(iter(obj.values()), None)
            for k, v in obj.items():
                if predicate(k, v):
                    return v
            return None

        fv = find_val

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


__all__ = ["FlextLdifUtilities", "u"]

u = FlextLdifUtilities
