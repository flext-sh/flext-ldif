"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations."""
# ruff: noqa: SLF001

from __future__ import annotations

import contextlib
import inspect
from collections.abc import (
    Callable,
    Collection as ABCCollection,
    Iterable,
    Mapping,
    Sequence,
)
from enum import Enum
from typing import (
    ClassVar,
    Literal,
    Self,
    TypeGuard,
    TypeIs,
    overload,
)

from flext_core import FlextLogger, FlextResult, r
from flext_core.typings import t
from flext_core.utilities import FlextUtilities as u_core

from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.configs import ProcessConfig, TransformConfig
from flext_ldif._utilities.decorators import FlextLdifUtilitiesDecorators
from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
from flext_ldif._utilities.filters import EntryFilter
from flext_ldif._utilities.fluent import DnOps, EntryOps
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers
from flext_ldif._utilities.pipeline import (
    Pipeline,
    ProcessingPipeline,
    ValidationPipeline,
    ValidationResult,
)
from flext_ldif._utilities.result import FlextLdifResult
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif._utilities.transformers import EntryTransformer
from flext_ldif._utilities.type_guards import FlextLdifUtilitiesTypeGuards
from flext_ldif._utilities.type_helpers import is_entry_sequence
from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import p

logger = FlextLogger(__name__)


class FlextLdifUtilities(u_core):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations."""

    # === EXPOSE BASE UTILITIES ===

    # === LDIF NAMESPACE ===
    class Ldif:
        """LDIF-specific utility namespace."""

        # === EXPOSE BASE UTILITIES (from parent FlextLdifUtilities) ===

        type VariadicCallable[T] = p.VariadicCallable[T]

        class ConvBuilder:
            """Conversion builder for type-safe value conversion (DSL pattern)."""

            def __init__(
                self,
                *,
                value: t.GeneralValueType,
            ) -> None:
                """Initialize conversion builder with a value."""
                self._value = value
                self._default: t.GeneralValueType = None
                self._target_type: str | None = None
                self._safe_mode = False

            def to_str(self, default: str = "") -> Self:
                """Convert to string using parent Conversion utilities."""
                self._default = default
                self._target_type = "to_str"
                return self

            def to_int(self, default: int = 0) -> Self:
                """Convert to int."""
                self._default = default
                self._target_type = "to_int"
                return self

            def to_bool(self, *, default: bool = False) -> Self:
                """Convert to bool."""
                self._default = default
                self._target_type = "to_bool"
                return self

            def str_list(self, default: list[str] | None = None) -> Self:
                """Convert to string list using parent Conversion utilities."""
                self._default = default or []
                self._target_type = "to_str_list"
                return self

            def safe(self) -> Self:
                """Enable safe mode."""
                self._safe_mode = True
                return self

            def build(self) -> t.GeneralValueType:
                """Build and return the converted value using parent utilities."""
                if self._value is None:
                    return self._default
                if self._target_type == "to_str":
                    str_default: str | None = (
                        self._default if isinstance(self._default, str) else None
                    )
                    return u_core.to_str(self._value, default=str_default)
                if self._target_type == "to_str_list":
                    list_default: list[str] | None = None
                    if isinstance(self._default, list):
                        list_default = [str(item) for item in self._default]
                    return u_core.to_str_list(self._value, default=list_default)
                if self._target_type == "to_int":
                    if self._safe_mode:
                        try:
                            if isinstance(self._value, (int, str)):
                                return int(self._value)
                            if isinstance(self._value, float):
                                return int(self._value)
                            return self._default
                        except (ValueError, TypeError):
                            return self._default
                    if isinstance(self._value, (int, str)):
                        return int(self._value)
                    if isinstance(self._value, float):
                        return int(self._value)
                    return self._default
                if self._target_type == "to_bool":
                    if isinstance(self._value, bool):
                        return self._value
                    if isinstance(self._value, str):
                        return self._value.lower() in {"true", "1", "yes", "on"}
                    return bool(self._value)
                return self._value if self._value is not None else self._default

        # === Static utility methods ===

        @staticmethod
        def get_from_mapping[T](
            mapping: Mapping[str, T],
            key: str,
            *,
            default: T | None = None,
        ) -> T | None:
            """Get value from mapping with default."""
            return mapping.get(key, default)

        @staticmethod
        def unwrap_or[T](result: r[T], *, default: T | None = None) -> T | None:
            """Unwrap FlextResult with default value."""
            if result.is_success:
                return result.value
            return default

        @staticmethod
        def batch_process[T, U](
            items: Sequence[T],
            func: Callable[[T], r[U]],
        ) -> r[list[U]]:
            """Execute batch of operations with FlextResult (simplified)."""
            results: list[U] = []
            for item in items:
                result = func(item)
                if result.is_failure:
                    return r[list[U]].fail(result.error or "Batch operation failed")
                results.append(result.value)
            return r[list[U]].ok(results)

        @staticmethod
        def find(
            items: Sequence[t.GeneralValueType],
            *,
            predicate: p.Ldif.ValuePredicate,
        ) -> t.GeneralValueType | None:
            """Find first item matching predicate."""
            for elem in items:
                if predicate(elem):
                    return elem
            return None

        match = staticmethod(u_core.match)

        # === LDIF-specific utility classes ===

        class ACL(FlextLdifUtilitiesACL):
            """ACL utilities for LDIF operations."""

        class Attribute(FlextLdifUtilitiesAttribute):
            """Attribute utilities for LDIF operations."""

        class Constants(c):
            """Constants for LDIF operations."""

            _CATEGORY_MAP: ClassVar[dict[str, type[Enum]]] = {
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
                cls,
                values: set[str],
                category: str,
            ) -> tuple[bool, set[str]]:
                """Validate multiple values for a category."""
                if category not in cls._CATEGORY_MAP:
                    msg = f"Unknown category: {category}"
                    raise KeyError(msg)
                valid_values = cls.get_valid_values(category)
                valid_lower = {v.lower() for v in valid_values}
                invalid = {v for v in values if v.lower() not in valid_lower}
                return len(invalid) == 0, invalid

        class Decorators(FlextLdifUtilitiesDecorators):
            """Decorator utilities for LDIF operations."""

        class Detection(FlextLdifUtilitiesDetection):
            """Detection utilities for LDIF operations."""

        class DN(FlextLdifUtilitiesDN):
            """DN utilities for LDIF operations."""

        class Entry:
            """Entry utilities for LDIF operations using composition to avoid circular imports."""

            @staticmethod
            def is_schema_entry(entry: m.Ldif.Entry, *, strict: bool = True) -> bool:
                """Check if entry is a REAL schema entry with schema definitions."""
                return FlextLdifUtilitiesEntry.is_schema_entry(entry, strict=strict)

            @staticmethod
            def has_objectclass(
                entry: m.Ldif.Entry,
                objectclasses: str | tuple[str, ...],
            ) -> bool:
                """Check if entry has specified objectClass."""
                return FlextLdifUtilitiesEntry.has_objectclass(entry, objectclasses)

            @staticmethod
            def has_all_attributes(
                entry: m.Ldif.Entry,
                attributes: list[str],
            ) -> bool:
                """Check if entry has all specified attributes."""
                return FlextLdifUtilitiesEntry.has_all_attributes(entry, attributes)

            @staticmethod
            def has_any_attributes(
                entry: m.Ldif.Entry,
                attributes: list[str],
            ) -> bool:
                """Check if entry has any of the specified attributes."""
                return FlextLdifUtilitiesEntry.has_any_attributes(entry, attributes)

            @staticmethod
            def remove_attributes(
                entry: m.Ldif.Entry,
                attributes: list[str],
            ) -> m.Ldif.Entry:
                """Remove specified attributes from entry."""
                return FlextLdifUtilitiesEntry.remove_attributes(entry, attributes)

            @staticmethod
            def transform_batch(
                entries: Sequence[m.Ldif.Entry],
                config: FlextLdifModelsSettings.EntryTransformConfig | None = None,
                **kwargs: object,
            ) -> r[list[m.Ldif.Entry]]:
                """Transform multiple entries with common operations."""
                return FlextLdifUtilitiesEntry.transform_batch(
                    entries,
                    config,
                    **kwargs,
                )

            @staticmethod
            def filter_batch(
                entries: Sequence[m.Ldif.Entry],
                config: FlextLdifModelsSettings.EntryFilterConfig | None = None,
                **kwargs: object,
            ) -> r[list[m.Ldif.Entry]]:
                """Filter entries based on criteria."""
                return FlextLdifUtilitiesEntry.filter_batch(entries, config, **kwargs)

            @staticmethod
            def matches_server_patterns(
                entry_dn: str,
                attributes: Mapping[str, t.GeneralValueType],
                config: FlextLdifModelsSettings.ServerPatternsConfig,
            ) -> bool:
                """Check if entry matches server-specific patterns."""
                return FlextLdifUtilitiesEntry.matches_server_patterns(
                    entry_dn,
                    attributes,
                    config,
                )

            @staticmethod
            def analyze_differences(
                entry_attrs: Mapping[str, t.GeneralValueType],
                converted_attrs: dict[str, list[str | bytes]],
                original_dn: str,
                cleaned_dn: str,
                normalize_attr_fn: Callable[[str], str] | None = None,
            ) -> tuple[
                dict[str, t.MetadataAttributeValue],
                dict[str, dict[str, t.MetadataAttributeValue]],
                dict[str, t.MetadataAttributeValue],
                dict[str, str],
            ]:
                """Analyze DN and attribute differences for round-trip support."""
                return FlextLdifUtilitiesEntry.analyze_differences(
                    entry_attrs,
                    converted_attrs,
                    original_dn,
                    cleaned_dn,
                    normalize_attr_fn,
                )

        class Events(FlextLdifUtilitiesEvents):
            """Event utilities for LDIF operations."""

        class Metadata(FlextLdifUtilitiesMetadata):
            """Metadata utilities for LDIF operations."""

        class ObjectClass(FlextLdifUtilitiesObjectClass):
            """ObjectClass utilities for LDIF operations."""

        class OID(FlextLdifUtilitiesOID):
            """OID utilities for LDIF operations."""

        class LdifParser(FlextLdifUtilitiesParser):
            """LDIF parser utilities."""

        class Parsers(FlextLdifUtilitiesParsers):
            """Parser utilities for LDIF operations."""

        class Schema(FlextLdifUtilitiesSchema):
            """Schema utilities for LDIF operations."""

        class Server(FlextLdifUtilitiesServer):
            """Server utilities for LDIF operations."""

        class LdifValidation(FlextLdifUtilitiesValidation):
            """LDIF validation utilities."""

        class Writer(FlextLdifUtilitiesWriter):
            """Writer utilities for LDIF operations."""

        class Writers(FlextLdifUtilitiesWriters):
            """Writers utilities for LDIF operations."""

        # === Power Methods (new) ===

        @staticmethod
        def is_ldif_process_call(
            items: object,
            processor_normalized: object,
            processor: object | None,
            config: ProcessConfig | None,
            source_server: c.Ldif.ServerTypes,
            target_server: c.Ldif.ServerTypes | None,
        ) -> bool:
            """Check if this is an LDIF-specific process call."""
            is_sequence_entry = isinstance(items, Sequence) and not isinstance(
                items,
                (str, bytes, dict),
            )

            if is_sequence_entry and items and isinstance(items, Sequence):
                first_item = items[0] if len(items) > 0 else None
                if first_item is not None and not isinstance(first_item, m.Ldif.Entry):
                    return False

            has_ldif_config = (
                (processor_normalized is None and processor is None)
                or isinstance(processor_normalized, ProcessConfig)
                or config is not None
                or source_server != "auto"
                or target_server is not None
            )
            return bool(is_sequence_entry and has_ldif_config)

        @staticmethod
        def process_ldif_entries(
            entries: Sequence[t.GeneralValueType],
            config: ProcessConfig | None,
            source_server: c.Ldif.ServerTypes,
            target_server: c.Ldif.ServerTypes | None,
            *,
            _normalize_dns: bool,  # Unused: reserved for future DN normalization control
            _normalize_attrs: bool,  # Unused: reserved for future attribute normalization control
        ) -> FlextLdifResult[list[m.Ldif.Entry]]:
            """Process LDIF entries with pipeline."""
            if config is None:
                config_base = ProcessConfig()
                config_base_model = config_base
                process_config = config_base_model.model_copy(
                    update={
                        "source_server": source_server,
                        "target_server": target_server or c.Ldif.ServerTypes.RFC,
                    },
                )
                transform_config = TransformConfig()
                if hasattr(transform_config, "model_copy"):
                    transform_config = transform_config.model_copy(
                        update={"process_config": process_config},
                    )
                else:
                    transform_config.process_config = process_config
            else:
                transform_config = TransformConfig()
                if hasattr(transform_config, "model_copy"):
                    transform_config = transform_config.model_copy(
                        update={"process_config": config},
                    )
                else:
                    transform_config.process_config = config
            pipeline = ProcessingPipeline(transform_config)
            entries_list = [e for e in entries if isinstance(e, m.Ldif.Entry)]
            pipeline_result = pipeline.execute(entries_list)
            if pipeline_result.is_failure:
                return FlextLdifResult.fail(
                    pipeline_result.error or "Pipeline execution failed",
                )
            domain_entries = pipeline_result.value
            converted_entries: list[m.Ldif.Entry] = [
                m.Ldif.Entry.model_validate(
                    entry.model_dump(exclude_computed_fields=True),
                )
                for entry in domain_entries
            ]
            return FlextLdifResult.ok(converted_entries)

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
        def evaluate_predicate(
            predicate: Callable[..., bool],
            key: str,
            value: t.GeneralValueType,
        ) -> bool:
            """Evaluate predicate with automatic 1-arg or 2-arg detection."""
            if not callable(predicate):
                return True
            if FlextLdifUtilities.Ldif.is_two_arg_processor(predicate):
                try:
                    result = FlextLdifUtilities.Ldif.call_processor(
                        predicate,
                        key,
                        value,
                    )
                    if isinstance(result, bool):
                        return result
                except (TypeError, ValueError):
                    try:
                        if FlextLdifUtilities.Ldif.is_object_arg_callable(predicate):
                            fallback_result: object = predicate(value)
                            if isinstance(fallback_result, bool):
                                return fallback_result
                    except (TypeError, ValueError):
                        pass
            else:
                try:
                    if FlextLdifUtilities.Ldif.is_object_arg_callable(predicate):
                        one_arg_result: object = predicate(value)
                        if isinstance(one_arg_result, bool):
                            return one_arg_result
                except (TypeError, ValueError):
                    pass
            return True

        TWO_ARG_THRESHOLD: int = 2
        """Minimum parameter count for 2-argument functions."""

        @staticmethod
        def is_two_arg_processor[T, R](
            func: Callable[[str, T], R] | Callable[[T], R],
        ) -> TypeGuard[Callable[[str, T], R]]:
            """Check if processor function accepts 2 arguments."""
            try:
                sig = inspect.signature(func)
                return len(sig.parameters) >= FlextLdifUtilities.Ldif.TWO_ARG_THRESHOLD
            except (ValueError, TypeError):
                return False

        @staticmethod
        def call_processor[T, R](
            processor_func: Callable[[str, T], R],
            key: str,
            value: T,
        ) -> R:
            """Call 2-arg processor function."""
            return processor_func(key, value)

        @staticmethod
        def is_no_arg_callable[R](
            func: Callable[[], R] | Callable[[object], R] | object,
        ) -> TypeGuard[Callable[[], R]]:
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
            func: Callable[[], R] | Callable[[object], R] | object,
        ) -> TypeGuard[Callable[[object], R]]:
            """Check if callable accepts 1 object argument."""
            if not callable(func):
                return False
            try:
                sig = inspect.signature(func)
                return len(sig.parameters) == 1
            except (ValueError, TypeError):
                return False

        @staticmethod
        def process_dict_items[R](
            items: dict[str, t.GeneralValueType],
            processor_func: Callable[..., R],
            predicate: Callable[..., bool] | None,
            filter_keys: set[str] | None,
            exclude_keys: set[str] | None,
        ) -> list[R]:
            """Process dictionary items."""
            results: list[R] = []
            for key, value in items.items():
                if FlextLdifUtilities.Ldif.should_skip_key(
                    key,
                    filter_keys,
                    exclude_keys,
                ):
                    continue
                if (
                    predicate is not None
                    and not FlextLdifUtilities.Ldif.evaluate_predicate(
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
        def _call_single_item_processor[R](
            processor_func: Callable[..., R],
            item: object,
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
                    "Processor requires 2 arguments but single item provided",
                )
            except Exception as e:
                return r[list[R]].fail(f"Processing failed: {e}")

        @staticmethod
        def process_list_items[R](
            items: list[object] | tuple[object, ...],
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
                except Exception as e:
                    if on_error == "fail":
                        return r[list[R]].fail(f"Processing failed: {e}")
                    if on_error == "skip":
                        continue
                    errors.append(str(e))
            return r[list[R]].ok(results)

        @staticmethod
        @overload
        def process[T, R](
            items_or_entries: T
            | list[T]
            | tuple[T, ...]
            | dict[str, T]
            | Mapping[str, T],
            processor_or_config: Callable[[T], R] | Callable[[str, T], R] | None = None,
            *,
            processor: Callable[[T], R] | Callable[[str, T], R] | None = None,
            on_error: str = "collect",
            predicate: Callable[[T], bool] | Callable[[str, T], bool] | None = None,
            filter_keys: set[str] | None = None,
            exclude_keys: set[str] | None = None,
            config: ProcessConfig | None = None,
            source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
            target_server: c.Ldif.ServerTypes | None = None,
            normalize_dns: bool = True,
            normalize_attrs: bool = True,
        ) -> r[list[R]]: ...

        @staticmethod
        @overload
        def process(
            items_or_entries: Sequence[m.Ldif.Entry],
            processor_or_config: ProcessConfig | None = None,
            *,
            processor: Callable[[m.Ldif.Entry], object] | None = None,
            on_error: str = "collect",
            predicate: Callable[[m.Ldif.Entry], bool] | None = None,
            filter_keys: set[str] | None = None,
            exclude_keys: set[str] | None = None,
            config: ProcessConfig | None = None,
            source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
            target_server: c.Ldif.ServerTypes | None = None,
            normalize_dns: bool = True,
            normalize_attrs: bool = True,
        ) -> FlextLdifResult[list[m.Ldif.Entry]]: ...

        @staticmethod
        def process[T, R](
            items_or_entries: (
                T
                | list[T]
                | tuple[T, ...]
                | dict[str, T]
                | Mapping[str, T]
                | Sequence[m.Ldif.Entry]
            ),
            processor_or_config: (
                Callable[[T], R] | Callable[[str, T], R] | ProcessConfig | None
            ) = None,
            *,
            processor: Callable[[T], R] | Callable[[str, T], R] | None = None,
            on_error: str = "collect",
            predicate: Callable[[T], bool] | Callable[[str, T], bool] | None = None,
            filter_keys: set[str] | None = None,
            exclude_keys: set[str] | None = None,
            config: ProcessConfig | None = None,
            source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC,
            target_server: c.Ldif.ServerTypes | None = None,
            normalize_dns: bool = True,
            normalize_attrs: bool = True,
        ) -> r[list[R]] | FlextLdifResult[list[m.Ldif.Entry]]:
            """Universal entry processor."""
            processor_normalized = (
                processor_or_config if processor_or_config is not None else processor
            )
            if FlextLdifUtilities.Ldif.is_ldif_process_call(
                items_or_entries,
                processor_normalized,
                processor,
                config,
                source_server,
                target_server,
            ) and is_entry_sequence(items_or_entries):
                entries_seq: Sequence[m.Ldif.Entry] = [
                    item for item in items_or_entries if isinstance(item, m.Ldif.Entry)
                ]
                return FlextLdifUtilities.Ldif.process_ldif_entries(
                    entries_seq,
                    config,
                    source_server,
                    target_server,
                    _normalize_dns=normalize_dns,
                    _normalize_attrs=normalize_attrs,
                )

            items: (
                object
                | list[object]
                | tuple[object, ...]
                | dict[str, t.GeneralValueType]
                | Mapping[str, object]
            ) = items_or_entries
            if processor_normalized is None or isinstance(
                processor_normalized,
                ProcessConfig,
            ):
                msg = "processor is required for base class process"
                return FlextLdifResult[list[m.Ldif.Entry]].fail(msg)
            processor_func = processor_normalized

            if isinstance(items, dict):
                dict_items: dict[str, t.GeneralValueType] = items  # INTENTIONAL CAST
                results = FlextLdifUtilities.Ldif.process_dict_items(
                    dict_items,
                    processor_func,
                    predicate,
                    filter_keys,
                    exclude_keys,
                )
                return r[str].ok(results)
            if isinstance(items, (list, tuple)):
                list_items: list[object] | tuple[object, ...] = items
                return FlextLdifUtilities.Ldif.process_list_items(
                    list_items,
                    processor_func,
                    predicate,
                    on_error,
                )
            return FlextLdifUtilities.Ldif._call_single_item_processor(
                processor_func,
                items,
            )

        @staticmethod
        def transform_entries(
            entries: Sequence[m.Ldif.Entry],
            *transformers: EntryTransformer[m.Ldif.Entry],
            fail_fast: bool = True,
        ) -> FlextLdifResult[list[m.Ldif.Entry]]:
            """Apply LDIF entry transformations via pipeline."""
            pipeline = Pipeline(fail_fast=fail_fast)
            for transformer in transformers:
                _ = pipeline.add(transformer)  # Explicitly ignore return value
            entries_list = list(entries)
            pipeline_result = pipeline.execute(entries_list)
            if pipeline_result.is_failure:
                return FlextLdifResult.fail(
                    pipeline_result.error or "Pipeline execution failed",
                )
            transformed_entries = pipeline_result.value
            return FlextLdifResult.ok(transformed_entries)

        @staticmethod
        def filter[T, R](
            items_or_entries: (
                T
                | list[T]
                | tuple[T, ...]
                | dict[str, T]
                | Mapping[str, T]
                | Sequence[m.Ldif.Entry]
            ),
            predicate_or_filter1: (
                FlextLdifUtilities.Ldif.VariadicCallable[bool]
                | EntryFilter[m.Ldif.Entry]
            ),
            *filters: EntryFilter[m.Ldif.Entry],
            _mapper: FlextLdifUtilities.Ldif.VariadicCallable[R] | None = None,
            mode: Literal["all", "any"] = "all",
        ) -> (
            list[T]
            | list[R]
            | dict[str, T]
            | dict[str, R]
            | list[object]
            | dict[str, t.GeneralValueType]
            | FlextLdifResult[list[m.Ldif.Entry]]
        ):
            """Filter entries using composable filter predicates."""
            if not isinstance(predicate_or_filter1, EntryFilter):
                predicate: FlextLdifUtilities.Ldif.VariadicCallable[bool] = (
                    predicate_or_filter1
                )

                def predicate_callable(item: object) -> bool:
                    item_typed = u_core.Mapper.narrow_to_general_value_type(
                        item,
                    )
                    return predicate(item_typed)

                return FlextLdifUtilities.Ldif.filter_base_class(
                    items_or_entries,
                    predicate_callable,
                )

            if (
                isinstance(items_or_entries, Sequence)
                and not isinstance(items_or_entries, (str, bytes, dict))
                and items_or_entries
                and isinstance(items_or_entries[0], m.Ldif.Entry)
            ):
                entries_list: list[m.Ldif.Entry] = [
                    e for e in items_or_entries if isinstance(e, m.Ldif.Entry)
                ]
                filter_entry = predicate_or_filter1
                return FlextLdifUtilities.Ldif.filter_ldif_entries(
                    entries_list,
                    filter_entry,
                    filters,
                    mode,
                )

            def predicate_wrapper(item: object) -> bool:
                """Wrap EntryFilter as VariadicCallable for base class compatibility."""
                if isinstance(predicate_or_filter1, EntryFilter) and isinstance(
                    item, m.Ldif.Entry
                ):
                    return predicate_or_filter1.matches(item)
                return False

            return FlextLdifUtilities.Ldif.filter_base_class(
                items_or_entries,
                predicate_wrapper,
            )

        @staticmethod
        def filter_base_class(
            items_or_entries: Sequence[object] | Mapping[str, object] | object,
            predicate: Callable[[object], bool],
            _mapper: Callable[[object], object] | None = None,
        ) -> list[object] | dict[str, t.GeneralValueType]:
            """Filter using base class Collection.filter (internal helper)."""
            if isinstance(items_or_entries, (list, tuple)):
                items_list: list[object] = list(items_or_entries)
                list_filter_result = u_core.Collection.filter(items_list, predicate)
                if isinstance(list_filter_result, list):
                    return list_filter_result
                return list(list_filter_result) if list_filter_result else []
            if isinstance(items_or_entries, dict):
                items_dict: dict[str, t.GeneralValueType] = {}
                for k, v in items_or_entries.items():
                    items_dict[k] = u_core.Mapper.narrow_to_general_value_type(v)
                dict_filter_result = u_core.Collection.filter(items_dict, predicate)
                if isinstance(dict_filter_result, dict):
                    return dict_filter_result
                return {}
            items_single_list: list[object] = [items_or_entries]
            single_filter_result = u_core.Collection.filter(
                items_single_list, predicate
            )
            if isinstance(single_filter_result, list):
                return single_filter_result
            return list(single_filter_result) if single_filter_result else []

        @staticmethod
        def filter_ldif_entries(
            entries: Sequence[m.Ldif.Entry],
            predicate_or_filter1: EntryFilter[m.Ldif.Entry],
            filters: tuple[EntryFilter[m.Ldif.Entry], ...],
            mode: Literal["all", "any"],
        ) -> FlextLdifResult[list[m.Ldif.Entry]]:
            """Filter LDIF entries using EntryFilter (internal helper)."""
            filter_list: list[EntryFilter[m.Ldif.Entry]] = [
                predicate_or_filter1,
            ] + list(filters)
            if not filter_list:
                return FlextLdifResult.ok(list(entries))
            combined: EntryFilter[m.Ldif.Entry] = filter_list[0]
            for f in filter_list[1:]:
                combined = combined & f if mode == "all" else combined | f
            filtered = [entry for entry in entries if combined.matches(entry)]
            return FlextLdifResult.ok(filtered)

        @staticmethod
        def _is_entry_sequence(
            value: object,
        ) -> TypeIs[Sequence[m.Ldif.Entry]]:
            """Check if value is a Sequence of Entry objects."""
            if not isinstance(value, Sequence):
                return False
            if isinstance(value, (str, bytes)):
                return False
            if len(value) > 0:
                return isinstance(value[0], m.Ldif.Entry)
            return True

        @staticmethod
        def _validate_entries(
            entries: Sequence[m.Ldif.Entry],
            *,
            strict: bool,
            collect_all: bool,
            max_errors: int,
        ) -> FlextLdifResult[list[ValidationResult]]:
            """Internal: Validate LDIF entries."""
            pipeline = ValidationPipeline(
                strict=strict,
                collect_all=collect_all,
                max_errors=max_errors,
            )
            return FlextLdifResult.from_result(pipeline.validate(entries))

        @staticmethod
        @overload
        def validate(
            value_or_entries: Sequence[m.Ldif.Entry],
            *,
            strict: bool = True,
            collect_all: bool = True,
            max_errors: int = 0,
        ) -> FlextLdifResult[list[ValidationResult]]: ...

        @staticmethod
        @overload
        def validate(
            value_or_entries: t.GeneralValueType,
            validator_first: p.ValidatorSpec,
            *validators_rest: p.ValidatorSpec,
            strict: bool = True,
            collect_all: bool = True,
            max_errors: int = 0,
        ) -> r[t.GeneralValueType]: ...

        @staticmethod
        def validate(
            value_or_entries: Sequence[m.Ldif.Entry] | t.GeneralValueType,
            validator_first: p.ValidatorSpec | None = None,
            *validators_rest: p.ValidatorSpec,
            strict: bool = True,
            collect_all: bool = True,
            max_errors: int = 0,
        ) -> FlextLdifResult[list[ValidationResult]] | r[t.GeneralValueType]:
            """Validate entries against rules."""
            if (
                FlextLdifUtilities.Ldif._is_entry_sequence(value_or_entries)
                and validator_first is None
            ):
                return FlextLdifUtilities.Ldif._validate_entries(
                    value_or_entries,
                    strict=strict,
                    collect_all=collect_all,
                    max_errors=max_errors,
                )

            validators: tuple[p.ValidatorSpec, ...] = (
                (validator_first, *validators_rest) if validator_first else ()
            )
            return u_core.validate(value_or_entries, *validators)

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
            value: t.GeneralValueType,
            *,
            default: list[t.GeneralValueType] | None = None,
        ) -> list[t.GeneralValueType]:
            """Normalize to list using u.build() DSL (mnemonic: nl)."""
            extracted_value: t.GeneralValueType | None
            if isinstance(value, FlextResult):
                extracted_value = value.value if not value.is_failure else None
            else:
                extracted_value = value
            default_list: list[t.GeneralValueType] = (
                default if default is not None else []
            )
            extracted: t.GeneralValueType = (
                extracted_value if extracted_value is not None else default_list
            )
            ops: dict[str, t.GeneralValueType] = {
                "ensure": "list",
                "ensure_default": default_list,
            }
            result = cls.build(extracted, ops=ops)
            if isinstance(result, (list, tuple)):
                return list(result)
            result_typed = u_core.Mapper.narrow_to_general_value_type(result)
            return [result_typed]

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

        @staticmethod
        def pipe_ldif(
            value: t.GeneralValueType,
            *ops: dict[str, t.GeneralValueType]
            | Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> t.GeneralValueType:
            """LDIF-specific pipe - supports dict operations via flow()."""
            result: t.GeneralValueType = value
            for op in ops:
                if callable(op) and not isinstance(op, dict):
                    result = op(result)
                elif isinstance(op, dict) and isinstance(result, dict):
                    result = {**result, **op}
            return result

        @staticmethod
        def pp(
            value: t.GeneralValueType,
            *ops: dict[str, t.GeneralValueType]
            | Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> t.GeneralValueType:
            """Alias for pipe_ldif (mnemonic: pp)."""
            return FlextLdifUtilities.Ldif.pipe_ldif(value, *ops)

        @classmethod
        def zip_with(
            cls,
            *sequences: Sequence[t.GeneralValueType],
            combiner: FlextLdifUtilities.Ldif.VariadicCallable[t.GeneralValueType]
            | None = None,
        ) -> list[t.GeneralValueType]:
            """Zip with combiner (generalized: uses zip from base, mnemonic: zw)."""
            if not sequences:
                return []
            zipped = zip(*sequences, strict=False)
            if combiner is None:
                return [tuple(items) for items in zipped]
            result: list[t.GeneralValueType] = []
            for items_tuple in zipped:
                items_list = list(items_tuple)
                combined = combiner(*items_list)
                result.append(combined)
            return result

        zw = zip_with

        @classmethod
        def group_by(
            cls,
            items: Sequence[t.GeneralValueType],
            *,
            key: Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> dict[t.GeneralValueType, list[t.GeneralValueType]]:
            """Group by key function (generalized, mnemonic: gb)."""
            items_list = list(items) if isinstance(items, Sequence) else [items]
            result: dict[t.GeneralValueType, list[t.GeneralValueType]] = {}
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
            items: Sequence[t.GeneralValueType],
            *,
            predicate: Callable[[t.GeneralValueType], bool],
        ) -> tuple[list[t.GeneralValueType], list[t.GeneralValueType]]:
            """Partition items by predicate into (matches, non-matches) (mnemonic: pt)."""
            matches: list[t.GeneralValueType] = []
            non_matches: list[t.GeneralValueType] = []
            for item in items:
                if predicate(item):
                    matches.append(item)
                else:
                    non_matches.append(item)
            return matches, non_matches

        pt = partition

        @classmethod
        @overload
        def get_ldif(
            cls,
            data: Mapping[str, t.GeneralValueType],
            key: str,
            *,
            default: str = "",
        ) -> str: ...

        @classmethod
        @overload
        def get_ldif[T](
            cls,
            data: Mapping[str, t.GeneralValueType] | t.GeneralValueType,
            key: str,
            *,
            default: list[T],
        ) -> list[T]: ...

        @classmethod
        @overload
        def get_ldif[T](
            cls,
            data: Mapping[str, t.GeneralValueType] | t.GeneralValueType,
            key: str,
            *,
            default: T | None = None,
        ) -> T | None: ...

        @classmethod
        def get_ldif[T](
            cls,
            data: Mapping[str, t.GeneralValueType] | t.GeneralValueType,
            key: str,
            *,
            default: t.GeneralValueType | T | None = None,
        ) -> t.GeneralValueType | T | None:
            """Safe get with optional mapping (DSL pattern)."""
            if isinstance(data, Mapping):
                return FlextLdifUtilities.Ldif.get_from_mapping(
                    data,
                    key,
                    default=default,
                )
            return default

        @classmethod
        def pluck(
            cls,
            items: object,
            *,
            key: str | int | Callable[[object], object],
        ) -> list[object]:
            """Extract values from sequence by key/index/function (mnemonic: pk)."""
            if not isinstance(items, Iterable):
                return []
            result: list[object] = []
            for item in items:
                if callable(key):
                    result.append(key(item))
                elif isinstance(key, str) and isinstance(item, Mapping):
                    result.append(item.get(key))
                elif isinstance(key, int) and isinstance(item, Sequence):
                    result.append(item[key] if len(item) > key else None)
                elif hasattr(item, str(key)):
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

            if other is not None and isinstance(value, str) and isinstance(other, str):
                return normalize_single(value) == normalize_single(other)

            if isinstance(value, str):
                return normalize_single(value)

            if isinstance(value, (list, tuple)):
                return [normalize_single(str(v)) for v in value]

            if isinstance(value, (set, frozenset)):
                return {normalize_single(str(v)) for v in value}

            return value

        nz = normalize_ldif

        @classmethod
        def pairs(
            cls,
            d: dict[str, t.GeneralValueType] | Mapping[str, t.GeneralValueType],
        ) -> list[tuple[str, t.GeneralValueType]]:
            """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr)."""
            return list(d.items())

        pr = pairs

        @staticmethod
        def count[T](
            items: list[T] | tuple[T, ...],
            predicate: Callable[[T], bool] | None = None,
        ) -> int:
            """Count items (generalized: uses count from base, mnemonic: ct)."""
            if predicate is not None:
                filtered_items = [item for item in items if predicate(item)]
                return u.count(filtered_items)
            return u.count(items)

        ct = count

        @classmethod
        def omit(
            cls,
            obj: dict[str, t.GeneralValueType],
            *keys: str,
        ) -> dict[str, t.GeneralValueType]:
            """Omit keys using u.map_dict() DSL (mnemonic: om)."""
            if not obj or not keys:
                return dict(obj) if obj else {}
            keys_set = set(keys)
            return cls.map_dict(obj, predicate=lambda k, _: k not in keys_set)

        om = omit

        @staticmethod
        def is_empty_value(value: object) -> bool:
            """Check if value is empty (empty string, list, or dict)."""
            if isinstance(value, str) and not value:
                return True
            if isinstance(value, list) and not value:
                return True
            return bool(isinstance(value, dict) and not value)

        @staticmethod
        def merge_dicts(
            *dicts: Mapping[str, t.GeneralValueType],
            strategy: str = "deep",
            filter_none: bool = False,
            filter_empty: bool = False,
        ) -> r[dict[str, t.GeneralValueType]]:
            """Merge multiple dicts with filtering options (mnemonic: mg)."""
            _mappings_list: list[Mapping[str, t.GeneralValueType]] = [
                dict_item
                for dict_item in dicts
                if isinstance(dict_item, (dict, Mapping))
            ]
            dicts_typed: tuple[Mapping[str, t.GeneralValueType], ...] = dicts
            if not dicts_typed:
                return r[dict[str, t.GeneralValueType]].ok({})
            merged: dict[str, t.GeneralValueType] = {}
            for dict_item in dicts_typed:
                dict_item_dict: dict[str, t.GeneralValueType] = (
                    dict(dict_item) if isinstance(dict_item, Mapping) else dict_item
                )
                merge_result = u_core.merge(
                    merged,
                    dict_item_dict,
                    strategy=strategy,
                )
                if merge_result.is_failure:
                    return r[dict[str, t.GeneralValueType]].fail(
                        merge_result.error or "Merge failed",
                    )
                merged = merge_result.value
            if filter_none or filter_empty:
                filtered: dict[str, t.GeneralValueType] = {}
                for key, value in merged.items():
                    if filter_none and value is None:
                        continue
                    if filter_empty and FlextLdifUtilities.Ldif.is_empty_value(value):
                        continue
                    filtered[key] = value
                merged = filtered
            return r[dict[str, t.GeneralValueType]].ok(merged)

        mg = merge_dicts

        @classmethod
        def smart_convert(
            cls,
            value: t.GeneralValueType | r[t.GeneralValueType],
            *,
            target_type: str,
            predicate: Callable[[t.GeneralValueType], bool] | None = None,
            default: t.GeneralValueType = None,
        ) -> t.GeneralValueType:
            """Smart convert using u.build() DSL (mnemonic: sc)."""
            extracted: t.GeneralValueType = (
                value.value
                if isinstance(value, FlextResult) and not value.is_failure
                else value
                if not isinstance(value, FlextResult)
                else default
            )
            if extracted is None:
                return default

            conv_builder = cls.conv(extracted)
            conv_result: t.GeneralValueType = None
            if target_type == "str":  # String comparison for target_type
                str_default = default if isinstance(default, str) else ""
                conv_result = conv_builder.to_str(default=str_default).build()
            elif target_type == "int":  # String comparison for target_type
                int_default = default if isinstance(default, int) else 0
                conv_result = conv_builder.to_int(default=int_default).build()
            elif target_type == "bool":  # String comparison for target_type
                bool_default = default if isinstance(default, bool) else False
                conv_result = conv_builder.to_bool(default=bool_default).build()
            elif target_type == "list":  # String comparison for target_type
                list_default: list[str] = []
                if isinstance(default, list):
                    list_default = [str(item) for item in default]
                conv_result = conv_builder.str_list(default=list_default).build()
                if predicate and isinstance(conv_result, list):
                    filtered = [item for item in conv_result if predicate(item)]
                    return filtered or (
                        conv_result if conv_result is not None else default
                    )
            else:
                ops: dict[str, t.GeneralValueType] = {
                    "ensure": target_type,
                    "ensure_default": default,
                }
                if predicate:
                    pass
                conv_result = cls.build(extracted, ops=ops)
            return conv_result if conv_result is not None else default

        sc = smart_convert

        @staticmethod
        def is_type(
            value: object,
            type_spec: str | type | tuple[type, ...],
        ) -> bool:
            """Type check using u.build() DSL (mnemonic: it)."""
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
                resolved_type = (
                    type_map.get(t_val)
                    if isinstance(t_val, str)
                    else (t_val if isinstance(t_val, type) else None)
                )
                if resolved_type and isinstance(value, resolved_type):
                    return True
            return False

        @classmethod
        def as_type(
            cls,
            value: t.GeneralValueType,
            *,
            target: type | str,
            default: t.GeneralValueType | None = None,
        ) -> t.GeneralValueType:
            """Safe cast using u.convert() or u.ensure() (mnemonic: at)."""
            type_map = {
                "list": list,
                "dict": dict,
                "str": str,
                "int": int,
                "bool": bool,
                "tuple": tuple,
            }
            target_type = (
                type_map.get(target)
                if isinstance(target, str)
                else (target if isinstance(target, type) else None)
            )
            if target_type is None:
                return default

            if target_type is str:
                str_default = default if isinstance(default, str) else ""
                return (
                    FlextLdifUtilities.Ldif
                    .conv(value)
                    .to_str(default=str_default)
                    .safe()
                    .build()
                )
            if target_type is int:
                int_default = default if isinstance(default, int) else 0
                return cls.conv(value).to_int(default=int_default).safe().build()
            if target_type is bool:
                bool_default = default if isinstance(default, bool) else False
                return (
                    FlextLdifUtilities.Ldif
                    .conv(value)
                    .to_bool(default=bool_default)
                    .safe()
                    .build()
                )
            if target_type is list:
                list_default: list[str] = []
                if isinstance(default, list):
                    list_default = [str(item) for item in default]
                return (
                    FlextLdifUtilities.Ldif
                    .conv(value)
                    .str_list(default=list_default)
                    .safe()
                    .build()
                )

            ops: dict[str, t.GeneralValueType] = {}
            result = cls.build(value, ops=ops)
            if result is None:
                return cls.or_(None, default=default)
            result_typed = u_core.Mapper.narrow_to_general_value_type(result)
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

        gd = guard_simple

        @classmethod
        def thru(
            cls,
            value: object,
            *,
            fn: Callable[[object], object],
        ) -> object:
            """Thru using direct call (mnemonic: th)."""
            return fn(value)

        th = thru

        @classmethod
        def comp(
            cls,
            *fns: Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> Callable[[t.GeneralValueType], t.GeneralValueType]:
            """Compose using u.chain() (mnemonic: cp)."""
            if not fns:
                return lambda x: x
            return lambda value: cls.chain(value, *fns)

        cp = comp

        @classmethod
        def juxt(
            cls,
            *fns: Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> Callable[[t.GeneralValueType], tuple[t.GeneralValueType, ...]]:
            """Juxtapose functions (mnemonic: jx)."""
            if not fns:
                return lambda _x: ()
            return lambda value: tuple(fn(value) for fn in fns)

        jx = juxt

        @classmethod
        def curry(
            cls,
            fn: Callable[..., t.GeneralValueType],
            *args: t.GeneralValueType,
        ) -> Callable[..., t.GeneralValueType]:
            """Curry function (mnemonic: cy)."""

            def curried(
                *more_args: t.GeneralValueType,
                **_kwargs: t.GeneralValueType,  # Protocol requires **kwargs
            ) -> t.GeneralValueType:
                combined_args: tuple[t.GeneralValueType, ...] = args + more_args
                converted_args: list[object] = []
                for arg in combined_args:
                    if isinstance(arg, (str, int, float, bool)):
                        converted_args.append(arg)
                    elif arg is None:
                        converted_args.append(None)
                    elif (
                        isinstance(arg, (list, tuple))
                        and not isinstance(
                            arg,
                            (str, bytes),
                        )
                    ) or (
                        isinstance(arg, (dict, Mapping))
                        and not isinstance(
                            arg,
                            (str, bytes),
                        )
                    ):
                        converted_args.append(arg)
                    else:
                        converted_args.append(str(arg))
                if len(converted_args) == 0:
                    result = fn()
                elif len(converted_args) == 1:
                    typed_arg = u_core.Mapper.narrow_to_general_value_type(
                        converted_args[0],
                    )
                    result = fn(typed_arg)
                else:
                    typed_args = [
                        u_core.Mapper.narrow_to_general_value_type(arg)
                        for arg in converted_args
                    ]
                    result = fn(*typed_args)
                return u_core.Mapper.narrow_to_general_value_type(result)

            return curried

        cy = curry

        @classmethod
        def _detect_predicate_type(
            cls,
            pairs: tuple[
                tuple[Callable[[], bool] | Callable[[object], bool] | bool, object],
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
        def _evaluate_value_arg_predicate(
            cls,
            *,
            pred: Callable[[], bool] | Callable[[object], bool] | bool,
            value: object,
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
        def _evaluate_no_arg_result(
            cls,
            result_val: object,
        ) -> object:
            """Evaluate a no-arg result value."""
            if callable(result_val) and FlextLdifUtilities.Ldif.is_no_arg_callable(
                result_val,
            ):
                return result_val()
            return result_val

        @classmethod
        def _evaluate_value_arg_result(
            cls,
            result_val: object,
            value: object,
        ) -> object:
            """Evaluate a value-arg result value."""
            if callable(result_val) and FlextLdifUtilities.Ldif.is_object_arg_callable(
                result_val,
            ):
                return result_val(value)
            return result_val

        @classmethod
        def cond(
            cls,
            *pairs: tuple[Callable[[], bool] | Callable[[object], bool] | bool, object],
            default: object | None = None,
        ) -> Callable[[], object] | Callable[[object], object]:
            """Cond pattern (mnemonic: cd)."""
            is_no_arg = cls._detect_predicate_type(pairs)

            if is_no_arg:

                def conditional_no_arg() -> object:
                    for pred, result_val in pairs:
                        evaluated = False
                        if FlextLdifUtilities.Ldif.is_no_arg_callable(pred):
                            with contextlib.suppress(TypeError):
                                evaluated = bool(pred())
                        elif not callable(pred):
                            evaluated = bool(pred)
                        if evaluated:
                            return cls._evaluate_no_arg_result(result_val)
                    if (
                        default is not None
                        and callable(default)
                        and FlextLdifUtilities.Ldif.is_no_arg_callable(default)
                    ):
                        return default()
                    return default

                return conditional_no_arg

            def conditional(value: object) -> object:
                for pred, result_val in pairs:
                    if cls._evaluate_value_arg_predicate(pred=pred, value=value):
                        return cls._evaluate_value_arg_result(result_val, value)
                if (
                    default is not None
                    and callable(default)
                    and FlextLdifUtilities.Ldif.is_object_arg_callable(default)
                ):
                    return default(value)
                return default

            return conditional

        cd = cond

        @classmethod
        def switch(
            cls,
            value: object,
            cases: dict[object, object],
            default: object | None = None,
        ) -> object:
            """Switch using dict lookup (mnemonic: sw)."""
            result = cases.get(value, default)
            return result(value) if callable(result) else result

        sw = switch

        @classmethod
        def defaults(
            cls,
            *dicts: dict[str, t.GeneralValueType] | None,
        ) -> dict[str, t.GeneralValueType]:
            """Defaults merge - first wins using u.flow() DSL (mnemonic: df)."""
            if not dicts:
                return {}

            def apply_defaults(acc: object, d: object) -> object:
                """Apply defaults using fold() pattern: first wins, later fill missing/None."""
                if not isinstance(acc, dict) or not isinstance(d, dict):
                    return acc
                filtered = cls.map_dict(
                    d,
                    predicate=lambda k, _v: k not in acc or acc.get(k) is None,
                )
                acc.update(filtered)
                return acc

            dict_list = [
                dict_item for dict_item in dicts if isinstance(dict_item, dict)
            ]
            if dict_list:
                result = cls.fold(
                    dict_list,
                    folder=apply_defaults,
                    initial={},
                )
                return result if isinstance(result, dict) else {}
            return {}

        d = defaults

        @classmethod
        def deep_merge(
            cls,
            *dicts: Mapping[str, t.GeneralValueType] | None,
        ) -> dict[str, t.GeneralValueType]:
            """Deep merge using u.merge() with deep strategy (mnemonic: dm)."""
            if not dicts:
                return {}
            mapping_list = [
                dict_item for dict_item in dicts if isinstance(dict_item, Mapping)
            ]
            if not mapping_list:
                return {}
            merged: dict[str, t.GeneralValueType] = dict(mapping_list[0])
            for mapping in mapping_list[1:]:
                merge_result = u_core.merge(merged, dict(mapping), strategy="deep")
                if merge_result.is_success and isinstance(merge_result.value, dict):
                    merged = merge_result.value
            return merged

        dm = deep_merge

        @classmethod
        def update_inplace(
            cls,
            obj: dict[str, t.GeneralValueType],
            *updates: Mapping[str, t.GeneralValueType] | None,
        ) -> dict[str, t.GeneralValueType]:
            """Update in-place using u.flow() pattern (mnemonic: ui)."""
            for update in updates:
                if update is not None and isinstance(update, Mapping):
                    obj.update(update)
            return obj

        ui = update_inplace

        @classmethod
        def _apply_deep_defaults_recursive(
            cls,
            acc: object,
            d: object,
        ) -> object:
            """Apply deep defaults recursively: first wins, recurse nested."""
            if not isinstance(acc, dict) or not isinstance(d, dict):
                return acc
            acc_dict: dict[str, t.GeneralValueType] = acc
            d_dict: dict[str, t.GeneralValueType] = d
            for k, v in d_dict.items():
                if k not in acc_dict:
                    acc_dict[k] = v
                else:
                    current = acc_dict[k]
                    if isinstance(current, dict) and isinstance(v, dict):
                        acc_dict[k] = cls.defaults_deep(current, v)
            return acc_dict

        @classmethod
        def defaults_deep(
            cls,
            *dicts: dict[str, t.GeneralValueType] | None,
        ) -> dict[str, t.GeneralValueType]:
            """Deep defaults using u.merge() deep strategy + first wins (mnemonic: dd)."""
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
                dict_list,
                folder=cls._apply_deep_defaults_recursive,
                initial={},
            )
            if isinstance(result, dict):
                return result
            return {}

        dd = defaults_deep

        @staticmethod
        def take(
            data_or_items: Mapping[str, object] | Sequence[object] | object,
            key_or_n: str | int,
            *,
            as_type: type[object] | None = None,
            default: object | None = None,
            from_start: bool = True,
        ) -> dict[str, t.GeneralValueType] | list[object] | object | None:
            """Take value from data with type guard (mnemonic: tk)."""
            if isinstance(key_or_n, str):
                value: object = None
                if isinstance(data_or_items, Mapping):
                    value = data_or_items.get(key_or_n, default)
                elif hasattr(data_or_items, key_or_n):
                    value = getattr(data_or_items, key_or_n, default)
                else:
                    value = default

                if as_type is not None and value is not None:
                    if isinstance(value, as_type):
                        return value
                    return default
                return value

            n = key_or_n
            if isinstance(data_or_items, dict):
                items = list(data_or_items.items())
                sliced = items[:n] if from_start else items[-n:]
                sliced_dict: dict[str, t.GeneralValueType] = {
                    k: v for k, v in sliced if isinstance(k, str)
                }
                return sliced_dict  # Overloads ensure type safety at call sites
            if isinstance(data_or_items, (list, tuple)):
                if from_start:
                    return list(data_or_items[:n])
                return list(data_or_items[-n:])
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
            except Exception as e:
                if isinstance(e, catch):
                    return default
                raise

        tr = try_

        @classmethod
        def let(
            cls,
            value: t.GeneralValueType,
            *,
            fn: Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> t.GeneralValueType:
            """Let using chain() (mnemonic: lt)."""
            return FlextLdifUtilities.Ldif.chain(value, fn)

        lt = let

        @classmethod
        def apply(
            cls,
            fn: (
                FlextLdifUtilities.Ldif.VariadicCallable[t.GeneralValueType]
                | t.GeneralValueType
            ),
            *args: t.GeneralValueType,
            **kwargs: t.GeneralValueType,
        ) -> t.GeneralValueType:
            """Apply function (mnemonic: ap)."""
            if callable(fn):
                return fn(*args, **kwargs)
            return fn

        ap = apply

        @classmethod
        def bind(
            cls,
            value: t.GeneralValueType,
            *fns: Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> t.GeneralValueType:
            """Bind using chain() (mnemonic: bd)."""
            return FlextLdifUtilities.Ldif.chain(value, *fns)

        bd = bind

        @classmethod
        def lift(
            cls,
            fn: Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> Callable[[t.GeneralValueType], t.GeneralValueType | None]:
            """Lift function for optionals (mnemonic: lf)."""

            def lifted_fn(v: t.GeneralValueType) -> t.GeneralValueType | None:
                """Lifted function with safe None handling using DSL."""
                return (
                    FlextLdifUtilities.Ldif.maybe(
                        cls.tr(lambda: fn(v), default=None),
                        default=None,
                    )
                    if v is not None
                    else None
                )

            return lifted_fn

        lf = lift

        @classmethod
        def seq(
            cls,
            *values: t.GeneralValueType,
        ) -> list[t.GeneralValueType]:
            """Sequence constructor (mnemonic: sq)."""
            return list(values)

        sq = seq

        @classmethod
        def assoc(
            cls,
            data: Mapping[str, t.GeneralValueType],
            key: str,
            value: t.GeneralValueType,
        ) -> dict[str, t.GeneralValueType]:
            """Associate key-value using u.merge() DSL (mnemonic: ac)."""
            merge_result = u_core.merge(dict(data), {key: value}, strategy="override")
            if merge_result.is_success and isinstance(merge_result.value, dict):
                return merge_result.value
            return {**dict(data), key: value}  # Fallback

        ac = assoc

        @classmethod
        def dissoc(
            cls,
            data: Mapping[str, t.GeneralValueType],
            *keys: str,
        ) -> dict[str, t.GeneralValueType]:
            """Dissociate keys using omit DSL (mnemonic: ds)."""
            return {k: v for k, v in data.items() if k not in keys}

        ds = dissoc

        @classmethod
        def update(
            cls,
            data: Mapping[str, t.GeneralValueType],
            updates: Mapping[str, t.GeneralValueType],
        ) -> dict[str, t.GeneralValueType]:
            """Update dict using u.merge() (mnemonic: ud)."""
            merge_result = u_core.merge(dict(data), dict(updates), strategy="override")
            if merge_result.is_success and isinstance(merge_result.value, dict):
                return merge_result.value
            return {**dict(data), **dict(updates)}  # Fallback

        ud = update

        @classmethod
        def evolve(
            cls,
            obj: Mapping[str, t.GeneralValueType],
            *transforms: Mapping[str, t.GeneralValueType]
            | Callable[[dict[str, t.GeneralValueType]], dict[str, t.GeneralValueType]],
        ) -> dict[str, t.GeneralValueType]:
            """Evolve using u.flow() pattern (mnemonic: ev)."""
            result: dict[str, t.GeneralValueType] = dict(obj)
            for transform in transforms:
                if callable(transform) and not isinstance(transform, Mapping):
                    transformed = transform(result)
                    if isinstance(transformed, dict):
                        result = transformed
                elif isinstance(transform, Mapping):
                    result.update(transform)
            return result

        ev = evolve

        @classmethod
        def keys[T](
            cls,
            items: dict[str, T] | r[dict[str, T]],
            *,
            default: list[str] | None = None,
        ) -> list[str]:
            """Get keys from dict (mnemonic: ky)."""
            if isinstance(items, r):
                if items.is_success and isinstance(items.value, dict):
                    return list(items.value.keys())
                return default or []
            if isinstance(items, dict):
                return list(items.keys())
            return default or []

        ky = keys

        @classmethod
        def dict_vals[T](
            cls,
            items: dict[str, T] | r[dict[str, T]],
            *,
            default: list[T] | None = None,
        ) -> list[T]:
            """Get values from dict (mnemonic: vl)."""
            if isinstance(items, r):
                if items.is_success and isinstance(items.value, dict):
                    return list(items.value.values())
                return default or []
            if isinstance(items, dict):
                return list(items.values())
            return default or []

        vl = dict_vals

        @classmethod
        def invert(
            cls,
            obj: dict[str, t.GeneralValueType],
        ) -> dict[str, str]:
            """Invert dict using u.map_dict() pattern (mnemonic: iv)."""
            if isinstance(obj, dict):
                str_dict: Mapping[str, str] = {k: str(v) for k, v in obj.items()}
                inverted = u.mapper().invert_dict(str_dict)
                return dict(inverted)
            return {}

        iv = invert

        @classmethod
        def where(
            cls,
            obj: dict[str, t.GeneralValueType],
            *,
            predicate: Callable[[str, object], bool] | None = None,
        ) -> dict[str, t.GeneralValueType]:
            """Where using u.filter() (mnemonic: wh)."""
            if not isinstance(obj, dict):
                return {}
            if predicate is None:
                return dict(obj)
            return {k: v for k, v in obj.items() if predicate(k, v)}

        wh = where

        @classmethod
        def prop(
            cls,
            key: str,
        ) -> Callable[[object], object]:
            """Property accessor using u.get() (mnemonic: pp)."""

            def getter(obj: object) -> object:
                """Get value from object by key."""
                if isinstance(obj, Mapping):
                    return obj.get(key)
                if hasattr(obj, key):
                    return getattr(obj, key)
                return None

            return getter

        prop_get = prop

        @classmethod
        def props(
            cls,
            *keys: str,
        ) -> Callable[[object], dict[str, t.GeneralValueType]]:
            """Props accessor using u.pick() directly (mnemonic: ps)."""

            def accessor(obj: object) -> dict[str, t.GeneralValueType]:
                if isinstance(obj, (dict, Mapping)):
                    picked = cls.pick(obj, *keys, as_dict=True)
                    return picked if isinstance(picked, dict) else {}
                result_dict: dict[str, t.GeneralValueType] = {}
                for k in keys:
                    if isinstance(obj, Mapping):
                        result_dict[k] = obj.get(k, None)
                    elif hasattr(obj, k):
                        result_dict[k] = getattr(obj, k, None)
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
            """Path accessor using u.chain() DSL (mnemonic: ph)."""

            def make_getter(
                key: str,
            ) -> Callable[[t.GeneralValueType], t.GeneralValueType]:
                def getter_fn(obj: t.GeneralValueType) -> t.GeneralValueType:
                    """Get value from object by key."""
                    if isinstance(obj, Mapping):
                        return obj.get(key, None)
                    if hasattr(obj, key):
                        return getattr(obj, key, None)
                    return None

                return getter_fn

            getters: list[Callable[[t.GeneralValueType], t.GeneralValueType]] = [
                make_getter(k) for k in keys
            ]
            return lambda obj: cls.chain(obj, *getters) if obj is not None else None

        ph = path

        # === COLLECTION METHODS ===
        @staticmethod
        def sum(
            items: Sequence[int | float | object] | dict[str, int | float | object],
        ) -> int | float:
            """Sum of numeric items."""
            if isinstance(items, dict):
                total_dict: int | float = 0
                for v in items.values():
                    if isinstance(v, (int, float)):
                        total_dict += v
                return total_dict
            if not items:
                return 0
            has_float = any(isinstance(v, float) for v in items)
            total_seq: int | float = 0.0 if has_float else 0
            for v in items:
                if isinstance(v, (int, float)):
                    total_seq += v
            return total_seq

        @staticmethod
        def empty(value: object) -> bool:
            """Check if value is empty."""
            if value is None:
                return True
            if isinstance(value, (str, bytes)):
                return len(value) == 0
            if isinstance(value, (list, dict, set)):
                return len(value) == 0
            return False

        @staticmethod
        def conv(value: t.GeneralValueType) -> FlextLdifUtilities.Ldif.ConvBuilder:
            """Create conversion builder (DSL entry point)."""
            return FlextLdifUtilities.Ldif.ConvBuilder(value=value)

        @staticmethod
        def all_(*args: object) -> bool:
            """Check if all values are truthy."""
            return all(args)

        @staticmethod
        def any_(*args: object) -> bool:
            """Check if any value is truthy."""
            return any(args)

        @staticmethod
        def or_[T: t.GeneralValueType](
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
            value: t.GeneralValueType | None,
            *,
            default: t.GeneralValueType | None = None,
            mapper: Callable[[t.GeneralValueType], t.GeneralValueType] | None = None,
        ) -> t.GeneralValueType:
            """Maybe monad pattern (mnemonic: mb)."""
            if value is None:
                return default
            if mapper:
                return mapper(value)
            return value

        mb = maybe

        @staticmethod
        def chain(
            value: t.GeneralValueType,
            *funcs: Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> t.GeneralValueType:
            """Chain function calls (DSL helper, mnemonic: ch)."""
            result = value
            for func in funcs:
                result = func(result)
            return result

        ch = chain

        @staticmethod
        def pick(
            data: dict[str, t.GeneralValueType] | object,
            *keys: str,
            as_dict: bool = True,
        ) -> dict[str, t.GeneralValueType] | list[object]:
            """Pick keys from dict (DSL helper, mnemonic: pc)."""
            if not isinstance(data, dict):
                return {} if as_dict else []
            if as_dict:
                return {k: data[k] for k in keys if k in data}
            return [data[k] for k in keys if k in data]

        pc = pick

        @staticmethod
        def map_dict(
            obj: dict[str, t.GeneralValueType],
            *,
            mapper: (
                Callable[[str, t.GeneralValueType], t.GeneralValueType] | None
            ) = None,
            key_mapper: Callable[[str], str] | None = None,
            predicate: Callable[[str, t.GeneralValueType], bool] | None = None,
        ) -> dict[str, t.GeneralValueType]:
            """Map dict with optional transformations (mnemonic: md)."""
            result: dict[str, t.GeneralValueType] = {}
            for k, v in obj.items():
                if predicate and not predicate(k, v):
                    continue
                new_k = key_mapper(k) if key_mapper else k
                new_v: t.GeneralValueType = mapper(k, v) if mapper else v
                result[new_k] = new_v
            return result

        md = map_dict

        @staticmethod
        def reduce_dict(
            items: (
                Sequence[dict[str, t.GeneralValueType]]
                | dict[str, t.GeneralValueType]
                | t.GeneralValueType
            ),
            *,
            processor: (
                Callable[[str, t.GeneralValueType], tuple[str, t.GeneralValueType]]
                | None
            ) = None,
            predicate: Callable[[str, t.GeneralValueType], bool] | None = None,
            default: dict[str, t.GeneralValueType] | None = None,
        ) -> dict[str, t.GeneralValueType]:
            """Reduce dicts (mnemonic: rd)."""
            if not items:
                return default or {}

            items_list: list[dict[str, t.GeneralValueType]] = []
            if isinstance(items, dict):
                items_list = [items]
            elif isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
                items_list = [item for item in items if isinstance(item, dict)]

            result: dict[str, t.GeneralValueType] = default.copy() if default else {}
            for d_item in items_list:
                for key, val in d_item.items():
                    if predicate and not predicate(key, val):
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
            items: Sequence[object] | object,
            *,
            initial: object,
            folder: Callable[[object, object], object] | None = None,
            predicate: Callable[[object], bool] | None = None,
        ) -> object:
            """Fold items using folder function (mnemonic: fd)."""
            if not folder:
                return initial
            items_list = list(items) if isinstance(items, Sequence) else [items]
            if predicate:
                items_list = [item for item in items_list if predicate(item)]
            result = initial
            for item in items_list:
                result = folder(result, item)
            return result

        fd = fold

        @staticmethod
        def map_filter(
            items: Sequence[object] | object,
            *,
            mapper: Callable[[object], object] | None = None,
            predicate: Callable[[object], bool] | None = None,
        ) -> list[object]:
            """Map then filter items (mnemonic: mf)."""
            items_list = list(items) if isinstance(items, Sequence) else [items]
            if mapper:
                items_list = [mapper(item) for item in items_list]
            if predicate:
                items_list = [item for item in items_list if predicate(item)]
            return items_list

        mf = map_filter

        @staticmethod
        def process_flatten(
            items: ABCCollection[object] | object,
            *,
            processor: Callable[[object], object] | None = None,
            on_error: str = "skip",
        ) -> list[object]:
            """Process and flatten items (mnemonic: pf)."""
            items_list = list(items) if isinstance(items, ABCCollection) else [items]
            result: list[object] = []
            for item in items_list:
                try:
                    processed = processor(item) if processor else item
                    if isinstance(processed, (list, tuple)):
                        result.extend(processed)
                    else:
                        result.append(processed)
                except Exception:
                    if on_error == "fail":
                        raise
                    if on_error == "return":
                        return result
            return result

        pf = process_flatten

        @staticmethod
        def build(
            value: t.GeneralValueType,
            *,
            ops: dict[str, t.GeneralValueType] | None = None,
        ) -> t.GeneralValueType:
            """Build value using operations dict (DSL helper)."""
            if ops is None:
                return value
            return value

        @staticmethod
        def find_key(
            obj: dict[str, t.GeneralValueType],
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
            obj: dict[str, t.GeneralValueType],
            *,
            predicate: Callable[[str, t.GeneralValueType], bool] | None = None,
        ) -> t.GeneralValueType:
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
            """Extract value from FlextResult with optional default (DSL helper)."""
            if result.is_success:
                return result.value
            return default

        # === Type Guards ===
        class TypeGuards(FlextLdifUtilitiesTypeGuards):
            """Type guards for Model identification."""


u = FlextLdifUtilities

__all__ = [
    "FlextLdifUtilities",
    "u",
]
