"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

This module provides LDIF-specific utility functions building on flext-core
u, following SOLID and DRY principles.

Provides power method infrastructure:
    - FlextLdifResult: Extended result type with DSL operators
    - Transformers: Entry transformation pipeline components
    - Filters: Entry filtering with composable operators
    - Fluent APIs: DnOps, EntryOps for method chaining
    - Pipeline: Orchestration for multi-step processing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from collections.abc import (
    Callable,
    Collection as ABCCollection,
    Iterable,
    Mapping,
    Sequence,
)
from typing import Literal, Self, TypeGuard, overload

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextUtilities,
    r,
)
from flext_core.runtime import FlextRuntime
from flext_core.typings import t as flext_core_t
from flext_core.utilities import ValidatorSpec

# Local aliases for model types
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.configs import ProcessConfig
from flext_ldif._utilities.decorators import FlextLdifUtilitiesDecorators
from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
from flext_ldif._utilities.filters import (
    EntryFilter,
)

# Import fluent classes for DnOps and EntryOps
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
from flext_ldif._utilities.transformers import (
    EntryTransformer,
)
from flext_ldif._utilities.type_guards import FlextLdifUtilitiesTypeGuards
from flext_ldif._utilities.type_helpers import (
    is_entry_sequence,
)
from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifUtilities(FlextUtilities):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations.

    Extends flext-core utility functions building on
    flext-core, following SOLID and DRY principles.

    Business Rules:
    ───────────────
    1. All utility methods MUST be static (no instance state)
    2. All operations MUST return r[T] for error handling
    3. LDIF-specific helpers MUST extend flext-core u
    4. Common patterns MUST be consolidated here (DRY principle)

    Power Methods:
        - process() - Universal entry processor
        - transform() - Transformation pipeline
        - filter() - Entry filtering
        - validate() - Universal validator
        - write() - Universal writer
        - dn() - Fluent DN operations
        - entry() - Fluent entry operations

    Submodules (LDIF-specific):
        - ACL, Attribute, Constants, Decorators, Detection
        - DN, Entry, Events, Metadata, ObjectClass
        - OID, Parser, Parsers, Schema, Server
        - Validation, Writer, Writers

    Inherited from u
        - Enum, Collection, Args, Model, Cache
        - Validation, Generators, Text, Guards
        - Reliability, Checker, Configuration, Context
        - Mapper, Domain, Pagination, Parser
        - Convenience shortcuts: is_enum_member, parse_enum, to_str, to_str_list

    Usage:
        # Import from facade (utilities.py)
        from flext_ldif import u

        # LDIF-specific access
        u.DN.parse("cn=test,dc=example,dc=com")
        u.Entry.has_objectclass(entry, "person")

        # Power methods
        result = u.process(entries, source_server="oid")
        result = u.transform(entries, Normalize.dn())
        result = u.filter(entries, Filter.by_objectclass("person"))
    """

    # === LDIF NAMESPACE ===
    # Project-specific namespace for LDIF utilities
    # Access via u.* pattern for better organization
    class Ldif:
        """LDIF-specific utility namespace.

        This namespace groups all LDIF-specific utilities for better organization
        and cross-project access. Access via u.* pattern.

        Example:
            from flext_ldif import u
            result = u.DN.parse("cn=test,dc=example")
            entry = u.Entry.create("cn=test", attrs={"cn": ["test"]})

        """

        # Type alias for variadic callable (Python 3.13+ compatible)
        # Use p.VariadicCallable from protocols to avoid Any
        type VariadicCallable[T] = p.VariadicCallable[T]

        class ConvBuilder:
            """Conversion builder for type-safe value conversion (DSL pattern).

            This builder uses parent FlextUtilities.Conversion utilities for actual
            conversion operations, providing a fluent DSL interface on top.
            """

            def __init__(self, value: t.Ldif.ValueType) -> None:
                """Initialize conversion builder with a value.

                Args:
                    value: The value to convert.

                """
                self._value = value
                self._default: t.Ldif.ValueType | None = None
                self._target_type: str | None = None
                self._safe_mode = False

            def to_str(self, default: str = "") -> Self:
                """Convert to string using parent Conversion utilities."""
                self._default = default
                self._target_type = "to_str"
                return self

            def int(self, default: int = 0) -> Self:
                """Convert to int."""
                self._default = default
                self._target_type = "int"
                return self

            def bool(self, *, default: bool = False) -> Self:
                """Convert to bool."""
                self._default = default
                self._target_type = "bool"
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

            def build(self) -> t.Ldif.ValueType:
                """Build and return the converted value using parent utilities."""
                if self._value is None:
                    return self._default
                if self._target_type == "to_str":
                    # Use parent convenience shortcut with proper type narrowing
                    str_default: str | None = (
                        self._default if isinstance(self._default, str) else None
                    )
                    return FlextUtilities.to_str(self._value, default=str_default)
                if self._target_type == "to_str_list":
                    # Use parent convenience shortcut with proper type narrowing
                    list_default: list[str] | None = None
                    if isinstance(self._default, list) and all(
                        isinstance(item, str) for item in self._default
                    ):
                        # Type narrowing: self._default is list[str] after isinstance check
                        list_default = self._default
                    return FlextUtilities.to_str_list(self._value, default=list_default)
                if self._target_type == "int":
                    if self._safe_mode:
                        try:
                            # Type narrowing: ensure value is compatible with int()
                            if isinstance(self._value, (int, str)):
                                return int(self._value)
                            if isinstance(self._value, float):
                                return int(self._value)
                            return self._default
                        except (ValueError, TypeError):
                            return self._default
                    # Type narrowing: ensure value is compatible with int()
                    if isinstance(self._value, (int, str)):
                        return int(self._value)
                    if isinstance(self._value, float):
                        return int(self._value)
                    return self._default
                if self._target_type == "bool":
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
            """Get value from mapping with default.

            Type-safe wrapper around dict.get() that works with any Mapping type.
            NOTE: Named differently from parent FlextUtilities.get() due to different signature.

            Args:
                mapping: Dictionary or Mapping to get value from
                key: Key to look up
                default: Default value if key not found

            Returns:
                Value from mapping or default

            """
            # Use flext-core mapper for consistent behavior
            return FlextUtilities.mapper().get(mapping, key, default=default)

        @staticmethod
        def unwrap_or[T](result: r[T], *, default: T | None = None) -> T | None:
            """Unwrap FlextResult with default value.

            Args:
                result: FlextResult to unwrap
                default: Default value if failure

            Returns:
                Unwrapped value or default

            """
            if result.is_success:
                return result.value
            return default

        @staticmethod
        def batch_process[T, U](
            items: Sequence[T],
            func: Callable[[T], r[U]],
        ) -> r[list[U]]:
            """Execute batch of operations with FlextResult (simplified).

            NOTE: Named differently from parent FlextUtilities.batch() due to different signature.
            The parent method has more advanced options (size, on_error, parallel, etc.).

            Args:
                items: Sequence of items to process
                func: Function to apply to each item

            Returns:
                FlextResult with list of results or first error

            """
            results: list[U] = []
            for item in items:
                result = func(item)
                if result.is_failure:
                    return r[list[U]].fail(result.error or "Batch operation failed")
                results.append(result.value)
            return r[list[U]].ok(results)

        @staticmethod
        def find[T](
            items: Sequence[T],
            *,
            predicate: Callable[[T], bool],
        ) -> T | None:
            """Find first item matching predicate.

            Args:
                items: Sequence to search
                predicate: Function to test each item

            Returns:
                First matching item or None

            """
            for item in items:
                if predicate(item):
                    return item
            return None

        # === LDIF-specific utility classes ===

        class ACL(FlextLdifUtilitiesACL):
            """ACL utilities for LDIF operations."""

        class Attribute(FlextLdifUtilitiesAttribute):
            """Attribute utilities for LDIF operations."""

        class Constants(c):
            """Constants for LDIF operations."""

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
                    entries, config, **kwargs
                )

            @staticmethod
            def filter_batch(
                entries: Sequence[m.Ldif.Entry],
                config: FlextLdifModelsSettings.EntryFilterConfig | None = None,
                **kwargs: object,
            ) -> r[list[m.Ldif.Entry]]:
                """Filter entries based on criteria."""
                return FlextLdifUtilitiesEntry.filter_batch(entries, config, **kwargs)

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
            entries: Sequence[m.Ldif.Entry],
            config: ProcessConfig | None,
            source_server: c.Ldif.ServerTypes,
            target_server: c.Ldif.ServerTypes | None,
            *,
            _normalize_dns: bool,  # Unused: reserved for future DN normalization control
            _normalize_attrs: bool,  # Unused: reserved for future attribute normalization control
        ) -> FlextLdifResult[list[m.Ldif.Entry]]:
            """Process LDIF entries with pipeline."""
            if config is None:
                # Create ProcessConfig with default factory
                # Use model_copy to update server types (Pydantic v2 pattern)
                config_base = ProcessConfig()
                config_base_model = config_base
                process_config = config_base_model.model_copy(
                    update={
                        "source_server": source_server,
                        "target_server": target_server or c.Ldif.ServerTypes.RFC,
                    }
                )
                # Create TransformConfig with ProcessConfig
                transform_config = m.Ldif.TransformConfig()
                if hasattr(transform_config, "model_copy"):
                    transform_config = transform_config.model_copy(
                        update={"process_config": process_config}
                    )
                else:
                    # Fallback for older Pydantic versions or non-Pydantic models
                    transform_config.process_config = process_config
            else:
                # Create TransformConfig with existing ProcessConfig
                transform_config = m.Ldif.TransformConfig()
                if hasattr(transform_config, "model_copy"):
                    transform_config = transform_config.model_copy(
                        update={"process_config": config}
                    )
                else:
                    # Fallback for older Pydantic versions or non-Pydantic models
                    transform_config.process_config = config
            pipeline = ProcessingPipeline(transform_config)
            pipeline_result = pipeline.execute(list(entries))
            if pipeline_result.is_failure:
                return FlextLdifResult.fail(
                    pipeline_result.error or "Pipeline execution failed"
                )
            # Convert FlextLdifModelsDomains.Entry to m.Ldif.Entry using model_validate
            domain_entries = pipeline_result.value
            converted_entries: list[m.Ldif.Entry] = [
                m.Ldif.Entry.model_validate(
                    entry.model_dump(exclude_computed_fields=True)
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
        def evaluate_predicate[T](
            predicate: Callable[[str, T], bool] | Callable[[T], bool],
            key: str,
            value: T,
        ) -> bool:
            """Evaluate predicate with automatic 1-arg or 2-arg detection."""
            if not callable(predicate):
                return True
            # Use TypeGuard for type narrowing
            if FlextLdifUtilities.Ldif.is_two_arg_processor(predicate):
                # TypeGuard ensures predicate is Callable[[str, T], bool]
                try:
                    result = FlextLdifUtilities.Ldif.call_processor(
                        predicate, key, value
                    )
                    if isinstance(result, bool):
                        return result
                except (TypeError, ValueError):
                    # Fallback: try as 1-arg predicate
                    try:
                        result = FlextLdifUtilities.Ldif.call_processor_single_arg(
                            predicate, value
                        )
                        if isinstance(result, bool):
                            return result
                    except (TypeError, ValueError):
                        pass
            else:
                # TypeGuard ensures predicate is Callable[[T], bool]
                try:
                    result = FlextLdifUtilities.Ldif.call_processor_single_arg(
                        predicate, value
                    )
                    if isinstance(result, bool):
                        return result
                except (TypeError, ValueError):
                    pass
            return True

        TWO_ARG_THRESHOLD: int = 2
        """Minimum parameter count for 2-argument functions."""

        @staticmethod
        def is_two_arg_processor[T, R](
            func: Callable[[str, T], R] | Callable[[T], R],
        ) -> TypeGuard[Callable[[str, T], R]]:
            """Check if processor function accepts 2 arguments.

            Uses inspect to determine parameter count at runtime.
            TypeGuard ensures MyPy understands the type narrowing.
            """
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
        def call_processor_single_arg[T, R](
            processor_func: Callable[[T], R],
            value: T,
        ) -> R:
            """Call 1-arg processor function."""
            return processor_func(value)

        @staticmethod
        def is_no_arg_callable[R](
            func: Callable[[], R] | Callable[[object], R] | object,
        ) -> TypeGuard[Callable[[], R]]:
            """Check if callable accepts 0 arguments.

            Uses inspect to determine parameter count at runtime.
            TypeGuard ensures MyPy understands the type narrowing.
            """
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
            """Check if callable accepts 1 object argument.

            Uses inspect to determine parameter count at runtime.
            TypeGuard ensures MyPy understands the type narrowing.
            """
            if not callable(func):
                return False
            try:
                sig = inspect.signature(func)
                return len(sig.parameters) == 1
            except (ValueError, TypeError):
                return False

        @staticmethod
        def process_dict_items[T, R](
            items: dict[str, T],
            processor_func: Callable[[str, T], R] | Callable[[T], R],
            predicate: Callable[[str, T], bool] | Callable[[T], bool] | None,
            filter_keys: set[str] | None,
            exclude_keys: set[str] | None,
        ) -> list[R]:
            """Process dictionary items.

            Handles both 1-arg and 2-arg processor functions via type narrowing.
            """
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
                # Type narrowing: use TypeGuard to narrow union type
                if FlextLdifUtilities.Ldif.is_two_arg_processor(processor_func):
                    result_item = processor_func(key, value)
                else:
                    result_item = processor_func(value)
                results.append(result_item)
            return results

        @staticmethod
        def process_list_items[T, R](
            items: list[T] | tuple[T, ...],
            processor_func: Callable[[T], R],
            predicate: Callable[[T], bool] | None,
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
                    result_item = processor_func(item)
                    results.append(result_item)
                except Exception as e:
                    if on_error == "fail":
                        return r.fail(f"Processing failed: {e}")
                    if on_error == "skip":
                        continue
                    errors.append(str(e))
            return r.ok(results)

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
            """Universal entry processor.

            Processes entries with DN normalization, attribute normalization,
            and optional server-specific transformations.

            Args:
                items_or_entries: Items to process (base class) or entries (LDIF-specific)
                processor_or_config: Processor function (base class) or
                    ProcessConfig (LDIF-specific)
                on_error: Error handling mode
                predicate: Optional filter predicate
                filter_keys: Keys to include
                exclude_keys: Keys to exclude
                config: ProcessConfig for detailed configuration (LDIF-specific)
                source_server: Source server type (or "auto" for detection)
                target_server: Target server type (optional)
                normalize_dns: Enable DN normalization
                normalize_attrs: Enable attribute normalization

            Returns:
                FlextResult or FlextLdifResult containing processed items/entries

            Examples:
                >>> result = FlextLdifUtilities.process(entries, source_server="oid")
                >>> result = FlextLdifUtilities.process(
                ...     entries,
                ...     config=ProcessConfig.builder()
                ...     .source("oid")
                ...     .target("oud")
                ...     .normalize_dn(case="lower")
                ...     .build(),
                ... )

            """
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
                # Type narrowing: items_or_entries is Sequence after is_entry_sequence check
                # We know from is_ldif_process_call that entries contain m.Ldif.Entry instances
                entries_obj: object = items_or_entries
                if isinstance(entries_obj, (list, tuple)):
                    return FlextLdifUtilities.Ldif.process_ldif_entries(
                        entries_obj,
                        config,
                        source_server,
                        target_server,
                        _normalize_dns=normalize_dns,
                        _normalize_attrs=normalize_attrs,
                    )
                return r.fail("Invalid entry sequence type")

            items: (
                object
                | list[object]
                | tuple[object, ...]
                | dict[str, object]
                | Mapping[str, object]
            ) = items_or_entries
            # Processor can accept 1 or 2 args - use VariadicCallable for flexibility
            # Type narrowing: exclude ProcessConfig and None
            if processor_normalized is None or isinstance(
                processor_normalized, ProcessConfig
            ):
                msg = "processor is required for base class process"
                return r.fail(msg)
            processor_func = processor_normalized

            if isinstance(items, dict):
                results = FlextLdifUtilities.Ldif.process_dict_items(
                    items,
                    processor_func,
                    predicate,
                    filter_keys,
                    exclude_keys,
                )
                # Type narrowing: results is list[R] from process_dict_items
                return r.ok(results)
            if isinstance(items, (list, tuple)):
                # Adapt predicate to match process_list_items signature
                # process_list_items expects Callable[[T], bool] | None
                # but predicate can be Callable[[T], bool] | Callable[[str, T], bool] | None
                # process_list_items handles both, pass as-is
                # Type narrowing: result is r[list[R] | dict[str, R]] from process_list_items
                return FlextLdifUtilities.Ldif.process_list_items(
                    items,
                    processor_func,
                    predicate,
                    on_error,
                )
            # Single item processing
            try:
                # Process single items through processor_func
                # Processor function accepts various types
                result_item = processor_func(items)
                return r.ok([result_item])
            except Exception as e:
                return r.fail(f"Processing failed: {e}")

        @staticmethod
        def transform_entries(
            entries: Sequence[m.Ldif.Entry],
            *transformers: EntryTransformer[m.Ldif.Entry],
            fail_fast: bool = True,
        ) -> FlextLdifResult[list[m.Ldif.Entry]]:
            """Apply LDIF entry transformations via pipeline.

            This is the LDIF-specific entry transformation method.
            For dict/Mapping transformations, use the inherited transform() method.

            Args:
                entries: Sequence of LDIF entries to transform
                *transformers: One or more EntryTransformer instances to apply
                fail_fast: Stop on first error (default: True)

            Returns:
                FlextLdifResult containing list of transformed entries

            Example:
                >>> result = u.transform_entries(
                ...     entries, Normalize.dn(), Normalize.attrs()
                ... )

            """
            pipeline = Pipeline(fail_fast=fail_fast)
            # All transformers and pipeline now use m.Ldif.Entry, no conversion needed
            for transformer in transformers:
                _ = pipeline.add(transformer)  # Explicitly ignore return value
            # entries are already m.Ldif.Entry, pipeline expects m.Ldif.Entry
            entries_list = list(entries)
            pipeline_result = pipeline.execute(entries_list)
            if pipeline_result.is_failure:
                return FlextLdifResult.fail(
                    pipeline_result.error or "Pipeline execution failed"
                )
            # Pipeline returns list[m.Ldif.Entry], which matches return type
            transformed_entries = pipeline_result.value
            return FlextLdifResult.ok(transformed_entries)

        # NOTE: The inherited FlextUtilities.transform() handles dict/Mapping transformations.
        # For LDIF entry transformations, use transform_entries() instead.

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
            mapper: FlextLdifUtilities.Ldif.VariadicCallable[R] | None = None,
            mode: Literal["all", "any"] = "all",
        ) -> (
            list[T]
            | list[R]
            | dict[str, T]
            | dict[str, R]
            | FlextLdifResult[list[m.Ldif.Entry]]
        ):
            """Filter entries using composable filter predicates.

            Args:
                entries: Entries to filter
                *filters: Filters to apply
                mode: "all" for AND (default), "any" for OR

            Returns:
                FlextLdifResult containing filtered entries

            Examples:
                >>> result = FlextLdifUtilities.filter(
                ...     entries,
                ...     Filter.by_objectclass("person"),
                ... )
                >>> # Complex filter with operators
                >>> result = FlextLdifUtilities.filter(
                ...     entries,
                ...     Filter.by_dn(r".*ou=users.*")
                ...     & Filter.by_objectclass("inetOrgPerson"),
                ... )

            """
            # Type narrowing: check if this is LDIF-specific call (entries with EntryFilter)
            # Base class filter - delegate to FlextUtilitiesCollection.filter when not EntryFilter
            if not isinstance(predicate_or_filter1, EntryFilter):
                # Type already narrowed by isinstance check
                predicate: FlextLdifUtilities.Ldif.VariadicCallable[bool] = (
                    predicate_or_filter1
                )

                return FlextLdifUtilities.Ldif.filter_base_class(
                    items_or_entries,
                    predicate,
                    mapper,
                )

            # LDIF-specific filter with EntryFilter
            if isinstance(items_or_entries, Sequence) and not isinstance(
                items_or_entries,
                (str, bytes, dict),
            ):
                # Type already narrowed by isinstance checks
                entries: Sequence[m.Ldif.Entry] = items_or_entries
                filter_entry: EntryFilter[m.Ldif.Entry] = predicate_or_filter1
                return FlextLdifUtilities.Ldif.filter_ldif_entries(
                    entries,
                    filter_entry,
                    filters,
                    mode,
                )

            # Fallback: delegate to base class with proper type narrowing
            # predicate_or_filter1 is EntryFilter here, but we need VariadicCallable
            # This branch is unreachable in normal use since EntryFilter is for sequences
            # Convert EntryFilter to VariadicCallable via lambda wrapper
            def predicate_wrapper(item: object) -> bool:
                """Wrap EntryFilter as VariadicCallable for base class compatibility."""
                if isinstance(predicate_or_filter1, EntryFilter):
                    # EntryFilter.matches() returns bool - type narrowing ensures EntryFilter type
                    entry_filter: EntryFilter[object] = predicate_or_filter1
                    return entry_filter.matches(item)
                return False

            # Type narrowing: items_or_entries is compatible with base class signature
            # Return type already declared in filter_base_class signature
            return FlextLdifUtilities.Ldif.filter_base_class(
                items_or_entries,
                predicate_wrapper,
                mapper,
            )

        @staticmethod
        def filter_base_class[T, R](
            items_or_entries: (
                T
                | list[T]
                | tuple[T, ...]
                | dict[str, T]
                | Mapping[str, T]
                | Sequence[m.Ldif.Entry]
            ),
            predicate: FlextLdifUtilities.Ldif.VariadicCallable[bool],
            mapper: FlextLdifUtilities.Ldif.VariadicCallable[R] | None,
        ) -> list[T] | list[R] | dict[str, T] | dict[str, R]:
            """Filter using base class Collection.filter (internal helper)."""
            if isinstance(items_or_entries, (list, tuple)):
                # Type narrowing: items_or_entries is list[object] | tuple[object, ...]
                items_list: list[object] | tuple[object, ...] = items_or_entries
                if mapper is None:
                    result_list = FlextUtilities.Collection.filter(
                        items_list,
                        predicate,
                    )
                else:
                    # mapper is VariadicCallable[R], compatible with VariadicCallable[t.GeneralValueType]
                    # t.GeneralValueType is a wide union type that includes R
                    result_list = FlextUtilities.Collection.filter(
                        items_list,
                        predicate,
                        mapper=mapper,
                    )
                # Type narrowing: result_list is list[T] | list[R] from Collection.filter
                return result_list
            if isinstance(items_or_entries, (dict, Mapping)):
                # Type narrowing: items_or_entries is dict[str, object] | Mapping[str, object]
                items_dict: dict[str, object] | Mapping[str, object] = items_or_entries
                if mapper is None:
                    result_dict = FlextUtilities.Collection.filter(
                        items_dict,
                        predicate,
                    )
                else:
                    # mapper is VariadicCallable[R], compatible with VariadicCallable[t.GeneralValueType]
                    # t.GeneralValueType is a wide union type that includes R
                    result_dict = FlextUtilities.Collection.filter(
                        items_dict,
                        predicate,
                        mapper=mapper,
                    )
                # Type narrowing: result_dict is dict[str, T] | dict[str, R] from Collection.filter
                return result_dict
            # Single item case - wrap in list
            items_single_list: list[object] = [items_or_entries]
            if mapper is None:
                result_single = FlextUtilities.Collection.filter(
                    items_single_list,
                    predicate,
                )
            else:
                # mapper is VariadicCallable[R], compatible with VariadicCallable[t.GeneralValueType]
                # t.GeneralValueType is a wide union type that includes R
                result_single = FlextUtilities.Collection.filter(
                    items_single_list,
                    predicate,
                    mapper=mapper,
                )
            # Type narrowing: result_single is list[T] | list[R] from Collection.filter
            return result_single

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
            # Combine filters based on mode
            combined: EntryFilter[m.Ldif.Entry] = filter_list[0]
            for f in filter_list[1:]:
                combined = combined & f if mode == "all" else combined | f
            filtered = [entry for entry in entries if combined.matches(entry)]
            return FlextLdifResult.ok(filtered)

        @staticmethod
        def validate[T](
            value_or_entries: T | Sequence[m.Ldif.Entry],
            *validators_or_none: ValidatorSpec,
            mode: str = "all",
            fail_fast: bool = True,
            collect_errors: bool = False,
            field_name: str | None = None,
            strict: bool = True,
            collect_all: bool = True,
            max_errors: int = 0,
        ) -> r[T] | FlextLdifResult[list[ValidationResult]]:
            """Validate entries against rules.

            Args:
                value_or_entries: Value to validate or entries list
                *validators_or_none: Validators to apply
                mode: Validation mode
                fail_fast: Stop on first error
                collect_errors: Collect all errors
                field_name: Field name for errors
                strict: Use strict RFC validation
                collect_all: Collect all errors vs fail on first
                max_errors: Maximum errors to collect (0 = unlimited)

            Returns:
                FlextLdifResult containing list of ValidationResults or r[T]

            Examples:
                >>> result = FlextLdifUtilities.validate(entries, strict=True)
                >>> for validation in result.value:
                ...     if not validation.is_valid:
                ...         print(validation.errors)

            """
            # Type narrowing: check if this is LDIF-specific call (entries without validators)
            # Base class validate - delegate to FlextUtilitiesValidation when not entries
            if not (
                isinstance(value_or_entries, Sequence)
                and not isinstance(value_or_entries, (str, bytes))
                and len(validators_or_none) == 0
            ):
                # Base class validate - delegate to FlextUtilitiesValidation
                # Type narrowing: value_or_entries is T
                value_base: T = value_or_entries
                validate_result = FlextUtilities.Validation.validate(
                    value_base,
                    *validators_or_none,
                    mode=mode,
                    fail_fast=fail_fast,
                    collect_errors=collect_errors,
                    field_name=field_name,
                )
                # Convert RuntimeResult to FlextResult if needed
                if isinstance(validate_result, FlextRuntime.RuntimeResult):
                    if validate_result.is_success:
                        return r.ok(validate_result.value)
                    error_msg = (
                        validate_result.error
                        if hasattr(validate_result, "error")
                        else str(validate_result)
                    )
                    return r.fail(error_msg)
                return validate_result

            # LDIF-specific validate with entries
            if (
                isinstance(value_or_entries, Sequence)
                and not isinstance(value_or_entries, (str, bytes))
                and len(validators_or_none) == 0
            ):
                # LDIF-specific validate - type narrowing ensures list[Entry]
                entries: list[m.Ldif.Entry] = value_or_entries
                pipeline = ValidationPipeline(
                    strict=strict,
                    collect_all=collect_all,
                    max_errors=max_errors,
                )
                return FlextLdifResult.from_result(pipeline.validate(entries))

            # Fallback: delegate to base class validate
            # Type narrowing: value_or_entries is T
            value_fallback: T = value_or_entries
            validate_result = FlextUtilities.Validation.validate(
                value_fallback,
                *validators_or_none,
                mode=mode,
                fail_fast=fail_fast,
                collect_errors=collect_errors,
                field_name=field_name,
            )
            # Convert RuntimeResult to FlextResult if needed
            if isinstance(validate_result, FlextRuntime.RuntimeResult):
                if validate_result.is_success:
                    return r.ok(validate_result.value)
                error_msg = (
                    validate_result.error
                    if hasattr(validate_result, "error")
                    else str(validate_result)
                )
                return r.fail(error_msg)
            return validate_result

        @classmethod
        def dn(cls, dn: str) -> DnOps:
            """Create fluent DN operations.

            Args:
                dn: DN to operate on

            Returns:
                DnOps instance for method chaining

            Examples:
                >>> result = (
                ...     FlextLdifUtilities.dn("CN=Test, DC=Example, DC=Com")
                ...     .normalize(case="lower")
                ...     .clean()
                ...     .replace_base("dc=example,dc=com", "dc=new,dc=com")
                ...     .build()
                ... )

            """
            return DnOps(dn)

        @classmethod
        def entry(cls, entry: m.Ldif.Entry) -> EntryOps:
            """Create fluent entry operations.

            Args:
                entry: Entry to operate on

            Returns:
                EntryOps instance for method chaining

            Examples:
                >>> result = (
                ...     FlextLdifUtilities.entry(entry)
                ...     .normalize_dn()
                ...     .filter_attrs(exclude=["userPassword"])
                ...     .attach_metadata(source="oid")
                ...     .build()
                ... )

            """
            return EntryOps(entry)

        # map_filter - use static method implementation below
        # mf alias defined after static method

        # process_flatten - use static method implementation below
        # pf alias defined after static method

        @classmethod
        def normalize_list(
            cls,
            value: t.GeneralValueType,
            *,
            mapper: Callable[[t.GeneralValueType], t.GeneralValueType] | None = None,
            predicate: Callable[[t.GeneralValueType], bool] | None = None,
            default: list[t.GeneralValueType] | None = None,
        ) -> list[t.GeneralValueType]:
            """Normalize to list using u.build() DSL (mnemonic: nl).

            Args:
                value: Value to normalize (handles Result types)
                mapper: Optional transformation
                predicate: Optional filter
                default: Default list

            Returns:
                Normalized list

            Examples:
                >>> items = cls.nl(result.value, mapper=str.strip, predicate=bool)

            """
            # Extract from Result using u.or_() DSL
            # Type narrowing: check if value is Result before accessing attributes
            extracted_value: t.GeneralValueType
            if isinstance(value, FlextResult):
                # Type narrowing: value is FlextResult after isinstance check
                extracted_value = value.value if not value.is_failure else value
            else:
                extracted_value = value
            extracted = cls.or_(
                extracted_value,
                default=default or [],
            )
            # Use u.build() DSL for list normalization (more generic than u.conv().str_list())
            ops: dict[str, object] = {"ensure": "list", "ensure_default": default or []}
            if mapper:
                ops["map"] = mapper
            if predicate:
                ops["filter"] = predicate
            result = cls.build(extracted, ops=ops)
            # Ensure list[t.GeneralValueType] return type
            if isinstance(result, (list, tuple)):
                # Type narrowing: result is list/tuple
                return list(result)
            # Type narrowing: result is object, but we know it's t.GeneralValueType
            result_typed: t.GeneralValueType = result
            return [result_typed]

        # Mnemonic helper
        nl = normalize_list

        # reduce_dict - use static method implementation below
        # rd alias defined after static method

        # chain - use static method implementation below
        # ch alias defined after static method

        # when delegated to base class via u.when() - simple ternary
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

        # fold - use static method implementation below
        # fd alias defined after static method

        # LDIF-specific pipe with dict support - named differently to avoid override conflict
        @overload
        @staticmethod
        def pipe_ldif(
            value: t.GeneralValueType,
            *ops: dict[str, t.GeneralValueType]
            | Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> t.GeneralValueType: ...

        @overload
        @staticmethod
        def pipe_ldif(
            value: t.GeneralValueType,
            *operations: Callable[[t.GeneralValueType], t.GeneralValueType],
            on_error: str = "stop",
        ) -> r[t.GeneralValueType]: ...

        @staticmethod
        def pipe_ldif(
            value: t.GeneralValueType,
            *ops: dict[str, t.GeneralValueType]
            | Callable[[t.GeneralValueType], t.GeneralValueType],
            on_error: str = "stop",
        ) -> t.GeneralValueType | r[t.GeneralValueType]:
            """LDIF-specific pipe - supports dict operations via flow()."""
            # Type narrowing: check if this is base class call (only Callable operations, no dicts)
            if ops and all(callable(op) and not isinstance(op, dict) for op in ops):
                # Base class pipe - delegate to FlextUtilitiesReliability.pipe
                # Type narrowing: op is Callable[[object], object] after callable check
                operations_list: list[Callable[[object], object]] = [
                    op for op in ops if callable(op) and not isinstance(op, dict)
                ]
                # Type narrowing: pipe_result is r[t.GeneralValueType]
                return FlextUtilities.Reliability.pipe(
                    value,
                    *operations_list,
                    on_error=on_error,
                )

            # LDIF-specific pipe using flow()
            flow_ops: list[t.ConfigurationDict | Callable[[object], object]] = []
            for op in ops:
                if isinstance(op, dict):
                    # dict[str, object] is compatible with ConfigurationDict (dict[str, t.GeneralValueType])
                    flow_ops.append(op)
                elif callable(op):
                    # Type narrowing: op is Callable[[object], object] after callable check
                    flow_ops.append(op)
            # Type narrowing: flow returns t.GeneralValueType
            return FlextUtilities.Reliability.flow(value, *flow_ops)

        # Alias for pipe_ldif (mnemonic: pp)
        @staticmethod
        def pp(
            value: t.GeneralValueType,
            *ops: dict[str, t.GeneralValueType]
            | Callable[[t.GeneralValueType], t.GeneralValueType],
        ) -> t.GeneralValueType:
            """Alias for pipe_ldif (mnemonic: pp)."""
            return FlextLdifUtilities.Ldif.pipe_ldif(value, *ops)

        @classmethod
        def tap(
            cls,
            value: t.GeneralValueType,
            *,
            side_effect: Callable[[t.GeneralValueType], t.GeneralValueType] | None,
        ) -> t.GeneralValueType:
            """Tap into pipeline for side effects (DSL pattern).

            Executes side_effect function but returns original value.
            Useful for logging/debugging in pipelines.

            Args:
                value: Value to tap
                side_effect: Function to execute (receives value)

            Returns:
                Original value unchanged

            Examples:
                >>> # Log intermediate value
                >>> result = FlextLdifUtilities.pipe(
                ...     data,
                ...     lambda x: x.split(","),
                ...     lambda x: FlextLdifUtilities.tap(x, side_effect=print),
                ...     lambda x: [s.strip() for s in x],
                ... )

            """
            if side_effect:
                _ = side_effect(value)  # Explicitly ignore return value
            return value

        # maybe - use static method implementation below
        # mb alias defined after static method

        # zip_with delegated to base class via u.zip_with() - Sequence vs ABCCollection
        @classmethod
        def zip_with(
            cls,
            *sequences: Sequence[t.GeneralValueType],
            combiner: FlextLdifUtilities.Ldif.VariadicCallable[t.GeneralValueType]
            | None = None,
        ) -> list[t.GeneralValueType]:
            """Zip with combiner (generalized: uses zip from base, mnemonic: zw)."""
            # Use built-in zip and apply combiner if provided
            if not sequences:
                return []
            zipped = zip(*sequences, strict=False)
            if combiner is None:
                # Return list of tuples
                return [tuple(items) for items in zipped]
            # Apply combiner to each tuple
            result: list[t.GeneralValueType] = []
            for items_tuple in zipped:
                # Convert tuple to list for combiner
                items_list = list(items_tuple)
                combined = combiner(*items_list)
                result.append(combined)
            return result

        zw = zip_with

        # group_by - implement directly to avoid generic type inference issues
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

        # partition - split sequence into two lists based on predicate
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

        # LDIF-specific get - renamed to avoid @classmethod/@staticmethod conflict with base
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
            # Type narrowing: ensure data is Mapping for get_from_mapping()
            if isinstance(data, Mapping):
                return FlextLdifUtilities.Ldif.get_from_mapping(
                    data,
                    key,
                    default=default,
                )
            # Non-mapping: return default
            return default

        # get: Inherited from FlextUtilities with all overloads - no override needed

        # pluck - extract values from sequence of objects by key/index/function
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

        # normalize_ldif - different signature from base FlextUtilities.normalize
        # Base: normalize(text, pattern, replacement) for string normalization
        # LDIF: normalize_ldif(value, other, case) for case-based comparison
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
            """Normalize for LDIF comparison (mnemonic: nz).

            Different from base normalize() which normalizes whitespace in strings.
            This method normalizes case for LDIF attribute comparison.

            Supports two usage patterns:
            1. normalize_ldif(value, case="lower") -> normalized string
            2. normalize_ldif(value, other) -> bool (comparison)

            Args:
                value: Value to normalize
                other: Optional second value for comparison
                case: Case folding option ("lower", "upper", "preserve")

            Returns:
                Normalized value or bool comparison result

            """

            # Normalize single value based on case
            def normalize_single(v: str) -> str:
                if case == "lower":
                    return v.lower()
                if case == "upper":
                    return v.upper()
                return v

            # If other is provided and is a string, do comparison
            if other is not None and isinstance(value, str) and isinstance(other, str):
                return normalize_single(value) == normalize_single(other)

            # Normalize single string value
            if isinstance(value, str):
                return normalize_single(value)

            # Normalize collections
            if isinstance(value, (list, tuple)):
                return [normalize_single(str(v)) for v in value]

            if isinstance(value, (set, frozenset)):
                return {normalize_single(str(v)) for v in value}

            # All supported types handled above - return value as-is for unsupported types
            # Type narrowing: value is not str, list, tuple, set, or frozenset
            # This is reachable for unsupported types (e.g., int, float, None)
            return value

        nz = normalize_ldif

        # pairs - returns dict/mapping items as list of tuples
        @classmethod
        def pairs(
            cls,
            d: dict[str, object] | Mapping[str, object],
        ) -> list[tuple[str, object]]:
            """Convert dict/mapping to list of (key, value) tuples (mnemonic: pr)."""
            return list(d.items())

        pr = pairs

        # count delegated to base class via u.count()
        @staticmethod
        def count[T](
            items: list[T] | tuple[T, ...],
            predicate: Callable[[T], bool] | None = None,
        ) -> int:
            """Count items (generalized: uses count from base, mnemonic: ct)."""
            return FlextUtilities.Collection.count(items, predicate=predicate)

        ct = count

        # pick - use static method implementation below
        # pc alias defined after static method

        @classmethod
        def omit(
            cls,
            obj: dict[str, object],
            *keys: str,
        ) -> dict[str, object]:
            """Omit keys using u.map_dict() DSL (mnemonic: om).

            Args:
                obj: Dict to omit from
                *keys: Keys to omit

            Returns:
                New dict without keys

            Examples:
                >>> result = cls.om({"a": 1, "b": 2}, "b")

            """
            if not obj or not keys:
                return dict(obj) if obj else {}
            # Use u.map_dict() with predicate to filter out keys
            keys_set = set(keys)
            return cls.map_dict(obj, predicate=lambda k, _: k not in keys_set)

        # Mnemonic helper
        om = omit

        # merge_dicts - different signature from base FlextUtilities.merge
        # Base: merge(base, other, strategy) for two dicts
        # LDIF: merge_dicts(*dicts, strategy, filter_none, filter_empty) for variadic merge
        @staticmethod
        def is_empty_value(value: object) -> bool:
            """Check if value is empty (empty string, list, or dict)."""
            # Check each empty type explicitly (can't use 'in' with unhashable types)
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
            """Merge multiple dicts with filtering options (mnemonic: mg).

            Different from base merge() which takes exactly two dicts.
            This method accepts variadic dicts with additional filtering options.

            Args:
                *dicts: Dicts to merge (variadic)
                strategy: Merge strategy ("override", "deep", "append")
                filter_none: Skip None values
                filter_empty: Skip empty strings/lists/dicts

            Returns:
                FlextResult containing merged dict

            Examples:
                >>> result = cls.mg({"a": 1}, {"b": 2})
                >>> if result.is_success:
                ...     merged = result.value

            """
            # Convert dicts to Mapping[str, t.GeneralValueType] for u.merge()
            # Use list comprehension for better performance
            # Type narrowing: isinstance already guarantees Mapping[str, t.GeneralValueType]
            _mappings_list: list[
                Mapping[str, flext_core_t.FlextTypes.GeneralValueType]
            ] = [
                dict_item
                for dict_item in dicts
                if isinstance(dict_item, (dict, Mapping))
            ]
            # Type already matches via type narrowing
            dicts_typed: tuple[Mapping[str, t.GeneralValueType], ...] = dicts
            # Merge dicts sequentially using base class merge method
            if not dicts_typed:
                return r[dict[str, t.GeneralValueType]].ok({})
            merged: dict[str, t.GeneralValueType] = {}
            for dict_item in dicts_typed:
                # Convert Mapping to dict for base class merge()
                dict_item_dict: dict[str, t.GeneralValueType] = (
                    dict(dict_item) if isinstance(dict_item, Mapping) else dict_item
                )
                merge_result = FlextUtilities.merge(
                    merged,
                    dict_item_dict,
                    strategy=strategy,
                )
                if merge_result.is_failure:
                    return r[dict[str, t.GeneralValueType]].fail(
                        merge_result.error or "Merge failed",
                    )
                merged = merge_result.value
            # Apply filtering if requested
            if filter_none or filter_empty:
                filtered: dict[str, t.GeneralValueType] = {}
                for key, value in merged.items():
                    # Filter None values
                    if filter_none and value is None:
                        continue
                    # Filter empty values (empty strings, lists, dicts)
                    if filter_empty and FlextLdifUtilities.Ldif.is_empty_value(value):
                        continue
                    filtered[key] = value
                merged = filtered
            return r[dict[str, t.GeneralValueType]].ok(merged)

        # Mnemonic helper
        mg = merge_dicts

        # map_dict - use static method implementation below
        # md alias defined after static method

        @classmethod
        def smart_convert(
            cls,
            value: object,
            *,
            target_type: str,
            predicate: Callable[[object], bool] | None = None,
            default: object | None = None,
        ) -> object:
            """Smart convert using u.build() DSL (mnemonic: sc).

            Args:
                value: Value to convert
                target_type: "list", "dict", "str", etc.
                predicate: Optional filter
                default: Default value

            Returns:
                Converted value or default

            Examples:
                >>> result = cls.sc(
                ...     data,
                ...     target_type="list",
                ...     predicate=lambda x: isinstance(x, dict),
                ... )

            """
            # Extract from Result using u.or_() DSL
            extracted = cls.or_(
                value.value
                if isinstance(value, FlextResult) and not value.is_failure
                else value,
                default=default,
            )
            if extracted is None:
                return default

            # Use cls.conv() builder DSL for type conversion
            conv_builder = cls.conv(extracted)
            conv_result: object = None
            if target_type == "str":  # String comparison for target_type
                str_default = default if isinstance(default, str) else ""
                conv_result = conv_builder.to_str(default=str_default).build()
            elif target_type == "int":  # String comparison for target_type
                int_default = default if isinstance(default, int) else 0
                conv_result = conv_builder.int(default=int_default).build()
            elif target_type == "bool":  # String comparison for target_type
                bool_default = default if isinstance(default, bool) else False
                conv_result = conv_builder.bool(default=bool_default).build()
            elif target_type == "list":  # String comparison for target_type
                list_default = default if isinstance(default, list) else []
                conv_result = conv_builder.str_list(default=list_default).build()
                if predicate and isinstance(conv_result, list):
                    filtered = [item for item in conv_result if predicate(item)]
                    return filtered or (
                        conv_result if conv_result is not None else default
                    )
            else:
                # Fallback to u.build() for other types
                ops: dict[str, object] = {
                    "ensure": target_type,
                    "ensure_default": default,
                }
                if predicate:
                    ops["filter"] = predicate
                conv_result = cls.build(extracted, ops=ops)
            # Use Python's native or for heterogeneous types instead of or_() with generic constraint
            return conv_result if conv_result is not None else default

        # Mnemonic helper
        sc = smart_convert

        @staticmethod
        def is_type(
            value: object,
            type_spec: str | type | tuple[type, ...],
        ) -> bool:
            """Type check using u.build() DSL (mnemonic: it).

            Checks if value is instance of any type using u.build() ensure pattern.
            Overrides base class to support multiple types via tuple.

            Args:
                value: Value to check
                type_spec: Type specification (compatible with base class signature)

            Returns:
                True if value matches any type

            Examples:
                >>> if cls.it(value, dict):
                ...     process(value)
                >>> if cls.it(value, (dict, list)):
                ...     process(value)

            """
            # Convert type_spec to tuple if single type for compatibility
            types_tuple: tuple[str | type, ...] = (
                type_spec if isinstance(type_spec, tuple) else (type_spec,)
            )

            # Use u.build() with ensure to check types
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
            """Safe cast using u.convert() or u.ensure() (mnemonic: at).

            Args:
                value: Value to cast
                target: Target type/name
                default: Default if fails

            Returns:
                Casted value or default

            Examples:
                >>> items = cls.at(value, target="list", default=[])

            """
            # Use u.conv() builder DSL for type conversion
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

            # Use FlextLdifUtilities.conv() builder for common types with safe mode
            if target_type is str:
                str_default = default if isinstance(default, str) else ""
                return (
                    FlextLdifUtilities.Ldif.conv(value)
                    .to_str(default=str_default)
                    .safe()
                    .build()
                )
            if target_type is int:
                int_default = default if isinstance(default, int) else 0
                return cls.conv(value).int(default=int_default).safe().build()
            if target_type is bool:
                bool_default = default if isinstance(default, bool) else False
                return (
                    FlextLdifUtilities.Ldif.conv(value)
                    .bool(default=bool_default)
                    .safe()
                    .build()
                )
            if target_type is list:
                list_default = default if isinstance(default, list) else []
                return (
                    FlextLdifUtilities.Ldif.conv(value)
                    .str_list(default=list_default)
                    .safe()
                    .build()
                )

            # Fallback to u.build() for dict, tuple and other types
            ops: dict[str, object] = {"ensure": target_type, "ensure_default": default}
            result = cls.build(value, ops=ops)
            # Ensure result is t.GeneralValueType for or_()
            # Type narrowing: result is object, but we know it's t.GeneralValueType
            result_typed: t.GeneralValueType | None = (
                result if result is not None else None
            )
            return cls.or_(result_typed, default=default)

        # Mnemonic helper
        # at method already has overloads defined above - this is the LDIF-specific implementation
        # The overloads handle both base class and LDIF-specific cases

        @classmethod
        def guard_simple[T](
            cls,
            value: T,
            *,
            check: Callable[[T], bool] | bool,
            default: T | None = None,
        ) -> T | None:
            """Simple guard using check pattern (mnemonic: gd).

            Simplified version of u.guard() for common use cases.
            This is NOT an override of u.guard() - it's a separate method.

            Args:
                value: Value to guard
                check: Check function/bool
                default: Default if fails

            Returns:
                Value or default

            Examples:
                >>> result = cls.gd(data, check=lambda x: len(x) > 0, default=[])

            """
            check_result = check(value) if callable(check) else bool(check)
            return value if check_result else default

        # Mnemonic helper
        gd = guard_simple

        @classmethod
        def thru(
            cls,
            value: object,
            *,
            fn: Callable[[object], object],
        ) -> object:
            """Thru using direct call (mnemonic: th).

            Args:
                value: Value to pass through
                fn: Function to apply

            Returns:
                Function result

            Examples:
                >>> result = cls.th(data, fn=lambda x: x.split(","))

            """
            return fn(value)

        # Mnemonic helper
        th = thru

        @classmethod
        def comp(
            cls,
            *fns: Callable[[object], object],
        ) -> Callable[[object], object]:
            """Compose using u.chain() (mnemonic: cp).

            Args:
                *fns: Functions to compose

            Returns:
                Composed function

            Examples:
                >>> fn = cls.cp(
                ...     lambda x: x.split(","), lambda x: [s.strip() for s in x]
                ... )

            """
            if not fns:
                return lambda x: x
            return lambda value: cls.chain(value, *fns)

        # Mnemonic helper
        cp = comp

        @classmethod
        def juxt(
            cls,
            *fns: Callable[[object], object],
        ) -> Callable[[object], tuple[object, ...]]:
            """Juxtapose functions (mnemonic: jx).

            Args:
                *fns: Functions to apply

            Returns:
                Function returning tuple of results

            Examples:
                >>> fn = cls.jx(len, str.upper, str.lower)

            """
            if not fns:
                return lambda _x: ()
            return lambda value: tuple(fn(value) for fn in fns)

        # Mnemonic helper
        jx = juxt

        @classmethod
        def curry(
            cls,
            fn: VariadicCallable[t.GeneralValueType],
            *args: t.GeneralValueType,
        ) -> VariadicCallable[t.GeneralValueType]:
            """Curry function (mnemonic: cy).

            Args:
                fn: Function to curry
                *args: Arguments to apply

            Returns:
                Curried function

            Examples:
                >>> add5 = cls.cy(lambda x, y: x + y, 5)

            """

            def curried(*more_args: t.GeneralValueType) -> t.GeneralValueType:
                # Combine args and more_args, then call fn
                combined_args: tuple[t.GeneralValueType, ...] = args + more_args
                # VariadicCallable accepts specific types, convert args appropriately
                # Convert to compatible types for VariadicCallable protocol
                converted_args: list[object] = []
                for arg in combined_args:
                    if isinstance(arg, (str, int, float, bool)):
                        # Type narrowing: scalar value
                        converted_args.append(arg)
                    elif arg is None:
                        # Handle None explicitly
                        converted_args.append(None)
                    elif isinstance(arg, (list, tuple)) and not isinstance(
                        arg, (str, bytes)
                    ):
                        # Type narrowing: arg is Sequence
                        converted_args.append(arg)
                    elif isinstance(arg, (dict, Mapping)) and not isinstance(
                        arg, (str, bytes)
                    ):
                        # Type narrowing: arg is Mapping
                        converted_args.append(arg)
                    else:
                        # Fallback: convert to string
                        converted_args.append(str(arg))
                # Call fn with converted args
                if len(converted_args) == 0:
                    result = fn()
                elif len(converted_args) == 1:
                    result = fn(converted_args[0])
                else:
                    result = fn(*converted_args)
                # Type narrowing: result is t.GeneralValueType
                return result

            # Type narrowing: curried has signature compatible with VariadicCallable[t.GeneralValueType]
            # Return type already declared as VariadicCallable[t.GeneralValueType]
            return curried

        # Mnemonic helper
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
        def _evaluate_no_arg_predicate(
            cls,
            *,
            pred: Callable[[], bool] | bool,
        ) -> bool:
            """Evaluate a no-arg predicate."""
            if callable(pred):
                # Type narrowing: callable check ensures it's Callable[[], bool]
                pred_no_arg: Callable[[], bool] = pred
                return pred_no_arg()
            return bool(pred)

        @classmethod
        def _evaluate_value_arg_predicate(
            cls,
            *,
            pred: Callable[[], bool] | Callable[[object], bool] | bool,
            value: object,
        ) -> bool:
            """Evaluate a value-arg predicate."""
            if callable(pred):
                # Use TypeGuards for type narrowing
                if FlextLdifUtilities.Ldif.is_no_arg_callable(pred):
                    # TypeGuard ensures pred is Callable[[], bool]
                    return pred()
                if FlextLdifUtilities.Ldif.is_object_arg_callable(pred):
                    # TypeGuard ensures pred is Callable[[object], bool]
                    return pred(value)
                # Fallback: try calling with value (runtime validation)
                try:
                    return bool(pred(value))
                except (TypeError, ValueError):
                    return bool(pred)
            return bool(pred)

        @classmethod
        def _evaluate_no_arg_result(
            cls,
            result_val: object,
        ) -> object:
            """Evaluate a no-arg result value."""
            if callable(result_val) and FlextLdifUtilities.Ldif.is_no_arg_callable(
                result_val
            ):
                # TypeGuard ensures result_val is Callable[[], object]
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
                result_val
            ):
                # TypeGuard ensures result_val is Callable[[object], object]
                return result_val(value)
            return result_val

        @classmethod
        def cond(
            cls,
            *pairs: tuple[Callable[[], bool] | Callable[[object], bool] | bool, object],
            default: object | None = None,
        ) -> Callable[[], object] | Callable[[object], object]:
            """Cond pattern (mnemonic: cd).

            Returns a function that evaluates predicates. Supports both no-arg and value-arg predicates.

            Args:
                *pairs: (predicate, value) tuples
                    - If predicate is callable with no args: returns function() -> value
                    - If predicate is callable with 1 arg: returns function(value) -> value
                default: Default if no match

            Returns:
                Function that evaluates predicates

            Examples:
                >>> # No-arg predicates: call with ()
                >>> result_fn = cls.cd((lambda: True, "yes"), default="no")
                >>> result = result_fn()
                >>> # Value-arg predicates: call with (value)
                >>> fn = cls.cd(
                ...     (lambda x: x > 10, "big"),
                ...     (lambda x: x > 5, "med"),
                ...     default="small",
                ... )
                >>> result = fn(15)

            """
            is_no_arg = cls._detect_predicate_type(pairs)

            if is_no_arg:

                def conditional_no_arg() -> object:
                    for pred, result_val in pairs:
                        # Type narrowing: is_no_arg ensures pred is Callable[[], bool] | bool
                        if cls._evaluate_no_arg_predicate(pred=pred):
                            return cls._evaluate_no_arg_result(result_val)
                    # Default handling - mypy sees this as potentially unreachable
                    # but it's reachable when no predicates match
                    if (
                        default is not None
                        and callable(default)
                        and FlextLdifUtilities.Ldif.is_no_arg_callable(default)
                    ):
                        # Type narrowing: callable check + is_no_arg ensures Callable[[], object]
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
                    # Type narrowing: callable check ensures Callable[[object], object]
                    return default(value)
                return default

            return conditional

        # Mnemonic helper
        cd = cond

        @classmethod
        def match[T](
            cls,
            value: object,
            *cases: tuple[type[object] | object | Callable[[object], bool], object],
            default: object | None = None,
        ) -> object:
            """Pattern match (mnemonic: mt).

            NOTE: Different from u.match() which has stricter typing.
            This method supports type matching, value matching, and predicate matching.

            Args:
                value: Value to match
                *cases: (pattern, result) tuples
                default: Default if no match

            Returns:
                Matching result

            Examples:
                >>> result = cls.mt(
                ...     "REDACTED_LDAP_BIND_PASSWORD", (str, lambda s: s.upper()), default="unknown"
                ... )

            """
            for pattern, result in cases:
                # Type match
                if isinstance(pattern, type) and isinstance(value, pattern):
                    return result(value) if callable(result) else result
                # Value match
                if pattern == value:
                    return result(value) if callable(result) else result
                # Predicate match (exclude types - they're handled above)
                # Combine conditions to avoid nested if (SIM102)
                if callable(pattern) and not isinstance(pattern, type):
                    # Type narrowing: pattern is callable and not a type, so it's a predicate function
                    # Check if it's a predicate (returns bool) vs extractor (returns object)
                    try:
                        pred_result = pattern(value)
                        if isinstance(pred_result, bool) and pred_result:
                            return result(value) if callable(result) else result
                    except (ValueError, TypeError, AttributeError):
                        pass
            if default is not None:
                return default(value) if callable(default) else default
            return None

        # Mnemonic helper
        mt = match

        @classmethod
        def switch(
            cls,
            value: object,
            cases: dict[object, object],
            default: object | None = None,
        ) -> object:
            """Switch using dict lookup (mnemonic: sw).

            Args:
                value: Value to switch on
                cases: Dict mapping cases to results
                default: Default if no match

            Returns:
                Matching result

            Examples:
                >>> result = cls.sw("a", {"a": 1, "b": 2}, default=0)

            """
            result = cases.get(value, default)
            return result(value) if callable(result) else result

        # Mnemonic helper
        sw = switch

        @classmethod
        def defaults(
            cls,
            *dicts: dict[str, object] | None,
        ) -> dict[str, object]:
            """Defaults merge - first wins using u.flow() DSL (mnemonic: df).

            Args:
                *dicts: Dicts to merge (later = defaults)

            Returns:
                Merged dict

            Examples:
                >>> result = cls.df({"a": 1}, {"b": 2, "a": 3})  # {"a":1, "b":2}

            """
            if not dicts:
                return {}
            # Use u.fold() DSL to apply first-wins logic: first dict wins, later dicts fill missing/None keys

            def apply_defaults(acc: object, d: object) -> object:
                """Apply defaults using fold() pattern: first wins, later fill missing/None."""
                if not isinstance(acc, dict) or not isinstance(d, dict):
                    return acc
                # Use u.map_dict() to filter: only include keys not in result or where result value is None
                filtered = cls.map_dict(
                    d,
                    predicate=lambda k, _v: k not in acc or acc.get(k) is None,
                )
                acc.update(filtered)
                return acc

            # Filter dicts first, then fold to apply defaults
            dict_list = [
                dict_item for dict_item in dicts if isinstance(dict_item, dict)
            ]
            if dict_list:
                result = cls.fold(
                    dict_list,
                    folder=apply_defaults,
                    initial={},
                )
                # Type narrowing: result is dict[str, object] after isinstance check
                return result if isinstance(result, dict) else {}
            return {}

        # Mnemonic helper
        df = defaults

        @classmethod
        def deep_merge(
            cls,
            *dicts: dict[str, object] | None,
        ) -> dict[str, object]:
            """Deep merge using u.merge() with deep strategy (mnemonic: dm).

            Args:
                *dicts: Dicts to merge

            Returns:
                Deeply merged dict

            Examples:
                >>> result = cls.dm(
                ...     {"a": {"b": 1}}, {"a": {"c": 2}}
                ... )  # {"a": {"b":1, "c":2}}

            """
            if not dicts:
                return {}
            # Filter to get only dict items, then u.merge() with u.or_() for fallback
            dict_list = [
                dict_item for dict_item in dicts if isinstance(dict_item, dict)
            ]
            if not dict_list:
                return {}
            # Type narrowing: dict_item is Mapping[str, t.GeneralValueType] (filter already ensures dict type)
            mappings: list[Mapping[str, flext_core_t.FlextTypes.GeneralValueType]] = (
                list(
                    dict_list,
                )
            )
            if not mappings:
                return {}
            # Merge mappings sequentially (merge accepts 2 args, not variadic)
            merged: dict[str, flext_core_t.FlextTypes.GeneralValueType] = dict(
                mappings[0]
            )
            for mapping in mappings[1:]:
                merge_result = FlextUtilities.merge(
                    merged,
                    dict(mapping),
                    strategy="deep",
                )
                if merge_result.is_success and isinstance(merge_result.value, dict):
                    merged = merge_result.value
            # Type narrowing: t.GeneralValueType is compatible with object
            return dict(merged)

        # Mnemonic helper
        dm = deep_merge

        @classmethod
        def update_inplace(
            cls,
            obj: dict[str, object],
            *updates: dict[str, object] | None,
        ) -> dict[str, object]:
            """Update in-place using u.flow() pattern (mnemonic: ui).

            Args:
                obj: Dict to update
                *updates: Dicts with updates

            Returns:
                Updated dict (same reference)

            Examples:
                >>> d = {"a": 1}
                >>> cls.ui(d, {"b": 2})  # d mutated

            """

            # Apply updates in-place using u.fold() DSL pattern for composition
            # Use u.fold() to apply all dict updates sequentially
            def apply_update(acc: object, update_item: object) -> object:
                """Apply single update using fold() pattern."""
                if isinstance(acc, dict) and isinstance(update_item, dict):
                    # Type narrowing: isinstance ensures dict[str, object] compatibility
                    acc_dict: dict[str, object] = acc
                    update_dict: dict[str, object] = update_item
                    acc_dict.update(update_dict)
                return acc

            # Filter dict updates first, then fold to apply them
            dict_updates = [u for u in updates if isinstance(u, dict)]
            if dict_updates:
                FlextLdifUtilities.Ldif.fold(
                    dict_updates,
                    folder=apply_update,
                    initial=obj,
                )
            return obj

        # Mnemonic helper
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
            acc_dict: dict[str, object] = acc
            d_dict: dict[str, object] = d
            for k, v in d_dict.items():
                if k not in acc_dict:
                    acc_dict[k] = v
                elif isinstance(acc_dict[k], dict) and isinstance(v, dict):
                    # Type narrowing: isinstance ensures dict[str, object] compatibility
                    acc_nested: dict[str, object] = acc_dict[k]
                    v_nested: dict[str, object] = v
                    acc_dict[k] = cls.defaults_deep(acc_nested, v_nested)
            return acc_dict

        @classmethod
        def defaults_deep(
            cls,
            *dicts: dict[str, object] | None,
        ) -> dict[str, object]:
            """Deep defaults using u.merge() deep strategy + first wins (mnemonic: dd).

            Args:
                *dicts: Dicts to merge (first wins, deep merge nested)

            Returns:
                Deeply merged dict with defaults

            Examples:
                >>> result = cls.dd(
                ...     {"a": {"b": 1}}, {"a": {"b": 2, "c": 3}}
                ... )  # {"a": {"b":1, "c":3}}

            """
            if not dicts:
                return {}
            # Filter and reverse dicts for first-wins logic
            dict_list = [
                dict_item
                for dict_item in reversed(dicts)
                if isinstance(dict_item, dict)
            ]
            if not dict_list:
                return {}
            # Apply deep defaults using fold pattern
            result = FlextLdifUtilities.Ldif.fold(
                dict_list,
                folder=cls._apply_deep_defaults_recursive,
                initial={},
            )
            # Type narrowing: fold with dict initial returns dict[str, object]
            if isinstance(result, dict):
                return result
            return {}

        # Mnemonic helper
        dd = defaults_deep

        @staticmethod
        @overload
        def take[T](
            data_or_items: Mapping[str, object] | object,
            key_or_n: str,
            *,
            as_type: type[T] | None = None,
            default: T | None = None,
            from_start: bool = True,
        ) -> T | None: ...

        @staticmethod
        @overload
        def take[T](
            data_or_items: dict[str, T],
            key_or_n: int,
            *,
            as_type: type[T] | None = None,
            default: T | None = None,
            from_start: bool = True,
        ) -> dict[str, T]: ...

        @staticmethod
        @overload
        def take[T](
            data_or_items: list[T] | tuple[T, ...],
            key_or_n: int,
            *,
            as_type: type[T] | None = None,
            default: T | None = None,
            from_start: bool = True,
        ) -> list[T]: ...

        @staticmethod
        def take[T](
            data_or_items: Mapping[str, object]
            | object
            | dict[str, T]
            | list[T]
            | tuple[T, ...],
            key_or_n: str | int,
            *,
            as_type: type[T] | None = None,
            default: T | None = None,
            from_start: bool = True,
        ) -> dict[str, T] | list[T] | T | None:
            """Take value from data with type guard (mnemonic: tk).

            Supports two modes:
            - Extraction mode (str key): Extract value from dict/object by key
            - Slice mode (int n): Take first/last n items from sequence/dict

            Args:
                data_or_items: Source data or items
                key_or_n: Key/attribute name (str) or number of items (int)
                as_type: Type to guard/validate against
                default: Default value if key not found or type mismatch
                from_start: Take from start if True, from end if False (slice mode)

            Returns:
                Extracted value, sliced items, or default

            Examples:
                >>> port = cls.tk(config, "port", as_type=int, default=8080)
                >>> first_two = cls.tk([1, 2, 3, 4], 2)  # [1, 2]

            """
            # Extraction mode - get value by key
            if isinstance(key_or_n, str):
                value: object = None
                if isinstance(data_or_items, Mapping):
                    value = data_or_items.get(key_or_n, default)
                elif hasattr(data_or_items, key_or_n):
                    value = getattr(data_or_items, key_or_n, default)
                else:
                    value = default

                # Type guard
                if as_type is not None and value is not None:
                    if isinstance(value, as_type):
                        return value
                    return default
                # Type narrowing: value is object | None, return type is T | None
                # Runtime validation ensures correctness, type checker accepts object as compatible
                return value

            # Slice mode - take n items
            n = key_or_n
            if isinstance(data_or_items, dict):
                items = list(data_or_items.items())
                sliced = items[:n] if from_start else items[-n:]
                # Type narrowing: check if data_or_items is dict[str, T] vs Mapping[str, object]
                # For dict[str, T], values are already T; for Mapping[str, object], conversion needed
                # Runtime validation ensures correctness, type narrowing handles conversion
                result_dict: dict[str, T] = dict(sliced)
                return result_dict
            if isinstance(data_or_items, (list, tuple)):
                if from_start:
                    return list(data_or_items[:n])
                return list(data_or_items[-n:])
            return default

        # Mnemonic helper
        tk = take

        # try_ delegated to base class via FlextUtilities.try_()
        @classmethod
        def try_[T](
            cls,
            func: Callable[[], T],
            *,
            default: T | None = None,
            catch: type[Exception] | tuple[type[Exception], ...] = Exception,
        ) -> T | None:
            """Try using FlextUtilities.try_() (mnemonic: tr)."""
            # Use getattr to avoid mypy attr-defined error if method doesn't exist
            try_method = getattr(FlextUtilities, "try_", None)
            if try_method:
                # Type narrowing: result is object | None, return type is T | None
                # Runtime validation ensures correctness, type checker accepts object as compatible
                return try_method(func, default=default, catch=catch)
            # Fallback: manual try/except
            try:
                return func()
            except catch:
                return default

        tr = try_

        # or_ - use static method implementation below
        # oo alias defined after static method

        # let delegated to base class via u.chain()
        @classmethod
        def let(
            cls,
            value: object,
            *,
            fn: Callable[[object], object],
        ) -> object:
            """Let using chain() (mnemonic: lt)."""
            return FlextLdifUtilities.Ldif.chain(value, fn)

        lt = let

        @classmethod
        def apply(
            cls,
            fn: FlextLdifUtilities.Ldif.VariadicCallable[t.GeneralValueType] | object,
            *args: t.GeneralValueType,
            **kwargs: t.GeneralValueType,
        ) -> t.GeneralValueType:
            """Apply function (mnemonic: ap).

            Args:
                fn: Function to apply
                *args: Positional args
                **kwargs: Keyword args

            Returns:
                Function result

            Examples:
                >>> result = cls.ap(process_data, "arg1", option=True)

            """
            if callable(fn):
                fn_callable: FlextLdifUtilities.Ldif.VariadicCallable[
                    t.GeneralValueType
                ] = fn
                # Convert args and kwargs to compatible types for VariadicCallable
                converted_args: list[
                    str
                    | int
                    | float
                    | bool
                    | Sequence[str | int | float | bool | None]
                    | Mapping[str, str | int | float | bool | None]
                ] = []
                for arg in args:
                    if isinstance(arg, (str, int, float, bool)) or arg is None:
                        # Type narrowing: isinstance ensures compatible union type
                        scalar_val: (
                            str
                            | int
                            | float
                            | bool
                            | Sequence[str | int | float | bool | None]
                            | Mapping[str, str | int | float | bool | None]
                        ) = arg
                        converted_args.append(scalar_val)
                    elif isinstance(arg, Sequence):
                        # Type narrowing: isinstance ensures Sequence[str | int | float | bool | None]
                        converted_args.append(arg)
                    elif isinstance(arg, Mapping):
                        # Type narrowing: isinstance ensures Mapping[str, str | int | float | bool | None]
                        converted_args.append(arg)
                    else:
                        # Fallback: convert to string
                        converted_args.append(str(arg))
                # Convert kwargs similarly
                converted_kwargs: dict[
                    str,
                    str
                    | int
                    | float
                    | bool
                    | Sequence[str | int | float | bool | None]
                    | Mapping[str, str | int | float | bool | None],
                ] = {}
                for k, v in kwargs.items():
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        # Type narrowing: isinstance ensures compatible union type
                        scalar_kwarg_val: (
                            str
                            | int
                            | float
                            | bool
                            | Sequence[str | int | float | bool | None]
                            | Mapping[str, str | int | float | bool | None]
                        ) = v
                        converted_kwargs[k] = scalar_kwarg_val
                    elif isinstance(v, Sequence):
                        # Type narrowing: isinstance ensures Sequence[str | int | float | bool | None]
                        converted_kwargs[k] = v
                    elif isinstance(v, Mapping):
                        # Type narrowing: isinstance ensures Mapping[str, str | int | float | bool | None]
                        converted_kwargs[k] = v
                    else:
                        converted_kwargs[k] = str(v)
                return fn_callable(*converted_args, **converted_kwargs)
            return fn

        # Mnemonic helper
        ap = apply

        # bind delegated to base class via u.chain()
        @classmethod
        def bind(
            cls,
            value: object,
            *fns: Callable[[object], object],
        ) -> object:
            """Bind using chain() (mnemonic: bd)."""
            return FlextLdifUtilities.Ldif.chain(value, *fns)

        bd = bind

        @classmethod
        def lift(
            cls,
            fn: Callable[[object], object],
        ) -> Callable[[object], object | None]:
            """Lift function for optionals (mnemonic: lf).

            Args:
                fn: Function to lift

            Returns:
                Lifted function

            Examples:
                >>> safe_int = cls.lf(int)

            """

            # Use ternary operator + FlextLdifUtilities.maybe() DSL for safe None handling
            def lifted_fn(v: object) -> object | None:
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

        # Mnemonic helper
        lf = lift

        @classmethod
        def seq(
            cls,
            *values: object,
        ) -> list[object]:
            """Sequence constructor (mnemonic: sq).

            Args:
                *values: Values to sequence

            Returns:
                List of values

            Examples:
                >>> items = cls.sq(1, 2, 3)

            """
            # Use u.mapper().ensure() or direct list conversion for multiple values
            # values is a tuple from *values, convert to list
            return list(values)

        # Mnemonic helper
        sq = seq

        @classmethod
        def assoc(
            cls,
            data: dict[str, object],
            key: str,
            value: object,
        ) -> dict[str, object]:
            """Associate key-value using u.merge() DSL (mnemonic: ac).

            Args:
                data: Source dict
                key: Key to associate
                value: Value to associate

            Returns:
                New dict with association

            Examples:
                >>> updated = cls.ac({"a": 1}, "b", 2)

            """
            # Use u.merge() DSL for unified behavior with override strategy
            # Type narrowing: object is compatible with t.GeneralValueType (t.GeneralValueType includes object)
            # Create update dict directly without cast
            update_dict = {key: value}
            # Type narrowing: dict[str, object] values are compatible with t.GeneralValueType
            # Use data directly as it's compatible with Mapping[str, t.GeneralValueType]
            data_mapping = data
            # Use FlextUtilities.merge() for two-dict merge
            merge_result = FlextUtilities.merge(
                dict(data_mapping),
                dict(update_dict),
                strategy="override",
            )
            or_result = FlextLdifUtilities.Ldif.or_(
                merge_result.value
                if merge_result.is_success and isinstance(merge_result.value, dict)
                else None,
                default={**data, key: value},
            )
            # Type narrowing: or_() returns object | None, but default ensures dict[str, object]
            if isinstance(or_result, dict):
                return or_result
            return {**data, key: value}  # Fallback

        # Mnemonic helper
        ac = assoc

        @classmethod
        def dissoc(
            cls,
            data: dict[str, object],
            *keys: str,
        ) -> dict[str, object]:
            """Dissociate keys using omit DSL (mnemonic: ds).

            Args:
                data: Source dict
                *keys: Keys to remove

            Returns:
                New dict without keys

            Examples:
                >>> updated = cls.ds({"a": 1, "b": 2}, "b")

            """
            # Use omit() DSL pattern (reuse existing generalized function)
            return cls.om(data, *keys)

        # Mnemonic helper
        ds = dissoc

        @classmethod
        def update(
            cls,
            data: dict[str, object],
            updates: dict[str, object],
        ) -> dict[str, object]:
            """Update dict using u.merge() (mnemonic: ud).

            Args:
                data: Source dict
                updates: Updates to apply

            Returns:
                New dict with updates

            Examples:
                >>> updated = cls.ud({"a": 1}, {"b": 2})

            """
            # Use u.merge() for unified behavior
            # Type narrowing: dict[str, object] is compatible with Mapping[str, t.GeneralValueType]
            # t.GeneralValueType includes object, so no cast needed
            mappings: list[Mapping[str, flext_core_t.FlextTypes.GeneralValueType]] = [
                data,
                updates,
            ]
            # Use merge_dicts for variadic merge
            merge_result = FlextLdifUtilities.Ldif.merge_dicts(
                *tuple(mappings),
                strategy="override",
            )
            if merge_result.is_success and isinstance(merge_result.value, dict):
                # Convert t.GeneralValueType values to object
                merged_dict: dict[str, flext_core_t.FlextTypes.GeneralValueType] = (
                    merge_result.value
                )
                # Type narrowing: t.GeneralValueType includes object, so no cast needed
                return dict(merged_dict)
            return {**data, **updates}  # Fallback

        # Mnemonic helper
        ud = update

        @classmethod
        def evolve(
            cls,
            obj: dict[str, object],
            *transforms: dict[str, object]
            | Callable[[dict[str, object]], dict[str, object]],
        ) -> dict[str, object]:
            """Evolve using u.flow() pattern (mnemonic: ev).

            Args:
                obj: Source object
                *transforms: Dict updates or transform functions

            Returns:
                Evolved object

            Examples:
                >>> result = cls.ev({"a": 1}, {"b": 2}, lambda d: {**d, "c": 3})

            """
            # Convert transforms to compatible format for u.flow()
            flow_ops: list[t.ConfigurationDict | Callable[[object], object]] = []
            for transform in transforms:
                if callable(transform):
                    # Wrap dict transform function to accept object
                    def wrap_transform(
                        t: Callable[[dict[str, object]], dict[str, object]],
                    ) -> Callable[[object], object]:
                        # Type narrowing: isinstance ensures dict[str, object]
                        def wrapped(o: object) -> object:
                            if isinstance(o, dict):
                                return t(o)
                            return o

                        return wrapped

                    # Type narrowing: transform is Callable after check
                    flow_ops.append(wrap_transform(transform))
                elif isinstance(transform, dict):
                    # Type narrowing: isinstance ensures dict[str, object] compatible with ConfigurationDict
                    flow_ops.append(transform)
            flow_result = FlextUtilities.Reliability.flow(obj, *flow_ops)
            # Type narrowing: flow() returns object, but context ensures dict[str, object]
            if isinstance(flow_result, dict):
                return flow_result
            return {}  # Fallback

        # Mnemonic helper
        ev = evolve

        # keys - get dict keys directly
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

        # dict_vals - get dict values directly
        # Different from base FlextUtilities.vals which extracts values from FlextResult sequences
        @classmethod
        def dict_vals[T](
            cls,
            items: dict[str, T] | r[dict[str, T]],
            *,
            default: list[T] | None = None,
        ) -> list[T]:
            """Get values from dict (mnemonic: vl).

            Different from base vals() which extracts values from FlextResult sequences.
            This method extracts values from dicts or r[dict].
            """
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
            obj: dict[str, object],
        ) -> dict[object, str]:
            """Invert dict using u.map_dict() pattern (mnemonic: iv).

            Args:
                obj: Dict to invert

            Returns:
                Inverted dict

            Examples:
                >>> inverted = cls.iv({"a": 1, "b": 2})

            """
            if isinstance(obj, dict):
                # Use flext-core mapper for consistent behavior
                return FlextUtilities.mapper().invert_dict(obj)
            return {}

        # Mnemonic helper
        iv = invert

        @classmethod
        def where(
            cls,
            obj: dict[str, object],
            *,
            predicate: Callable[[str, object], bool] | None = None,
        ) -> dict[str, object]:
            """Where using u.filter() (mnemonic: wh).

            Args:
                obj: Dict to filter
                predicate: (k,v) -> bool

            Returns:
                Filtered dict

            Examples:
                >>> filtered = cls.wh({"a": 1, "b": 2}, predicate=lambda k, v: v > 1)

            """
            if not isinstance(obj, dict):
                return {}
            if predicate is None:
                return dict(obj)
            # Use dict comprehension for dict filtering with (key, value) predicate
            return {k: v for k, v in obj.items() if predicate(k, v)}

        # Mnemonic helper
        wh = where

        # find_key - use static method implementation below
        # fk alias defined after static method

        # find_val - use static method implementation below
        # fv alias defined after static method

        @classmethod
        def prop(
            cls,
            key: str,
        ) -> Callable[[object], object]:
            """Property accessor using u.get() (mnemonic: pp).

            Args:
                key: Property key

            Returns:
                Accessor function

            Examples:
                >>> get_name = cls.pp("name")

            """

            def getter(obj: object) -> object:
                """Get value from object by key."""
                if isinstance(obj, Mapping):
                    return obj.get(key)
                if hasattr(obj, key):
                    return getattr(obj, key)
                return None

            return getter

        # Mnemonic helper
        # Note: pp already defined for pipe, using prop_get for prop
        prop_get = prop

        @classmethod
        def props(
            cls,
            *keys: str,
        ) -> Callable[[object], dict[str, object]]:
            """Props accessor using u.pick() directly (mnemonic: ps).

            Args:
                *keys: Property keys

            Returns:
                Accessor function returning dict

            Examples:
                >>> get_fields = cls.ps("name", "age")

            """

            def accessor(obj: object) -> dict[str, object]:
                if isinstance(obj, (dict, Mapping)):
                    picked = cls.pick(obj, *keys, as_dict=True)
                    return picked if isinstance(picked, dict) else {}
                # For non-dict objects, try to get attributes
                result_dict: dict[str, object] = {}
                for k in keys:
                    if isinstance(obj, Mapping):
                        result_dict[k] = obj.get(k, None)
                    elif hasattr(obj, k):
                        result_dict[k] = getattr(obj, k, None)
                    else:
                        result_dict[k] = None
                return result_dict

            return accessor

        # Mnemonic helper
        ps = props

        @classmethod
        def path(
            cls,
            *keys: str,
        ) -> Callable[[object], object]:
            """Path accessor using u.chain() DSL (mnemonic: ph).

            Args:
                *keys: Path keys

            Returns:
                Path accessor function

            Examples:
                >>> get_nested = cls.ph("user", "profile", "name")

            """

            # Use FlextLdifUtilities.Ldif.chain() to compose get operations
            # Create properly typed single-argument lambdas using closure factory
            def make_getter(key: str) -> Callable[[object], object]:
                def getter_fn(obj: object) -> object:
                    """Get value from object by key."""
                    if isinstance(obj, Mapping):
                        return obj.get(key, None)
                    if hasattr(obj, key):
                        return getattr(obj, key, None)
                    return None

                return getter_fn

            getters: list[Callable[[object], object]] = [make_getter(k) for k in keys]
            return lambda obj: cls.chain(obj, *getters) if obj is not None else None

        # Mnemonic helper
        ph = path

        # === COLLECTION METHODS ===
        @staticmethod
        def sum(
            items: Sequence[int | float | object] | dict[str, int | float | object],
        ) -> int | float:
            """Sum of numeric items.

            Args:
                items: Sequence of numbers or dict with numeric values

            Returns:
                Sum of numeric values

            """
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
            return FlextLdifUtilities.Ldif.ConvBuilder(value)

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
            value: object | None,
            *,
            default: object | None = None,
            mapper: Callable[[object], object] | None = None,
        ) -> object:
            """Maybe monad pattern (mnemonic: mb)."""
            if value is None:
                return default
            if mapper:
                return mapper(value)
            return value

        mb = maybe

        @staticmethod
        def chain(value: object, *funcs: Callable[[object], object]) -> object:
            """Chain function calls (DSL helper, mnemonic: ch)."""
            result = value
            for func in funcs:
                result = func(result)
            return result

        ch = chain

        @staticmethod
        def pick(
            data: dict[str, object] | object,
            *keys: str,
            as_dict: bool = True,
        ) -> dict[str, object] | list[object]:
            """Pick keys from dict (DSL helper, mnemonic: pc)."""
            if not isinstance(data, dict):
                return {} if as_dict else []
            if as_dict:
                return {k: data[k] for k in keys if k in data}
            return [data[k] for k in keys if k in data]

        pc = pick

        @staticmethod
        def map_dict(
            obj: dict[str, object],
            *,
            mapper: Callable[[str, object], object] | None = None,
            key_mapper: Callable[[str], str] | None = None,
            predicate: Callable[[str, object], bool] | None = None,
        ) -> dict[str, object]:
            """Map dict with optional transformations (mnemonic: md)."""
            result: dict[str, object] = {}
            for k, v in obj.items():
                if predicate and not predicate(k, v):
                    continue
                new_k = key_mapper(k) if key_mapper else k
                new_v = mapper(k, v) if mapper else v
                result[new_k] = new_v
            return result

        md = map_dict

        @staticmethod
        def reduce_dict(
            items: Sequence[dict[str, object]] | dict[str, object] | object,
            *,
            processor: Callable[[str, object], tuple[str, object]] | None = None,
            predicate: Callable[[str, object], bool] | None = None,
            default: dict[str, object] | None = None,
        ) -> dict[str, object]:
            """Reduce dicts (mnemonic: rd)."""
            if not items:
                return default or {}

            items_list: list[dict[str, object]] = []
            if isinstance(items, dict):
                items_list = [items]
            elif isinstance(items, Sequence):
                items_list = [item for item in items if isinstance(item, dict)]

            result: dict[str, object] = default.copy() if default else {}
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
                    # skip: continue
            return result

        pf = process_flatten

        @staticmethod
        def build(value: object, *, ops: dict[str, object] | None = None) -> object:
            """Build value using operations dict (DSL helper)."""
            if ops is None:
                return value
            # Simple implementation - apply operations if needed
            return value

        @staticmethod
        def find_key(
            obj: dict[str, object],
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
            obj: dict[str, object],
            *,
            predicate: Callable[[str, object], bool] | None = None,
        ) -> object | None:
            """Find first value matching predicate (mnemonic: fv)."""
            if not predicate:
                return next(iter(obj.values()), None)
            for k, v in obj.items():
                if predicate(k, v):
                    return v
            return None

        fv = find_val

        # merge method removed - use merge_dicts() for variadic merge or FlextUtilities.merge() for two-dict merge
        # This avoids override incompatibility with base class merge(base, other, strategy) signature

        # Result DSL helpers - temporary until migrated to flext-core
        # result_val_opt differs from base result_val() which requires default: T (not T | None)
        # Use overload to support both T and T | None while maintaining compatibility
        @staticmethod
        @overload
        def result_val_opt[T](result: r[T], default: T) -> T: ...

        @staticmethod
        @overload
        def result_val_opt[T](result: r[T], default: None = None) -> T | None: ...

        @staticmethod
        def result_val_opt[T](result: r[T], default: T | None = None) -> T | None:
            """Extract value from FlextResult with optional default (DSL helper).

            Different from base result_val() which requires a non-None default.
            This method allows None as default for optional extraction.

            Args:
                result: FlextResult to unwrap
                default: Default value if result is failure (can be None)

            Returns:
                Result value if success, otherwise default

            Examples:
                >>> result = r.ok("value")
                >>> value = u.result_val_opt(result, default="default")  # "value"
                >>> failed = r.fail("error")
                >>> value = u.result_val_opt(failed, default="default")  # "default"

            """
            if result.is_success:
                return result.value
            return default

        # === Type Guards ===
        class TypeGuards(FlextLdifUtilitiesTypeGuards):
            """Type guards for Model identification.

            Safe type narrowing for SchemaAttribute and SchemaObjectClass
            Models without circular imports.

            Access via: u.TypeGuards.is_schema_attribute(obj)
            """

            # All methods inherited from FlextLdifUtilitiesTypeGuards


# NOTE: Dynamic assignments (FlextLdifUtilities.Ldif.Entry = ...) are FORBIDDEN per CLAUDE.md
# Root aliases are PROIBIDOS - always use u.* namespace completo
# Removed: FlextLdifUtilities.process
# Use: u.process

# Runtime alias for basic class (objetos nested sem aliases redundantes)
# Pattern: Classes básicas sempre com runtime alias, objetos nested sem aliases redundantes
u = FlextLdifUtilities

__all__ = [
    "FlextLdifUtilities",
    "u",
]
