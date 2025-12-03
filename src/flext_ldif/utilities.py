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

from collections.abc import Callable, Mapping, Sequence
from itertools import starmap
from typing import Literal

from flext_core import (
    FlextDecorators,
    FlextExceptions,
    FlextLogger,
    FlextResult,
    FlextService,
)
from flext_core.handlers import FlextHandlers
from flext_core.mixins import FlextMixins
from flext_core.utilities import FlextUtilities

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.builders import (
    FilterConfigBuilder,
    ProcessConfigBuilder,
    TransformConfigBuilder,
    WriteConfigBuilder,
)
from flext_ldif._utilities.configs import (
    AclConversionConfig,
    AttrNormalizationConfig,
    CaseFoldOption,
    DnNormalizationConfig,
    EscapeHandlingOption,
    FilterConfig,
    LoadConfig,
    MetadataConfig,
    OutputFormat,
    ProcessConfig,
    SchemaParseConfig,
    ServerType,
    SortOption,
    SpaceHandlingOption,
    TransformConfig,
    ValidationConfig,
    ValidationRuleSet,
    WriteConfig,
)
from flext_ldif._utilities.decorators import FlextLdifUtilitiesDecorators
from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
from flext_ldif._utilities.filters import (
    AndFilter,
    ByAttrsFilter,
    ByAttrValueFilter,
    ByDnFilter,
    ByDnUnderBaseFilter,
    ByObjectClassFilter,
    CustomFilter,
    EntryFilter,
    ExcludeAttrsFilter,
    Filter,
    IsSchemaEntryFilter,
    NotFilter,
    OrFilter,
)
from flext_ldif._utilities.fluent import DnOps, EntryOps
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers
from flext_ldif._utilities.pipeline import (
    Pipeline,
    PipelineStep,
    ProcessingPipeline,
    ValidationPipeline,
    ValidationResult,
)
from flext_ldif._utilities.power_protocols import (
    BatchTransformerProtocol,
    FailableTransformer,
    FilterPredicate,
    FilterProtocol,
    FluentBuilderProtocol,
    FluentOpsProtocol,
    LoadableProtocol,
    PipelineStepProtocol,
    SimpleTransformer,
    TransformerProtocol,
    ValidationReportProtocol,
    ValidationRuleProtocol,
    ValidatorProtocol,
    WritableProtocol,
)
from flext_ldif._utilities.result import FlextLdifResult
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif._utilities.transformers import (
    BooleanFormat,
    ConvertBooleansTransformer,
    CustomTransformer,
    EntryTransformer,
    FilterAttrsTransformer,
    Normalize,
    NormalizeAttrsTransformer,
    NormalizeDnTransformer,
    RemoveAttrsTransformer,
    ReplaceBaseDnTransformer,
    Transform,
)
from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters
from flext_ldif.constants import FlextLdifConstants, FlextLdifUtilitiesConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.typings import FlextLdifTypes

# Aliases for simplified usage - after all imports
u = FlextUtilities  # Utilities (from flext-core)
t = FlextLdifTypes  # Types (from flext-ldif)
c = FlextLdifConstants  # Constants
m = FlextLdifModels  # Models
p = FlextLdifProtocols  # Protocols
r = FlextResult  # Result
e = FlextExceptions  # Exceptions
d = FlextDecorators  # Decorators
s = FlextService  # Service
x = FlextMixins  # Mixins
h = FlextHandlers  # Handlers

logger = FlextLogger(__name__)


class FlextLdifUtilities(FlextUtilities):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations.

    Extends flext-core utility functions building on
    flext-core, following SOLID and DRY principles.

    Business Rules:
    ───────────────
    1. All utility methods MUST be static (no instance state)
    2. All operations MUST return FlextResult[T] for error handling
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
        - Validation, Generators, TextProcessor, TypeGuards
        - Reliability, TypeChecker, Configuration, Context
        - DataMapper, Domain, Pagination, StringParser

    Usage:
        from flext_ldif.utilities import FlextLdifUtilities

        # LDIF-specific access
        FlextLdifUtilities.DN.parse("cn=test,dc=example,dc=com")
        FlextLdifUtilities.Entry.has_objectclass(entry, "person")

        # Power methods
        result = FlextLdifUtilities.process(entries, source_server="oid")
        result = FlextLdifUtilities.transform(entries, Normalize.dn())
        result = FlextLdifUtilities.filter(entries, Filter.by_objectclass("person"))

        # unce
        result = FlextLdifUtilities.Validation.is_valid_email("test@example.com")
    """

    # === Existing submodule references (preserved) ===
    ACL = FlextLdifUtilitiesACL
    Attribute = FlextLdifUtilitiesAttribute
    Constants = FlextLdifUtilitiesConstants
    Decorators = FlextLdifUtilitiesDecorators
    Detection = FlextLdifUtilitiesDetection
    DN = FlextLdifUtilitiesDN
    Entry = FlextLdifUtilitiesEntry
    Events = FlextLdifUtilitiesEvents
    Metadata = FlextLdifUtilitiesMetadata
    ObjectClass = FlextLdifUtilitiesObjectClass
    OID = FlextLdifUtilitiesOID
    Parser = FlextLdifUtilitiesParser
    Parsers = FlextLdifUtilitiesParsers
    Schema = FlextLdifUtilitiesSchema
    Server = FlextLdifUtilitiesServer
    Validation = FlextLdifUtilitiesValidation
    Writer = FlextLdifUtilitiesWriter
    Writers = FlextLdifUtilitiesWriters

    # === Power Methods (new) ===

    @classmethod
    def process(
        cls,
        entries: Sequence[FlextLdifModelsDomains.Entry],
        *,
        config: ProcessConfig | None = None,
        source_server: ServerType = "auto",
        target_server: ServerType | None = None,
        normalize_dns: bool = True,
        normalize_attrs: bool = True,
    ) -> FlextLdifResult[list[FlextLdifModelsDomains.Entry]]:
        """Universal entry processor.

        Processes entries with DN normalization, attribute normalization,
        and optional server-specific transformations.

        Args:
            entries: Entries to process
            config: ProcessConfig for detailed configuration
            source_server: Source server type (or "auto" for detection)
            target_server: Target server type (optional)
            normalize_dns: Enable DN normalization
            normalize_attrs: Enable attribute normalization

        Returns:
            FlextLdifResult containing processed entries

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
        # Use provided config or build from parameters
        if config is None:
            config = ProcessConfig(
                source_server=source_server,
                target_server=target_server,
                normalize_dns=normalize_dns,
                normalize_attrs=normalize_attrs,
            )

        pipeline = ProcessingPipeline(config)
        return FlextLdifResult.from_result(pipeline.execute(list(entries)))

    @classmethod
    def transform(
        cls,
        entries: Sequence[FlextLdifModelsDomains.Entry],
        *transformers: EntryTransformer[FlextLdifModelsDomains.Entry],
        fail_fast: bool = True,
    ) -> FlextLdifResult[list[FlextLdifModelsDomains.Entry]]:
        """Apply transformation pipeline to entries.

        Args:
            entries: Entries to transform
            *transformers: Transformers to apply in sequence
            fail_fast: Stop on first error

        Returns:
            FlextLdifResult containing transformed entries

        Examples:
            >>> result = FlextLdifUtilities.transform(
            ...     entries,
            ...     Normalize.dn(case="lower"),
            ...     Transform.replace_base("dc=old", "dc=new"),
            ...     Transform.filter_attrs(exclude=["userPassword"]),
            ... )

        """
        pipeline = Pipeline(fail_fast=fail_fast)
        for transformer in transformers:
            pipeline.add(transformer)

        return FlextLdifResult.from_result(pipeline.execute(list(entries)))

    @classmethod
    def filter(
        cls,
        entries: Sequence[FlextLdifModelsDomains.Entry],
        *filters: EntryFilter[FlextLdifModelsDomains.Entry],
        mode: Literal["all", "any"] = "all",
    ) -> FlextLdifResult[list[FlextLdifModelsDomains.Entry]]:
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
        if not filters:
            return FlextLdifResult.ok(list(entries))

        # Combine filters based on mode
        combined: EntryFilter[FlextLdifModelsDomains.Entry] = filters[0]
        for f in filters[1:]:
            combined = combined & f if mode == "all" else combined | f

        filtered = [entry for entry in entries if combined.matches(entry)]
        return FlextLdifResult.ok(filtered)

    @classmethod
    def validate(
        cls,
        entries: Sequence[FlextLdifModelsDomains.Entry],
        *,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> FlextLdifResult[list[ValidationResult]]:
        """Validate entries against rules.

        Args:
            entries: Entries to validate
            strict: Use strict RFC validation
            collect_all: Collect all errors vs fail on first
            max_errors: Maximum errors to collect (0 = unlimited)

        Returns:
            FlextLdifResult containing list of ValidationResults

        Examples:
            >>> result = FlextLdifUtilities.validate(entries, strict=True)
            >>> for validation in result.unwrap():
            ...     if not validation.is_valid:
            ...         print(validation.errors)

        """
        pipeline = ValidationPipeline(
            strict=strict,
            collect_all=collect_all,
            max_errors=max_errors,
        )
        return FlextLdifResult.from_result(pipeline.validate(list(entries)))

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
    def entry(cls, entry: FlextLdifModelsDomains.Entry) -> EntryOps:
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

    @classmethod
    def map_filter(
        cls,
        items: Sequence[object] | object,
        *,
        mapper: object | None = None,
        predicate: object | None = None,
    ) -> list[object]:
        """Map then filter items in a single operation (DSL pattern).

        Combines map and filter operations for cleaner code.
        Automatically handles type conversions and empty results.

        Args:
            items: Items to process (list, tuple, or single item)
            mapper: Transformation function (default: identity)
            predicate: Filter function (default: bool)

        Returns:
            Processed list of items

        Examples:
            >>> # Split, strip, and filter empty strings
            >>> perms = FlextLdifUtilities.map_filter(
            ...     "read,write,add".split(","),
            ...     mapper=str.strip,
            ...     predicate=bool,
            ... )
            >>> # Process with custom mapper and filter
            >>> results = FlextLdifUtilities.map_filter(
            ...     raw_data,
            ...     mapper=lambda x: x.strip().lower(),
            ...     predicate=lambda x: len(x) > 0,
            ... )

        """
        if not items:
            return []
        items_list = list(items) if isinstance(items, (list, tuple, Sequence)) else [items]

        mapped_result = u.map(items_list, mapper=mapper) if mapper else items_list
        mapped_list = (
            list(mapped_result)
            if isinstance(mapped_result, (list, tuple, Sequence))
            else [mapped_result]
        )

        filtered_result = u.filter(mapped_list, predicate=predicate) if predicate else mapped_list
        return (
            list(filtered_result)
            if isinstance(filtered_result, (list, tuple, Sequence))
            else [filtered_result]
        )

    @classmethod
    def process_flatten(
        cls,
        items: Sequence[object] | object,
        *,
        processor: object | None = None,
        on_error: Literal["skip", "fail", "return"] = "skip",
    ) -> list[object]:
        """Process items and flatten nested results (DSL pattern).

        Combines process and flatten operations for cleaner code.
        Handles nested lists/tuples automatically.

        Args:
            items: Items to process
            processor: Processing function (default: identity)
            on_error: Error handling strategy (default: "skip")

        Returns:
            Flattened list of processed items

        Examples:
            >>> # Process and flatten nested results
            >>> rules = FlextLdifUtilities.process_flatten(
            ...     pattern_items,
            ...     processor=lambda item: extract_rules(item),
            ...     on_error="skip",
            ... )
            >>> # Flatten nested lists
            >>> flat = FlextLdifUtilities.process_flatten(
            ...     [[1, 2], [3, 4], [5]],
            ... )

        """
        if not items:
            return []
        items_list = list(items) if isinstance(items, (list, tuple, Sequence)) else [items]

        if processor:
            process_result = u.process(items_list, processor=processor, on_error=on_error)
            if process_result.is_failure:
                return []
            processed = process_result.value
        else:
            processed = items_list

        if not isinstance(processed, (list, tuple, Sequence)):
            return [processed]

        flattened: list[object] = []
        for item in processed:
            if isinstance(item, (list, tuple, Sequence)):
                flattened.extend(item)
            else:
                flattened.append(item)

        return flattened

    @classmethod
    def normalize_list(
        cls,
        value: object,
        *,
        mapper: object | None = None,
        predicate: object | None = None,
        default: list[object] | None = None,
    ) -> list[object]:
        """Normalize value to list with optional map/filter (DSL pattern).

        Intelligently converts various types to list with optional transformations.
        Handles None, single items, sequences, and Result types.

        Args:
            value: Value to normalize
            mapper: Optional transformation function
            predicate: Optional filter function
            default: Default value if conversion fails (default: [])

        Returns:
            Normalized list

        Examples:
            >>> # Normalize with map and filter
            >>> perms = FlextLdifUtilities.normalize_list(
            ...     raw_perms,
            ...     mapper=str.strip,
            ...     predicate=bool,
            ... )
            >>> # Normalize Result type
            >>> items = FlextLdifUtilities.normalize_list(
            ...     result.value,
            ...     default=[],
            ... )

        """
        if value is None:
            return default or []

        if isinstance(value, FlextResult):
            if value.is_failure:
                return default or []
            value = value.value

        if isinstance(value, (list, tuple, Sequence)):
            items_list = list(value)
        else:
            items_list = [value]

        if mapper:
            mapped_result = u.map(items_list, mapper=mapper)
            items_list = (
                list(mapped_result)
                if isinstance(mapped_result, (list, tuple, Sequence))
                else [mapped_result]
            )

        if predicate:
            filtered_result = u.filter(items_list, predicate=predicate)
            items_list = (
                list(filtered_result)
                if isinstance(filtered_result, (list, tuple, Sequence))
                else [filtered_result]
            )

        return items_list

    @classmethod
    def reduce_dict(
        cls,
        items: Sequence[dict[str, object]] | dict[str, object] | object,
        *,
        processor: object | None = None,
        predicate: object | None = None,
        default: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Reduce list of dicts into single dict (DSL pattern).

        Combines multiple dicts into one, optionally processing/filtering entries.
        Handles empty inputs, single dicts, and nested structures.

        Args:
            items: Dicts to merge (list of dicts, single dict, or nested structure)
            processor: Optional function to transform (key, value) pairs
            predicate: Optional function to filter (key, value) pairs
            default: Default dict if reduction fails (default: {})

        Returns:
            Merged dict with all entries

        Examples:
            >>> # Merge multiple dicts
            >>> result = FlextLdifUtilities.reduce_dict(
            ...     [{"a": 1}, {"b": 2}, {"c": 3}],
            ... )
            >>> # Process and merge
            >>> result = FlextLdifUtilities.reduce_dict(
            ...     dict_list,
            ...     processor=lambda k, v: (k.upper(), v * 2),
            ...     predicate=lambda k, v: v > 0,
            ... )

        """
        if not items:
            return default or {}

        items_list = cls.normalize_list(items, default=[])

        result: dict[str, object] = {}
        for item in items_list:
            if not isinstance(item, dict):
                continue

            if processor:
                process_result = u.process(
                    item,
                    processor=processor,  # type: ignore[arg-type]
                    predicate=predicate,  # type: ignore[arg-type]
                    on_error="skip",
                )
                if process_result.is_success and isinstance(process_result.value, dict):
                    result.update(process_result.value)
            elif predicate:
                filtered = u.filter(
                    item,
                    predicate=predicate,  # type: ignore[arg-type]
                )
                if isinstance(filtered, dict):
                    result.update(filtered)
            else:
                result.update(item)

        return result

    @classmethod
    def chain(
        cls,
        value: object,
        *,
        ops: list[dict[str, object]] | None = None,
        on_error: Literal["skip", "fail", "return"] = "skip",
    ) -> object:
        """Chain multiple DSL operations sequentially (DSL pattern).

        Applies multiple operation dicts in sequence, each building on previous result.
        Enables complex transformation pipelines with clean syntax.

        Args:
            value: Initial value to process
            ops: List of operation dicts (each can have map, filter, normalize, etc.)
            on_error: Error handling strategy (default: "skip")

        Returns:
            Final processed value

        Examples:
            >>> # Chain map_filter and reduce_dict
            >>> result = FlextLdifUtilities.chain(
            ...     raw_data,
            ...     ops=[
            ...         {"map": str.strip, "filter": bool},
            ...         {"normalize": "lower"},
            ...     ],
            ... )

        """
        if not ops:
            return value

        current = value
        for op in ops:
            if not isinstance(op, dict):
                continue

            try:
                # Apply map_filter if both map and filter present
                if "map" in op and "filter" in op:
                    current = cls.map_filter(
                        current,
                        mapper=op["map"],  # type: ignore[arg-type]
                        predicate=op["filter"],  # type: ignore[arg-type]
                    )
                # Apply normalize_list if normalize present
                elif "normalize" in op:
                    current = cls.normalize_list(
                        current,
                        mapper=op.get("map"),  # type: ignore[arg-type]
                        predicate=op.get("filter"),  # type: ignore[arg-type]
                        default=op.get("default"),  # type: ignore[arg-type]
                    )
                # Apply reduce_dict if reduce present
                elif "reduce" in op:
                    current = cls.reduce_dict(
                        current,
                        processor=op.get("processor"),  # type: ignore[arg-type]
                        predicate=op.get("predicate"),  # type: ignore[arg-type]
                        default=op.get("default"),  # type: ignore[arg-type]
                    )
                # Fallback to u.build for other operations
                else:
                    current = u.build(current, ops=op, on_error=on_error)

            except Exception:
                if on_error == "fail":
                    raise
                if on_error == "return":
                    return value
                # on_error == "skip": continue

        return current

    @classmethod
    def when(
        cls,
        *,
        condition: bool,
        then: object | None = None,
        else_: object | None = None,
    ) -> object:
        """Functional conditional (DSL pattern).

        Returns then value if condition is True, else_ value otherwise.
        Enables functional-style conditionals without if/else blocks.

        Args:
            condition: Boolean condition
            then: Value to return if condition is True
            else_: Value to return if condition is False

        Returns:
            then or else_ value

        Examples:
            >>> # Conditional value selection
            >>> result = FlextLdifUtilities.when(
            ...     len(items) > 0,
            ...     then=items[0],
            ...     else_=default_value,
            ... )

        """
        return then if condition else else_

    @classmethod
    def fold(
        cls,
        items: Sequence[object] | object,
        *,
        initial: object,
        folder: object | None = None,
        predicate: object | None = None,
    ) -> object:
        """Fold/reduce items with accumulator (DSL pattern).

        Reduces items to single value using folder function and initial accumulator.
        Supports optional filtering before folding.

        Args:
            items: Items to fold
            initial: Initial accumulator value
            folder: Function (acc, item) -> new_acc
            predicate: Optional filter function

        Returns:
            Final accumulator value

        Examples:
            >>> # Sum with fold
            >>> total = FlextLdifUtilities.fold(
            ...     [1, 2, 3, 4],
            ...     initial=0,
            ...     folder=lambda acc, x: acc + x,
            ... )
            >>> # Merge dicts with fold
            >>> merged = FlextLdifUtilities.fold(
            ...     dict_list,
            ...     initial={},
            ...     folder=lambda acc, d: {**acc, **d} if isinstance(d, dict) else acc,
            ... )

        """
        if not items:
            return initial

        items_list = cls.normalize_list(items, default=[])

        if predicate:
            filtered_result = u.filter(items_list, predicate=predicate)  # type: ignore[arg-type]
            items_list = (
                list(filtered_result)
                if isinstance(filtered_result, (list, tuple, Sequence))
                else []
            )

        if not folder:
            return initial

        accumulator = initial
        for item in items_list:
            try:
                accumulator = folder(accumulator, item)  # type: ignore[operator, assignment]
            except Exception as e:
                logger.debug(f"Fold error on item {item}: {e}")
                continue

        return accumulator

    @classmethod
    def pipe(
        cls,
        value: object,
        *ops: object,
        on_error: Literal["skip", "fail", "return"] = "skip",
    ) -> object:
        """Pipe value through operations (DSL pattern).

        Functional pipe operator: value |> op1 |> op2 |> op3
        Each operation receives previous result.

        Args:
            value: Initial value
            *ops: Operations to apply (functions or operation dicts)
            on_error: Error handling (default: "skip")

        Returns:
            Final processed value

        Examples:
            >>> # Pipe through functions
            >>> result = FlextLdifUtilities.pipe(
            ...     raw_data,
            ...     lambda x: x.split(","),
            ...     lambda x: [s.strip() for s in x],
            ...     lambda x: [s for s in x if s],
            ... )
            >>> # Pipe with DSL operations
            >>> result = FlextLdifUtilities.pipe(
            ...     data,
            ...     {"map": str.strip},
            ...     {"filter": bool},
            ...     {"normalize": "list"},
            ... )

        """
        current = value
        for op in ops:
            try:
                if callable(op):
                    current = op(current)  # type: ignore[operator]
                elif isinstance(op, dict):
                    current = cls.chain(current, ops=[op], on_error=on_error)
                else:
                    current = op
            except Exception:
                if on_error == "fail":
                    raise
                if on_error == "return":
                    return value
        return current

    @classmethod
    def tap(
        cls,
        value: object,
        *,
        side_effect: object,
    ) -> object:
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
        if callable(side_effect):
            side_effect(value)  # type: ignore[operator]
        return value

    @classmethod
    def maybe(
        cls,
        value: object | None,
        *,
        default: object | None = None,
        mapper: object | None = None,
    ) -> object:
        """Maybe monad for optional values (DSL pattern).

        Returns default if value is None, otherwise applies mapper if provided.

        Args:
            value: Optional value
            default: Default if value is None
            mapper: Optional transformation function

        Returns:
            Processed value or default

        Examples:
            >>> # Safe access with default
            >>> result = FlextLdifUtilities.maybe(
            ...     config.get("key"),
            ...     default=[],
            ...     mapper=lambda x: x.split(","),
            ... )

        """
        if value is None:
            return default
        if mapper and callable(mapper):
            return mapper(value)  # type: ignore[operator]
        return value

    @classmethod
    def zip_with(
        cls,
        *sequences: Sequence[object],
        combiner: object | None = None,
    ) -> list[object]:
        """Zip sequences with combiner function (DSL pattern).

        Zips multiple sequences and applies combiner to each tuple.
        Default combiner returns tuple.

        Args:
            *sequences: Sequences to zip
            combiner: Function to combine tuples (default: tuple)

        Returns:
            List of combined results

        Examples:
            >>> # Zip with custom combiner
            >>> result = FlextLdifUtilities.zip_with(
            ...     [1, 2, 3],
            ...     ["a", "b", "c"],
            ...     combiner=lambda x, y: f"{x}:{y}",
            ... )

        """
        if not sequences:
            return []
        if len(sequences) == 1:
            return list(sequences[0])

        zipped = zip(*sequences, strict=False)
        if combiner and callable(combiner):
            return list(starmap(combiner, zipped))  # type: ignore[operator]
        return [tuple(items) for items in zipped]

    @classmethod
    def group_by(
        cls,
        items: Sequence[object],
        *,
        key: object,
    ) -> dict[object, list[object]]:
        """Group items by key function (DSL pattern).

        Groups items into dict where keys are from key function.

        Args:
            items: Items to group
            key: Function to extract key from item

        Returns:
            Dict mapping keys to lists of items

        Examples:
            >>> # Group by first letter
            >>> result = FlextLdifUtilities.group_by(
            ...     ["apple", "banana", "apricot"],
            ...     key=lambda x: x[0],
            ... )

        """
        if not items:
            return {}
        if not callable(key):
            return {}

        grouped: dict[object, list[object]] = {}
        for item in items:
            k = key(item)  # type: ignore[operator]
            if k not in grouped:
                grouped[k] = []
            grouped[k].append(item)
        return grouped

    @classmethod
    def partition(
        cls,
        items: Sequence[object],
        *,
        predicate: object,
    ) -> tuple[list[object], list[object]]:
        """Partition items by predicate (DSL pattern).

        Splits items into (true_items, false_items) based on predicate.

        Args:
            items: Items to partition
            predicate: Function to test items

        Returns:
            Tuple of (matching_items, non_matching_items)

        Examples:
            >>> # Partition by condition
            >>> evens, odds = FlextLdifUtilities.partition(
            ...     [1, 2, 3, 4, 5],
            ...     predicate=lambda x: x % 2 == 0,
            ... )

        """
        if not items:
            return ([], [])
        if not callable(predicate):
            return (list(items), [])

        true_items: list[object] = []
        false_items: list[object] = []
        for item in items:
            if predicate(item):  # type: ignore[operator]
                true_items.append(item)
            else:
                false_items.append(item)
        return (true_items, false_items)

    @classmethod
    def get(
        cls,
        obj: object,
        key: str | int,
        *,
        default: object | None = None,
        mapper: object | None = None,
    ) -> object:
        """Safe get with optional mapping (DSL pattern).

        Gets value from dict/list with default and optional transformation.
        Uses maybe() internally for consistent None handling.

        Args:
            obj: Object to get from (dict, list, etc.)
            key: Key/index to get
            default: Default if not found
            mapper: Optional transformation function

        Returns:
            Value or default (optionally mapped)

        Examples:
            >>> # Safe dict access
            >>> value = FlextLdifUtilities.get(
            ...     config,
            ...     "key",
            ...     default=[],
            ...     mapper=lambda x: x.split(","),
            ... )

        """
        if isinstance(obj, dict):
            value = obj.get(key) if isinstance(key, str) else None
        elif isinstance(obj, (list, tuple)) and isinstance(key, int):
            value = obj[key] if 0 <= key < len(obj) else None
        else:
            value = None

        return cls.maybe(value, default=default, mapper=mapper)

    @classmethod
    def pluck(
        cls,
        items: Sequence[object],
        *,
        key: str | int | object,
    ) -> list[object]:
        """Pluck values from items (DSL pattern).

        Extracts values from list of dicts/objects by key.

        Args:
            items: Items to pluck from
            key: Key to extract (str for dicts, int for tuples, or function)

        Returns:
            List of extracted values

        Examples:
            >>> # Pluck from dicts
            >>> names = FlextLdifUtilities.pluck(
            ...     [{"name": "a"}, {"name": "b"}],
            ...     key="name",
            ... )
            >>> # Pluck with function
            >>> lengths = FlextLdifUtilities.pluck(
            ...     ["abc", "de", "f"],
            ...     key=len,
            ... )

        """
        if not items:
            return []

        if callable(key):
            return [key(item) for item in items]  # type: ignore[operator]

        result: list[object] = []
        for item in items:
            if isinstance(item, dict) and isinstance(key, str):
                result.append(item.get(key))
            elif isinstance(item, (list, tuple)) and isinstance(key, int):
                if 0 <= key < len(item):
                    result.append(item[key])
            else:
                result.append(None)

        return result

    @classmethod
    def pick(
        cls,
        obj: dict[str, object],
        *keys: str,
    ) -> dict[str, object]:
        """Pick keys from dict (DSL pattern).

        Creates new dict with only specified keys.

        Args:
            obj: Dict to pick from
            *keys: Keys to pick

        Returns:
            New dict with picked keys

        Examples:
            >>> # Pick specific keys
            >>> result = FlextLdifUtilities.pick(
            ...     {"a": 1, "b": 2, "c": 3},
            ...     "a",
            ...     "c",
            ... )

        """
        if not obj or not keys:
            return {}
        return {k: obj[k] for k in keys if k in obj}

    @classmethod
    def omit(
        cls,
        obj: dict[str, object],
        *keys: str,
    ) -> dict[str, object]:
        """Omit keys from dict (DSL pattern).

        Creates new dict without specified keys.

        Args:
            obj: Dict to omit from
            *keys: Keys to omit

        Returns:
            New dict without omitted keys

        Examples:
            >>> # Omit specific keys
            >>> result = FlextLdifUtilities.omit(
            ...     {"a": 1, "b": 2, "c": 3},
            ...     "b",
            ... )

        """
        if not obj:
            return {}
        if not keys:
            return dict(obj)
        return {k: v for k, v in obj.items() if k not in keys}

    @classmethod
    def merge(
        cls,
        *dicts: dict[str, object] | None,
        combiner: object | None = None,
    ) -> dict[str, object]:
        """Merge multiple dicts with optional combiner (DSL pattern).

        Combines dicts, optionally using combiner for conflicts.

        Args:
            *dicts: Dicts to merge
            combiner: Function (key, val1, val2) -> merged_value

        Returns:
            Merged dict

        Examples:
            >>> # Simple merge
            >>> result = FlextLdifUtilities.merge(
            ...     {"a": 1}, {"b": 2}, {"c": 3},
            ... )
            >>> # Merge with combiner
            >>> result = FlextLdifUtilities.merge(
            ...     {"a": 1}, {"a": 2},
            ...     combiner=lambda k, v1, v2: v1 + v2,
            ... )

        """
        if not dicts:
            return {}
        result: dict[str, object] = {}
        for d in dicts:
            if not isinstance(d, dict):
                continue
            for k, v in d.items():
                if k in result and combiner and callable(combiner):
                    result[k] = combiner(k, result[k], v)  # type: ignore[operator]
                else:
                    result[k] = v
        return result

    @classmethod
    def map_dict(
        cls,
        obj: dict[str, object],
        *,
        mapper: object | None = None,
        key_mapper: object | None = None,
        predicate: object | None = None,
    ) -> dict[str, object]:
        """Map dict keys/values with optional filter (DSL pattern).

        Transforms dict keys/values and optionally filters entries.

        Args:
            obj: Dict to map
            mapper: Function (key, value) -> new_value
            key_mapper: Function (key) -> new_key
            predicate: Function (key, value) -> bool

        Returns:
            Mapped dict

        Examples:
            >>> # Map values
            >>> result = FlextLdifUtilities.map_dict(
            ...     {"a": 1, "b": 2},
            ...     mapper=lambda k, v: v * 2,
            ... )
            >>> # Map keys and values
            >>> result = FlextLdifUtilities.map_dict(
            ...     {"a": 1},
            ...     key_mapper=str.upper,
            ...     mapper=lambda k, v: v * 2,
            ... )

        """
        if not isinstance(obj, dict):
            return {}
        result: dict[str, object] = {}
        for k, v in obj.items():
            if predicate and not predicate(k, v):  # type: ignore[operator]
                continue
            new_key = key_mapper(k) if key_mapper and callable(key_mapper) else k  # type: ignore[operator]
            new_value = mapper(k, v) if mapper and callable(mapper) else v  # type: ignore[operator]
            result[new_key] = new_value
        return result

    @classmethod
    def smart_convert(
        cls,
        value: object,
        *,
        target_type: str,
        predicate: object | None = None,
        default: object | None = None,
    ) -> object:
        """Smart type conversion with validation (DSL pattern).

        Converts value to target_type with optional predicate filtering.
        Handles None, Result types, and type validation.

        Args:
            value: Value to convert
            target_type: Target type ("list", "dict", "str", etc.)
            predicate: Optional filter function
            default: Default value if conversion fails

        Returns:
            Converted value or default

        Examples:
            >>> # Convert to list with predicate
            >>> result = FlextLdifUtilities.smart_convert(
            ...     raw_data,
            ...     target_type="list",
            ...     predicate=lambda x: isinstance(x, dict),
            ...     default=[],
            ... )

        """
        # Extract value from Result if needed
        extracted = cls.maybe(
            value,
            default=default,
            mapper=lambda v: v.value if isinstance(v, FlextResult) and not v.is_failure else default,
        )
        if extracted is None:
            return default

        # Convert based on target_type
        converters: dict[str, Callable[[object], object]] = {
            "list": lambda v: cls.map_filter(
                cls.normalize_list(v, default=default or []),
                predicate=predicate,
            ) if predicate else cls.normalize_list(v, default=default or []),
            "dict": lambda v: (
                u.filter(v, predicate=predicate)  # type: ignore[arg-type]
                if predicate and isinstance(v, dict)
                else (v if isinstance(v, dict) else (default or {}))
            ),
        }

        converter = converters.get(target_type)
        return converter(extracted) if converter else (extracted if extracted is not None else default)

    @classmethod
    def is_type(
        cls,
        value: object,
        *types: type | str,
    ) -> bool:
        """Type check helper (DSL pattern).

        Checks if value is instance of any type.

        Args:
            value: Value to check
            *types: Types to check against

        Returns:
            True if value matches any type

        Examples:
            >>> # Check multiple types
            >>> if FlextLdifUtilities.is_type(value, dict, list):
            ...     process(value)

        """
        if not types:
            return False
        type_map = {
            "list": list,
            "dict": dict,
            "str": str,
            "int": int,
            "bool": bool,
            "tuple": tuple,
        }
        resolved_types = [type_map.get(t, t) if isinstance(t, str) else t for t in types]
        return any(isinstance(value, t) for t in resolved_types)

    @classmethod
    def as_type(
        cls,
        value: object,
        *,
        target: type | str,
        default: object | None = None,
    ) -> object:
        """Safe type cast (DSL pattern).

        Casts value to target type if possible, returns default otherwise.

        Args:
            value: Value to cast
            target: Target type or type name
            default: Default if cast fails

        Returns:
            Casted value or default

        Examples:
            >>> # Safe cast to list
            >>> items = FlextLdifUtilities.as_type(
            ...     value,
            ...     target="list",
            ...     default=[],
            ... )

        """
        if value is None:
            return default

        type_map: dict[str, type] = {
            "list": list,
            "dict": dict,
            "str": str,
            "int": int,
            "bool": bool,
            "tuple": tuple,
        }
        resolved_type = type_map.get(target, target) if isinstance(target, str) else target

        if not isinstance(resolved_type, type):
            return default

        if isinstance(value, resolved_type):
            return value
        if resolved_type is list and isinstance(value, (tuple, Sequence)):
            return list(value)
        if resolved_type is dict and isinstance(value, (dict, Mapping)):
            return dict(value)
        if resolved_type is str:
            return str(value)
        if resolved_type is int:
            try:
                return int(value)  # type: ignore[arg-type]
            except (ValueError, TypeError):
                return default
        if resolved_type is bool:
            return bool(value)

        return default

    @classmethod
    def guard(
        cls,
        value: object,
        *,
        check: object,
        default: object | None = None,
    ) -> object:
        """Guard clause helper (DSL pattern).

        Returns value if check passes, default otherwise.

        Args:
            value: Value to guard
            check: Function or predicate to check
            default: Default if check fails

        Returns:
            Value or default

        Examples:
            >>> # Guard with predicate
            >>> result = FlextLdifUtilities.guard(
            ...     data,
            ...     check=lambda x: len(x) > 0,
            ...     default=[],
            ... )

        """
        if callable(check):
            return value if check(value) else default  # type: ignore[operator]
        return value if check else default

    @classmethod
    def thru(
        cls,
        value: object,
        *,
        fn: object,
    ) -> object:
        """Thru operator - pass value through function (DSL pattern).

        Applies function and returns result. Alias for function call.

        Args:
            value: Value to pass through
            fn: Function to apply

        Returns:
            Function result

        Examples:
            >>> # Apply function
            >>> result = FlextLdifUtilities.thru(
            ...     data,
            ...     fn=lambda x: x.split(","),
            ... )

        """
        return fn(value) if callable(fn) else value  # type: ignore[operator]

    @classmethod
    def comp(
        cls,
        *fns: object,
    ) -> object:
        """Function composition (DSL pattern).

        Composes multiple functions into one.

        Args:
            *fns: Functions to compose

        Returns:
            Composed function

        Examples:
            >>> # Compose functions
            >>> fn = FlextLdifUtilities.comp(
            ...     lambda x: x.split(","),
            ...     lambda x: [s.strip() for s in x],
            ...     lambda x: [s for s in x if s],
            ... )
            >>> result = fn("a, b, c")

        """
        if not fns:
            return lambda x: x

        def composed(value: object) -> object:
            result = value
            for fn in reversed(fns):
                if callable(fn):
                    result = fn(result)  # type: ignore[operator]
            return result

        return composed

    @classmethod
    def juxt(
        cls,
        *fns: object,
    ) -> object:
        """Juxtapose - apply multiple functions to same value (DSL pattern).

        Returns tuple of results from each function.

        Args:
            *fns: Functions to apply

        Returns:
            Function that returns tuple of results

        Examples:
            >>> # Apply multiple functions
            >>> fn = FlextLdifUtilities.juxt(
            ...     len,
            ...     lambda x: x.upper(),
            ...     lambda x: x.lower(),
            ... )
            >>> length, upper, lower = fn("Hello")

        """
        if not fns:
            return lambda x: ()

        def juxtaposed(value: object) -> tuple[object, ...]:
            return tuple(fn(value) if callable(fn) else fn for fn in fns)  # type: ignore[operator]

        return juxtaposed

    @classmethod
    def curry(
        cls,
        fn: object,
        *args: object,
    ) -> object:
        """Curry function (DSL pattern).

        Partially applies arguments to function.

        Args:
            fn: Function to curry
            *args: Arguments to apply

        Returns:
            Curried function

        Examples:
            >>> # Curry function
            >>> add = lambda x, y: x + y
            >>> add5 = FlextLdifUtilities.curry(add, 5)
            >>> result = add5(3)  # 8

        """
        if not callable(fn):
            return fn

        def curried(*more_args: object) -> object:
            return fn(*(args + more_args))  # type: ignore[operator]

        return curried

    @classmethod
    def cond(
        cls,
        *pairs: tuple[object, object],
        default: object | None = None,
    ) -> object:
        """Conditional (cond pattern from Clojure).

        Evaluates predicates in order, returns first matching value.

        Args:
            *pairs: (predicate, value) tuples
            default: Default value if no predicate matches

        Returns:
            Function that returns matching value

        Examples:
            >>> # Conditional logic
            >>> fn = FlextLdifUtilities.cond(
            ...     (lambda x: x > 10, "big"),
            ...     (lambda x: x > 5, "medium"),
            ...     (lambda x: True, "small"),
            ... )
            >>> result = fn(7)  # "medium"

        """
        def conditional(value: object) -> object:
            for predicate, result_value in pairs:
                if callable(predicate) and predicate(value):  # type: ignore[operator]
                    return result_value if not callable(result_value) else result_value(value)  # type: ignore[operator]
                if predicate:
                    return result_value if not callable(result_value) else result_value(value)  # type: ignore[operator]
            return default if not callable(default) else default(value)  # type: ignore[operator]

        return conditional

    @classmethod
    def match(
        cls,
        value: object,
        *cases: tuple[object, object],
        default: object | None = None,
    ) -> object:
        """Pattern matching (DSL pattern).

        Matches value against cases, returns first match.
        Supports type matching, value matching, and callable predicates.

        Args:
            value: Value to match
            *cases: (pattern, result) tuples
                - pattern can be: type, value, or callable predicate
                - result can be: value or callable function
            default: Default if no match

        Returns:
            Matching result

        Examples:
            >>> # Pattern matching by type
            >>> result = FlextLdifUtilities.match(
            ...     "REDACTED_LDAP_BIND_PASSWORD",
            ...     (str, lambda s: s.upper()),
            ...     (int, lambda i: i * 2),
            ...     default="unknown",
            ... )
            >>> # Pattern matching by value
            >>> result = FlextLdifUtilities.match(
            ...     "REDACTED_LDAP_BIND_PASSWORD",
            ...     ("REDACTED_LDAP_BIND_PASSWORD", "Administrator"),
            ...     ("user", "User"),
            ...     default="Guest",
            ... )

        """
        for pattern, result in cases:
            # Type matching
            if isinstance(pattern, type) and isinstance(value, pattern):
                return result(value) if callable(result) else result  # type: ignore[operator]
            # Value matching
            if pattern == value:
                return result(value) if callable(result) else result  # type: ignore[operator]
            # Callable predicate matching
            if callable(pattern) and pattern(value):  # type: ignore[operator]
                return result(value) if callable(result) else result  # type: ignore[operator]
        return default(value) if callable(default) else default  # type: ignore[operator]

    @classmethod
    def switch(
        cls,
        value: object,
        cases: dict[object, object],
        default: object | None = None,
    ) -> object:
        """Switch statement (DSL pattern).

        Matches value against dict keys, returns value.

        Args:
            value: Value to switch on
            cases: Dict mapping cases to results
            default: Default if no match

        Returns:
            Matching result

        Examples:
            >>> # Switch statement
            >>> result = FlextLdifUtilities.switch(
            ...     "a",
            ...     {"a": 1, "b": 2, "c": 3},
            ...     default=0,
            ... )

        """
        result = cases.get(value, default)
        return result if not callable(result) else result(value)  # type: ignore[operator]

    @classmethod
    def defaults(
        cls,
        *dicts: dict[str, object] | None,
    ) -> dict[str, object]:
        """Defaults - merge dicts with first value winning (DSL pattern).

        Merges dicts, keeping first non-None value for each key.

        Args:
            *dicts: Dicts to merge (later dicts provide defaults)

        Returns:
            Merged dict

        Examples:
            >>> # Merge with defaults
            >>> result = FlextLdifUtilities.defaults(
            ...     {"a": 1, "b": 2},
            ...     {"b": 3, "c": 4},
            ... )
            >>> # {"a": 1, "b": 2, "c": 4}

        """
        if not dicts:
            return {}
        result: dict[str, object] = {}
        for d in reversed(dicts):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k not in result or result[k] is None:
                        result[k] = v
        return result

    @classmethod
    def deep_merge(
        cls,
        *dicts: dict[str, object] | None,
    ) -> dict[str, object]:
        """Deep merge dicts (DSL pattern).

        Recursively merges nested dicts.

        Args:
            *dicts: Dicts to merge

        Returns:
            Deeply merged dict

        Examples:
            >>> # Deep merge
            >>> result = FlextLdifUtilities.deep_merge(
            ...     {"a": {"b": 1}},
            ...     {"a": {"c": 2}},
            ... )
            >>> # {"a": {"b": 1, "c": 2}}

        """
        if not dicts:
            return {}
        result: dict[str, object] = {}
        for d in dicts:
            if not isinstance(d, dict):
                continue
            for k, v in d.items():
                if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                    result[k] = cls.deep_merge(result[k], v)  # type: ignore[arg-type]
                else:
                    result[k] = v
        return result

    @classmethod
    def update(
        cls,
        obj: dict[str, object],
        *updates: dict[str, object] | None,
    ) -> dict[str, object]:
        """Update dict in place (DSL pattern).

        Updates obj with values from updates dicts.

        Args:
            obj: Dict to update
            *updates: Dicts with updates

        Returns:
            Updated dict (same reference)

        Examples:
            >>> # Update dict
            >>> d = {"a": 1}
            >>> FlextLdifUtilities.update(d, {"b": 2}, {"c": 3})
            >>> # d is now {"a": 1, "b": 2, "c": 3}

        """
        for update_dict in updates:
            if isinstance(update_dict, dict):
                obj.update(update_dict)
        return obj

    @classmethod
    def defaults_deep(
        cls,
        *dicts: dict[str, object] | None,
    ) -> dict[str, object]:
        """Deep defaults - merge with first value winning recursively (DSL pattern).

        Deep merges dicts, keeping first non-None value at each level.

        Args:
            *dicts: Dicts to merge

        Returns:
            Deeply merged dict with defaults

        Examples:
            >>> # Deep defaults
            >>> result = FlextLdifUtilities.defaults_deep(
            ...     {"a": {"b": 1}},
            ...     {"a": {"b": 2, "c": 3}},
            ... )
            >>> # {"a": {"b": 1, "c": 3}}

        """
        if not dicts:
            return {}
        result: dict[str, object] = {}
        for d in reversed(dicts):
            if not isinstance(d, dict):
                continue
            for k, v in d.items():
                if k not in result:
                    result[k] = v
                elif isinstance(result[k], dict) and isinstance(v, dict):
                    result[k] = cls.defaults_deep(result[k], v)  # type: ignore[arg-type]
        return result

    @classmethod
    def take(
        cls,
        data: object,
        key: str,
        *,
        as_type: type | str | None = None,
        default: object | None = None,
        guard: bool = True,
    ) -> object:
        """Extract value with type guard (DSL pattern).

        Wrapper around u.take with enhanced type support.

        Args:
            data: Source data (dict or object)
            key: Key/attribute name
            as_type: Type to guard against (type or string name)
            default: Default value if not found
            guard: If True, validate type

        Returns:
            Extracted value or default

        Examples:
            >>> # Extract with type guard
            >>> port = FlextLdifUtilities.take(
            ...     config,
            ...     "port",
            ...     as_type=int,
            ...     default=8080,
            ... )

        """
        value = u.take(data, key, as_type=None, default=default, guard=False)
        if value is None:
            return default
        if as_type and guard:
            return cls.as_type(value, target=as_type, default=default)
        return value

    @classmethod
    def try_(
        cls,
        fn: object,
        *,
        default: object | None = None,
        catch: type[BaseException] | tuple[type[BaseException], ...] = Exception,
    ) -> object:
        """Try-catch wrapper (DSL pattern).

        Wrapper around u.try_ with enhanced error handling.

        Args:
            fn: Function to execute
            default: Default value on error
            catch: Exception types to catch

        Returns:
            Function result or default

        Examples:
            >>> # Safe execution
            >>> result = FlextLdifUtilities.try_(
            ...     lambda: int(value),
            ...     default=0,
            ...     catch=(ValueError, TypeError),
            ... )

        """
        return u.try_(fn, default=default, catch=catch)

    @classmethod
    def or_(
        cls,
        value: object,
        *,
        default: object,
    ) -> object:
        """Null coalescing operator (DSL pattern).

        Returns value if truthy, default otherwise.

        Args:
            value: Value to check
            default: Default if value is falsy

        Returns:
            Value or default

        Examples:
            >>> # Null coalescing
            >>> name = FlextLdifUtilities.or_(
            ...     user.get("name"),
            ...     default="unknown",
            ... )

        """
        return u.or_(value, default=default)

    @classmethod
    def let(
        cls,
        value: object,
        *,
        fn: object,
    ) -> object:
        """Let binding (DSL pattern).

        Binds value to function scope (monadic bind).

        Args:
            value: Value to bind
            fn: Function to apply

        Returns:
            Function result

        Examples:
            >>> # Let binding
            >>> result = FlextLdifUtilities.let(
            ...     data,
            ...     fn=lambda x: x.get("value", 0),
            ... )

        """
        return fn(value) if callable(fn) else value  # type: ignore[operator]

    @classmethod
    def apply(
        cls,
        fn: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        """Apply function with args/kwargs (DSL pattern).

        Functional application helper.

        Args:
            fn: Function to apply
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Examples:
            >>> # Apply function
            >>> result = FlextLdifUtilities.apply(
            ...     process_data,
            ...     "arg1",
            ...     "arg2",
            ...     option=True,
            ... )

        """
        if callable(fn):
            return fn(*args, **kwargs)  # type: ignore[operator]
        return fn

    @classmethod
    def bind(
        cls,
        value: object,
        *fns: object,
    ) -> object:
        """Monadic bind (DSL pattern).

        Chains operations on value (flatMap).

        Args:
            value: Value to bind
            *fns: Functions to chain

        Returns:
            Final result

        Examples:
            >>> # Monadic bind
            >>> result = FlextLdifUtilities.bind(
            ...     data,
            ...     lambda x: x.get("items"),
            ...     lambda items: [i for i in items if i],
            ...     lambda filtered: len(filtered),
            ... )

        """
        result = value
        for fn in fns:
            if callable(fn):
                result = fn(result)  # type: ignore[operator]
                if result is None:
                    break
        return result

    @classmethod
    def lift(
        cls,
        fn: object,
    ) -> object:
        """Lift function to handle optional values (DSL pattern).

        Transforms function to work with optional values.

        Args:
            fn: Function to lift

        Returns:
            Lifted function

        Examples:
            >>> # Lift function
            >>> safe_int = FlextLdifUtilities.lift(int)
            >>> result = safe_int(None)  # Returns None instead of error

        """
        if not callable(fn):
            return fn

        def lifted(value: object) -> object:
            if value is None:
                return None
            try:
                return fn(value)  # type: ignore[operator]
            except (ValueError, TypeError, AttributeError):
                return None

        return lifted

    @classmethod
    def seq(
        cls,
        *values: object,
    ) -> list[object]:
        """Sequence constructor (DSL pattern).

        Creates list from values.

        Args:
            *values: Values to sequence

        Returns:
            List of values

        Examples:
            >>> # Create sequence
            >>> items = FlextLdifUtilities.seq(1, 2, 3, 4, 5)

        """
        return list(values)

    @classmethod
    def assoc(
        cls,
        data: dict[str, object],
        key: str,
        value: object,
    ) -> dict[str, object]:
        """Associate key-value (DSL pattern).

        Creates new dict with added/updated key-value.

        Args:
            data: Source dict
            key: Key to associate
            value: Value to associate

        Returns:
            New dict with association

        Examples:
            >>> # Associate value
            >>> updated = FlextLdifUtilities.assoc(
            ...     {"a": 1},
            ...     "b",
            ...     2,
            ... )

        """
        result = dict(data)
        result[key] = value
        return result

    @classmethod
    def dissoc(
        cls,
        data: dict[str, object],
        *keys: str,
    ) -> dict[str, object]:
        """Dissociate keys (DSL pattern).

        Creates new dict without specified keys.

        Args:
            data: Source dict
            *keys: Keys to remove

        Returns:
            New dict without keys

        Examples:
            >>> # Dissociate keys
            >>> updated = FlextLdifUtilities.dissoc(
            ...     {"a": 1, "b": 2, "c": 3},
            ...     "b",
            ...     "c",
            ... )

        """
        return cls.omit(data, *keys)

    @classmethod
    def update(
        cls,
        data: dict[str, object],
        updates: dict[str, object],
    ) -> dict[str, object]:
        """Update dict with another dict (DSL pattern).

        Creates new dict with merged updates.

        Args:
            data: Source dict
            updates: Updates to apply

        Returns:
            New dict with updates

        Examples:
            >>> # Update dict
            >>> updated = FlextLdifUtilities.update(
            ...     {"a": 1, "b": 2},
            ...     {"b": 3, "c": 4},
            ... )

        """
        result = dict(data)
        result.update(updates)
        return result

    @classmethod
    def evolve(
        cls,
        obj: dict[str, object],
        *transforms: dict[str, object] | Callable[[dict[str, object]], dict[str, object]],
    ) -> dict[str, object]:
        """Evolve object through transforms (DSL pattern).

        Applies multiple transforms to create new object.

        Args:
            obj: Source object
            *transforms: Dict updates or transform functions

        Returns:
            Evolved object

        Examples:
            >>> # Evolve with transforms
            >>> result = FlextLdifUtilities.evolve(
            ...     {"a": 1, "b": 2},
            ...     {"b": 3},
            ...     lambda d: {**d, "c": d.get("a", 0) + d.get("b", 0)},
            ... )

        """
        result = dict(obj)
        for transform in transforms:
            if callable(transform):
                result = transform(result)  # type: ignore[operator]
            elif isinstance(transform, dict):
                result.update(transform)
        return result

    @classmethod
    def keys(
        cls,
        obj: dict[str, object],
    ) -> list[str]:
        """Get dict keys as list (DSL pattern).

        Args:
            obj: Dict to get keys from

        Returns:
            List of keys

        Examples:
            >>> # Get keys
            >>> keys = FlextLdifUtilities.keys({"a": 1, "b": 2})

        """
        return list(obj.keys()) if isinstance(obj, dict) else []

    @classmethod
    def vals(
        cls,
        obj: dict[str, object],
    ) -> list[object]:
        """Get dict values as list (DSL pattern).

        Args:
            obj: Dict to get values from

        Returns:
            List of values

        Examples:
            >>> # Get values
            >>> values = FlextLdifUtilities.vals({"a": 1, "b": 2})

        """
        return list(obj.values()) if isinstance(obj, dict) else []

    @classmethod
    def pairs(
        cls,
        obj: dict[str, object],
    ) -> list[tuple[str, object]]:
        """Get dict key-value pairs (DSL pattern).

        Args:
            obj: Dict to get pairs from

        Returns:
            List of (key, value) tuples

        Examples:
            >>> # Get pairs
            >>> pairs = FlextLdifUtilities.pairs({"a": 1, "b": 2})

        """
        return list(obj.items()) if isinstance(obj, dict) else []

    @classmethod
    def invert(
        cls,
        obj: dict[str, object],
    ) -> dict[object, str]:
        """Invert dict keys and values (DSL pattern).

        Args:
            obj: Dict to invert

        Returns:
            Inverted dict

        Examples:
            >>> # Invert dict
            >>> inverted = FlextLdifUtilities.invert({"a": 1, "b": 2})

        """
        return {v: k for k, v in obj.items()} if isinstance(obj, dict) else {}

    @classmethod
    def where(
        cls,
        obj: dict[str, object],
        *,
        predicate: object | None = None,
    ) -> dict[str, object]:
        """Filter dict by predicate (DSL pattern).

        Args:
            obj: Dict to filter
            predicate: Function (key, value) -> bool

        Returns:
            Filtered dict

        Examples:
            >>> # Filter dict
            >>> filtered = FlextLdifUtilities.where(
            ...     {"a": 1, "b": 2, "c": 3},
            ...     predicate=lambda k, v: v > 1,
            ... )

        """
        if not isinstance(obj, dict):
            return {}
        if not predicate:
            return dict(obj)
        return {k: v for k, v in obj.items() if predicate(k, v)}  # type: ignore[operator]

    @classmethod
    def find_key(
        cls,
        obj: dict[str, object],
        *,
        predicate: object | None = None,
    ) -> str | None:
        """Find key matching predicate (DSL pattern).

        Args:
            obj: Dict to search
            predicate: Function (key, value) -> bool

        Returns:
            First matching key or None

        Examples:
            >>> # Find key
            >>> key = FlextLdifUtilities.find_key(
            ...     {"a": 1, "b": 2},
            ...     predicate=lambda k, v: v == 2,
            ... )

        """
        if not isinstance(obj, dict) or not predicate:
            return None
        for k, v in obj.items():
            if predicate(k, v):  # type: ignore[operator]
                return k
        return None

    @classmethod
    def find_val(
        cls,
        obj: dict[str, object],
        *,
        predicate: object | None = None,
    ) -> object | None:
        """Find value matching predicate (DSL pattern).

        Args:
            obj: Dict to search
            predicate: Function (key, value) -> bool

        Returns:
            First matching value or None

        Examples:
            >>> # Find value
            >>> value = FlextLdifUtilities.find_val(
            ...     {"a": 1, "b": 2},
            ...     predicate=lambda k, v: k == "b",
            ... )

        """
        if not isinstance(obj, dict) or not predicate:
            return None
        for k, v in obj.items():
            if predicate(k, v):  # type: ignore[operator]
                return v
        return None

    @classmethod
    def prop(
        cls,
        key: str,
    ) -> object:
        """Property accessor (DSL pattern).

        Returns function that extracts property from object.

        Args:
            key: Property key

        Returns:
            Function that extracts property

        Examples:
            >>> # Create property accessor
            >>> get_name = FlextLdifUtilities.prop("name")
            >>> name = get_name({"name": "John"})

        """
        def accessor(obj: object) -> object:
            if isinstance(obj, dict):
                return obj.get(key)
            return getattr(obj, key, None) if hasattr(obj, key) else None

        return accessor

    @classmethod
    def props(
        cls,
        *keys: str,
    ) -> object:
        """Multiple property accessors (DSL pattern).

        Returns function that extracts multiple properties.

        Args:
            *keys: Property keys

        Returns:
            Function that returns dict of properties

        Examples:
            >>> # Create props accessor
            >>> get_fields = FlextLdifUtilities.props("name", "age")
            >>> fields = get_fields({"name": "John", "age": 30, "city": "NY"})

        """
        def accessor(obj: object) -> dict[str, object]:
            result: dict[str, object] = {}
            for key in keys:
                if isinstance(obj, dict):
                    if key in obj:
                        result[key] = obj[key]
                elif hasattr(obj, key):
                    result[key] = getattr(obj, key)
            return result

        return accessor

    @classmethod
    def path(
        cls,
        *keys: str,
    ) -> object:
        """Path accessor for nested structures (DSL pattern).

        Returns function that accesses nested path.

        Args:
            *keys: Path keys

        Returns:
            Function that accesses nested path

        Examples:
            >>> # Create path accessor
            >>> get_nested = FlextLdifUtilities.path("user", "profile", "name")
            >>> name = get_nested({"user": {"profile": {"name": "John"}}})

        """
        def accessor(obj: object) -> object:
            result = obj
            for key in keys:
                if result is None:
                    return None
                if isinstance(result, dict):
                    result = result.get(key)
                elif hasattr(result, key):
                    result = getattr(result, key)
                else:
                    return None
            return result

        return accessor


__all__ = [
    "AclConversionConfig",
    "AndFilter",
    "AttrNormalizationConfig",
    "BatchTransformerProtocol",
    "BooleanFormat",
    "ByAttrValueFilter",
    "ByAttrsFilter",
    "ByDnFilter",
    "ByDnUnderBaseFilter",
    "ByObjectClassFilter",
    "CaseFoldOption",
    "ConvertBooleansTransformer",
    "CustomFilter",
    "CustomTransformer",
    "DnNormalizationConfig",
    "DnOps",
    "EntryFilter",
    "EntryOps",
    "EntryTransformer",
    "EscapeHandlingOption",
    "ExcludeAttrsFilter",
    "FailableTransformer",
    "Filter",
    "FilterAttrsTransformer",
    "FilterConfig",
    "FilterConfigBuilder",
    "FilterPredicate",
    "FilterProtocol",
    "FlextLdifResult",
    "FlextLdifUtilities",
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesConstants",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDecorators",
    "FlextLdifUtilitiesDetection",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesParsers",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
    "FlextLdifUtilitiesWriters",
    "FluentBuilderProtocol",
    "FluentOpsProtocol",
    "IsSchemaEntryFilter",
    "LoadConfig",
    "LoadableProtocol",
    "MetadataConfig",
    "Normalize",
    "NormalizeAttrsTransformer",
    "NormalizeDnTransformer",
    "NotFilter",
    "OrFilter",
    "OutputFormat",
    "Pipeline",
    "PipelineStep",
    "PipelineStepProtocol",
    "ProcessConfig",
    "ProcessConfigBuilder",
    "ProcessingPipeline",
    "RemoveAttrsTransformer",
    "ReplaceBaseDnTransformer",
    "SchemaParseConfig",
    "ServerType",
    "SimpleTransformer",
    "SortOption",
    "SpaceHandlingOption",
    "Transform",
    "TransformConfig",
    "TransformConfigBuilder",
    "TransformerProtocol",
    "ValidationConfig",
    "ValidationPipeline",
    "ValidationReportProtocol",
    "ValidationResult",
    "ValidationRuleProtocol",
    "ValidationRuleSet",
    "ValidatorProtocol",
    "WritableProtocol",
    "WriteConfig",
    "WriteConfigBuilder",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]
