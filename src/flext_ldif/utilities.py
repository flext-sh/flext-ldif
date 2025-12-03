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
from typing import Literal, cast

from flext_core import (
    FlextDecorators,
    FlextExceptions,
    FlextLogger,
    FlextResult,
    FlextService,
)
from flext_core.handlers import FlextHandlers
from flext_core.mixins import FlextMixins
from flext_core.typings import t as flext_core_types
from flext_core.utilities import FlextUtilities

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.builders import (
    FilterConfigBuilder,
    ProcessConfigBuilder,
    TransformConfigBuilder,
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
    Validation = FlextLdifUtilitiesValidation  # type: ignore[assignment]  # LDIF-specific validation extends core Validation
    Writer = FlextLdifUtilitiesWriter
    Writers = FlextLdifUtilitiesWriters

    # === Power Methods (new) ===

    @classmethod
    def process(  # type: ignore[override]  # LDIF-specific power method: different signature from u.process()
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
    def transform(  # type: ignore[override]  # LDIF-specific power method: different signature from u.transform()
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
            _ = pipeline.add(transformer)  # Explicitly ignore return value
        return FlextLdifResult.from_result(pipeline.execute(list(entries)))

    @classmethod
    def filter(  # type: ignore[override]  # LDIF-specific power method: different signature from u.filter()
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
    def validate(  # type: ignore[override]  # LDIF-specific power method: different signature from u.validate()
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
        mapper: Callable[[object], object] | None = None,
        predicate: Callable[[object], bool] | None = None,
    ) -> list[object]:
        """Map then filter items (generalized: uses map_filter from base, mnemonic: mf).

        Args:
            items: Items to process
            mapper: Transformation function
            predicate: Filter function

        Returns:
            Processed list

        Examples:
            >>> perms = cls.mf("read,write,add".split(","), mapper=str.strip, predicate=bool)  # noqa: E501

        """
        return u.map_filter(items, mapper=mapper, predicate=predicate)

    # Mnemonic helper
    mf = map_filter

    @classmethod
    def process_flatten(  # type: ignore[override]  # Extended signature with Literal for better type safety
        cls,
        items: Sequence[object] | object,
        *,
        processor: Callable[[object], object] | None = None,
        on_error: Literal["skip", "fail", "return"] = "skip",
    ) -> list[object]:
        """Process and flatten using u.process_flatten() (mnemonic: pf).

        Delegates to u.process_flatten() for unified behavior.

        Args:
            items: Items to process
            processor: Processing function
            on_error: Error handling

        Returns:
            Flattened list

        Examples:
            >>> flat = cls.pf([[1,2], [3,4]], processor=lambda x: x*2)

        """
        # Convert on_error Literal to str for u.process_flatten()
        on_error_str: str = "skip" if on_error == "skip" else ("fail" if on_error == "fail" else "return")
        return u.process_flatten(items, processor=processor, on_error=on_error_str)

    # Mnemonic helper
    pf = process_flatten

    @classmethod
    def normalize_list(
        cls,
        value: object,
        *,
        mapper: Callable[[object], object] | None = None,
        predicate: Callable[[object], bool] | None = None,
        default: list[object] | None = None,
    ) -> list[object]:
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
        extracted = u.or_(
            value.value if isinstance(value, FlextResult) and not value.is_failure else value,
            default=default or [],
        )
        # Use u.build() DSL for normalization
        ops: dict[str, object] = {"ensure": "list", "ensure_default": default or []}
        if mapper:
            ops["map"] = mapper
        if predicate:
            ops["filter"] = predicate
        result = u.build(extracted, ops=ops)
        return list(result) if isinstance(result, (list, tuple)) else [result]

    # Mnemonic helper
    nl = normalize_list

    @classmethod
    def reduce_dict(
        cls,
        items: Sequence[dict[str, object]] | dict[str, object] | object,
        *,
        processor: Callable[[str, object], tuple[str, object]] | None = None,
        predicate: Callable[[str, object], bool] | None = None,
        default: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Reduce dicts using u.merge() + u.build() DSL (mnemonic: rd).

        Args:
            items: Dicts to merge
            processor: Transform (k,v) -> (new_k, new_v)
            predicate: Filter (k,v) -> bool
            default: Default dict

        Returns:
            Merged dict

        Examples:
            >>> result = cls.rd([{"a":1}, {"b":2}], predicate=lambda k,v: v>0)

        """
        return u.reduce_dict(items, processor=processor, predicate=predicate, default=default)

    # Mnemonic helper
    rd = reduce_dict

    @classmethod
    def chain(
        cls,
        value: object,
        *funcs: Callable[[object], object],
    ) -> object:
        """Chain operations using u.chain() (mnemonic: ch).

        Delegates to u.chain() for unified behavior.

        Args:
            value: Initial value
            *funcs: Functions to apply in sequence

        Returns:
            Final processed value

        Examples:
            >>> result = cls.ch(data, lambda x: x.split(","), lambda x: [s.strip() for s in x])

        """
        return u.chain(value, *funcs)

    # Mnemonic helper
    ch = chain

    @classmethod
    def when[T](
        cls,
        *,
        condition: bool = False,
        then_value: T | None = None,
        else_value: T | None = None,
    ) -> T | None:
        """Functional conditional (DSL pattern).

        Delegates to u.when() for unified conditional handling.

        Args:
            condition: Boolean condition
            then_value: Value to return if condition is True
            else_value: Value to return if condition is False

        Returns:
            then_value or else_value

        Examples:
            >>> # Conditional value selection
            >>> result = FlextLdifUtilities.when(
            ...     condition=len(items) > 0,
            ...     then_value=items[0],
            ...     else_value=default_value,
            ... )

        """
        return u.when(condition=condition, then_value=then_value, else_value=else_value)

    @classmethod
    def fold(
        cls,
        items: Sequence[object] | object,
        *,
        initial: object,
        folder: Callable[[object, object], object] | None = None,
        predicate: Callable[[object], bool] | None = None,
    ) -> object:
        """Fold using u.filter() + manual fold (mnemonic: fd).

        Args:
            items: Items to fold
            initial: Initial accumulator
            folder: (acc, item) -> new_acc
            predicate: Optional filter

        Returns:
            Final accumulator

        Examples:
            >>> total = cls.fd([1,2,3], initial=0, folder=lambda a,x: a+x)

        """
        if not folder:
            return initial
        return u.fold(items, initial=initial, folder=folder, predicate=predicate)

    # Mnemonic helper
    fd = fold

    @classmethod
    def pipe(  # type: ignore[override]  # Uses u.flow() instead of u.pipe() for simpler API
        cls,
        value: object,
        *ops: dict[str, object] | Callable[[object], object],
    ) -> object:
        """Pipe using u.flow() (mnemonic: pp).

        Delegates to u.flow() for unified behavior.

        Args:
            value: Initial value
            *ops: Functions or DSL dicts

        Returns:
            Final result

        Examples:
            >>> result = cls.pp(data, lambda x: x.split(","), {"map": str.strip})

        """
        return u.flow(value, *ops)

    # Mnemonic helper
    pp = pipe

    @classmethod
    def tap(
        cls,
        value: object,
        *,
        side_effect: Callable[[object], object] | None,
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
        if side_effect:
            _ = side_effect(value)  # Explicitly ignore return value
        return value

    @classmethod
    def maybe(
        cls,
        value: object | None,
        *,
        default: object | None = None,
        mapper: Callable[[object], object] | None = None,
    ) -> object:
        """Maybe monad (generalized: uses maybe from base, mnemonic: mb).

        Args:
            value: Optional value
            default: Default if None
            mapper: Optional transformation

        Returns:
            Processed value or default

        Examples:
            >>> result = cls.mb(config.get("key"), default=[], mapper=lambda x: x.split(","))

        """
        return u.maybe(value, default=default, mapper=mapper)

    # Mnemonic helper
    mb = maybe

    @classmethod
    def zip_with(
        cls,
        *sequences: Sequence[object],
        combiner: Callable[[object, ...], object] | None = None,  # type: ignore[misc]  # Variable args
    ) -> list[object]:
        """Zip with combiner (generalized: uses zip_with from base, mnemonic: zw).

        Args:
            *sequences: Sequences to zip
            combiner: Combine function (default: tuple)

        Returns:
            List of combined results

        Examples:
            >>> result = cls.zw([1,2], ["a","b"], combiner=lambda x,y: f"{x}:{y}")

        """
        return u.zip_with(*sequences, combiner=combiner)

    # Mnemonic helper
    zw = zip_with

    @classmethod
    def group_by(
        cls,
        items: Sequence[object],
        *,
        key: Callable[[object], object],
    ) -> dict[object, list[object]]:
        """Group by key function (generalized: uses group from base, mnemonic: gb).

        Args:
            items: Items to group
            key: Extract key function

        Returns:
            Dict mapping keys to item lists

        Examples:
            >>> result = cls.gb(["a","b","a"], key=lambda x: x)

        """
        items_list = list(items) if isinstance(items, Sequence) else [items]
        # Use existing group() method which accepts list[T] | tuple[T, ...]
        return cast("dict[object, list[object]]", u.group(items_list, key=key))

    # Mnemonic helper
    gb = group_by

    @classmethod
    def partition(
        cls,
        items: object,
        *,
        predicate: Callable[[object], bool],
    ) -> tuple[list[object], list[object]]:
        """Partition (generalized: uses partition from base, mnemonic: pt).

        Args:
            items: Items to partition
            predicate: Test function

        Returns:
            (true_items, false_items)

        Examples:
            >>> evens, odds = cls.pt([1,2,3], predicate=lambda x: x%2==0)

        """
        return u.partition(items, predicate=predicate)

    # Mnemonic helper
    pt = partition

    @classmethod
    def get(  # type: ignore[override]  # Simplified signature, delegates to u.get()
        cls,
        data: Mapping[str, object] | object,
        key: str,
        *,
        default: object | None = None,
    ) -> object:
        """Safe get with optional mapping (DSL pattern).

        Delegates to u.get() for unified behavior. Use u.flow() or u.chain() for mapping.

        Args:
            data: Object to get from (dict, list, etc.)
            key: Key/index to get
            default: Default if not found

        Returns:
            Value or default

        Examples:
            >>> # Safe dict access
            >>> value = FlextLdifUtilities.get(config, "key", default=[])
            >>> # With mapping
            >>> value = FlextLdifUtilities.chain(
            ...     FlextLdifUtilities.get(config, "key", default=""),
            ...     lambda x: x.split(","),
            ... )

        """
        return u.get(data, key, default=default)

    @classmethod
    def pluck(
        cls,
        items: object,
        *,
        key: str | int | Callable[[object], object],
    ) -> list[object]:
        """Pluck using u.pluck() (mnemonic: pk).

        Delegates to u.pluck() for unified behavior.

        Args:
            items: Items to pluck from
            key: Key/extractor (str/int/callable)

        Returns:
            List of extracted values

        Examples:
            >>> names = cls.pk([{"n":"a"}], key="n")
            >>> lens = cls.pk(["abc"], key=len)

        """
        return u.pluck(items, key=key)

    # Mnemonic helper
    pk = pluck

    @classmethod
    def pick[T](
        cls,
        data: Mapping[str, object] | object,
        *keys: str,
        as_dict: bool = True,
    ) -> dict[str, object] | list[object]:
        """Pick keys using u.pick() (mnemonic: pc).

        Delegates to u.pick() for unified behavior.

        Args:
            data: Dict or object to pick from
            *keys: Keys to pick
            as_dict: If True, return dict; if False, return list

        Returns:
            New dict with picked keys or list of values

        Examples:
            >>> result = cls.pc({"a":1, "b":2}, "a", "b")

        """
        return u.pick(data, *keys, as_dict=as_dict)

    # Mnemonic helper
    pc = pick

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
            >>> result = cls.om({"a":1, "b":2}, "b")

        """
        if not obj or not keys:
            return dict(obj) if obj else {}
        # Use u.map_dict() with predicate to filter out keys
        keys_set = set(keys)
        return u.map_dict(obj, predicate=lambda k, _: k not in keys_set)

    # Mnemonic helper
    om = omit

    @classmethod
    def merge(  # type: ignore[override]  # Returns dict[str, object] instead of dict[str, GeneralValueType]
        cls,
        *dicts: Mapping[str, object] | dict[str, object],
        strategy: str = "deep",
        filter_none: bool = False,
        filter_empty: bool = False,
    ) -> r[dict[str, object]]:
        """Merge dicts using u.merge() (mnemonic: mg).

        Delegates to u.merge() for unified behavior.

        Args:
            *dicts: Dicts to merge
            strategy: Merge strategy ("override", "deep", "append")
            filter_none: Skip None values
            filter_empty: Skip empty strings/lists/dicts

        Returns:
            FlextResult containing merged dict

        Examples:
            >>> result = cls.mg({"a":1}, {"b":2})
            >>> if result.is_success:
            ...     merged = result.value

        """
        # Convert dicts to Mapping[str, GeneralValueType] for u.merge()
        # Use list comprehension for better performance
        mappings_list: list[Mapping[str, flext_core_types.GeneralValueType]] = [
            cast("Mapping[str, flext_core_types.GeneralValueType]", d)
            for d in dicts
            if isinstance(d, (dict, Mapping))
        ]
        if not mappings_list:
            return r[dict[str, object]].ok({})
        # Use list comprehension for better performance
        merge_result = u.merge(*tuple(mappings_list), strategy=strategy, filter_none=filter_none, filter_empty=filter_empty)
        # Convert GeneralValueType back to object
        if merge_result.is_success:
            return r[dict[str, object]].ok(cast("dict[str, object]", merge_result.value))
        return r[dict[str, object]].fail(merge_result.error)

    # Mnemonic helper
    mg = merge

    @classmethod
    def map_dict(
        cls,
        obj: dict[str, object],
        *,
        mapper: Callable[[str, object], object] | None = None,
        key_mapper: Callable[[str], str] | None = None,
        predicate: Callable[[str, object], bool] | None = None,
    ) -> dict[str, object]:
        """Map dict (generalized: uses map_dict from base, mnemonic: md).

        Args:
            obj: Dict to map
            mapper: (k,v) -> new_v
            key_mapper: (k) -> new_k
            predicate: (k,v) -> bool

        Returns:
            Mapped dict

        Examples:
            >>> result = cls.md({"a":1}, mapper=lambda k,v: v*2, key_mapper=str.upper)

        """
        return u.map_dict(obj, mapper=mapper, key_mapper=key_mapper, predicate=predicate)

    # Mnemonic helper
    md = map_dict

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
            >>> result = cls.sc(data, target_type="list", predicate=lambda x: isinstance(x, dict))

        """
        # Extract from Result using u.or_()
        extracted = u.or_(
            value.value if isinstance(value, FlextResult) and not value.is_failure else value,
            default=default,
        )
        if extracted is None:
            return default

        # Use u.build() DSL for conversion
        ops: dict[str, object] = {"ensure": target_type, "ensure_default": default}
        if predicate:
            ops["filter"] = predicate
        result = u.build(extracted, ops=ops)
        return u.or_(result, default=default)

    # Mnemonic helper
    sc = smart_convert

    @classmethod
    def is_type(
        cls,
        value: object,
        *types: type | str,
    ) -> bool:
        """Type check using u.build() DSL (mnemonic: it).

        Checks if value is instance of any type using u.build() ensure pattern.

        Args:
            value: Value to check
            *types: Types to check against

        Returns:
            True if value matches any type

        Examples:
            >>> if cls.it(value, dict, list): process(value)

        """
        if not types:
            return False
        # Use u.build() with ensure to check types
        type_map = {"list": list, "dict": dict, "str": str, "int": int, "bool": bool, "tuple": tuple}
        for t_val in types:
            resolved_type = type_map.get(t_val) if isinstance(t_val, str) else (t_val if isinstance(t_val, type) else None)
            if resolved_type and isinstance(value, resolved_type):
                return True
        return False

    @classmethod
    def as_type(
        cls,
        value: object,
        *,
        target: type | str,
        default: object | None = None,
    ) -> object:
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
        # Use u.build() DSL for type conversion
        type_map = {"list": list, "dict": dict, "str": str, "int": int, "bool": bool, "tuple": tuple}
        target_type = type_map.get(target) if isinstance(target, str) else (target if isinstance(target, type) else None)
        if target_type is None:
            return default
        # Use u.build() with ensure for conversion
        ops: dict[str, object] = {"ensure": target_type, "ensure_default": default}
        result = u.build(value, ops=ops)
        return u.or_(result, default=default)

    # Mnemonic helper
    @classmethod
    def at[T](  # type: ignore[override]  # Different purpose: type casting vs index access
        cls,
        value: object,
        *,
        target: type[T] | str,
        default: T | None = None,
    ) -> T | None:
        """Type casting alias (mnemonic: at).

        NOTE: Different from u.at() which accesses by index/key.
        This method casts types, supporting str type names.

        Args:
            value: Value to cast
            target: Target type/name
            default: Default if fails

        Returns:
            Casted value or default

        Examples:
            >>> items = cls.at(value, target="list", default=[])

        """
        # Convert str to type if needed
        if isinstance(target, str):
            result = cls.as_type(value, target=target, default=default)
            return cast("T | None", result)
        # Use u.as_() for type objects
        if isinstance(target, type):
            typed_target = target  # Type narrowing: target is type[T]
            return u.as_(value, typed_target, default=default)
        # Fallback for non-type, non-str targets (should not happen in practice)
        return default  # type: ignore[unreachable]  # Mypy false positive: return is reachable

    @classmethod  # type: ignore[assignment]  # Different purpose: type casting vs index access
    def guard[T](  # type: ignore[override]  # Simplified version of u.guard()
        cls,
        value: T,
        *,
        check: Callable[[T], bool] | bool,
        default: T | None = None,
    ) -> T | None:
        """Guard using u.when() pattern (mnemonic: gd).

        Simplified version of u.guard() for common use cases.

        Args:
            value: Value to guard
            check: Check function/bool
            default: Default if fails

        Returns:
            Value or default

        Examples:
            >>> result = cls.gd(data, check=lambda x: len(x)>0, default=[])

        """
        check_result = check(value) if callable(check) else bool(check)
        return u.when(condition=check_result, then_value=value, else_value=default)

    # Mnemonic helper
    gd = guard

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
            >>> fn = cls.cp(lambda x: x.split(","), lambda x: [s.strip() for s in x])

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
        fn: Callable[[object, ...], object],  # type: ignore[misc]  # Variable args
        *args: object,
    ) -> Callable[[object, ...], object]:  # type: ignore[misc]  # Variable args
        """Curry function (mnemonic: cy).

        Args:
            fn: Function to curry
            *args: Arguments to apply

        Returns:
            Curried function

        Examples:
            >>> add5 = cls.cy(lambda x,y: x+y, 5)

        """
        return lambda *more_args: fn(*(args + more_args))

    # Mnemonic helper
    cy = curry

    @classmethod
    def cond(  # noqa: C901  # Complex conditional logic required
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
            >>> fn = cls.cd((lambda x: x>10, "big"), (lambda x: x>5, "med"), default="small")
            >>> result = fn(15)

        """
        # Check if predicates are no-arg by inspecting first predicate
        is_no_arg = False
        if pairs:
            first_pred = pairs[0][0]
            if callable(first_pred):
                try:
                    import inspect  # noqa: PLC0415  # Import inside conditional for performance
                    sig = inspect.signature(first_pred)
                    param_count = len(sig.parameters)
                    is_no_arg = param_count == 0
                except (ValueError, TypeError):
                    pass

        if is_no_arg:
            # No-arg predicates: return function() -> value
            def conditional_no_arg() -> object:
                for pred, result_val in pairs:
                    check = pred() if callable(pred) else bool(pred)  # type: ignore[call-arg]  # No-arg
                    if check:
                        return result_val() if callable(result_val) else result_val  # type: ignore[call-arg]  # No-arg
                return default() if callable(default) else default  # type: ignore[call-arg]  # No-arg
            return conditional_no_arg

        # Value-arg predicates: return function(value) -> value
        def conditional(value: object) -> object:
            for pred, result_val in pairs:
                # Type narrowing: predicates in value-arg branch accept 1 arg
                if callable(pred):
                    pred_fn = cast("Callable[[object], bool]", pred)
                    check = pred_fn(value)
                else:
                    check = bool(pred)
                if check:
                    if callable(result_val):
                        result_fn = cast("Callable[[object], object]", result_val)
                        return result_fn(value)
                    return result_val
            if default is not None and callable(default):
                default_fn = cast("Callable[[object], object]", default)
                return default_fn(value)
            return default
        return conditional

    # Mnemonic helper
    cd = cond

    @classmethod
    def match(
        cls,
        value: object,
        *cases: tuple[type[object] | object | Callable[[object], bool], object],
        default: object | None = None,
    ) -> object:
        """Pattern match (mnemonic: mt).

        Args:
            value: Value to match
            *cases: (pattern, result) tuples
            default: Default if no match

        Returns:
            Matching result

        Examples:
            >>> result = cls.mt("REDACTED_LDAP_BIND_PASSWORD", (str, lambda s: s.upper()), default="unknown")

        """
        for pattern, result in cases:
            # Type match
            if isinstance(pattern, type) and isinstance(value, pattern):
                return result(value) if callable(result) else result
            # Value match
            if pattern == value:
                return result(value) if callable(result) else result
            # Predicate match
            if callable(pattern):
                pattern_fn = cast("Callable[[object], bool]", pattern)
                if pattern_fn(value):
                    return result(value) if callable(result) else result
        return default(value) if callable(default) else default

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
            >>> result = cls.df({"a":1}, {"b":2, "a":3})  # {"a":1, "b":2}

        """
        if not dicts:
            return {}
        # Use u.reduce_dict() to apply first-wins logic: first dict wins, later dicts fill missing/None keys

        # Use u.map_dict() with predicate for first-wins logic
        # Build result: first dict wins, later dicts fill missing/None keys
        result: dict[str, object] = {}
        for d in dicts:  # Process in original order (first dict wins)
            if isinstance(d, dict):
                # Use u.map_dict() to filter: only include keys not in result or where result value is None
                filtered = u.map_dict(d, predicate=lambda k, _v: k not in result or result.get(k) is None)
                result.update(filtered)
        return result

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
            >>> result = cls.dm({"a": {"b":1}}, {"a": {"c":2}})  # {"a": {"b":1, "c":2}}

        """
        if not dicts:
            return {}
        mappings: list[Mapping[str, flext_core_types.GeneralValueType]] = [
            cast("Mapping[str, flext_core_types.GeneralValueType]", d) for d in dicts if isinstance(d, dict)
        ]
        if not mappings:
            return {}
        merge_result = u.merge(*tuple(mappings), strategy="deep")
        if merge_result.is_success and isinstance(merge_result.value, dict):
            return cast("dict[str, object]", merge_result.value)
        return {}

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
        # Apply updates in-place using u.filter() DSL pattern
        # Use u.filter() to get only dict updates, then apply via dict.update()
        dict_updates = u.filter(updates, predicate=lambda x: isinstance(x, dict))
        # u.filter() on list returns list, iterate and apply updates
        if isinstance(dict_updates, list):
            for update_dict in dict_updates:
                obj.update(cast("dict[str, object]", update_dict))
        return obj

    # Mnemonic helper
    ui = update_inplace

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
            >>> result = cls.dd({"a": {"b":1}}, {"a": {"b":2, "c":3}})  # {"a": {"b":1, "c":3}}

        """
        if not dicts:
            return {}
        # Use u.merge() with deep strategy for nested merging
        mappings: list[Mapping[str, flext_core_types.GeneralValueType]] = [
            cast("Mapping[str, flext_core_types.GeneralValueType]", d) for d in reversed(dicts) if isinstance(d, dict)
        ]
        if not mappings:
            return {}
        merge_result = u.merge(*tuple(mappings), strategy="deep")
        if merge_result.is_success and isinstance(merge_result.value, dict):
            # Apply first-wins logic recursively: first dict wins, later dicts fill missing keys
            result: dict[str, object] = {}
            for d in reversed(dicts):  # Process in original order (first dict wins)
                if isinstance(d, dict):
                    # Apply first-wins logic: only include keys not in result or recurse for nested dicts
                    for k, v in d.items():
                        if k not in result:
                            result[k] = v
                        elif isinstance(result[k], dict) and isinstance(v, dict):
                            # Recurse for nested dicts using u.merge() DSL
                            nested_result = cls.dd(cast("dict[str, object]", result[k]), v)
                            result[k] = nested_result
            return result
        return {}

    # Mnemonic helper
    dd = defaults_deep

    @classmethod
    def take[T](  # type: ignore[override]  # Extended functionality
        cls,
        data_or_items: object,
        key_or_n: str | int,
        *,
        as_type: type[T] | None = None,
        default: T | None = None,
        guard: bool = True,
        from_start: bool = True,
    ) -> dict[str, T] | list[T] | T | None:
        """Take with type guard using u.take() (mnemonic: tk).

        Delegates to u.take() for unified behavior.

        Args:
            data_or_items: Source data or items
            key_or_n: Key/attribute name (str) or number of items (int)
            as_type: Type to guard
            default: Default value
            guard: Validate type
            from_start: Take from start if True

        Returns:
            Extracted value or default

        Examples:
            >>> port = cls.tk(config, "port", as_type=int, default=8080)

        """
        # u.take() handles both str (extraction) and int (slice) modes
        # Type narrowing for mypy - u.take() has overloads for str vs int
        if isinstance(key_or_n, str):
            # Extraction mode - returns T | None
            # Narrow data_or_items type for mypy
            if isinstance(data_or_items, (dict, Mapping)):
                return u.take(data_or_items, key_or_n, as_type=as_type, default=default, guard=guard, from_start=from_start)
            return u.take(data_or_items, key_or_n, as_type=as_type, default=default, guard=guard, from_start=from_start)
        # Slice mode - key_or_n is int, returns dict[str, T] | list[T]
        # Narrow data_or_items type for mypy overload resolution
        if isinstance(data_or_items, dict):
            result_dict = u.take(data_or_items, key_or_n, as_type=as_type, default=default, guard=guard, from_start=from_start)
            return cast("dict[str, T]", result_dict)
        if isinstance(data_or_items, (list, tuple)):
            result_list = u.take(data_or_items, key_or_n, as_type=as_type, default=default, guard=guard, from_start=from_start)
            return cast("list[T]", result_list)
        # Fallback for object type
        return default

    # Mnemonic helper
    tk = take

    @classmethod
    def try_[T](
        cls,
        func: Callable[[], T],
        *,
        default: T | None = None,
        catch: type[Exception] | tuple[type[Exception], ...] = Exception,
    ) -> T | None:
        """Try using u.try_() (mnemonic: tr).

        Delegates to u.try_() for unified behavior.

        Args:
            func: Function to execute
            default: Default on error
            catch: Exception types

        Returns:
            Result or default

        Examples:
            >>> result = cls.tr(lambda: int(value), default=0)

        """
        return u.try_(func, default=default, catch=catch)

    # Mnemonic helper
    tr = try_

    @classmethod
    def or_[T](
        cls,
        *values: T | None,
        default: T | None = None,
    ) -> T | None:
        """Null coalesce using u.or_() (mnemonic: oo).

        Delegates to u.or_() for unified behavior.

        Args:
            *values: Values to try in order
            default: Default if all are None

        Returns:
            First non-None value or default

        Examples:
            >>> name = cls.oo(user.get("name"), default="unknown")
            >>> port = cls.oo(config.get("port"), env.get("PORT"), default=8080)

        """
        return u.or_(*values, default=default)

    # Mnemonic helper
    oo = or_

    @classmethod
    def let(
        cls,
        value: object,
        *,
        fn: Callable[[object], object],
    ) -> object:
        """Let using chain() (mnemonic: lt).

        Delegates to chain() for unified behavior.

        Args:
            value: Value to bind
            fn: Function to apply

        Returns:
            Function result

        Examples:
            >>> result = cls.lt(data, fn=lambda x: x.get("value", 0))

        """
        return cls.chain(value, fn)

    # Mnemonic helper
    lt = let

    @classmethod
    def apply(
        cls,
        fn: Callable[[object, ...], object] | object,  # type: ignore[misc]  # Variable args
        *args: object,
        **kwargs: object,
    ) -> object:
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
            return fn(*args, **kwargs)
        return fn

    # Mnemonic helper
    ap = apply

    @classmethod
    def bind(
        cls,
        value: object,
        *fns: Callable[[object], object],
    ) -> object:
        """Bind using chain() (mnemonic: bd).

        Delegates to chain() for unified behavior.

        Args:
            value: Value to bind
            *fns: Functions to chain

        Returns:
            Final result

        Examples:
            >>> result = cls.bd(data, lambda x: x.get("items"), lambda i: len(i))

        """
        return cls.chain(value, *fns)

    # Mnemonic helper
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
        # Use u.when() DSL for conditional execution with safe None handling
        def lifted_fn(v: object) -> object | None:
            """Lifted function with safe None handling using DSL."""
            if v is None:
                return None
            return cls.tr(lambda: fn(v), default=None)
        
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
        # Use u.ensure_str_list() or direct list conversion for multiple values
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
        # Use u.merge() for unified behavior
        update_dict: Mapping[str, flext_core_types.GeneralValueType] = {key: cast("flext_core_types.GeneralValueType", value)}
        data_mapping: Mapping[str, flext_core_types.GeneralValueType] = cast("Mapping[str, flext_core_types.GeneralValueType]", data)
        merge_result = u.merge(data_mapping, update_dict, strategy="override")
        if merge_result.is_success and isinstance(merge_result.value, dict):
            return cast("dict[str, object]", merge_result.value)
        return {**data, key: value}  # Fallback

    # Mnemonic helper
    ac = assoc

    @classmethod
    def dissoc(
        cls,
        data: dict[str, object],
        *keys: str,
    ) -> dict[str, object]:
        """Dissociate keys using omit (mnemonic: ds).

        Args:
            data: Source dict
            *keys: Keys to remove

        Returns:
            New dict without keys

        Examples:
            >>> updated = cls.ds({"a":1, "b":2}, "b")

        """
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
            >>> updated = cls.ud({"a":1}, {"b":2})

        """
        # Use u.merge() for unified behavior
        mappings: list[Mapping[str, flext_core_types.GeneralValueType]] = [
            cast("Mapping[str, flext_core_types.GeneralValueType]", data),
            cast("Mapping[str, flext_core_types.GeneralValueType]", updates),
        ]
        merge_result = u.merge(*tuple(mappings), strategy="override")
        if merge_result.is_success and isinstance(merge_result.value, dict):
            return cast("dict[str, object]", merge_result.value)
        return {**data, **updates}  # Fallback

    # Mnemonic helper
    ud = update

    @classmethod
    def evolve(
        cls,
        obj: dict[str, object],
        *transforms: dict[str, object] | Callable[[dict[str, object]], dict[str, object]],
    ) -> dict[str, object]:
        """Evolve using u.flow() pattern (mnemonic: ev).

        Args:
            obj: Source object
            *transforms: Dict updates or transform functions

        Returns:
            Evolved object

        Examples:
            >>> result = cls.ev({"a":1}, {"b":2}, lambda d: {**d, "c":3})

        """
        # Convert transforms to compatible format for u.flow()
        flow_ops: list[dict[str, object] | Callable[[object], object]] = []
        for transform in transforms:
            if callable(transform):
                # Wrap dict transform function to accept object
                def wrap_transform(t: Callable[[dict[str, object]], dict[str, object]]) -> Callable[[object], object]:
                    return lambda obj: t(cast("dict[str, object]", obj)) if isinstance(obj, dict) else obj
                flow_ops.append(wrap_transform(transform))
            elif isinstance(transform, dict):
                flow_ops.append(transform)
        return cast("dict[str, object]", u.flow(obj, *flow_ops))

    # Mnemonic helper
    ev = evolve

    @classmethod
    def keys[T](
        cls,
        items: dict[str, T] | r[dict[str, T]],
        *,
        default: list[str] | None = None,
    ) -> list[str]:
        """Get keys using u.keys() (mnemonic: ky).

        Delegates to u.keys() for unified behavior.

        Args:
            items: Dict or Result containing dict
            default: Default if empty/failed

        Returns:
            List of keys

        Examples:
            >>> keys = cls.ky({"a": 1, "b": 2})

        """
        return u.keys(items, default=default or [])

    # Mnemonic helper
    ky = keys

    @classmethod
    def vals[T](
        cls,
        items: dict[str, T] | r[dict[str, T]],
        *,
        default: list[T] | None = None,
    ) -> list[T]:
        """Get values using u.vals() (mnemonic: vl).

        Delegates to u.vals() for unified behavior.

        Args:
            items: Dict or Result containing dict
            default: Default if empty/failed

        Returns:
            List of values

        Examples:
            >>> values = cls.vl({"a": 1, "b": 2})

        """
        return u.vals(items, default=default or [])

    # Mnemonic helper
    vl = vals

    @classmethod
    def pairs(
        cls,
        obj: dict[str, object],
    ) -> list[tuple[str, object]]:
        """Get pairs using u.map_dict() pattern (mnemonic: pr).

        Args:
            obj: Dict to get pairs from

        Returns:
            List of (key, value) tuples

        Examples:
            >>> pairs = cls.pr({"a": 1, "b": 2})

        """
        if isinstance(obj, dict):
            return list(obj.items())
        return []  # type: ignore[unreachable]  # Mypy false positive: return is reachable

    # Mnemonic helper
    pr = pairs  # type: ignore[assignment]

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
            return {v: k for k, v in obj.items()}
        return {}  # type: ignore[unreachable]  # Mypy false positive: return is reachable

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
            >>> filtered = cls.wh({"a":1, "b":2}, predicate=lambda k,v: v>1)

        """
        if not isinstance(obj, dict):
            return {}  # type: ignore[unreachable]  # Mypy false positive: return is reachable
        if predicate is None:
            return dict(obj)
        filtered = u.filter(obj, predicate=predicate)
        if isinstance(filtered, dict):
            return filtered
        return {}

    # Mnemonic helper
    wh = where

    @classmethod
    def find_key(
        cls,
        obj: dict[str, object],
        *,
        predicate: Callable[[str, object], bool] | None = None,
    ) -> str | None:
        """Find key (generalized: uses find_key from base, mnemonic: fk).

        Args:
            obj: Dict to search
            predicate: (k,v) -> bool

        Returns:
            First matching key or None

        Examples:
            >>> key = cls.fk({"a":1, "b":2}, predicate=lambda k,v: v==2)

        """
        return u.find_key(obj, predicate=predicate)

    # Mnemonic helper
    fk = find_key

    @classmethod
    def find_val(
        cls,
        obj: dict[str, object],
        *,
        predicate: Callable[[str, object], bool] | None = None,
    ) -> object | None:
        """Find value (generalized: uses find_val from base, mnemonic: fv).

        Args:
            obj: Dict to search
            predicate: (k,v) -> bool

        Returns:
            First matching value or None

        Examples:
            >>> value = cls.fv({"a":1, "b":2}, predicate=lambda k,v: k=="b")

        """
        return u.find_val(obj, predicate=predicate)

    # Mnemonic helper
    fv = find_val

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
        return lambda obj: u.get(obj, key)

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
            return {k: cls.get(obj, k) for k in keys}
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
        # Use u.chain() to compose get operations
        getters = [lambda o, k=k: cls.get(o, k) for k in keys]
        return lambda obj: cls.chain(obj, *getters) if obj is not None else None

    # Mnemonic helper
    ph = path


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
]
