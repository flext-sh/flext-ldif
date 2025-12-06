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

from collections.abc import Sequence
from typing import Literal

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
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import m

# Aliases for static method calls and type references - after all imports
# Note: u = FlextLdifUtilities is defined in utilities.py to avoid circular import
# Use domain-specific classes that inherit from flext-core
c = FlextLdifConstants  # Domain-specific constants (extends FlextConstants)

# u is imported from utilities.py where FlextLdifUtilities is defined


class FlextLdifUtilities:
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
        - Validation, Generators, Text, Guards
        - Reliability, Checker, Configuration, Context
        - Mapper, Domain, Pagination, Parser

    Usage:
        from flext_ldif._utilities import FlextLdifUtilities

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

    # === Existing submodule classes (real inheritance instead of aliases) ===
    class ACL(FlextLdifUtilitiesACL):
        """ACL utilities for LDIF operations."""

    class Attribute(FlextLdifUtilitiesAttribute):
        """Attribute utilities for LDIF operations."""

    class Constants(FlextLdifConstants):
        """Constants for LDIF operations."""

    class Decorators(FlextLdifUtilitiesDecorators):
        """Decorator utilities for LDIF operations."""

    class Detection(FlextLdifUtilitiesDetection):
        """Detection utilities for LDIF operations."""

    class DN(FlextLdifUtilitiesDN):
        """DN utilities for LDIF operations."""

    class Entry(FlextLdifUtilitiesEntry):
        """Entry utilities for LDIF operations."""

    class Events(FlextLdifUtilitiesEvents):
        """Event utilities for LDIF operations."""

    class Metadata(FlextLdifUtilitiesMetadata):
        """Metadata utilities for LDIF operations."""

    class ObjectClass(FlextLdifUtilitiesObjectClass):
        """ObjectClass utilities for LDIF operations."""

    class OID(FlextLdifUtilitiesOID):
        """OID utilities for LDIF operations."""

    class Parser(FlextLdifUtilitiesParser):
        """LDIF parser utilities."""

    class Parsers(FlextLdifUtilitiesParsers):
        """Parser utilities for LDIF operations."""

    class Schema(FlextLdifUtilitiesSchema):
        """Schema utilities for LDIF operations."""

    class Server(FlextLdifUtilitiesServer):
        """Server utilities for LDIF operations."""

    class Validation(FlextLdifUtilitiesValidation):
        """LDIF validation utilities."""

    class Writer(FlextLdifUtilitiesWriter):
        """Writer utilities for LDIF operations."""

    class Writers(FlextLdifUtilitiesWriters):
        """Writers utilities for LDIF operations."""

    # === Power Methods (new) ===

    @classmethod
    def process(
        cls,
        entries: Sequence[m.Entry],
        *,
        config: ProcessConfig | None = None,
        **kwargs: object,
    ) -> FlextLdifResult[list[m.Entry]]:
        """Universal entry processor.

        Processes entries with DN normalization, attribute normalization,
        and optional server-specific transformations.

        Args:
            entries: Entries to process
            config: ProcessConfig for detailed configuration
            **kwargs: Optional ProcessConfig parameters (source_server,
                target_server, normalize_dns, normalize_attrs) -
                used only if config is None

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
        # Use provided config or build from kwargs
        if config is None:
            # Use model_validate which accepts dict[str, object]
            # and validates at runtime
            config = ProcessConfig.model_validate(kwargs)

        pipeline = ProcessingPipeline(config)
        return FlextLdifResult.from_result(pipeline.execute(list(entries)))

    @classmethod
    def transform(
        cls,
        entries: Sequence[m.Entry],
        *transformers: EntryTransformer[m.Entry],
        fail_fast: bool = True,
    ) -> FlextLdifResult[list[m.Entry]]:
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
        entries: Sequence[m.Entry],
        *filters: EntryFilter[m.Entry],
        mode: Literal["all", "any"] = "all",
    ) -> FlextLdifResult[list[m.Entry]]:
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
        combined: EntryFilter[m.Entry] = filters[0]
        for f in filters[1:]:
            combined = combined & f if mode == "all" else combined | f

        filtered = [entry for entry in entries if combined.matches(entry)]
        return FlextLdifResult.ok(filtered)

    @classmethod
    def validate(
        cls,
        entries: Sequence[m.Entry],
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
    def entry(cls, entry: m.Entry) -> EntryOps:
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


# Define u alias for FlextLdifUtilities (required for __all__ export)
u = FlextLdifUtilities

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
    "FlextLdifConstants",
    "FlextLdifResult",
    "FlextLdifUtilities",
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
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
    "m",
    "u",
]
