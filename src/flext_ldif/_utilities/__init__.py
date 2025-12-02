"""Extracted nested classes from FlextLdifUtilities for better modularity.

This module contains nested classes that were extracted from FlextLdifUtilities
to separate files while maintaining 100% backward compatibility through aliases.

Also provides power method infrastructure:
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
from flext_ldif.constants import FlextLdifUtilitiesConstants


class FlextLdifUtilities:
    """Unified LDIF utilities namespace combining all domain-specific utility classes.

    Organizes LDIF-specific utilities into logical nested classes for better API
    organization and discoverability.

    Power Methods (new):
        - process() - Universal entry processor
        - transform() - Transformation pipeline
        - filter() - Entry filtering
        - validate() - Universal validator
        - write() - Universal writer
        - dn() - Fluent DN operations
        - entry() - Fluent entry operations

    Submodules (existing):
        - ACL, Attribute, Constants, Decorators, Detection
        - DN, Entry, Events, Metadata, ObjectClass
        - OID, Parser, Parsers, Schema, Server
        - Validation, Writer, Writers

    Usage:
        from flext_ldif._utilities import FlextLdifUtilities

        # Existing submodule access
        FlextLdifUtilities.DN.parse("cn=test,dc=example,dc=com")
        FlextLdifUtilities.Entry.has_objectclass(entry, "person")

        # Power methods
        result = FlextLdifUtilities.process(entries, source_server="oid")
        result = FlextLdifUtilities.transform(entries, Normalize.dn())
        result = FlextLdifUtilities.filter(entries, Filter.by_objectclass("person"))
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
    # Power Method Fluent APIs
    "DnOps",
    # Power Method Filters
    "EntryFilter",
    "EntryOps",
    # Power Method Transformers
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
    # Power Method Result
    "FlextLdifResult",
    # Existing utilities
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
    # Power Method Pipeline
    "PipelineStep",
    "PipelineStepProtocol",
    "ProcessConfig",
    # Power Method Builders
    "ProcessConfigBuilder",
    "ProcessingPipeline",
    "RemoveAttrsTransformer",
    "ReplaceBaseDnTransformer",
    "SchemaParseConfig",
    # Power Method Configs
    "ServerType",
    "SimpleTransformer",
    "SortOption",
    "SpaceHandlingOption",
    "Transform",
    "TransformConfig",
    "TransformConfigBuilder",
    # Power Method Protocols
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
]
