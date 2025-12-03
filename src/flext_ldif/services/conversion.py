"""Quirks conversion matrix for LDAP server translation.

This module provides the QuirksConversionMatrix facade that enables
conversion between LDAP server quirks (OUD, OID, OpenLDAP, etc.) using
a universal Entry model as the pivot point.

Conversion Pattern:
 Source -> Write to LDIF -> Parse with Target -> Entry Model

All server conversions work through the universal Entry model, which stores
server-specific metadata. This simplifies conversions to: write->parse pipeline.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import time
import traceback
from collections.abc import Callable, Sequence
from typing import ClassVar, Self, cast, override

from flext_core import (
    FlextLogger,
    FlextRuntime,
    FlextService,
    r,
    t,
    u,
)
from pydantic import Field

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

# Constants
TUPLE_LENGTH_PAIR = 2

# Type alias for source/target - can be server quirk instance or server type string
# Business Rule: ServerQuirkOrType allows either a server quirk instance or a server type string.
# Implication: This enables flexible conversion APIs that accept both runtime instances
# and type identifiers. Use isinstance checks for type narrowing.
type ServerQuirkOrType = FlextLdifServersBase | str

# Type alias for ConvertibleModel Union (used in return types)
# Use actual types from domain models for proper type checking

type ConvertibleModelUnion = (
    FlextLdifModelsDomains.Entry
    | FlextLdifModelsDomains.SchemaAttribute
    | FlextLdifModelsDomains.SchemaObjectClass
    | FlextLdifModelsDomains.Acl
)

# Module-level logger
logger = FlextLogger(__name__)


def _get_schema_quirk(
    quirk: FlextLdifServersBase,
) -> FlextLdifServersBase.Schema:
    """Get schema quirk from base quirk with proper type narrowing.

    Args:
        quirk: Base quirk instance

    Returns:
        Schema quirk instance with proper type

    Raises:
        TypeError: If quirk doesn't have schema capabilities

    """
    # FIRST: Check if already a Schema quirk instance (isinstance check)
    # This avoids false positives from __getattr__ delegation in base class
    if u.is_type(quirk, FlextLdifServersBase.Schema):
        return quirk

    # SECOND: Get schema from schema_quirk attribute
    return _get_schema_from_attribute(quirk)


def _validate_schema_quirk(
    quirk: FlextLdifServersBase,
) -> FlextLdifServersBase.Schema:
    """Validate and return quirk as Schema type."""
    if not u.is_type(quirk, FlextLdifServersBase.Schema):
        msg = f"Expected Schema quirk, got {type(quirk)}"
        raise TypeError(msg)
    return quirk


def _get_schema_from_attribute(
    quirk: FlextLdifServersBase,
) -> FlextLdifServersBase.Schema:
    """Get schema quirk from schema_quirk attribute."""
    if hasattr(quirk, "schema_quirk"):
        schema = quirk.schema_quirk
        if schema is None:
            msg = "Quirk has schema_quirk attribute but it is None"
            raise TypeError(msg)
        if not u.is_type(schema, FlextLdifServersBase.Schema):
            msg = f"Expected Schema quirk, got {type(schema)}"
            raise TypeError(msg)
        return schema
    msg = "Quirk must be a Schema quirk or have schema_quirk attribute"
    raise TypeError(msg)


class FlextLdifConversion(
    FlextService[ConvertibleModelUnion],
):
    """Facade for universal, model-driven quirk-to-quirk conversion.

    Business Rule: Conversion service uses RFC as universal intermediate representation
    for all server-to-server conversions. Conversion pipeline: source.normalize_to_rfc()
    -> RFC Model -> target.denormalize_from_rfc() -> Target Model. This ensures consistent
    conversions regardless of source/target server types.

    Implication: All conversions maintain RFC compliance while adapting to server-specific
    formats. DN case consistency is tracked via DN registry for round-trip conversions.
    Model-driven approach ensures type safety and consistency across conversions.

    This class provides a unified interface for converting LDIF data models between
    different server formats (OUD, OID, etc.) by using RFC as a universal
    intermediate representation. The entire process is model-driven, ensuring
    type safety and consistency.

    The conversion pipeline is:
    1.  `source.normalize_to_rfc(model)` -> RFC Model
    2.  `target.denormalize_from_rfc(RFC Model)` -> Target Model

    FlextService V2 Integration:
    - Inherits from FlextService[FlextLdifTypes.ConvertibleModel]
    - Implements execute() method for health checks
    - Provides stateless conversion operations
    """

    # Maximum number of errors to show in batch conversion
    MAX_ERRORS_TO_SHOW: ClassVar[int] = 5

    # DN registry for tracking DN case consistency during conversions
    dn_registry: FlextLdifModelsDomains.DnRegistry = Field(
        default_factory=FlextLdifModelsDomains.DnRegistry,
    )

    def __new__(cls) -> Self:
        """Create service instance with matching signature for type checker."""
        instance = super().__new__(cls)
        # Type narrowing: ensure instance is of correct type
        if not isinstance(instance, cls):
            msg = f"Expected {cls.__name__}, got {type(instance).__name__}"
            raise TypeError(msg)
        return instance

    def __init__(self) -> None:
        """Initialize the conversion facade with DN case registry."""
        super().__init__()

    @staticmethod
    def _resolve_quirk(quirk_or_type: ServerQuirkOrType) -> FlextLdifServersBase:
        """Resolve server quirk instance from string type or return instance.

        Args:
            quirk_or_type: Either a server quirk instance or server type string

        Returns:
            Server quirk instance

        Raises:
            ValueError: If server type string cannot be resolved

        """
        if u.is_type(quirk_or_type, str):
            server = FlextLdifServer()
            # Get base quirk from registry
            resolved_result = server.quirk(quirk_or_type)
            # Use u.val() for unified result value extraction (DSL pattern)
            resolved = u.val(resolved_result)
            if resolved is None:
                error_msg = f"Unknown server type: {quirk_or_type}"
                raise ValueError(error_msg)
            return resolved
        return quirk_or_type

    @override
    def execute(
        self,
    ) -> r[ConvertibleModelUnion]:
        """Execute conversion service health check.

        Business Rule: Execute method provides service health check for protocol compliance.
        Returns fail-fast error indicating conversion requires explicit source/target parameters.

        Implication: This method enables service-based execution patterns while maintaining
        type safety. Used internally by service orchestration layers for health monitoring.

        Returns:
            FlextResult with empty Entry model for health check

        Note:
            Returns empty Entry model to satisfy FlextService type constraints.
            This is a health check, actual conversions use convert() method.

        """
        try:
            # Return empty Entry for health check to satisfy type constraints
            empty_entry = FlextLdifModelsDomains.Entry(
                dn=FlextLdifModelsDomains.DistinguishedName(value="cn=health-check"),
                attributes=FlextLdifModelsDomains.LdifAttributes(attributes={}),
            )
            return r[ConvertibleModelUnion].ok(empty_entry)
        except Exception as e:
            return r[ConvertibleModelUnion].fail(
                f"Conversion service health check failed: {e}",
            )

    def convert(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        model_instance: FlextLdifTypes.ConvertibleModel,
    ) -> r[ConvertibleModelUnion]:
        """Convert a model from a source server format to a target server format.

        Business Rule: Conversion uses RFC as universal intermediate representation.
        Pipeline: source.normalize_to_rfc() -> RFC Model -> target.denormalize_from_rfc().
        All conversions emit ConversionEvent for audit trail (MANDATORY). DN case
        consistency is tracked via DN registry for round-trip conversions.

        Implication: Model-based conversion ensures type safety and consistency.
        Conversion events enable monitoring and debugging of conversion operations.
        Server-specific transformations are handled by quirks, ensuring RFC compliance.

        Model-based conversion only - no legacy string/dict support.
        Emits ConversionEvent for all conversions (MANDATORY - eventos obrigatórios).

        Args:
            source: Source quirk instance or server type string
            target: Target quirk instance or server type string
            model_instance: Model instance to convert (Entry, SchemaAttribute, SchemaObjectClass, or Acl)

        Returns:
            FlextResult with converted model (target server format)

        """
        # Track conversion duration (MANDATORY - eventos obrigatórios)
        start_time = time.perf_counter()

        # Determine conversion type and get source/target format names
        source_format = FlextLdifUtilities.match(
            source,
            (str, lambda s: s),
            default=lambda src: getattr(src, "server_name", "unknown"),
        )
        target_format = FlextLdifUtilities.match(
            target,
            (str, lambda t: t),
            default=lambda tgt: getattr(tgt, "server_name", "unknown"),
        )

        # Model-based conversion only
        model_type = type(model_instance).__name__
        conversion_operation = f"convert_{model_type}"

        self.logger.debug(
            "Converting model",
            source_format=source_format,
            target_format=target_format,
            model_type=model_type,
        )

        # Execute model-based conversion
        result = self._convert_model(source, target, model_instance)

        # Calculate duration and emit ConversionEvent (MANDATORY - eventos obrigatórios)
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Emit ConversionEvent with results
        # Use u.when() for conditional assignment (DSL pattern)
        items_converted = u.when(condition=result.is_success, then_value=1, else_value=0)
        items_failed = u.when(condition=result.is_success, then_value=0, else_value=1)

        # Create conversion event config
        conversion_config = FlextLdifModels.ConversionEventConfig(
            conversion_operation=conversion_operation,
            source_format=source_format,
            target_format=target_format,
            items_processed=1,
            items_converted=items_converted,
            items_failed=items_failed,
            conversion_duration_ms=duration_ms,
            error_details=u.when(
                condition=u.val(result) is None,
                then_value=[
                    FlextLdifModelsDomains.ErrorDetail(
                        item=model_type,
                        error=u.err(result) or "Unknown error",
                    ),
                ],
                else_value=[],
            ),
        )
        _ = FlextLdifUtilities.Events.log_and_emit_conversion_event(
            logger=logger,
            config=conversion_config,
            log_level=u.when(condition=result.is_success, then_value="info", else_value="error"),
        )

        return result

    def _convert_model(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        model_instance: FlextLdifTypes.ConvertibleModel,
    ) -> r[ConvertibleModelUnion]:
        """Convert model between source and target server formats via write->parse pipeline.

        Business Rule: Internal conversion method uses write->parse pipeline for
        server-agnostic conversions. Source model is written to LDIF using source quirk,
        then parsed using target quirk. This ensures RFC compliance while adapting to
        server-specific formats.

        Implication: Write->parse pipeline enables conversions between any server types
        without direct server-to-server conversion logic. All conversions maintain RFC
        compliance with server-specific enhancements.

        Supports Entry, SchemaAttribute, SchemaObjectClass, and Acl conversions.
        Uses write->parse pipeline for server-agnostic conversions.

        This approach eliminates the need for normalize_to_rfc/denormalize_from_rfc
        and ensures all conversions go through the same parse/write codepath used
        in normal parsing and writing operations.
        """
        try:
            # Resolve quirks if they are strings
            source_quirk = self._resolve_quirk(source)
            target_quirk = self._resolve_quirk(target)

            # Route to appropriate conversion handler based on model type
            # Each branch returns a specific subtype of ConvertibleModel Union
            return FlextLdifUtilities.match(
                model_instance,
                (
                    FlextLdifModelsDomains.Entry,
                    lambda e: self._convert_entry(source_quirk, target_quirk, e),
                ),
                (
                    FlextLdifModelsDomains.SchemaAttribute,
                    lambda a: self._convert_schema_attribute(
                        source_quirk,
                        target_quirk,
                        a,
                    ),
                ),
                (
                    FlextLdifModelsDomains.SchemaObjectClass,
                    lambda oc: self._convert_schema_objectclass(
                        source_quirk,
                        target_quirk,
                        oc,
                    ),
                ),
                (
                    FlextLdifModelsDomains.Acl,
                    lambda acl: self._convert_acl(source_quirk, target_quirk, acl),
                ),
                default=lambda _: r.fail(
                    f"Unsupported model type for conversion: {type(model_instance).__name__}",
                ),
            )

        except Exception as e:
            return r.fail(f"Model conversion failed: {e}")

    @staticmethod
    def _normalize_metadata_value(value: object) -> t.MetadataAttributeValue:
        """Normalize metadata value to proper type."""
        return FlextLdifUtilities.match(
            value,
            (
                lambda v: u.is_type(v, dict, list, str, int, float, bool),
                lambda v: v,
            ),
            default=lambda v: str(v) if v is not None else "",
        )

    @staticmethod
    def _analyze_boolean_conversions(
        boolean_conversions: object,
        target_server_type: str,
    ) -> dict[str, dict[str, str]]:
        """Analyze boolean conversions for target compatibility."""
        analysis: dict[str, dict[str, str]] = {}
        if not boolean_conversions:
            return analysis
        boolean_conv_typed = cast("t.GeneralValueType", boolean_conversions)
        if not FlextRuntime.is_dict_like(boolean_conv_typed):
            return analysis

        def process_conversion(item: tuple[str, object]) -> tuple[str, dict[str, str]] | None:
            """Process single conversion info."""
            attr_name, conv_info = item
            conv_info_typed = cast("t.GeneralValueType", conv_info)
            if not FlextRuntime.is_dict_like(conv_info_typed):
                return None
            original_format = (
                u.take(conv_info_typed, "format", default="")
                if u.is_type(conv_info_typed, dict)
                else ""
            )
            return (
                f"boolean_{attr_name}",
                {
                    "source_format": str(original_format),
                    "target_server": str(target_server_type),
                    "action": "convert_to_target_format",
                },
            )

        return FlextLdifUtilities.pipe(
            boolean_conv_typed,
            lambda d: u.pairs(d) if u.is_type(d, dict) else [],
            lambda pairs: u.process(
                pairs,
                processor=process_conversion,
                on_error="skip",
            ),
            lambda result: u.reduce_dict(
                u.map_filter(
                    u.val(result, default=[]),
                    predicate=lambda item: (
                        u.is_type(item, tuple)
                        and u.count(item) == TUPLE_LENGTH_PAIR
                        and u.is_type(item[0], str)
                        and u.is_type(item[1], dict)
                    ),
                ),
            ),
            lambda reduced: u.evolve(analysis, reduced),
        )

    @staticmethod
    def _analyze_attribute_case(
        original_attribute_case: object,
        target_server_type: str,
    ) -> dict[str, dict[str, t.MetadataAttributeValue]]:
        """Analyze attribute case for target compatibility."""
        return FlextLdifUtilities.when(
            condition=bool(original_attribute_case),
            then=lambda: {
                "attribute_case": {
                    "source_case": FlextLdifConversion._normalize_metadata_value(
                        original_attribute_case,
                    ),
                    "target_server": str(target_server_type),
                    "action": "apply_target_conventions",
                }
            },
            else_={},
        )

    @staticmethod
    def _analyze_dn_format(
        original_format_details: object,
        target_server_type: str,
    ) -> dict[str, dict[str, t.MetadataAttributeValue]]:
        """Analyze DN spacing for target compatibility."""
        return FlextLdifUtilities.pipe(
            original_format_details,
            lambda d: (
                u.take(d, "dn_spacing")
                if u.is_type(d, dict)
                else None
            ),
            lambda spacing: (
                {
                    "dn_format": {
                        "source_dn": FlextLdifConversion._normalize_metadata_value(
                            spacing,
                        ),
                        "target_server": str(target_server_type),
                        "action": "normalize_for_target",
                    }
                }
                if spacing
                else {}
            ),
        )

    def _analyze_metadata_for_conversion(
        self,
        source_metadata: (
            FlextLdifModelsDomains.QuirkMetadata
            | FlextLdifModelsMetadata.DynamicMetadata
            | None
        ),
        target_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str,
    ) -> dict[str, str | dict[str, str | t.MetadataAttributeValue]]:
        """Analyze source metadata for intelligent conversion to target server.

        This method analyzes metadata to guide conversion decisions.
        It does NOT directly restore original values - it analyzes and recommends
        appropriate conversions for the target server.

        Args:
            source_metadata: Original entry metadata (may be None or QuirkMetadata)
            target_server_type: Target LDAP server type

        Returns:
            Analysis dictionary with conversion recommendations

        """
        conversion_analysis: dict[
            str,
            str | dict[str, str | t.MetadataAttributeValue],
        ] = {}

        if not source_metadata or not hasattr(source_metadata, "boolean_conversions"):
            return conversion_analysis

        target_server_str = str(target_server_type)
        get_boolean = u.prop("boolean_conversions")
        get_attr_case = u.prop("original_attribute_case")
        get_format_details = u.prop("original_format_details")

        boolean_conversions = u.maybe(
            get_boolean(source_metadata),
            default={},
        )
        boolean_analysis = FlextLdifConversion._analyze_boolean_conversions(
            boolean_conversions, target_server_str
        )

        return FlextLdifUtilities.pipe(
            conversion_analysis,
            lambda acc: u.evolve(
                acc,
                u.map_dict(
                    boolean_analysis,
                    mapper=lambda k, v: (
                        k,
                        cast("str | dict[str, str | t.MetadataAttributeValue]", v),
                    ),
                ),
            ),
            lambda acc: u.evolve(
                acc,
                FlextLdifConversion._analyze_attribute_case(
                    u.maybe(get_attr_case(source_metadata), default={}),
                    target_server_str,
                ),
            ),
            lambda acc: u.evolve(
                acc,
                FlextLdifConversion._analyze_dn_format(
                    u.maybe(get_format_details(source_metadata), default={}),
                    target_server_str,
                ),
            ),
        )

    def _convert_entry(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        entry: FlextLdifModelsDomains.Entry,
    ) -> r[ConvertibleModelUnion]:
        """Convert Entry model directly without serialization.

        Entry models are already RFC-compliant. Instead of Source.write() -> Target.parse()
        (which fails because parsers expect their own format), we return the model directly.
        The target.write() will be called by the consumer to serialize to target format.

        Architecture: Entry RFC Model -> Target.write() -> Target LDIF format
        """
        try:
            # Validate entry DN using FlextLdifUtilities.DN before conversion
            entry_dn = (
                str(FlextLdifUtilities.DN.get_dn_value(entry.dn)) if entry.dn else ""
            )
            if not FlextLdifUtilities.DN.validate(entry_dn):
                return r[ConvertibleModelUnion].fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )

            # Register entry DN for case consistency during conversion
            _ = self.dn_registry.register_dn(entry_dn)

            # Clone the model to avoid mutating the original
            converted_entry = entry.model_copy(deep=True)

            # Get target server type and validate against valid server types
            get_server_name = u.prop("server_name")
            target_server_type_raw = u.maybe(
                get_server_name(target_quirk),
                default="unknown",
            )

            # Normalize server type using constants (handles aliases and canonicalization)
            target_server_type_str = FlextLdifUtilities.or_(
                target_server_type_raw if target_server_type_raw != "unknown" else None,
                default=FlextLdifConstants.ServerTypes.RFC,
            )
            # normalize_server_type returns canonical ServerTypeLiteral value (validated at runtime)
            validated_quirk_type = FlextLdifConstants.normalize_server_type(
                str(target_server_type_str),
            )

            # Use validated_quirk_type for analysis
            conversion_analysis = self._analyze_metadata_for_conversion(
                entry.metadata,
                validated_quirk_type,
            )

            # Store analysis in converted entry for downstream processing
            get_metadata = u.prop("metadata")
            get_extensions = u.prop("extensions")

            converted_entry = FlextLdifUtilities.pipe(
                converted_entry,
                lambda entry: (
                    entry.model_copy(
                        update={
                            "metadata": FlextLdifModelsDomains.QuirkMetadata(
                                quirk_type=validated_quirk_type,
                            )
                        },
                        deep=True,
                    )
                    if not get_metadata(entry)
                    else entry
                ),
                lambda entry: (
                    entry.model_copy(
                        update={
                            "metadata": entry.metadata.model_copy(
                                update={
                                    "extensions": (
                                        FlextLdifModelsMetadata.DynamicMetadata()
                                        if not get_extensions(entry.metadata)
                                        else entry.metadata.extensions
                                    )
                                },
                                deep=True,
                            )
                        },
                        deep=True,
                    )
                    if get_metadata(entry)
                    else entry
                ),
                lambda entry: (
                    entry.model_copy(
                        update={
                            "metadata": entry.metadata.model_copy(
                                update={
                                    "extensions": u.evolve(
                                        entry.metadata.extensions or FlextLdifModelsMetadata.DynamicMetadata(),
                                        {
                                            "conversion_analysis": str(conversion_analysis),
                                            FlextLdifConstants.MetadataKeys.CONVERTED_FROM_SERVER: u.maybe(
                                                u.prop("server_name")(source_quirk),
                                                default="unknown",
                                            ),
                                        },
                                    )
                                },
                                deep=True,
                            )
                        },
                        deep=True,
                    )
                    if conversion_analysis and get_metadata(entry)
                    else entry.model_copy(
                        update={
                            "metadata": entry.metadata.model_copy(
                                update={
                                    "extensions": {
                                        FlextLdifConstants.MetadataKeys.CONVERTED_FROM_SERVER: u.maybe(
                                            u.prop("server_name")(source_quirk),
                                            default="unknown",
                                        ),
                                    }
                                },
                                deep=True,
                            )
                        },
                        deep=True,
                    )
                    if get_metadata(entry)
                    else entry
                ),
            )

            # Return RFC model - consumer will call target.write() to serialize
            return r[ConvertibleModelUnion].ok(converted_entry)

        except Exception as e:
            logger.exception(
                "Failed to convert Entry model",
                error=str(e),
            )
            return r[ConvertibleModelUnion].fail(
                f"Entry conversion failed: {e}"
            )

    @staticmethod
    def _get_schema_quirk_safe(
        quirk: FlextLdifServersBase,
        quirk_type: str,
    ) -> r[FlextLdifServersBase.Schema]:
        """Get schema quirk safely with error handling."""
        return FlextLdifUtilities.try_(
            lambda: _get_schema_quirk(quirk),
            default=None,
        ).pipe(
            lambda result: (
                r.ok(result)
                if result is not None
                else r.fail(f"{quirk_type} quirk error: Schema not available")
            ),
        )

    @staticmethod
    def _validate_ldif_string(ldif_string: str, operation: str) -> r[str]:
        """Validate LDIF string is not empty."""
        return FlextLdifUtilities.when(
            condition=bool(ldif_string and ldif_string.strip()),
            then=lambda: r.ok(ldif_string),
            else_=lambda: r.fail(
                f"Write operation returned empty {operation} LDIF",
            ),
        )

    @staticmethod
    def _process_schema_conversion_pipeline(
        config: FlextLdifModelsConfig.SchemaConversionPipelineConfig,
    ) -> r[ConvertibleModelUnion]:
        """Process schema conversion pipeline (write->parse)."""
        write_result = config.write_method(config.source_schema)
        # Use u.val() for unified result value extraction (DSL pattern)
        write_value = u.val(write_result)
        if write_value is None:
            return r.fail(
                f"Failed to write {config.item_name} in source format: {u.err(write_result)}",
            )

        ldif_result = FlextLdifConversion._validate_ldif_string(write_value, config.item_name)
        ldif_string = u.val(ldif_result)
        if ldif_string is None:
            return cast("r[ConvertibleModelUnion]", ldif_result)

        parse_result = config.parse_method(config.target_schema, ldif_string)
        # Use u.val() for unified result value extraction (DSL pattern)
        parsed_value = u.val(parse_result)
        if parsed_value is None:
            return r.fail(
                f"Failed to parse {config.item_name} in target format: {u.err(parse_result)}",
            )
        return r[ConvertibleModelUnion].ok(
            cast("ConvertibleModelUnion", parsed_value),
        )

    def _convert_schema_attribute(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        attribute: FlextLdifModelsDomains.SchemaAttribute,
    ) -> r[ConvertibleModelUnion]:
        """Convert SchemaAttribute model via write_attribute->parse_attribute pipeline."""
        try:
            source_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                source_quirk, "Source"
            )
            # Use u.val() for unified result value extraction (DSL pattern)
            source_schema = u.val(source_schema_result)
            if source_schema is None:
                return cast("r[ConvertibleModelUnion]", source_schema_result)

            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk, "Target"
            )
            target_schema = u.val(target_schema_result)
            if target_schema is None:
                return cast("r[ConvertibleModelUnion]", target_schema_result)
            config = FlextLdifModelsConfig.SchemaConversionPipelineConfig(
                source_schema=source_schema,
                target_schema=target_schema,
                write_method=lambda s: cast("FlextLdifServersBase.Schema", s).write_attribute(attribute),
                parse_method=lambda t, ldif: cast(
                    "r[object]",
                    cast("FlextLdifServersBase.Schema", t).parse_attribute(ldif),
                ),
                item_name="attribute",
            )
            return FlextLdifConversion._process_schema_conversion_pipeline(config)

        except Exception as e:
            return r[ConvertibleModelUnion].fail(
                f"SchemaAttribute conversion failed: {e}"
            )

    def _convert_schema_objectclass(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        objectclass: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> r[ConvertibleModelUnion]:
        """Convert SchemaObjectClass model via write_objectclass->parse_objectclass pipeline."""
        try:
            source_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                source_quirk, "Source"
            )
            # Use u.val() for unified result value extraction (DSL pattern)
            source_schema = u.val(source_schema_result)
            if source_schema is None:
                return cast("r[ConvertibleModelUnion]", source_schema_result)

            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk, "Target"
            )
            target_schema = u.val(target_schema_result)
            if target_schema is None:
                return cast("r[ConvertibleModelUnion]", target_schema_result)
            config = FlextLdifModelsConfig.SchemaConversionPipelineConfig(
                source_schema=source_schema,
                target_schema=target_schema,
                write_method=lambda s: cast("FlextLdifServersBase.Schema", s).write_objectclass(objectclass),
                parse_method=lambda t, ldif: cast(
                    "r[object]",
                    cast("FlextLdifServersBase.Schema", t).parse_objectclass(ldif),
                ),
                item_name="objectclass",
            )
            return FlextLdifConversion._process_schema_conversion_pipeline(config)

        except Exception as e:
            return r[ConvertibleModelUnion].fail(
                f"SchemaObjectClass conversion failed: {e}"
            )

    def _get_acl_classes(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
    ) -> r[
        tuple[
            FlextLdifProtocols.Quirks.AclProtocol,
            FlextLdifProtocols.Quirks.AclProtocol,
        ]
    ]:
        """Get and validate ACL classes from quirks."""
        source_class = type(source_quirk)
        target_class = type(target_quirk)

        if not hasattr(source_class, "Acl"):
            return r.fail(
                f"Source quirk {source_class.__name__} does not have Acl nested class",
            )
        if not hasattr(target_class, "Acl"):
            return r.fail(
                f"Target quirk {target_class.__name__} does not have Acl nested class",
            )

        # Business Rule: Create ACL quirks and validate protocol compliance
        # ACL quirks must implement AclProtocol with parse() and write() methods
        # Use structural checks first, then isinstance for runtime_checkable Protocol
        # This ensures type safety while satisfying pyright strict mode
        source_acl = source_class.Acl()
        target_acl = target_class.Acl()

        # Business Rule: Validate ACL quirks implement AclProtocol structurally
        # AclProtocol requires parse() and write() methods per protocol definition
        # Use structural checks only (hasattr) to avoid pyright Protocol overlap warnings
        # Runtime behavior: Structural typing ensures correct implementation
        required_methods = ("parse", "write")
        if not u.all_(
            *(
                hasattr(source_acl, method) and callable(getattr(source_acl, method))
                for method in required_methods
            )
        ):
            return r.fail(
                f"Source ACL quirk {source_class.__name__} missing required AclProtocol methods",
            )
        if not u.all_(
            *(
                hasattr(target_acl, method) and callable(getattr(target_acl, method))
                for method in required_methods
            )
        ):
            return r.fail(
                f"Target ACL quirk {target_class.__name__} missing required AclProtocol methods",
            )

        # Use cast after structural validation - satisfies pyright without Protocol overlap warnings
        # Business Rule: Structural typing ensures runtime correctness, cast satisfies type checker
        source_acl_typed = cast("FlextLdifProtocols.Quirks.AclProtocol", source_acl)
        target_acl_typed = cast("FlextLdifProtocols.Quirks.AclProtocol", target_acl)
        return r.ok((source_acl_typed, target_acl_typed))

    def _write_acl_to_string(
        self,
        acl: FlextLdifModelsDomains.Acl,
        source_acl: FlextLdifProtocols.Quirks.AclProtocol,
    ) -> r[str]:
        """Write ACL to LDIF string."""
        # Business Rule: Validate ACL model satisfies AclProtocol before writing
        # Acl model satisfies AclProtocol structurally (has required properties/methods)
        # Use structural checks only to avoid pyright Protocol overlap warnings
        # Runtime behavior: Structural typing ensures correct implementation
        # Check required AclProtocol attributes exist
        if not hasattr(acl, "permissions") or not hasattr(acl, "target"):
            return r.fail(
                f"ACL model missing required AclProtocol attributes: {type(acl).__name__}",
            )
        # Use cast after structural validation - satisfies pyright without Protocol overlap warnings
        # Business Rule: Structural typing ensures runtime correctness, cast satisfies type checker
        acl_protocol = cast("FlextLdifProtocols.Models.AclProtocol", acl)
        write_result = source_acl.write(acl_protocol)
        # Use u.val() for unified result value extraction (DSL pattern)
        write_value = u.val(write_result)
        if write_value is None:
            return r.fail(f"Failed to write ACL in source format: {u.err(write_result)}")

        # Use u.val() for unified result value extraction (DSL pattern)
        unwrapped = u.val(write_result)
        if unwrapped is None:
            return r.fail(u.err(write_result) or "Failed to write ACL")
        if not u.is_type(unwrapped, str):
            return r.fail(
                f"Write operation returned unexpected type: {type(unwrapped).__name__}, expected str",
            )

        ldif_string: str = unwrapped
        if not ldif_string or not ldif_string.strip():
            return r.fail("Write operation returned empty ACL LDIF")

        return r.ok(ldif_string)

    def _parse_acl_from_string(
        self,
        ldif_string: str,
        target_acl: FlextLdifProtocols.Quirks.AclProtocol,
    ) -> r[FlextLdifModelsDomains.Acl]:
        """Parse ACL from LDIF string."""
        parse_result = target_acl.parse(ldif_string)
        # Use u.val() for unified result value extraction (DSL pattern)
        converted_acl = u.val(parse_result)
        if converted_acl is None:
            return r.fail(f"Failed to parse ACL in target format: {u.err(parse_result)}")
        if not u.is_type(converted_acl, FlextLdifModelsDomains.Acl):
            return r.fail(
                f"ACL conversion produced invalid type: {type(converted_acl).__name__}, expected Acl",
            )

        return r.ok(converted_acl)

    @staticmethod
    def _perms_dict_to_model(
        perms_dict: dict[str, bool | None],
    ) -> FlextLdifModelsDomains.AclPermissions:
        """Convert permissions dict to AclPermissions model.

        Args:
            perms_dict: Dict with permission mappings

        Returns:
            AclPermissions model with non-None values

        """
        # Remove None values for cleaner model using u
        transform_result = u.transform(
            cast("dict[str, t.GeneralValueType]", perms_dict),
            strip_none=True,
        )
        # Use u.val() with fallback using u.when() (DSL pattern)
        clean_dict = u.when(
            condition=transform_result.is_success,
            then_value=u.val(transform_result),
            else_value=u.where(perms_dict, predicate=lambda _k, v: v is not None),
        )
        return FlextLdifModelsDomains.AclPermissions(**clean_dict)  # type: ignore[arg-type]

    @staticmethod
    def _normalize_permission_key(key: str) -> str:
        """Normalize permission key for mapping."""
        return FlextLdifUtilities.switch(
            key,
            {"self_write": "selfwrite"},
            default=key,
        )

    @staticmethod
    def _build_permissions_dict(mapped_perms: dict[str, bool]) -> dict[str, bool | None]:
        """Build permissions dict with standard keys."""
        key_mapping = {
            "read": "read",
            "write": "write",
            "add": "add",
            "delete": "delete",
            "search": "search",
            "compare": "compare",
            "self_write": "selfwrite",
            "proxy": "proxy",
            "browse": "browse",
            "auth": "auth",
            "all": "all",
        }
        return FlextLdifUtilities.map_dict(
            key_mapping,
            mapper=lambda _key, mapped_key: u.take(mapped_perms, mapped_key),
        )

    @staticmethod
    def _apply_oid_to_oud_mapping(
        orig_perms_dict: dict[str, bool],
        converted_acl: FlextLdifModelsDomains.Acl,
        perms_to_model: Callable[[dict[str, bool | None]], object],
    ) -> FlextLdifModelsDomains.Acl:
        """Apply OID to OUD permission mapping."""
        normalized_orig_perms = u.map_dict(
            orig_perms_dict,
            mapper=lambda k, v: (
                FlextLdifConversion._normalize_permission_key(k),
                v,
            ),
        )
        mapped_perms = FlextLdifUtilities.ACL.map_oid_to_oud_permissions(
            normalized_orig_perms,
        )
        oid_to_oud_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        return converted_acl.model_copy(
            update={"permissions": perms_to_model(oid_to_oud_perms)},
            deep=True,
        )

    @staticmethod
    def _apply_oud_to_oid_mapping(
        orig_perms_dict: dict[str, bool],
        converted_acl: FlextLdifModelsDomains.Acl,
        perms_to_model: Callable[[dict[str, bool | None]], object],
    ) -> FlextLdifModelsDomains.Acl:
        """Apply OUD to OID permission mapping."""
        mapped_perms = FlextLdifUtilities.ACL.map_oud_to_oid_permissions(
            orig_perms_dict,
        )
        oud_to_oid_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        return converted_acl.model_copy(
            update={"permissions": perms_to_model(oud_to_oid_perms)},
            deep=True,
        )

    def _apply_permission_mapping(
        self,
        config: FlextLdifModelsConfig.PermissionMappingConfig | None = None,
        **kwargs: object,
    ) -> FlextLdifModelsDomains.Acl:
        """Apply permission mapping based on server types.

        Args:
            config: Permission mapping configuration
            **kwargs: Backward compatibility parameters

        """
        if config is None:
            # Backward compatibility: build config from kwargs
            original_acl_raw = kwargs.pop("original_acl", None)
            converted_acl_raw = kwargs.pop("converted_acl", None)
            orig_perms_dict_raw = kwargs.pop("orig_perms_dict", None)
            source_server_type_raw = kwargs.pop("source_server_type", None)
            target_server_type_raw = kwargs.pop("target_server_type", None)
            converted_has_permissions_raw = kwargs.pop("converted_has_permissions", False)

            config = FlextLdifModelsConfig.PermissionMappingConfig(
                original_acl=cast("FlextLdifModelsDomains.Acl", original_acl_raw),
                converted_acl=cast("FlextLdifModelsDomains.Acl", converted_acl_raw),
                orig_perms_dict=cast("dict[str, bool]", orig_perms_dict_raw),
                source_server_type=cast("str | None", source_server_type_raw),
                target_server_type=cast("str | None", target_server_type_raw),
                converted_has_permissions=cast("bool", converted_has_permissions_raw),
            )

        normalized_source = u.maybe(
            config.source_server_type,
            mapper=FlextLdifConstants.normalize_server_type,
        )
        normalized_target = u.maybe(
            config.target_server_type,
            mapper=FlextLdifConstants.normalize_server_type,
        )

        mapping_type = FlextLdifUtilities.match(
            (normalized_source, normalized_target),
            (
                lambda pair: pair == ("oid", "oud"),
                lambda _pair: "oid_to_oud",
            ),
            (
                lambda pair: pair == ("oud", "oid"),
                lambda _pair: "oud_to_oid",
            ),
            (
                lambda _pair: (
                    not config.converted_has_permissions
                    and config.original_acl.permissions is not None
                ),
                lambda _pair: "preserve_original",
            ),
            default=lambda _pair: "none",
        )

        logger.debug(
            "ACL mapping decision",
            mapping_type=mapping_type,
            normalized_source=normalized_source,
            normalized_target=normalized_target,
        )

        return FlextLdifUtilities.switch(
            mapping_type,
            {
                "oid_to_oud": lambda: FlextLdifConversion._apply_oid_to_oud_mapping(
                    config.orig_perms_dict,
                    config.converted_acl,
                    self._perms_dict_to_model,
                ),
                "oud_to_oid": lambda: FlextLdifConversion._apply_oud_to_oid_mapping(
                    config.orig_perms_dict,
                    config.converted_acl,
                    self._perms_dict_to_model,
                ),
                "preserve_original": lambda: config.converted_acl.model_copy(
                    update={
                        "permissions": config.original_acl.permissions.model_copy(
                            deep=True,
                        )
                    },
                    deep=True,
                ),
            },
            default=lambda: config.converted_acl,
        )()

    def _preserve_acl_metadata(
        self,
        original_acl: FlextLdifModelsDomains.Acl,
        converted_acl: FlextLdifModelsDomains.Acl,
        source_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | str
        | None = None,
        target_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | str
        | None = None,
    ) -> FlextLdifModelsDomains.Acl:
        """Preserve permissions and metadata from original ACL.

        Args:
            original_acl: The original ACL before conversion
            converted_acl: The converted ACL (modified in-place)
            source_server_type: Server type of the source ACL (use FlextLdifConstants.ServerTypes)
            target_server_type: Server type of the target ACL (use FlextLdifConstants.ServerTypes)

        """
        # Preserve permissions from original ACL model since parsing may not extract them correctly
        # Check if converted ACL has actual permissions set (any field True)
        # Explicitly convert to bool to ensure type is bool not AclPermissions | None
        permission_fields = (
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "self_write",
            "proxy",
            "browse",
            "auth",
            "all",
        )
        converted_has_permissions: bool = bool(
            converted_acl.permissions
            and u.any_(
                *(
                    getattr(converted_acl.permissions, field, False)
                    for field in permission_fields
                )
            ),
        )

        if original_acl.permissions:
            # Get original permissions as dict for mapping
            orig_perms_dict = original_acl.permissions.model_dump(exclude_unset=True)
            # Remove None values and fields that are False (only keep True permissions)
            orig_perms_dict = u.filter(
                orig_perms_dict,
                predicate=lambda _k, v: v is True,  # Only include explicitly True permissions
            )

            logger.debug(
                "ACL permission preservation",
                source_server_type=source_server_type,
                target_server_type=target_server_type,
                original_permissions=orig_perms_dict,
            )

            if orig_perms_dict:
                converted_acl = self._apply_permission_mapping(
                    original_acl=original_acl,
                    converted_acl=converted_acl,
                    orig_perms_dict=orig_perms_dict,
                    source_server_type=source_server_type,
                    target_server_type=target_server_type,
                    converted_has_permissions=converted_has_permissions,
                )

        # Preserve metadata from original ACL model for proper server-specific formatting
        # Metadata contains source_subject_type and other conversion hints needed by target writers
        get_metadata = u.prop("metadata")
        get_extensions = u.prop("extensions")

        return FlextLdifUtilities.pipe(
            converted_acl,
            lambda acl: (
                acl.model_copy(
                    update={"metadata": original_acl.metadata.model_copy(deep=True)},
                    deep=True,
                )
                if get_metadata(original_acl) and not get_metadata(acl)
                else acl
            ),
            lambda acl: (
                FlextLdifUtilities.pipe(
                    acl,
                    lambda a: (
                        u.as_type(
                            get_extensions(a.metadata).model_dump(),
                            target="dict",
                            default={},
                        )
                        if get_metadata(a)
                        and get_extensions(a.metadata)
                        else {}
                    ),
                    lambda conv_ext: (
                        u.pipe(
                            u.as_type(
                                get_extensions(original_acl.metadata).model_dump(),
                                target="dict",
                                default={},
                            ),
                            lambda orig_ext: u.merge(conv_ext, orig_ext),
                            lambda merge_result: u.when(
                                condition=merge_result.is_success,
                                then_value=u.val(merge_result),
                                else_value=conv_ext,
                            ),
                        )
                        if get_metadata(original_acl)
                        and get_extensions(original_acl.metadata)
                        else conv_ext
                    ),
                    lambda merged_ext: (
                        acl.model_copy(
                            update={
                                "metadata": acl.metadata.model_copy(
                                    update={
                                        "extensions": FlextLdifModelsMetadata.DynamicMetadata(
                                            **merged_ext
                                        )
                                    },
                                    deep=True,
                                )
                            },
                            deep=True,
                        )
                        if merged_ext and get_metadata(acl)
                        else acl
                    ),
                )
                if (
                    get_metadata(original_acl)
                    and get_extensions(original_acl.metadata)
                    and get_metadata(acl)
                )
                else acl
            ),
        )

    def _convert_acl(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        acl: FlextLdifModelsDomains.Acl,
    ) -> r[ConvertibleModelUnion]:
        """Convert Acl model via Entry RFC + Metadata pipeline.

        Architecture: Source Acl -> Entry RFC + Metadata -> Target Acl
        - Source writes Acl to Entry.metadata.acls (RFC format)
        - Target parses Entry.metadata.acls to extract Acl (preserves subject via metadata)
        """
        try:
            # Create a deep copy of the ACL model to avoid modifying the original
            acl = acl.model_copy(deep=True)

            # Step 1: Create Entry RFC with Acl in metadata.acls
            # This preserves the Acl model with all its fields (subject, permissions, etc.)
            entry_dn = FlextLdifModelsDomains.DistinguishedName(
                value="cn=acl-conversion,dc=example,dc=com",
            )
            entry_attributes = FlextLdifModelsDomains.LdifAttributes(attributes={})

            # Create metadata with ACL stored in metadata.acls
            # Get server_type and default to None (RFC) if not valid
            get_server_type = u.prop("server_type")
            server_type_attr = u.maybe(get_server_type(source_quirk))

            # Use normalize_server_type directly - it handles aliases and validation
            source_server_type = FlextLdifUtilities.try_(
                lambda: (
                    FlextLdifConstants.normalize_server_type(server_type_attr)
                    if u.is_type(server_type_attr, str)
                    else None
                ),
                default=None,
            )

            metadata = FlextLdifModelsDomains.QuirkMetadata.create_for(
                source_server_type,
                extensions={},
            )
            metadata.acls = [acl]  # Store ACL in metadata.acls

            # Create Entry RFC with ACL in metadata
            rfc_entry = FlextLdifModelsDomains.Entry(
                dn=entry_dn,
                attributes=entry_attributes,
                metadata=metadata,
            )

            # Step 2: Convert Entry using Entry conversion (which preserves metadata.acls)
            entry_result = self._convert_entry(source_quirk, target_quirk, rfc_entry)
            # Use u.val() for unified result value extraction (DSL pattern)
            converted_entry = u.val(entry_result)
            if converted_entry is None:
                return entry_result
            if not u.is_type(converted_entry, FlextLdifModelsDomains.Entry):
                return r.fail(
                    f"Entry conversion returned unexpected type: {type(converted_entry).__name__}",
                )

            # Step 3: Extract ACL from converted Entry metadata.acls
            get_metadata = u.prop("metadata")
            get_acls = u.prop("acls")
            metadata = u.maybe(get_metadata(converted_entry))
            acls = u.maybe(get_acls(metadata)) if metadata else None

            if not acls:
                return r.fail(
                    "Converted entry has no ACLs in metadata.acls",
                )

            # Get first ACL from metadata (should be the converted one)
            # Type narrowing: metadata.acls contains FlextLdifModelsDomains.Acl, convert to FlextLdifModels.Acl
            domain_acl = acls[0]
            # Convert domain Acl to public Acl model
            converted_acl = FlextLdifUtilities.match(
                domain_acl,
                (
                    FlextLdifModelsDomains.Acl,
                    lambda acl: acl,
                ),
                default=lambda acl: FlextLdifModelsDomains.Acl.model_validate(
                    acl.model_dump(),
                ),
            )

            # Get target server type for permission mapping
            get_server_type = u.prop("server_type")
            target_server_type_raw = u.maybe(
                get_server_type(target_quirk),
                default="unknown",
            )
            # Use normalize_server_type directly - it handles aliases and validation
            target_server_type = FlextLdifUtilities.try_(
                lambda: (
                    FlextLdifConstants.normalize_server_type(target_server_type_raw)
                    if u.is_type(target_server_type_raw, str)
                    and target_server_type_raw != "unknown"
                    else None
                ),
                default=None,
            )

            # Preserve permissions and metadata from original ACL
            # Pass server types so permission mapping can be applied during preservation
            converted_acl = self._preserve_acl_metadata(
                acl,
                converted_acl,
                source_server_type=source_server_type,
                target_server_type=target_server_type,
            )

            # CRITICAL FIX: Update server_type to target server to ensure ACL writers recognize it
            # This is required so that the OID writer knows to use "by group=" syntax for OID ACLs
            converted_acl = converted_acl.model_copy(
                update={"server_type": target_server_type},
                deep=True,
            )

            # Return converted ACL with correct server_type
            return r.ok(converted_acl)

        except Exception as e:
            traceback.format_exc()
            logger.exception(
                "Failed to convert ACL model",
                error=str(e),
            )
            return r[ConvertibleModelUnion].fail(
                f"Acl conversion failed: {e}"
            )

    def _extract_and_register_dns(
        self,
        model: FlextLdifModelsDomains.Acl,
        data_type: str,
    ) -> None:
        """Extract DNs from ACL model and register with canonical case using FlextLdifUtilities.

        Extracts DNs from ACL models and registers them with the DN registry
        to ensure case consistency across conversions. Uses FlextLdifUtilities
        for RFC 4514 DN validation.

        Args:
            model: ACL Pydantic model containing potential DN references
            data_type: Type of data being processed (must be "acl")

        """
        if data_type != "acl":
            return

        # Extract DN from ACL subject (if present)
        if model.subject and model.subject.subject_value:
            subject_value = model.subject.subject_value

            # Extract DN from LDAP URL format: ldap:///cn=...,dc=...
            if "ldap:///" in subject_value:
                dn_part = subject_value.split("ldap:///", 1)[1].split("?", 1)[0]
                # Validate DN using FlextLdifUtilities before registering
                if dn_part and FlextLdifUtilities.DN.validate(dn_part):
                    _ = self.dn_registry.register_dn(dn_part)

            # Plain DN (not in LDAP URL format)
            elif "=" in subject_value or "," in subject_value:
                # Validate DN using FlextLdifUtilities.DN before registering
                if FlextLdifUtilities.DN.validate(subject_value):
                    _ = self.dn_registry.register_dn(subject_value)

    def _normalize_dns_in_model(
        self,
        acl: FlextLdifModelsDomains.Acl,
    ) -> r[FlextLdifModelsDomains.Acl]:
        """Normalize DN references in ACL model to use canonical case.

        For ACL models, DN normalization is typically a pass-through
        since ACLs contain LDAP URLs, not plain DNs.

        Args:
            acl: ACL Pydantic model with potential DN references

        Returns:
            FlextResult with normalized ACL model

        """
        # ACLs typically don't have direct DN fields to normalize
        # DN references are in LDAP URLs like "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        # which are handled during parsing/writing
        return r[FlextLdifModelsDomains.Acl].ok(acl)

    @staticmethod
    def _try_write_schema_item(
        source_quirk: object,
        schema_item: object,
        write_method: Callable[[object, object], r[str]],
        fallback: object,
    ) -> r[str | object]:
        """Try writing schema item, return fallback on error."""
        try:
            schema_quirk = _get_schema_quirk(cast("FlextLdifServersBase", source_quirk))
            write_result = write_method(schema_quirk, schema_item)
            # Use u.when() for conditional return (DSL pattern)
            return u.when(
                condition=write_result.is_success,
                then_value=r.ok(u.val(write_result)),
                else_value=r.ok(fallback),
            )
        except TypeError:
            return r.ok(fallback)

    def _write_attribute_to_rfc(
        self,
        source: ServerQuirkOrType,
        source_attr: FlextLdifModelsDomains.SchemaAttribute
        | t.MetadataAttributeValue
        | str,
    ) -> r[
        str | FlextLdifModelsDomains.SchemaAttribute | t.MetadataAttributeValue
    ]:
        """Write attribute to RFC string representation."""
        if isinstance(source_attr, str):
            return r.ok(source_attr)
        if not isinstance(source_attr, FlextLdifModelsDomains.SchemaAttribute):
            return r.ok(source_attr)

        source_quirk = self._resolve_quirk(source)
        return cast(
                    "r[str | FlextLdifModelsDomains.SchemaAttribute | t.MetadataAttributeValue]",
            FlextLdifConversion._try_write_schema_item(
                source_quirk,
                source_attr,
                lambda s, attr: cast("FlextLdifServersBase.Schema", s).write_attribute(
                    cast("FlextLdifModelsDomains.SchemaAttribute", attr)
                ),
                source_attr,
            ),
        )

    def _convert_attribute(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        data: str | t.MetadataAttributeValue,
    ) -> r[
        FlextLdifModelsDomains.SchemaAttribute | str | t.MetadataAttributeValue
    ]:
        """Convert attribute from source to target quirk via write->parse pipeline.

        Pipeline: parse source -> write as string -> parse target
        """
        try:
            if not isinstance(data, str):
                return r.fail("Attribute conversion requires string data")

            # Use u.map() for unified result pipeline (DSL pattern)
            parse_result = self._parse_source_attribute(source, data)
            parsed_attr = u.val(parse_result)
            if parsed_attr is None:
                return r[
                    FlextLdifModelsDomains.SchemaAttribute
                    | t.MetadataAttributeValue
                    | str
                ].fail(u.err(parse_result))

            # Use u.map() for unified result pipeline (DSL pattern)
            rfc_result = self._write_attribute_to_rfc(source, parsed_attr)
            rfc_value = u.val(rfc_result)
            if rfc_value is None:
                return cast(
                    "r[FlextLdifModelsDomains.SchemaAttribute | str | t.MetadataAttributeValue]",
                    rfc_result,
                )

            # Use u.when() for conditional type check (DSL pattern)
            if not u.is_type(rfc_value, str):
                return r.ok(rfc_value)

            # Use u.map() for unified result handling (DSL pattern)
            target_parse_result = self._parse_target_attribute(target, rfc_value)
            return u.map(
                target_parse_result,
                mapper=lambda parsed: self._write_target_attribute(parsed),
                default_error="Failed to parse target attribute",
            )

        except Exception as e:
            return r[
                FlextLdifModelsDomains.SchemaAttribute
                | str
                | t.MetadataAttributeValue
            ].fail(f"Attribute conversion failed: {e}")

    def _parse_source_attribute(
        self,
        source: ServerQuirkOrType,
        data: str | t.MetadataAttributeValue,
    ) -> r[FlextLdifModelsDomains.SchemaAttribute]:
        """Parse source attribute."""
        source_quirk = self._resolve_quirk(source)

        # Get source schema quirk with proper type narrowing
        try:
            source_schema = _get_schema_quirk(source_quirk)
        except TypeError as e:
            return r.fail(f"Source quirk error: {e}")

        # Ensure data is string for parse_attribute
        if isinstance(data, str):
            parse_method = source_schema.parse_attribute
            return parse_method(data)
        return r.fail("parse_attribute requires string data")

    def _parse_target_attribute(
        self,
        target: ServerQuirkOrType,
        rfc_value: str,
    ) -> r[FlextLdifModelsDomains.SchemaAttribute]:
        """Parse target attribute from RFC string."""
        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            target_schema = _get_schema_quirk(target_quirk)
        except TypeError as e:
            return r.fail(f"Target quirk error: {e}")

        parse_method = target_schema.parse_attribute
        return parse_method(rfc_value)

    def _write_target_attribute(
        self,
        parsed_attr: FlextLdifModelsDomains.SchemaAttribute
        | str
        | t.MetadataAttributeValue,
    ) -> r[
        FlextLdifModelsDomains.SchemaAttribute | str | t.MetadataAttributeValue
    ]:
        """Write target attribute to final format."""
        # Type narrowing: write_attribute requires SchemaAttribute
        if not isinstance(parsed_attr, FlextLdifModelsDomains.SchemaAttribute):
            # Return as-is if not SchemaAttribute - type narrowing for union type
            if isinstance(parsed_attr, dict):
                return r[
                    FlextLdifModelsDomains.SchemaAttribute
                    | t.MetadataAttributeValue
                    | str
                ].ok(parsed_attr)
            if isinstance(parsed_attr, str):
                return r[
                    FlextLdifModelsDomains.SchemaAttribute
                    | t.MetadataAttributeValue
                    | str
                ].ok(parsed_attr)
            msg = f"Expected SchemaAttribute | dict | str, got {type(parsed_attr)}"
            raise TypeError(msg)

        # Model-based conversion - return parsed attribute as-is
        # Schema quirks write via model conversion, not string-based
        return r[
            FlextLdifModelsDomains.SchemaAttribute | t.MetadataAttributeValue | str
        ].ok(parsed_attr)

    def _write_objectclass_to_rfc(
        self,
        source: ServerQuirkOrType,
        source_oc: FlextLdifModelsDomains.SchemaObjectClass
        | t.MetadataAttributeValue
        | str,
    ) -> r[
        str | FlextLdifModelsDomains.SchemaObjectClass | t.MetadataAttributeValue
    ]:
        """Write objectClass to RFC string representation."""
        if isinstance(source_oc, str):
            return r[
                str
                | FlextLdifModelsDomains.SchemaObjectClass
                | t.MetadataAttributeValue
            ].ok(source_oc)

        if not isinstance(source_oc, FlextLdifModelsDomains.SchemaObjectClass):
            if isinstance(source_oc, dict):
                return r[
                    str
                    | FlextLdifModelsDomains.SchemaObjectClass
                    | t.MetadataAttributeValue
                ].ok(source_oc)
            msg = f"Expected SchemaObjectClass | str | dict, got {type(source_oc)}"
            raise TypeError(msg)

        source_quirk = self._resolve_quirk(source)
        write_result = FlextLdifConversion._try_write_schema_item(
            source_quirk,
            source_oc,
            lambda s, oc: cast("FlextLdifServersBase.Schema", s).write_objectclass(
                cast("FlextLdifModelsDomains.SchemaObjectClass", oc)
            ),
            source_oc,
        )
        # Use u.val() for unified result value extraction (DSL pattern)
        write_value = u.val(write_result)
        if write_value is not None and isinstance(write_value, str):
            return r[
                str
                | FlextLdifModelsDomains.SchemaObjectClass
                | t.MetadataAttributeValue
            ].ok(write_value)
        return cast(
            "r[str | FlextLdifModelsDomains.SchemaObjectClass | t.MetadataAttributeValue]",
            write_result,
        )

    def _convert_objectclass(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        data: str | t.MetadataAttributeValue,
    ) -> r[
        FlextLdifModelsDomains.SchemaObjectClass | str | t.MetadataAttributeValue
    ]:
        """Convert objectClass from source to target quirk via write->parse pipeline.

        Pipeline: parse source -> write as string -> parse target
        """
        try:
            if not isinstance(data, str):
                return r.fail("ObjectClass conversion requires string data")

            # Use u.map() for unified result pipeline (DSL pattern)
            parse_result = self._parse_source_objectclass(source, data)
            parsed_oc = u.val(parse_result)
            if parsed_oc is None:
                return r[
                    FlextLdifModelsDomains.SchemaObjectClass
                    | str
                    | t.MetadataAttributeValue
                ].fail(u.err(parse_result) or "Failed to parse source objectClass")

            write_result = self._write_objectclass_to_rfc(source, parsed_oc)
            rfc_value = u.val(write_result)
            if rfc_value is None:
                return cast(
                    "r[FlextLdifModelsDomains.SchemaObjectClass | str | t.MetadataAttributeValue]",
                    write_result,
                )
            if not isinstance(rfc_value, str):
                if isinstance(rfc_value, (FlextLdifModelsDomains.SchemaObjectClass, dict)):
                    return r[
                        FlextLdifModelsDomains.SchemaObjectClass
                        | str
                        | t.MetadataAttributeValue
                    ].ok(rfc_value)
                msg = f"Expected SchemaObjectClass | str | dict, got {type(rfc_value)}"
                raise TypeError(msg)

            # Use u.map() for unified result handling (DSL pattern)
            target_result = self._parse_target_objectclass(target, rfc_value)
            return u.map(
                target_result,
                mapper=lambda parsed: self._write_target_objectclass(target, parsed),
                default_error="Failed to parse target objectClass",
            )

        except Exception as e:
            return r[
                FlextLdifModelsDomains.SchemaObjectClass
                | str
                | t.MetadataAttributeValue
            ].fail(f"ObjectClass conversion failed: {e}")

    def _parse_source_objectclass(
        self,
        source: ServerQuirkOrType,
        data: str | t.MetadataAttributeValue,
    ) -> r[FlextLdifModelsDomains.SchemaObjectClass]:
        """Parse source objectClass."""
        source_quirk = self._resolve_quirk(source)

        # Get source schema quirk with proper type narrowing
        try:
            source_schema = _get_schema_quirk(source_quirk)
        except TypeError as e:
            return r.fail(f"Source quirk error: {e}")

        # Ensure data is string for parse_objectclass
        if isinstance(data, str):
            parse_method = source_schema.parse_objectclass
            return parse_method(data)
        return r.fail("parse_objectclass requires string data")

    def _parse_target_objectclass(
        self,
        target: ServerQuirkOrType,
        rfc_value: str,
    ) -> r[FlextLdifModelsDomains.SchemaObjectClass]:
        """Parse target objectClass from RFC string."""
        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            target_schema = _get_schema_quirk(target_quirk)
        except TypeError as e:
            return r.fail(f"Target quirk error: {e}")

        parse_method = target_schema.parse_objectclass
        return parse_method(rfc_value)

    def _write_target_objectclass(
        self,
        target: ServerQuirkOrType,
        parsed_oc: FlextLdifModelsDomains.SchemaObjectClass
        | str
        | t.MetadataAttributeValue,
    ) -> r[
        FlextLdifModelsDomains.SchemaObjectClass | str | t.MetadataAttributeValue
    ]:
        """Write target objectClass to final format."""
        # Type narrowing: write_objectclass requires SchemaObjectClass
        if not isinstance(parsed_oc, FlextLdifModelsDomains.SchemaObjectClass):
            # Return as-is if not SchemaObjectClass - type narrowing for union type
            if isinstance(parsed_oc, str):
                return r[
                    FlextLdifModelsDomains.SchemaObjectClass
                    | str
                    | t.MetadataAttributeValue
                ].ok(parsed_oc)
            if isinstance(parsed_oc, dict):
                return r[
                    FlextLdifModelsDomains.SchemaObjectClass
                    | str
                    | t.MetadataAttributeValue
                ].ok(parsed_oc)
            msg = f"Expected SchemaObjectClass | str | dict, got {type(parsed_oc)}"
            raise TypeError(msg)

        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            schema_quirk = _get_schema_quirk(target_quirk)
        except TypeError:
            # Return as-is if no writer available
            return r[
                FlextLdifModelsDomains.SchemaObjectClass
                | str
                | t.MetadataAttributeValue
            ].ok(parsed_oc)

        # schema_quirk is already properly typed from _get_schema_quirk
        write_result = schema_quirk.write_objectclass(parsed_oc)
        # write_objectclass returns r[str] - convert to union type
        # Use u.val() for unified result value extraction (DSL pattern)
        written_str = u.val(write_result)
        if written_str is not None:
            # Type narrowing: write_objectclass returns str
            if not isinstance(written_str, str):
                msg = f"Expected str from write_objectclass, got {type(written_str)}"
                raise TypeError(msg)
            return r[
                FlextLdifModelsDomains.SchemaObjectClass
                | str
                | t.MetadataAttributeValue
            ].ok(written_str)
        # Use u.err() for unified error extraction (DSL pattern)
        error_msg = u.err(write_result) or "Failed to write objectClass"
        return r[
            FlextLdifModelsDomains.SchemaObjectClass | str | t.MetadataAttributeValue
        ].fail(error_msg)

    def batch_convert(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        model_list: Sequence[FlextLdifTypes.ConvertibleModel],
    ) -> r[list[ConvertibleModelUnion]]:
        """Convert multiple models from source to target quirk via RFC.

        Model-based batch conversion only - no legacy string/dict support.
        DN registry is shared across all conversions to ensure case consistency.
        Emits ConversionEvent with aggregated statistics (MANDATORY - eventos obrigatórios).

        Args:
            source: Source quirk instance
            target: Target quirk instance
            model_list: List of model instances to convert

        Returns:
            FlextResult containing list of converted models

        Examples:
            >>> entries = [entry1, entry2, entry3]
            >>> result = matrix.batch_convert(oud, oid, entries)
            >>> if result.is_success:
            ...     converted = result.unwrap()
            ...     print(f"Converted {len(converted)} entries")

        """
        # Track batch conversion duration (MANDATORY - eventos obrigatórios)
        start_time = time.perf_counter()

        # Get source/target format names
        source_format = FlextLdifUtilities.match(
            source,
            (str, lambda s: s),
            default=lambda src: u.maybe(
                u.prop("server_name")(src),
                default="unknown",
            ),
        )
        target_format = FlextLdifUtilities.match(
            target,
            (str, lambda t: t),
            default=lambda tgt: u.maybe(
                u.prop("server_name")(tgt),
                default="unknown",
            ),
        )

        # Handle empty list case - succeed with empty result
        # No event emission for empty batches (no work done)
        if not model_list:
            return r[list[ConvertibleModelUnion]].ok([])

        model_type = type(model_list[0]).__name__
        conversion_operation = f"batch_convert_{model_type}"

        try:
            # Collect converted models (concrete types from convert method)
            converted: list[ConvertibleModelUnion] = []
            errors: list[str] = []
            error_details: list[FlextLdifModelsDomains.ErrorDetail] = []

            for idx, model_item in enumerate(model_list):
                result = self.convert(source, target, model_item)
                # Use u.val() for unified result value extraction (DSL pattern)
                unwrapped = u.val(result)
                if unwrapped is not None:
                    # convert() returns ConvertibleModel (protocol-based)
                    # so unwrapped is already typed correctly
                    converted.append(unwrapped)
                else:
                    error_msg = u.err(result) or "Unknown error"
                    errors.append(f"Item {idx}: {error_msg}")
                    error_details.append(
                        FlextLdifModelsDomains.ErrorDetail(
                            item=f"batch_item_{idx}",
                            error=error_msg,
                        ),
                    )

            # Calculate duration and emit ConversionEvent (MANDATORY - eventos obrigatórios)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            items_processed = u.count(model_list)
            items_converted = u.count(converted)
            items_failed = u.count(errors)

            # Create conversion event config for batch
            conversion_config = FlextLdifModels.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=items_processed,
                items_converted=items_converted,
                items_failed=items_failed,
                conversion_duration_ms=duration_ms,
                error_details=error_details or None,
            )
            _ = FlextLdifUtilities.Events.log_and_emit_conversion_event(
                logger=logger,
                config=conversion_config,
                log_level="warning" if errors else "info",
            )

            if errors:
                error_count = u.count(errors)
                error_msg = (
                    f"Batch conversion completed with {error_count} errors:\n"
                    + "\n".join(errors[: self.MAX_ERRORS_TO_SHOW])
                )
                if error_count > self.MAX_ERRORS_TO_SHOW:
                    error_msg += (
                        f"\n... and {error_count - self.MAX_ERRORS_TO_SHOW} more errors"
                    )
                return r[list[ConvertibleModelUnion]].fail(
                    error_msg,
                )

            # converted already has correct type from declaration (line 1490)
            return r[list[ConvertibleModelUnion]].ok(converted)

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            # Emit ConversionEvent for exception case (MANDATORY - eventos obrigatórios)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Create conversion event config for exception case
            conversion_config = FlextLdifModels.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=u.count(model_list),
                items_converted=0,
                items_failed=u.count(model_list),
                conversion_duration_ms=duration_ms,
                error_details=[
                    FlextLdifModelsDomains.ErrorDetail(
                        item="batch_conversion",
                        error=f"Batch conversion failed: {e}",
                    ),
                ],
            )
            _ = FlextLdifUtilities.Events.log_and_emit_conversion_event(
                logger=logger,
                config=conversion_config,
                log_level="error",
            )

            return r[list[ConvertibleModelUnion]].fail(
                f"Batch conversion failed: {e}",
            )

    def validate_oud_conversion(self) -> r[bool]:
        """Validate DN case consistency for OUD target conversion.

        This should be called after batch conversions to OUD to ensure
        no DN case conflicts exist that would cause OUD to reject the data.

        Returns:
            r[bool]: Validation result with any inconsistencies in metadata

        Examples:
            >>> matrix = FlextLdifConversion()
            >>> # ... perform conversions ...
            >>> result = matrix.validate_oud_conversion()
            >>> if result.unwrap():
            ...     print("DN consistency validated for OUD")
            >>> else:
            ...     print(f"Warning: {result.metadata['warning']}")

        """
        return self.dn_registry.validate_oud_consistency()

    def reset_dn_registry(self) -> None:
        """Clear DN registry for new conversion session.

        Call this between independent conversion operations to avoid
        DN case pollution from previous conversions.

        Examples:
            >>> matrix = FlextLdifConversion()
            >>> # ... convert some entries ...
            >>> matrix.reset_dn_registry()  # Start fresh
            >>> # ... convert different entries ...

        """
        self.dn_registry.clear()

    def get_supported_conversions(
        self, quirk: FlextLdifServersBase
    ) -> FlextLdifTypes.CommonDict.DistributionDict:
        """Check which data types a quirk supports for conversion.

        Args:
            quirk: Quirk instance to check

        Returns:
            Dictionary mapping data_type to support status

        Examples:
            >>> registry = FlextLdifServer()
            >>> quirk = registry.quirk(FlextLdifConstants.ServerTypes.OUD)
            >>> supported = matrix.get_supported_conversions(quirk)
            >>> print(supported)
            {'attribute': True, 'objectclass': True, 'acl': True, 'entry': True}

        """
        support: FlextLdifTypes.CommonDict.DistributionDict = {
            "attribute": 0,
            FlextLdifConstants.DictKeys.OBJECTCLASS: 0,
            "acl": 0,
            "entry": 0,
        }

        # Check schema support
        support = self._check_schema_support(quirk, support)

        # Check ACL support
        support = self._check_acl_support(quirk, support)

        # Check Entry support
        support = self._check_entry_support(quirk, support)

        # Convert numeric values (0/1) to boolean (False/True) for return
        return {
            "attribute": bool(support.get("attribute", 0)),
            FlextLdifConstants.DictKeys.OBJECTCLASS: bool(
                support.get(FlextLdifConstants.DictKeys.OBJECTCLASS, 0),
            ),
            "acl": bool(support.get("acl", 0)),
            "entry": bool(support.get("entry", 0)),
        }

    def _get_schema_quirk_for_support_check(
        self,
        quirk: FlextLdifServersBase,
    ) -> FlextLdifProtocols.Quirks.SchemaProtocol | None:
        """Get schema quirk from base quirk for support checking.

        Args:
            quirk: Base quirk instance

        Returns:
            Schema quirk instance or None if not available

        """
        # Business Rule: Extract schema quirk from quirk instance
        # Schema quirks implement SchemaProtocol with parse() and write() methods
        # Use structural checks first, then isinstance for runtime_checkable Protocol
        # This ensures type safety while satisfying pyright strict mode
        # Business Rule: Extract schema quirk from quirk instance using structural checks
        # Schema quirks implement SchemaProtocol with parse() and write() methods
        # Use structural checks only to avoid pyright Protocol overlap warnings
        # Runtime behavior: Structural typing ensures correct implementation
        # Check if quirk is already a Schema quirk (has parse_attribute directly)
        if hasattr(quirk, "parse_attribute") or hasattr(quirk, "parse_objectclass"):
            # Validate structural compliance: has required SchemaProtocol methods
            required_methods = ("parse", "write")
            if all(
                hasattr(quirk, method) and callable(getattr(quirk, method))
                for method in required_methods
            ):
                # Use cast after structural validation - satisfies pyright without Protocol overlap warnings
                return cast("FlextLdifProtocols.Quirks.SchemaProtocol", quirk)
            return None
        # Check if quirk is a base quirk with schema_quirk attribute
        schema_quirk_raw = getattr(quirk, "schema_quirk", None)
        if schema_quirk_raw is not None:
            # Validate structural compliance: has required SchemaProtocol methods
            required_methods = ("parse", "write")
            if all(
                hasattr(schema_quirk_raw, method)
                and callable(getattr(schema_quirk_raw, method))
                for method in required_methods
            ):
                # Use cast after structural validation - satisfies pyright without Protocol overlap warnings
                return cast(
                    "FlextLdifProtocols.Quirks.SchemaProtocol", schema_quirk_raw
                )
            return None
        return None

    def _check_attribute_support(
        self,
        quirk_schema: FlextLdifProtocols.Quirks.SchemaProtocol,
        test_attr_def: str,
        support: FlextLdifTypes.CommonDict.DistributionDict,
    ) -> FlextLdifTypes.CommonDict.DistributionDict:
        """Check attribute support for schema quirk.

        Args:
            quirk_schema: Schema quirk instance
            test_attr_def: Test attribute definition string
            support: Support dictionary to update

        Returns:
            Updated support dictionary

        """
        if not hasattr(quirk_schema, "can_handle_attribute"):
            return support
        if not hasattr(quirk_schema, "parse_attribute"):
            return support

        can_handle_attr = getattr(quirk_schema, "can_handle_attribute", None)
        if can_handle_attr is None or not callable(can_handle_attr):
            return support
        if not can_handle_attr(test_attr_def):
            return support

        parse_attr = getattr(quirk_schema, "parse_attribute", None)
        if parse_attr is None or not callable(parse_attr):
            return support

        attr_result = parse_attr(test_attr_def)
        # Use u.val() for unified result value extraction (DSL pattern)
        if isinstance(attr_result, r) and u.val(attr_result) is not None:
            support["attribute"] = 1

        return support

    def _check_objectclass_support(
        self,
        quirk_schema: FlextLdifProtocols.Quirks.SchemaProtocol,
        test_oc_def: str,
        support: FlextLdifTypes.CommonDict.DistributionDict,
    ) -> FlextLdifTypes.CommonDict.DistributionDict:
        """Check objectClass support for schema quirk.

        Args:
            quirk_schema: Schema quirk instance
            test_oc_def: Test objectClass definition string
            support: Support dictionary to update

        Returns:
            Updated support dictionary

        """
        if not hasattr(quirk_schema, "can_handle_objectclass"):
            return support
        if not hasattr(quirk_schema, "parse_objectclass"):
            return support

        can_handle_oc = getattr(quirk_schema, "can_handle_objectclass", None)
        if can_handle_oc is None or not callable(can_handle_oc):
            return support
        if not can_handle_oc(test_oc_def):
            return support

        parse_oc = getattr(quirk_schema, "parse_objectclass", None)
        if parse_oc is None or not callable(parse_oc):
            return support

        oc_result = parse_oc(test_oc_def)
        # Use u.val() for unified result value extraction (DSL pattern)
        if isinstance(oc_result, r) and u.val(oc_result) is not None:
            support[FlextLdifConstants.DictKeys.OBJECTCLASS] = 1

        return support

    def _check_schema_support(
        self,
        quirk: FlextLdifServersBase,
        support: FlextLdifTypes.CommonDict.DistributionDict,
    ) -> FlextLdifTypes.CommonDict.DistributionDict:
        """Check schema (attribute and objectClass) support."""
        quirk_schema = self._get_schema_quirk_for_support_check(quirk)
        if quirk_schema is None:
            return support

        # Use quirk_schema for checks
        test_attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclTest' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )

        # Check attribute support
        support = self._check_attribute_support(quirk_schema, test_attr_def, support)

        # Check objectClass support
        return self._check_objectclass_support(quirk_schema, test_oc_def, support)

    def _check_acl_support(
        self,
        quirk: FlextLdifServersBase,
        support: FlextLdifTypes.CommonDict.DistributionDict,
    ) -> FlextLdifTypes.CommonDict.DistributionDict:
        """Check ACL support."""
        # No fallback - check both attributes explicitly
        acl = getattr(quirk, "acl_quirk", None)
        if acl is None:
            acl = getattr(quirk, "_acl_quirk", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if acl and callable(getattr(acl, "parse", None)):
            acl_result = acl.parse(test_acl_def)
            # Use u.val() for unified result value extraction (DSL pattern)
            if u.val(acl_result) is not None:
                support["acl"] = 1
        return support

    def _check_entry_support(
        self,
        quirk: FlextLdifServersBase,
        support: FlextLdifTypes.CommonDict.DistributionDict,
    ) -> FlextLdifTypes.CommonDict.DistributionDict:
        """Check Entry support."""
        # No fallback - check both attributes explicitly
        entry = getattr(quirk, "entry_quirk", None)
        if entry is None:
            entry = getattr(quirk, "_entry_quirk", None)
        if (
            entry is None
            and hasattr(quirk, "parse")
            and hasattr(quirk, "can_handle_entry")
        ):
            entry = quirk
        if entry is not None and callable(getattr(entry, "parse", None)):
            support["entry"] = 1
        return support


__all__ = ["FlextLdifConversion"]
