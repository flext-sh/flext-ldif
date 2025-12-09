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
from collections.abc import Callable, Mapping, Sequence
from typing import ClassVar, Self, cast, override

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextRuntime,
    FlextTypes,
    r,
)
from pydantic import Field

from flext_ldif.base import FlextLdifServiceBase

# Services CAN import models/types/constants (but not the reverse)
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t
from flext_ldif.utilities import FlextLdifUtilities as u

# Constants
TUPLE_LENGTH_PAIR = 2

# Type aliases moved to t.Ldif - use those instead
# str | FlextLdifServersBase = t.Ldif.Conversion.str | FlextLdifServersBase
# m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl = t.Ldif.Conversion.m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl

# Module-level logger
logger = FlextLogger(__name__)


def _get_schema_quirk(
    quirk: FlextLdifServersBase,
) -> object:
    """Get schema quirk from base quirk with proper type narrowing.

    Args:
        quirk: Base quirk instance

    Returns:
        Schema quirk protocol instance

    Raises:
        TypeError: If quirk doesn't have schema capabilities

    """
    # Get schema from schema_quirk attribute
    # Note: isinstance check with nested classes doesn't work with mypy
    # so we always use the attribute access pattern
    # schema_quirk satisfies SchemaProtocol via structural typing
    return _get_schema_from_attribute(quirk)


def _validate_schema_quirk(
    quirk: FlextLdifServersBase,
) -> object:
    """Validate and return quirk as Schema protocol."""
    # Use structural typing: check if quirk has schema methods
    # isinstance with nested classes doesn't work with mypy
    if not hasattr(quirk, "parse") or not hasattr(quirk, "write_attribute"):
        msg = f"Expected Schema quirk, got {type(quirk)}"
        raise TypeError(msg)
    # quirk satisfies SchemaProtocol via structural typing
    return quirk


def _get_schema_from_attribute(
    quirk: FlextLdifServersBase,
) -> object:
    """Get schema quirk from schema_quirk attribute."""
    if hasattr(quirk, "schema_quirk"):
        schema = quirk.schema_quirk
        # schema_quirk always returns SchemaProtocol, never None
        # Use structural typing: check if schema has Schema methods
        # isinstance with nested classes doesn't work with mypy
        if not hasattr(schema, "parse") or not hasattr(schema, "write_attribute"):
            msg = f"Expected Schema quirk, got {type(schema)}"
            raise TypeError(msg)
        # schema satisfies SchemaProtocol via structural typing
        return schema
    msg = "Quirk must be a Schema quirk or have schema_quirk attribute"
    raise TypeError(msg)


class FlextLdifConversion(
    FlextLdifServiceBase[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ],
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

    s V2 Integration:
    - Inherits from s[t.ConvertibleModel]
    - Implements execute() method for health checks
    - Provides stateless conversion operations
    """

    # Maximum number of errors to show in batch conversion
    MAX_ERRORS_TO_SHOW: ClassVar[int] = 5

    @staticmethod
    def _default_dn_registry() -> m.Ldif.DnRegistry:
        """Default DN registry factory function."""
        return m.Ldif.DnRegistry()

    # DN registry for tracking DN case consistency during conversions
    dn_registry: m.Ldif.DnRegistry = Field(
        default_factory=_default_dn_registry,
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
    def _resolve_quirk(
        quirk_or_type: str | FlextLdifServersBase,
    ) -> FlextLdifServersBase:
        """Resolve server quirk instance from string type or return instance.

        Args:
            quirk_or_type: Either a server quirk instance or server type string

        Returns:
            Server quirk instance

        Raises:
            ValueError: If server type string cannot be resolved

        """
        if isinstance(quirk_or_type, str):
            server = FlextLdifServer()
            # Get base quirk from registry
            # Type narrowing: quirk_or_type is str here (already checked with isinstance)
            server_type_str: str = quirk_or_type
            resolved_result = server.quirk(server_type_str)
            # Extract value from result with default fallback
            resolved = resolved_result.value if resolved_result.is_success else None
            if resolved is None:
                error_msg = f"Unknown server type: {quirk_or_type}"
                raise ValueError(error_msg)
            # Type narrowing: resolved is FlextLdifServersBase when not None
            return resolved
        # Type narrowing: quirk_or_type is FlextLdifServersBase here
        return quirk_or_type

    @override
    def execute(
        self,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Execute conversion service health check.

        Business Rule: Execute method provides service health check for protocol compliance.
        Returns fail-fast error indicating conversion requires explicit source/target parameters.

        Implication: This method enables service-based execution patterns while maintaining
        type safety. Used internally by service orchestration layers for health monitoring.

        Returns:
            r with empty Entry model for health check

        Note:
            Returns empty Entry model to satisfy s type constraints.
            This is a health check, actual conversions use convert() method.

        """
        try:
            # Return empty Entry for health check to satisfy type constraints
            empty_entry = m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="cn=health-check"),
                attributes=m.Ldif.LdifAttributes(attributes={}),
            )
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].ok(empty_entry)
        except Exception as e:
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"Conversion service health check failed: {e}",
            )

    def convert(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ),
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
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
            r with converted model (target server format)

        """
        # Track conversion duration (MANDATORY - eventos obrigatórios)
        start_time = time.perf_counter()

        # Determine conversion type and get source/target format names
        source_format_raw = u.Ldif.match(
            source,
            (str, lambda s: s),
            default=lambda src: getattr(src, "server_name", "unknown"),
        )
        target_format_raw = u.Ldif.match(
            target,
            (str, lambda t: t),
            default=lambda tgt: getattr(tgt, "server_name", "unknown"),
        )
        # Type narrowing: u.Ldif.match with (str, lambda) returns object, cast to str
        source_format: str = cast("str", source_format_raw)
        target_format: str = cast("str", target_format_raw)

        # Model-based conversion only
        model_type = type(model_instance).__name__
        conversion_operation = f"convert_{model_type}"

        self.logger.debug(
            "Converting model",
            source_format=str(source_format),
            target_format=str(target_format),
            model_type=model_type,
        )

        # Execute model-based conversion
        result = self._convert_model(source, target, model_instance)

        # Calculate duration and emit ConversionEvent (MANDATORY - eventos obrigatórios)
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Emit ConversionEvent with results
        # Conditional assignment using ternary operator
        items_converted = 1 if result.is_success else 0
        items_failed = 0 if result.is_success else 1

        # Create conversion event config using full namespace
        conversion_config = m.Ldif.ConversionEventConfig(
            conversion_operation=conversion_operation,
            source_format=source_format,
            target_format=target_format,
            items_processed=1,
            items_converted=items_converted,
            items_failed=items_failed,
            conversion_duration_ms=duration_ms,
            # Use result.is_failure to check for errors (u.val raises on failure)
            error_details=[
                m.Ldif.ErrorDetail(
                    item=model_type,
                    error=result.error or "Unknown error",
                ),
            ]
            if result.is_failure
            else [],
        )
        _ = u.Ldif.Events.log_and_emit_conversion_event(
            logger=logger,
            config=conversion_config,
            log_level="info" if result.is_success else "error",
        )

        return result

    def _convert_model(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ),
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
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
            match_result = u.Ldif.match(
                model_instance,
                (
                    m.Ldif.Entry,
                    lambda entry: self._convert_entry(
                        source_quirk,
                        target_quirk,
                        entry,
                    ),
                ),
                (
                    m.Ldif.SchemaAttribute,
                    lambda a: FlextLdifConversion._convert_schema_attribute(
                        source_quirk,
                        target_quirk,
                        a,
                    ),
                ),
                (
                    m.Ldif.SchemaObjectClass,
                    lambda oc: FlextLdifConversion._convert_schema_objectclass(
                        source_quirk,
                        target_quirk,
                        oc,
                    ),
                ),
                (
                    m.Ldif.Acl,
                    lambda acl: self._convert_acl(source_quirk, target_quirk, acl),
                ),
                default=lambda _: r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(
                    f"Unsupported model type for conversion: {type(model_instance).__name__}",
                ),
            )
            # Type narrowing: match returns object, cast to expected return type
            return cast(
                "r[m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl]",
                match_result,
            )

        except Exception as e:
            return FlextResult.fail(f"Model conversion failed: {e}")

    @staticmethod
    def _normalize_metadata_value(value: object) -> t.MetadataAttributeValue:
        """Normalize metadata value to proper type."""
        match_result = u.Ldif.match(
            value,
            (
                lambda v: isinstance(v, (dict, list, str, int, float, bool)),
                lambda v: cast("t.MetadataAttributeValue", v),
            ),
            default=lambda v: str(v) if v is not None else "",
        )
        # Type narrowing: match returns object, cast to expected return type
        return cast("t.MetadataAttributeValue", match_result)

    @staticmethod
    def _analyze_boolean_conversions(
        boolean_conversions: object,
        target_server_type: str,
    ) -> dict[str, dict[str, str]]:
        """Analyze boolean conversions for target compatibility."""
        analysis: dict[str, dict[str, str]] = {}
        if not boolean_conversions:
            return analysis
        # Type narrowing: boolean_conversions is FlextTypes.GeneralValueType
        boolean_conv_typed: FlextTypes.GeneralValueType = boolean_conversions
        if not isinstance(boolean_conv_typed, dict):
            return analysis

        def process_conversion(
            item: tuple[str, object],
        ) -> tuple[str, dict[str, str]]:
            """Process single conversion info."""
            attr_name, conv_info = item
            # Type narrowing: conv_info is FlextTypes.GeneralValueType
            conv_info_typed: FlextTypes.GeneralValueType = conv_info
            # Type narrowing: batch expects R | r[R], so return tuple directly
            # Skip invalid items by returning empty dict (batch will filter via post_validate if needed)
            if not isinstance(conv_info_typed, dict):
                return (
                    f"boolean_{attr_name}",
                    {
                        "source_format": "",
                        "target_server": str(target_server_type),
                        "action": "convert_to_target_format",
                    },
                )
            original_format = (
                u.Ldif.take(conv_info_typed, "format", default="")
                if isinstance(conv_info_typed, dict)
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

        # Convert dict to list of pairs for batch processing
        # Type narrowing: u.Ldif.pairs expects dict[str, object], but boolean_conv_typed is dict[str, GeneralValueType]
        # GeneralValueType is compatible with object, so direct call is safe
        if isinstance(boolean_conv_typed, dict):
            pairs_list: list[tuple[str, object]] = u.Ldif.pairs(boolean_conv_typed)
        else:
            pairs_list = []

        # Process pairs using u.Collection.batch (u.Collection.process has different signature)
        batch_result = u.Collection.batch(
            pairs_list,
            process_conversion,
            on_error="skip",
        )

        # Extract results from batch result dict
        if not batch_result.is_success:
            return analysis

        # batch_result.value is BatchResultDict when success
        batch_data = batch_result.value if batch_result.is_success else {}
        results_list_raw = (
            batch_data.get("results", []) if isinstance(batch_data, dict) else []
        )
        # Type narrowing: results_list_raw is list[tuple[str, dict[str, str]]] after isinstance checks
        results_list: list[tuple[str, dict[str, str]]] = results_list_raw

        # Filter and reduce to dict
        # Type narrowing: process_conversion now always returns tuple[str, dict[str, str]]
        # Filter to ensure valid tuples (batch may include errors)
        filtered_results = u.Ldif.map_filter(
            results_list,
            predicate=lambda item: (
                isinstance(item, tuple)
                and u.Collection.count(item) == TUPLE_LENGTH_PAIR
                and isinstance(item[0], str)
                and isinstance(item[1], dict)
            ),
        )

        # reduce_dict returns dict[str, object], need to cast to expected type
        reduced_raw = u.Ldif.reduce_dict(filtered_results)
        # evolve expects dict[str, object], so cast both analysis and reduced_raw
        # Type narrowing: analysis is dict[str, object]
        analysis_obj: dict[str, object] = analysis
        # Type narrowing: evolved_raw is dict[str, dict[str, str]]
        return u.Ldif.evolve(analysis_obj, reduced_raw)

    @staticmethod
    def _analyze_attribute_case(
        original_attribute_case: object,
        target_server_type: str,
    ) -> dict[str, dict[str, t.MetadataAttributeValue]]:
        """Analyze attribute case for target compatibility."""
        # DSL: Use u.when for conditional value
        if bool(original_attribute_case):
            return {
                "attribute_case": {
                    "source_case": FlextLdifConversion._normalize_metadata_value(
                        original_attribute_case,
                    ),
                    "target_server": str(target_server_type),
                    "action": "apply_target_conventions",
                },
            }
        return {}

    @staticmethod
    def _analyze_dn_format(
        original_format_details: object,
        target_server_type: str,
    ) -> dict[str, dict[str, t.MetadataAttributeValue]]:
        """Analyze DN spacing for target compatibility."""
        pipe_result = u.Reliability.pipe(
            original_format_details,
            lambda d: (u.Ldif.take(d, "dn_spacing") if isinstance(d, dict) else None),
            lambda spacing: (
                {
                    "dn_format": {
                        "source_dn": FlextLdifConversion._normalize_metadata_value(
                            spacing,
                        ),
                        "target_server": str(target_server_type),
                        "action": "normalize_for_target",
                    },
                }
                if spacing
                else {}
            ),
        )
        # Type narrowing: pipe returns object, but we know it's dict[str, dict[str, t.MetadataAttributeValue]]
        if isinstance(pipe_result, dict):
            return pipe_result
        return {}

    @staticmethod
    def _analyze_metadata_for_conversion(
        source_metadata: (m.Ldif.QuirkMetadata | m.Ldif.DynamicMetadata | None),
        target_server_type: str,
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
        get_boolean = u.mapper().prop("boolean_conversions")
        get_attr_case = u.mapper().prop("original_attribute_case")
        get_format_details = u.mapper().prop("original_format_details")

        boolean_conversions = u.Ldif.maybe(
            get_boolean(source_metadata),
            default={},
        )
        boolean_analysis = FlextLdifConversion._analyze_boolean_conversions(
            boolean_conversions,
            target_server_str,
        )

        # Type narrowing: evolve and map_dict expect dict[str, object]
        # conversion_analysis is already dict[str, str | dict[str, str | t.MetadataAttributeValue]]
        # which is compatible with dict[str, object]
        acc_typed: dict[str, object] = conversion_analysis
        # boolean_analysis is dict[str, dict[str, str]] which is compatible with dict[str, object]
        boolean_analysis_typed: dict[str, object] = (
            boolean_analysis if isinstance(boolean_analysis, dict) else {}
        )

        # Apply boolean analysis
        acc_typed = u.Ldif.evolve(
            acc_typed,
            u.Ldif.map_dict(
                boolean_analysis_typed,
                mapper=lambda k, v: (
                    k,
                    v if isinstance(v, (str, dict)) else str(v),
                ),
            ),
        )

        # Apply attribute case analysis
        attr_case_analysis = FlextLdifConversion._analyze_attribute_case(
            u.Ldif.maybe(get_attr_case(source_metadata), default={}),
            target_server_str,
        )
        # attr_case_analysis is dict[str, str] which is compatible with dict[str, object]
        attr_case_typed: dict[str, object] = (
            attr_case_analysis if isinstance(attr_case_analysis, dict) else {}
        )
        acc_typed = u.Ldif.evolve(acc_typed, attr_case_typed)

        # Apply DN format analysis
        dn_format_analysis = FlextLdifConversion._analyze_dn_format(
            u.Ldif.maybe(get_format_details(source_metadata), default={}),
            target_server_str,
        )
        # dn_format_analysis is dict[str, dict[str, t.MetadataAttributeValue]] which is compatible with dict[str, object]
        dn_format_typed: dict[str, object] = (
            dn_format_analysis if isinstance(dn_format_analysis, dict) else {}
        )
        acc_typed = u.Ldif.evolve(acc_typed, dn_format_typed)

        # Type narrowing: final result is dict[str, str | dict[str, str | t.MetadataAttributeValue]]
        # acc_typed is dict[str, object] which is compatible with the return type
        if isinstance(acc_typed, dict):
            return acc_typed
        return {}

    def _update_entry_metadata(
        self,
        entry: m.Ldif.Entry,
        validated_quirk_type: str,
        conversion_analysis: str | None,
        source_quirk_name: str,
    ) -> m.Ldif.Entry:
        """Update entry metadata for conversion (internal helper)."""
        get_metadata = u.mapper().prop("metadata")
        get_extensions = u.mapper().prop("extensions")

        # Step 1: Ensure metadata exists
        current_entry = entry
        if not get_metadata(current_entry):
            metadata_obj = m.Ldif.QuirkMetadata(quirk_type=validated_quirk_type)
            # metadata_obj is m.Ldif.QuirkMetadata which is t.MetadataAttributeValue
            current_entry = current_entry.model_copy(
                update={"metadata": metadata_obj},
                deep=True,
            )

        # Step 2: Ensure extensions exist
        entry_metadata = current_entry.metadata
        if (
            entry_metadata
            and get_metadata(current_entry)
            and not get_extensions(entry_metadata)
        ):
            updated_metadata = entry_metadata.model_copy(
                update={"extensions": m.Ldif.DynamicMetadata()},
                deep=True,
            )
            # updated_metadata is m.Ldif.QuirkMetadata which is t.MetadataAttributeValue
            current_entry = current_entry.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )

        # Step 3: Add conversion analysis
        entry_metadata = current_entry.metadata
        if entry_metadata and get_metadata(current_entry):
            extensions_update: dict[str, FlextTypes.GeneralValueType] = {
                "converted_from_server": source_quirk_name,
            }
            if conversion_analysis:
                extensions_update["conversion_analysis"] = conversion_analysis

            updated_extensions = (
                entry_metadata.extensions or m.Ldif.DynamicMetadata()
            ).model_copy(
                update=extensions_update,
                deep=True,
            )

            updated_metadata = entry_metadata.model_copy(
                update={"extensions": updated_extensions},
                deep=True,
            )
            # updated_metadata is m.Ldif.QuirkMetadata which is t.MetadataAttributeValue
            current_entry = current_entry.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )

        return current_entry

    def _convert_entry(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        entry: m.Ldif.Entry,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Convert Entry model directly without serialization.

        Entry models are already RFC-compliant. Instead of Source.write() -> Target.parse()
        (which fails because parsers expect their own format), we return the model directly.
        The target.write() will be called by the consumer to serialize to target format.

        Architecture: Entry RFC Model -> Target.write() -> Target LDIF format
        """
        try:
            # Validate entry DN using u.DN before conversion
            entry_dn = str(u.Ldif.DN.get_dn_value(entry.dn)) if entry.dn else ""
            if not u.Ldif.DN.validate(entry_dn):
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )

            # Register entry DN for case consistency during conversion
            _ = self.dn_registry.register_dn(entry_dn)

            # Clone the model to avoid mutating the original
            converted_entry = entry.model_copy(deep=True)

            # Get target server type and validate against valid server types
            get_server_name = u.mapper().prop("server_name")
            target_server_type_raw = u.Ldif.maybe(
                get_server_name(target_quirk),
                default="unknown",
            )

            # Normalize server type using constants (handles aliases and canonicalization)
            # Business Rule: normalize_server_type handles validation and returns ServerTypeLiteral
            # Type narrowing: target_server_type_raw is object from u.maybe, ensure it's str
            if (
                isinstance(target_server_type_raw, str)
                and target_server_type_raw != "unknown"
            ):
                normalized = c.normalize_server_type(target_server_type_raw)
                # normalize_server_type returns ServerTypeLiteral (validated at runtime)
                target_server_type_str: str = normalized
            else:
                # RFC.value is ServerTypeLiteral
                target_server_type_str = "rfc"
            # normalize_server_type returns canonical ServerTypeLiteral value (validated at runtime)
            validated_quirk_type = c.normalize_server_type(
                str(target_server_type_str),
            )

            # Use validated_quirk_type for analysis
            # Convert entry.metadata to m.Ldif.QuirkMetadata if needed
            metadata_for_analysis: (
                m.Ldif.QuirkMetadata | m.Ldif.DynamicMetadata | None
            ) = (
                entry.metadata
                if isinstance(
                    entry.metadata,
                    (
                        m.Ldif.QuirkMetadata,
                        m.Ldif.DynamicMetadata,
                    ),
                )
                else None
            )
            conversion_analysis = FlextLdifConversion._analyze_metadata_for_conversion(
                metadata_for_analysis,
                validated_quirk_type,
            )

            source_quirk_name = u.Ldif.maybe(
                get_server_name(source_quirk),
                default="unknown",
            )

            converted_entry = self._update_entry_metadata(
                converted_entry,
                validated_quirk_type,
                str(conversion_analysis) if conversion_analysis else None,
                str(source_quirk_name),
            )

            # Return RFC model - consumer will call target.write() to serialize
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].ok(converted_entry)

        except Exception as e:
            logger.exception(
                "Failed to convert Entry model",
                error=str(e),
            )
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"Entry conversion failed: {e}",
            )

    @staticmethod
    def _get_schema_quirk_safe(
        quirk: FlextLdifServersBase,
        quirk_type: str,
    ) -> r[object]:
        """Get schema quirk safely with error handling."""
        # DSL: Use u.try_ for safe execution
        result = u.try_(
            lambda: _get_schema_quirk(quirk),
            default=None,
        )
        if result is None:
            return r[object].fail(
                f"{quirk_type} quirk error: Schema not available",
            )

        return r[object].ok(result)

    @staticmethod
    def _validate_ldif_string(ldif_string: str, operation: str) -> r[str]:
        """Validate LDIF string is not empty."""
        # Use u.Guards.is_string_non_empty for validation
        if u.Guards.is_string_non_empty(ldif_string):
            return FlextResult.ok(ldif_string)
        return FlextResult.fail(f"Write operation returned empty {operation} LDIF")

    @staticmethod
    def _process_schema_conversion_pipeline(
        config: m.Ldif.Config.SchemaConversionPipelineConfig,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Process schema conversion pipeline (write->parse)."""
        write_result = config.write_method(config.source_schema)
        # Extract value from result: r.value if r.is_success else None
        write_value = write_result.value if write_result.is_success else None
        if write_value is None:
            return FlextResult.fail(
                f"Failed to write {config.item_name} in source format: {u.err(write_result)}",
            )

        ldif_result = FlextLdifConversion._validate_ldif_string(
            write_value,
            config.item_name,
        )
        ldif_string = ldif_result.value if ldif_result.is_success else None
        if ldif_string is None:
            # Return the failed result directly - type checker knows it's r[ConvertibleModelUnion]
            return ldif_result

        parse_result = config.parse_method(config.target_schema, ldif_string)
        # Extract value from result: r.value if r.is_success else None
        parsed_value = parse_result.value if parse_result.is_success else None
        if parsed_value is None:
            return FlextResult.fail(
                f"Failed to parse {config.item_name} in target format: {u.err(parse_result)}",
            )
        # Type narrowing: parsed_value is already ConvertibleModelUnion
        return r[
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ].ok(parsed_value)

    @staticmethod
    def _convert_schema_attribute(
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        attribute: m.Ldif.SchemaAttribute,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Convert SchemaAttribute model via write_attribute->parse_attribute pipeline."""
        try:
            source_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                source_quirk,
                "Source",
            )
            # Extract value from result: r.value if r.is_success else None
            source_schema = (
                source_schema_result.value if source_schema_result.is_success else None
            )
            if source_schema is None:
                # Return the failed result directly - type checker knows it's r[ConvertibleModelUnion]
                return source_schema_result

            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk,
                "Target",
            )
            target_schema = (
                target_schema_result.value if target_schema_result.is_success else None
            )
            if target_schema is None:
                return cast(
                    "r[m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl]",
                    target_schema_result,
                )
            config = m.Ldif.Config.SchemaConversionPipelineConfig(
                source_schema=source_schema,
                target_schema=target_schema,
                write_method=lambda _s: source_schema.write_attribute(attribute),
                parse_method=lambda _t, ldif: target_schema.parse_attribute(ldif),
                item_name="attribute",
            )
            return FlextLdifConversion._process_schema_conversion_pipeline(config)

        except Exception as e:
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"SchemaAttribute conversion failed: {e}",
            )

    @staticmethod
    def _convert_schema_objectclass(
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Convert SchemaObjectClass model via write_objectclass->parse_objectclass pipeline."""
        try:
            source_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                source_quirk,
                "Source",
            )
            # Extract value from result: r.value if r.is_success else None
            source_schema = (
                source_schema_result.value if source_schema_result.is_success else None
            )
            if source_schema is None:
                # Return the failed result directly - type checker knows it's r[ConvertibleModelUnion]
                return source_schema_result

            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk,
                "Target",
            )
            target_schema = (
                target_schema_result.value if target_schema_result.is_success else None
            )
            if target_schema is None:
                return cast(
                    "r[m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl]",
                    target_schema_result,
                )
            config = m.Ldif.Config.SchemaConversionPipelineConfig(
                source_schema=source_schema,
                target_schema=target_schema,
                write_method=lambda _s: source_schema.write_objectclass(objectclass),
                parse_method=lambda _t, ldif: target_schema.parse_objectclass(ldif),
                item_name="objectclass",
            )
            return FlextLdifConversion._process_schema_conversion_pipeline(config)

        except Exception as e:
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"SchemaObjectClass conversion failed: {e}",
            )

    @staticmethod
    def _get_acl_classes(
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
    ) -> r[tuple[object, object]]:
        """Get and validate ACL classes from quirks."""
        source_class = type(source_quirk)
        target_class = type(target_quirk)

        if not hasattr(source_class, "Acl"):
            return FlextResult.fail(
                f"Source quirk {source_class.__name__} does not have Acl nested class",
            )
        if not hasattr(target_class, "Acl"):
            return FlextResult.fail(
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
            ),
        ):
            return FlextResult.fail(
                f"Source ACL quirk {source_class.__name__} missing required AclProtocol methods",
            )
        if not u.all_(
            *(
                hasattr(target_acl, method) and callable(getattr(target_acl, method))
                for method in required_methods
            ),
        ):
            return FlextResult.fail(
                f"Target ACL quirk {target_class.__name__} missing required AclProtocol methods",
            )

        # Type narrowing: After structural validation, source_acl and target_acl satisfy AclProtocol
        # Protocols are runtime_checkable, so isinstance checks work

        if isinstance(source_acl, object) and isinstance(target_acl, object):
            return FlextResult.ok((source_acl, target_acl))
        return r.fail("ACL quirks do not satisfy AclProtocol")

    @staticmethod
    def _write_acl_to_string(
        acl: m.Ldif.Acl,
        source_acl: object,
    ) -> r[str]:
        """Write ACL to LDIF string."""
        # Business Rule: Validate ACL model satisfies AclProtocol before writing
        # Acl model satisfies AclProtocol structurally (has required properties/methods)
        # Use structural checks only to avoid pyright Protocol overlap warnings
        # Runtime behavior: Structural typing ensures correct implementation
        # Check required AclProtocol attributes exist
        if not hasattr(acl, "permissions") or not hasattr(acl, "target"):
            return FlextResult.fail(
                f"ACL model missing required AclProtocol attributes: {type(acl).__name__}",
            )
        # Type narrowing: After structural validation, acl satisfies AclProtocol
        # Protocols are runtime_checkable, so isinstance checks work
        # Type check: acl satisfies AclProtocol via structural typing
        if hasattr(acl, "write") and hasattr(acl, "parse"):
            write_result = source_acl.write(acl)
        else:
            return FlextResult.fail(
                f"ACL model does not satisfy AclProtocol: {type(acl).__name__}",
            )
        # Extract value from result: r.value if r.is_success else None
        write_value = write_result.value if write_result.is_success else None
        if write_value is None:
            return FlextResult.fail(
                f"Failed to write ACL in source format: {u.err(write_result)}",
            )
        # Type narrowing: write() returns r[str], so unwrap_or returns str | None
        # After None check, write_value is guaranteed to be str
        ldif_string: str = write_value
        if not ldif_string or not ldif_string.strip():
            return FlextResult.fail("Write operation returned empty ACL LDIF")

        return r.ok(ldif_string)

    @staticmethod
    def _parse_acl_from_string(
        ldif_string: str,
        target_acl: object,
    ) -> r[m.Ldif.Acl]:
        """Parse ACL from LDIF string."""
        parse_result = target_acl.parse(ldif_string)
        # Extract value from result: r.value if r.is_success else None
        converted_acl_raw = parse_result.value if parse_result.is_success else None
        if converted_acl_raw is None:
            return FlextResult.fail(
                f"Failed to parse ACL in target format: {u.err(parse_result)}",
            )
        # Type narrowing: parse() returns r[AclProtocol], unwrap_or returns AclProtocol | None
        # After None check, converted_acl_raw is AclProtocol. Implementation returns m.Ldif.Acl instances
        if isinstance(converted_acl_raw, m.Ldif.Acl):
            converted_acl: m.Ldif.Acl = converted_acl_raw
        else:
            return FlextResult.fail(
                f"Expected m.Ldif.Acl, got {type(converted_acl_raw).__name__}",
            )
        return r.ok(converted_acl)

    @staticmethod
    def _perms_dict_to_model(
        perms_dict: dict[str, bool | None],
    ) -> m.Ldif.AclPermissions:
        """Convert permissions dict to AclPermissions model.

        Args:
            perms_dict: Dict with permission mappings

        Returns:
            AclPermissions model with non-None values

        """
        # Remove None values for cleaner model (simple dict comprehension)
        clean_dict: dict[str, bool] = {
            k: v for k, v in perms_dict.items() if v is not None
        }
        # Use model_validate which accepts dict[str, object] and validates at runtime
        return m.Ldif.AclPermissions.model_validate(clean_dict)

    @staticmethod
    def _normalize_permission_key(key: str) -> str:
        """Normalize permission key for mapping."""
        switch_result = u.switch(
            key,
            {"self_write": "selfwrite"},
            default=key,
        )
        # Type narrowing: switch returns object, but we know it's str
        if isinstance(switch_result, str):
            return switch_result
        return str(switch_result) if switch_result is not None else key

    @staticmethod
    def _build_permissions_dict(
        mapped_perms: dict[str, bool],
    ) -> dict[str, bool | None]:
        """Build permissions dict with standard keys."""
        key_mapping: dict[str, object] = {
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
        map_result = u.Ldif.map_dict(
            key_mapping,
            mapper=lambda _key, mapped_key: u.Ldif.take(
                mapped_perms,
                str(mapped_key) if mapped_key is not None else "",
            ),
        )
        # Type narrowing: map_dict returns dict[str, object], but we know it's dict[str, bool | None]
        if isinstance(map_result, dict):
            return map_result
        return {}

    @staticmethod
    def _apply_oid_to_oud_mapping(
        orig_perms_dict: dict[str, bool],
        converted_acl: m.Ldif.Acl,
        perms_to_model: Callable[[dict[str, bool | None]], object],
    ) -> m.Ldif.Acl:
        """Apply OID to OUD permission mapping."""
        # map_dict expects dict[str, object], orig_perms_dict is dict[str, bool] which is compatible
        orig_perms_dict_typed: dict[str, object] = orig_perms_dict
        normalized_orig_perms_raw = u.Ldif.map_dict(
            orig_perms_dict_typed,
            mapper=lambda k, v: (
                FlextLdifConversion._normalize_permission_key(k),
                v,
            ),
        )
        # Type narrowing: map_dict returns dict[str, object], check if it's dict[str, bool]
        if isinstance(normalized_orig_perms_raw, dict):
            normalized_orig_perms: dict[str, bool] = {
                k: bool(v) if isinstance(v, bool) else False
                for k, v in normalized_orig_perms_raw.items()
            }
        else:
            normalized_orig_perms = {}
        mapped_perms = u.Ldif.ACL.map_oid_to_oud_permissions(
            normalized_orig_perms,
        )
        oid_to_oud_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        perms_model = perms_to_model(oid_to_oud_perms)
        # perms_model is already t.MetadataAttributeValue (from perms_to_model)
        return converted_acl.model_copy(
            update={"permissions": perms_model},
            deep=True,
        )

    @staticmethod
    def _apply_oud_to_oid_mapping(
        orig_perms_dict: dict[str, bool],
        converted_acl: m.Ldif.Acl,
        perms_to_model: Callable[[dict[str, bool | None]], object],
    ) -> m.Ldif.Acl:
        """Apply OUD to OID permission mapping."""
        mapped_perms = u.Ldif.ACL.map_oud_to_oid_permissions(
            orig_perms_dict,
        )
        oud_to_oid_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        perms_model = perms_to_model(oud_to_oid_perms)
        # perms_model is already t.MetadataAttributeValue (from perms_to_model)
        return converted_acl.model_copy(
            update={"permissions": perms_model},
            deep=True,
        )

    def _apply_permission_mapping(
        self,
        config: m.Ldif.Config.PermissionMappingConfig | None = None,
        **kwargs: object,
    ) -> m.Ldif.Acl:
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
            converted_has_permissions_raw = kwargs.pop(
                "converted_has_permissions",
                False,
            )

            config = m.Ldif.Config.PermissionMappingConfig(
                original_acl=cast(
                    "object",
                    cast("m.Ldif.Acl", original_acl_raw),
                ),
                converted_acl=cast(
                    "object",
                    cast("m.Ldif.Acl", converted_acl_raw),
                ),
                orig_perms_dict=cast("dict[str, bool]", orig_perms_dict_raw),
                source_server_type=cast("str | None", source_server_type_raw),
                target_server_type=cast("str | None", target_server_type_raw),
                converted_has_permissions=cast("bool", converted_has_permissions_raw),
            )

        # maybe expects mapper: Callable[[object], object], so wrap normalize_server_type
        def normalize_server_type_wrapper(value: object) -> object:
            """Wrapper for normalize_server_type to match maybe signature."""
            if isinstance(value, str):
                return c.normalize_server_type(value)
            return value

        normalized_source = u.Ldif.maybe(
            config.source_server_type,
            mapper=normalize_server_type_wrapper,
        )
        normalized_target = u.Ldif.maybe(
            config.target_server_type,
            mapper=normalize_server_type_wrapper,
        )

        mapping_type = u.Ldif.match(
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
            mapping_type=str(mapping_type),
            normalized_source=str(normalized_source),
            normalized_target=str(normalized_target),
        )

        switch_result = u.switch(
            mapping_type,
            {
                "oid_to_oud": lambda _: FlextLdifConversion._apply_oid_to_oud_mapping(
                    config.orig_perms_dict,
                    cast("m.Ldif.Acl", config.converted_acl),
                    self._perms_dict_to_model,
                ),
                "oud_to_oid": lambda _: FlextLdifConversion._apply_oud_to_oid_mapping(
                    config.orig_perms_dict,
                    cast("m.Ldif.Acl", config.converted_acl),
                    self._perms_dict_to_model,
                ),
                "preserve_original": lambda _: (
                    cast("m.Ldif.Acl", config.converted_acl).model_copy(
                        update={
                            "permissions": cast(
                                "t.MetadataAttributeValue",
                                (
                                    cast(
                                        "m.Ldif.AclPermissions",
                                        config.original_acl.permissions,
                                    ).model_copy(deep=True)
                                    if config.original_acl.permissions
                                    and hasattr(
                                        config.original_acl.permissions,
                                        "model_copy",
                                    )
                                    else None
                                ),
                            ),
                        },
                        deep=True,
                    )
                ),
            },
            default=lambda _: config.converted_acl,
        )
        # switch() already calls the lambda, so switch_result is the Acl result
        return cast("m.Ldif.Acl", switch_result)

    def _check_converted_has_permissions(self, converted_acl: m.Ldif.Acl) -> bool:
        """Check if converted ACL has any permissions set."""
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
        return bool(
            converted_acl.permissions
            and u.any_(
                *(
                    getattr(converted_acl.permissions, field, False)
                    for field in permission_fields
                ),
            ),
        )

    def _preserve_permissions(
        self,
        original_acl: m.Ldif.Acl,
        converted_acl: m.Ldif.Acl,
        source_server_type: str | None,
        target_server_type: str | None,
        *,
        converted_has_permissions: bool,
    ) -> m.Ldif.Acl:
        """Preserve permissions from original ACL."""
        if not original_acl.permissions:
            return converted_acl

        orig_perms_dict_raw = original_acl.permissions.model_dump(exclude_unset=True)
        orig_perms_dict: dict[str, bool] = {
            k: v for k, v in orig_perms_dict_raw.items() if v is True
        }

        logger.debug(
            "ACL permission preservation",
            source_server_type=source_server_type,
            target_server_type=target_server_type,
            original_permissions=orig_perms_dict,
        )

        if orig_perms_dict:
            return self._apply_permission_mapping(
                original_acl=original_acl,
                converted_acl=converted_acl,
                orig_perms_dict=orig_perms_dict,
                source_server_type=source_server_type,
                target_server_type=target_server_type,
                converted_has_permissions=converted_has_permissions,
            )

        return converted_acl

    def _get_extensions_dict(self, acl: m.Ldif.Acl) -> dict[str, object]:
        """Extract extensions dict from ACL metadata."""
        get_metadata = u.mapper().prop("metadata")
        get_extensions = u.mapper().prop("extensions")

        if not get_metadata(acl) or not acl.metadata:
            return {}

        extensions_raw = get_extensions(acl.metadata)
        if isinstance(extensions_raw, m.Ldif.DynamicMetadata):
            conv_ext_raw_typed = u.as_type(
                extensions_raw.model_dump(),
                target="dict",
                default={},
            )
            return cast("dict[str, object]", conv_ext_raw_typed)

        return {}

    def _convert_to_metadata_attribute_value(
        self,
        value: object,
    ) -> t.MetadataAttributeValue:
        """Convert value to MetadataAttributeValue type."""
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (list, tuple)):
            # list(value) is list[str | int | float | bool | None] which is t.MetadataAttributeValue
            return list(value)
        if isinstance(value, dict):
            dict_value: dict[str, t.MetadataAttributeValue] = {}
            for k, v in value.items():
                dict_value[k] = self._convert_to_metadata_attribute_value(v)
            return cast("t.MetadataAttributeValue", dict_value)
        return str(value)

    def _preserve_acl_metadata(
        self,
        original_acl: m.Ldif.Acl,
        converted_acl: m.Ldif.Acl,
        source_server_type: str | None = None,
        target_server_type: str | None = None,
    ) -> m.Ldif.Acl:
        """Preserve permissions and metadata from original ACL.

        Args:
            original_acl: The original ACL before conversion
            converted_acl: The converted ACL (modified in-place)
            source_server_type: Server type of the source ACL (use c.ServerTypes)
            target_server_type: Server type of the target ACL (use c.ServerTypes)

        """
        # Preserve permissions
        converted_has_permissions = self._check_converted_has_permissions(converted_acl)
        converted_acl = self._preserve_permissions(
            original_acl,
            converted_acl,
            source_server_type,
            target_server_type,
            converted_has_permissions=converted_has_permissions,
        )

        # Preserve metadata
        get_metadata = u.mapper().prop("metadata")
        get_extensions = u.mapper().prop("extensions")

        # Step 1: Preserve metadata from original ACL if converted ACL doesn't have it
        acl_step1: m.Ldif.Acl = (
            converted_acl.model_copy(
                update={
                    "metadata": cast(
                        "t.MetadataAttributeValue",
                        (
                            original_acl.metadata.model_copy(deep=True)
                            if original_acl.metadata
                            else None
                        ),
                    ),
                },
                deep=True,
            )
            if get_metadata(original_acl) and not get_metadata(converted_acl)
            else converted_acl
        )

        # Step 2: Merge extensions from original and converted ACL
        if not (
            get_metadata(original_acl)
            and get_extensions(original_acl.metadata)
            and get_metadata(acl_step1)
        ):
            return acl_step1

        # Get and merge extensions
        conv_ext = self._get_extensions_dict(acl_step1)
        orig_ext = self._get_extensions_dict(original_acl)

        conv_ext_typed: Mapping[str, FlextTypes.GeneralValueType] = cast(
            "Mapping[str, FlextTypes.GeneralValueType]",
            conv_ext,
        )
        orig_ext_typed: Mapping[str, FlextTypes.GeneralValueType] = cast(
            "Mapping[str, FlextTypes.GeneralValueType]",
            orig_ext,
        )
        merge_result = u.merge_dicts(conv_ext_typed, orig_ext_typed)
        merged_ext_raw = (
            merge_result.value
            if merge_result.is_success
            else None
            if isinstance(merge_result, r) and merge_result.is_success
            else conv_ext
        )
        merged_ext: dict[str, object] = cast("dict[str, object]", merged_ext_raw)

        if not merged_ext or not get_metadata(acl_step1) or not acl_step1.metadata:
            return acl_step1

        # Convert merged extensions to DynamicMetadata
        dynamic_metadata_dict: dict[str, t.MetadataAttributeValue] = {}
        for key, value in merged_ext.items():
            dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                value,
            )

        if acl_step1.metadata:
            updated_metadata = acl_step1.metadata.model_copy(
                update={"extensions": m.Ldif.DynamicMetadata(**dynamic_metadata_dict)},
                deep=True,
            )
            return acl_step1.model_copy(
                update={
                    "metadata": cast("t.MetadataAttributeValue", updated_metadata),
                },
                deep=True,
            )
        return acl_step1

    def _convert_acl(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        acl: m.Ldif.Acl,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
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
            entry_dn = m.Ldif.DistinguishedName(
                value="cn=acl-conversion,dc=example,dc=com",
            )
            entry_attributes = m.Ldif.LdifAttributes(attributes={})

            # Create metadata with ACL stored in metadata.acls
            # Get server_type and default to None (RFC) if not valid
            get_server_type = u.mapper().prop("server_type")
            server_type_attr = u.Ldif.maybe(get_server_type(source_quirk))

            # Use normalize_server_type directly - it handles aliases and validation
            # Type narrowing: normalize_server_type returns ServerTypeLiteral, but we need ServerTypeLiteral | None
            source_server_type_raw = u.try_(
                lambda: (
                    c.normalize_server_type(str(server_type_attr))
                    if isinstance(server_type_attr, str)
                    else None
                ),
                default=None,
            )
            # Type narrowing: ensure source_server_type is ServerTypeLiteral | None
            # Business Rule: source_server_type_raw is already ServerTypeLiteral | None from normalize_server_type
            # Use cast to ensure type checker knows it's the correct type
            source_server_type: str | None = cast(
                "str | None",
                source_server_type_raw,
            )

            entry_metadata = m.Ldif.QuirkMetadata.create_for(
                source_server_type,
                extensions={},
            )
            entry_metadata.acls = [acl]  # Store ACL in metadata.acls

            # Create Entry RFC with ACL in metadata
            rfc_entry = m.Ldif.Entry(
                dn=entry_dn,
                attributes=entry_attributes,
                metadata=entry_metadata,
            )

            # Step 2: Convert Entry using Entry conversion (which preserves metadata.acls)
            entry_result = self._convert_entry(source_quirk, target_quirk, rfc_entry)
            # Extract value from result: r.value if r.is_success else None
            converted_entry = entry_result.value if entry_result.is_success else None
            if converted_entry is None:
                return entry_result
            if not isinstance(converted_entry, m.Ldif.Entry):
                return FlextResult.fail(
                    f"Entry conversion returned unexpected type: {type(converted_entry).__name__}",
                )

            # Step 3: Extract ACL from converted Entry metadata.acls
            get_metadata = u.mapper().prop("metadata")
            get_acls = u.mapper().prop("acls")
            converted_metadata_raw = get_metadata(converted_entry)
            # Type narrowing: prop returns object, but we know it's QuirkMetadata | None
            if not isinstance(
                converted_metadata_raw,
                (m.Ldif.QuirkMetadata, type(None)),
            ):
                return FlextResult.fail(
                    f"Unexpected metadata type: {type(converted_metadata_raw).__name__}",
                )
            # Type narrowing: isinstance check ensures type is m.Ldif.QuirkMetadata | None
            converted_metadata: m.Ldif.QuirkMetadata | None = converted_metadata_raw
            acls_raw = get_acls(converted_metadata) if converted_metadata else None
            # Type narrowing: prop returns object, but we know it's list[Acl] | None
            if acls_raw is not None and not isinstance(acls_raw, list):
                return FlextResult.fail(
                    f"Unexpected acls type: {type(acls_raw).__name__}",
                )
            acls: list[m.Ldif.Acl] | None = cast(
                "list[m.Ldif.Acl] | None",
                acls_raw,
            )

            if not acls:
                return FlextResult.fail(
                    "Converted entry has no ACLs in metadata.acls",
                )

            # Get first ACL from metadata (should be the converted one)
            # Type narrowing: acls is list[Acl] | None, check before indexing
            if not u.Guards.is_list_non_empty(acls):
                return FlextResult.fail("No ACL found in converted entry metadata")
            domain_acl = acls[0]
            # Convert domain Acl to public Acl model
            match_result = u.Ldif.match(
                domain_acl,
                (
                    m.Ldif.Acl,
                    lambda acl: acl,
                ),
                default=lambda acl: m.Ldif.Acl.model_validate(
                    acl.model_dump(),
                ),
            )
            # Type narrowing: match returns object, but we know it's Acl
            converted_acl: m.Ldif.Acl = cast(
                "m.Ldif.Acl",
                match_result,
            )

            # Get target server type for permission mapping
            get_server_type = u.mapper().prop("server_type")
            target_server_type_raw = u.Ldif.maybe(
                get_server_type(target_quirk),
                default="unknown",
            )
            # Use normalize_server_type directly - it handles aliases and validation
            target_server_type = u.try_(
                lambda: (
                    c.normalize_server_type(target_server_type_raw)
                    if isinstance(target_server_type_raw, str)
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
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"Acl conversion failed: {e}",
            )

    def _extract_and_register_dns(
        self,
        model: m.Ldif.Acl,
        data_type: str,
    ) -> None:
        """Extract DNs from ACL model and register with canonical case using u.

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
                if dn_part and u.Ldif.DN.validate(dn_part):
                    _ = self.dn_registry.register_dn(dn_part)

            # Plain DN (not in LDAP URL format)
            elif "=" in subject_value or "," in subject_value:
                # Validate DN using u.DN before registering
                if u.Ldif.DN.validate(subject_value):
                    _ = self.dn_registry.register_dn(subject_value)

    def _normalize_dns_in_model(
        self,
        acl: m.Ldif.Acl,
    ) -> r[m.Ldif.Acl]:
        """Normalize DN references in ACL model to use canonical case.

        For ACL models, DN normalization is typically a pass-through
        since ACLs contain LDAP URLs, not plain DNs.

        Args:
            acl: ACL Pydantic model with potential DN references

        Returns:
            r with normalized ACL model

        """
        # ACLs typically don't have direct DN fields to normalize
        # DN references are in LDAP URLs like "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        # which are handled during parsing/writing
        return r[m.Ldif.Acl].ok(acl)

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
            # Conditional return using ternary operator
            # Type narrowing: write_result is r[str], extract value directly
            return (
                r.ok(write_result.value if write_result.is_success else None)
                if write_result.is_success
                else r.ok(fallback)
            )
        except TypeError:
            return r.ok(fallback)

    def _write_attribute_to_rfc(
        self,
        source: str | FlextLdifServersBase,
        source_attr: m.Ldif.SchemaAttribute | t.MetadataAttributeValue | str,
    ) -> r[str | m.Ldif.SchemaAttribute | t.MetadataAttributeValue]:
        """Write attribute to RFC string representation."""
        if isinstance(source_attr, str):
            return r.ok(source_attr)
        if not isinstance(source_attr, m.Ldif.SchemaAttribute):
            return r.ok(source_attr)

        source_quirk = self._resolve_quirk(source)
        return cast(
            "r[str | m.Ldif.SchemaAttribute | t.MetadataAttributeValue]",
            FlextLdifConversion._try_write_schema_item(
                source_quirk,
                source_attr,
                lambda s, attr: cast("FlextLdifServersBase.Schema", s).write_attribute(
                    cast("m.Ldif.SchemaAttribute", attr),
                ),
                source_attr,
            ),
        )

    def _convert_attribute(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        data: str | t.MetadataAttributeValue,
    ) -> r[m.Ldif.SchemaAttribute | str | t.MetadataAttributeValue]:
        """Convert attribute from source to target quirk via write->parse pipeline.

        Pipeline: parse source -> write as string -> parse target
        """
        try:
            if not isinstance(data, str):
                return FlextResult.fail("Attribute conversion requires string data")

            # Use u.map() for unified result pipeline (DSL pattern)
            parse_result = self._parse_source_attribute(source, data)
            parsed_attr = parse_result.value if parse_result.is_success else None
            if parsed_attr is None:
                return r[m.Ldif.SchemaAttribute | t.MetadataAttributeValue | str].fail(
                    u.err(parse_result),
                )

            # Use u.map() for unified result pipeline (DSL pattern)
            rfc_result = self._write_attribute_to_rfc(source, parsed_attr)
            rfc_value = rfc_result.value if rfc_result.is_success else None
            if rfc_value is None:
                # Type narrowing: rfc_result is r[str | m.Ldif.SchemaAttribute | t.MetadataAttributeValue]
                # which is compatible with return type r[m.Ldif.SchemaAttribute | str | t.MetadataAttributeValue]
                return rfc_result

            # Use u.when() for conditional type check (DSL pattern)
            if not isinstance(rfc_value, str):
                return r.ok(rfc_value)

            # Use u.map() for unified result handling (DSL pattern)
            target_parse_result = self._parse_target_attribute(target, rfc_value)
            # Type narrowing: mapper returns r, but u.map expects direct value
            # Use flat_map or handle result manually
            if target_parse_result.is_failure:
                # Type narrowing: target_parse_result is r[m.Ldif.SchemaAttribute]
                # which is compatible with return type r[m.Ldif.SchemaAttribute | str | t.MetadataAttributeValue]
                return target_parse_result
            # Type narrowing: when is_failure is False, value is guaranteed to be m.Ldif.SchemaAttribute
            parsed_value: m.Ldif.SchemaAttribute = target_parse_result.value
            # Type narrowing: write_result is r[m.Ldif.SchemaAttribute | str | t.MetadataAttributeValue]
            # which matches the return type exactly
            return self._write_target_attribute(parsed_value)

        except Exception as e:
            return r[m.Ldif.SchemaAttribute | str | t.MetadataAttributeValue].fail(
                f"Attribute conversion failed: {e}",
            )

    def _parse_source_attribute(
        self,
        source: str | FlextLdifServersBase,
        data: str | t.MetadataAttributeValue,
    ) -> r[m.Ldif.SchemaAttribute]:
        """Parse source attribute."""
        source_quirk = self._resolve_quirk(source)

        # Get source schema quirk with proper type narrowing
        try:
            source_schema = _get_schema_quirk(source_quirk)
        except TypeError as e:
            return FlextResult.fail(f"Source quirk error: {e}")

        # Ensure data is string for parse_attribute
        if isinstance(data, str):
            parse_method = source_schema.parse_attribute
            parse_result = parse_method(data)
            # Convert m.Ldif.SchemaAttribute to m.Ldif.SchemaAttribute
            if parse_result.is_success:
                attr_domain = parse_result.unwrap()
                return r[m.Ldif.SchemaAttribute].ok(
                    cast("m.Ldif.SchemaAttribute", attr_domain),
                )
            # Return result directly - type checker knows it's r[SchemaAttribute]
            return parse_result
        return r.fail("parse_attribute requires string data")

    def _parse_target_attribute(
        self,
        target: str | FlextLdifServersBase,
        rfc_value: str,
    ) -> r[m.Ldif.SchemaAttribute]:
        """Parse target attribute from RFC string."""
        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            target_schema = _get_schema_quirk(target_quirk)
        except TypeError as e:
            return FlextResult.fail(f"Target quirk error: {e}")

        parse_method = target_schema.parse_attribute
        parse_result = parse_method(rfc_value)
        # Convert m.Ldif.SchemaAttribute to m.Ldif.SchemaAttribute
        if parse_result.is_success:
            attr_domain = parse_result.unwrap()
            return r[m.Ldif.SchemaAttribute].ok(
                cast("m.Ldif.SchemaAttribute", attr_domain),
            )
        # Cast failure result to correct type
        return cast("r[m.Ldif.SchemaAttribute]", parse_result)

    def _write_target_attribute(
        self,
        parsed_attr: m.Ldif.SchemaAttribute | str | t.MetadataAttributeValue,
    ) -> r[m.Ldif.SchemaAttribute | str | t.MetadataAttributeValue]:
        """Write target attribute to final format."""
        # Type narrowing: write_attribute requires SchemaAttribute
        if not isinstance(parsed_attr, m.Ldif.SchemaAttribute):
            # Return as-is if not SchemaAttribute - type narrowing for union type
            if isinstance(parsed_attr, dict):
                return r[m.Ldif.SchemaAttribute | t.MetadataAttributeValue | str].ok(
                    parsed_attr,
                )
            if isinstance(parsed_attr, str):
                return r[m.Ldif.SchemaAttribute | t.MetadataAttributeValue | str].ok(
                    parsed_attr,
                )
            msg = f"Expected SchemaAttribute | dict | str, got {type(parsed_attr)}"
            raise TypeError(msg)

        # Model-based conversion - return parsed attribute as-is
        # Schema quirks write via model conversion, not string-based
        return r[m.Ldif.SchemaAttribute | t.MetadataAttributeValue | str].ok(
            parsed_attr,
        )

    def _write_objectclass_to_rfc(
        self,
        source: str | FlextLdifServersBase,
        source_oc: m.Ldif.SchemaObjectClass | t.MetadataAttributeValue | str,
    ) -> r[str | m.Ldif.SchemaObjectClass | t.MetadataAttributeValue]:
        """Write objectClass to RFC string representation."""
        if isinstance(source_oc, str):
            return r[str | m.Ldif.SchemaObjectClass | t.MetadataAttributeValue].ok(
                source_oc,
            )

        if not isinstance(source_oc, m.Ldif.SchemaObjectClass):
            if isinstance(source_oc, dict):
                return r[str | m.Ldif.SchemaObjectClass | t.MetadataAttributeValue].ok(
                    source_oc,
                )
            msg = f"Expected SchemaObjectClass | str | dict, got {type(source_oc)}"
            raise TypeError(msg)

        source_quirk = self._resolve_quirk(source)
        write_result = FlextLdifConversion._try_write_schema_item(
            source_quirk,
            source_oc,
            lambda s, oc: cast("FlextLdifServersBase.Schema", s).write_objectclass(
                cast("m.Ldif.SchemaObjectClass", oc),
            ),
            source_oc,
        )
        # Extract value from result: r.value if r.is_success else None
        write_value = write_result.value if write_result.is_success else None
        if write_value is not None and isinstance(write_value, str):
            return r[str | m.Ldif.SchemaObjectClass | t.MetadataAttributeValue].ok(
                write_value,
            )
        return cast(
            "r[str | m.Ldif.SchemaObjectClass | t.MetadataAttributeValue]",
            write_result,
        )

    def _convert_objectclass(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        data: str | t.MetadataAttributeValue,
    ) -> r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue]:
        """Convert objectClass from source to target quirk via write->parse pipeline.

        Pipeline: parse source -> write as string -> parse target
        """
        try:
            if not isinstance(data, str):
                return FlextResult.fail("ObjectClass conversion requires string data")

            # Use u.map() for unified result pipeline (DSL pattern)
            parse_result = self._parse_source_objectclass(source, data)
            parsed_oc = parse_result.value if parse_result.is_success else None
            if parsed_oc is None:
                return r[
                    m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue
                ].fail(
                    u.err(parse_result) or "Failed to parse source objectClass",
                )

            write_result = self._write_objectclass_to_rfc(source, parsed_oc)
            rfc_value = write_result.value if write_result.is_success else None
            if rfc_value is None:
                # Type narrowing: write_result is r[str | m.Ldif.SchemaObjectClass | t.MetadataAttributeValue]
                # which is compatible with return type r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue]
                return write_result
            if not isinstance(rfc_value, str):
                if isinstance(rfc_value, (m.Ldif.SchemaObjectClass, dict)):
                    return r[
                        m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue
                    ].ok(
                        rfc_value,
                    )
                return r[
                    m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue
                ].fail(
                    f"Expected SchemaObjectClass | str | dict, got {type(rfc_value)}",
                )

            # Use u.map() for unified result handling (DSL pattern)
            target_result = self._parse_target_objectclass(target, rfc_value)
            # Type narrowing: mapper returns r, but u.map expects direct value
            # Handle result manually
            if target_result.is_failure:
                # Type narrowing: target_result is r[m.Ldif.SchemaObjectClass]
                # which is compatible with return type r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue]
                return target_result
            parsed_value = target_result.value
            # Type narrowing: write_result is r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue]
            # which matches the return type exactly
            return self._write_target_objectclass(target, parsed_value)

        except Exception as e:
            return r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue].fail(
                f"ObjectClass conversion failed: {e}",
            )

    def _parse_source_objectclass(
        self,
        source: str | FlextLdifServersBase,
        data: str | t.MetadataAttributeValue,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse source objectClass."""
        source_quirk = self._resolve_quirk(source)

        # Get source schema quirk with proper type narrowing
        try:
            source_schema = _get_schema_quirk(source_quirk)
        except TypeError as e:
            return FlextResult.fail(f"Source quirk error: {e}")

        # Ensure data is string for parse_objectclass
        if isinstance(data, str):
            parse_method = source_schema.parse_objectclass
            parse_result = parse_method(data)
            # Convert m.Ldif.SchemaObjectClass to m.Ldif.SchemaObjectClass
            if parse_result.is_success:
                oc_domain = parse_result.unwrap()
                return r[m.Ldif.SchemaObjectClass].ok(
                    cast("m.Ldif.SchemaObjectClass", oc_domain),
                )
            # Cast failure result to correct type
            return cast("r[m.Ldif.SchemaObjectClass]", parse_result)
        return r.fail("parse_objectclass requires string data")

    def _parse_target_objectclass(
        self,
        target: str | FlextLdifServersBase,
        rfc_value: str,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse target objectClass from RFC string."""
        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            target_schema = _get_schema_quirk(target_quirk)
        except TypeError as e:
            return FlextResult.fail(f"Target quirk error: {e}")

        parse_method = target_schema.parse_objectclass
        parse_result = parse_method(rfc_value)
        # Convert m.Ldif.SchemaObjectClass to m.Ldif.SchemaObjectClass
        if parse_result.is_success:
            oc_domain = parse_result.unwrap()
            return r[m.Ldif.SchemaObjectClass].ok(
                cast("m.Ldif.SchemaObjectClass", oc_domain),
            )
        # Cast failure result to correct type
        return cast("r[m.Ldif.SchemaObjectClass]", parse_result)

    def _write_target_objectclass(
        self,
        target: str | FlextLdifServersBase,
        parsed_oc: m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue,
    ) -> r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue]:
        """Write target objectClass to final format."""
        # Type narrowing: write_objectclass requires SchemaObjectClass
        if not isinstance(parsed_oc, m.Ldif.SchemaObjectClass):
            # Return as-is if not SchemaObjectClass - type narrowing for union type
            if isinstance(parsed_oc, str):
                return r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue].ok(
                    parsed_oc,
                )
            if isinstance(parsed_oc, dict):
                return r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue].ok(
                    parsed_oc,
                )
            msg = f"Expected SchemaObjectClass | str | dict, got {type(parsed_oc)}"
            raise TypeError(msg)

        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            schema_quirk = _get_schema_quirk(target_quirk)
        except TypeError:
            # Return as-is if no writer available
            return r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue].ok(
                parsed_oc,
            )

        # schema_quirk is already properly typed from _get_schema_quirk
        write_result = schema_quirk.write_objectclass(parsed_oc)
        # write_objectclass returns r[str] - convert to union type
        # Extract value from result: r.value if r.is_success else None
        written_str = write_result.value if write_result.is_success else None
        if written_str is not None:
            # Type narrowing: write_objectclass returns str | SchemaObjectClass | MetadataAttributeValue
            # After None check, written_str is guaranteed to be one of these types
            return r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue].ok(
                written_str,
            )
        # Use u.err() for unified error extraction (DSL pattern)
        error_msg = u.err(write_result) or "Failed to write objectClass"
        return r[m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue].fail(
            error_msg,
        )

    def batch_convert(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_list: Sequence[t.ConvertibleModel],
    ) -> r[
        list[
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ]
    ]:
        """Convert multiple models from source to target quirk via RFC.

        Model-based batch conversion only - no legacy string/dict support.
        DN registry is shared across all conversions to ensure case consistency.
        Emits ConversionEvent with aggregated statistics (MANDATORY - eventos obrigatórios).

        Args:
            source: Source quirk instance
            target: Target quirk instance
            model_list: List of model instances to convert

        Returns:
            r containing list of converted models

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
        source_format_raw = u.Ldif.match(
            source,
            (str, lambda s: s),
            default=lambda src: u.Ldif.maybe(
                u.mapper().prop("server_name")(src),
                default="unknown",
            ),
        )
        target_format_raw = u.Ldif.match(
            target,
            (str, lambda t: t),
            default=lambda tgt: u.Ldif.maybe(
                u.mapper().prop("server_name")(tgt),
                default="unknown",
            ),
        )
        # Type narrowing: match returns object, but we know it's str
        source_format: str = cast("str", source_format_raw)
        target_format: str = cast("str", target_format_raw)

        # Handle empty list case - succeed with empty result
        # No event emission for empty batches (no work done)
        if not model_list:
            return r[
                list[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].ok([])

        model_type = type(model_list[0]).__name__
        conversion_operation = f"batch_convert_{model_type}"

        try:
            # Collect converted models (concrete types from convert method)
            converted: list[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ] = []
            errors: list[str] = []
            error_details: list[m.ErrorDetail] = []

            for idx, model_item in enumerate(model_list):
                result = self.convert(source, target, model_item)
                # Extract value from result: r.value if r.is_success else None
                unwrapped = result.value if result.is_success else None
                if unwrapped is not None:
                    # convert() returns ConvertibleModel (protocol-based)
                    # so unwrapped is already typed correctly
                    converted.append(unwrapped)
                else:
                    error_msg = u.err(result) or "Unknown error"
                    errors.append(f"Item {idx}: {error_msg}")
                    error_details.append(
                        m.ErrorDetail(
                            item=f"batch_item_{idx}",
                            error=error_msg,
                        ),
                    )

            # Calculate duration and emit ConversionEvent (MANDATORY - eventos obrigatórios)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Type narrowing: u.count expects generic types, model_list and converted are list[object] compatible
            model_list_typed: list[object] = model_list
            converted_typed: list[object] = converted
            errors_typed: list[object] = cast("list[object]", errors)
            items_processed = u.Collection.count(model_list_typed)
            items_converted = u.Collection.count(converted_typed)
            items_failed = u.Collection.count(errors_typed)

            # Create conversion event config for batch
            # Type narrowing: source_format and target_format are already str (from cast above)
            conversion_config = m.Ldif.LdifResults.Events.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=items_processed,
                items_converted=items_converted,
                items_failed=items_failed,
                conversion_duration_ms=duration_ms,
                error_details=error_details or None,
            )
            _ = u.Events.log_and_emit_conversion_event(
                logger=logger,
                config=conversion_config,
                log_level="warning" if errors else "info",
            )

            if errors:
                error_count = u.Collection.count(errors)
                error_msg = (
                    f"Batch conversion completed with {error_count} errors:\n"
                    + "\n".join(errors[: self.MAX_ERRORS_TO_SHOW])
                )
                if error_count > self.MAX_ERRORS_TO_SHOW:
                    error_msg += (
                        f"\n... and {error_count - self.MAX_ERRORS_TO_SHOW} more errors"
                    )
                return r[
                    list[
                        m.Ldif.Entry
                        | m.Ldif.SchemaAttribute
                        | m.Ldif.SchemaObjectClass
                        | m.Ldif.Acl
                    ]
                ].fail(
                    error_msg,
                )

            # converted already has correct type from declaration (line 1490)
            return r[
                list[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].ok(converted)

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            # Emit ConversionEvent for exception case (MANDATORY - eventos obrigatórios)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Create conversion event config for exception case
            # Type narrowing: source_format and target_format are already str (from cast above)
            # Type narrowing: u.count expects generic types, cast model_list to list[object]
            model_list_typed_exception: list[object] = cast("list[object]", model_list)
            conversion_config = m.Ldif.LdifResults.Events.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=u.Collection.count(model_list_typed_exception),
                items_converted=0,
                items_failed=u.Collection.count(model_list_typed_exception),
                conversion_duration_ms=duration_ms,
                error_details=[
                    m.ErrorDetail(
                        item="batch_conversion",
                        error=f"Batch conversion failed: {e}",
                    ),
                ],
            )
            _ = u.Events.log_and_emit_conversion_event(
                logger=logger,
                config=conversion_config,
                log_level="error",
            )

            return r[
                list[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].fail(
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

    def get_supported_conversions(self, quirk: FlextLdifServersBase) -> dict[str, bool]:
        """Check which data types a quirk supports for conversion.

        Args:
            quirk: Quirk instance to check

        Returns:
            Dictionary mapping data_type to support status

        Examples:
            >>> registry = FlextLdifServer()
            >>> quirk = registry.quirk("oud")
            >>> supported = matrix.get_supported_conversions(quirk)
            >>> print(supported)
            {'attribute': True, 'objectclass': True, 'acl': True, 'entry': True}

        """
        support: t.CommonDict.DistributionDict = {
            "attribute": 0,
            "objectclass": 0,
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
            "objectclass": bool(
                support.get("objectclass", 0),
            ),
            "acl": bool(support.get("acl", 0)),
            "entry": bool(support.get("entry", 0)),
        }

    def _get_schema_quirk_for_support_check(
        self,
        quirk: FlextLdifServersBase,
    ) -> object | None:
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

                return cast("object", quirk)
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

                return cast("object", schema_quirk_raw)
            return None
        return None

    def _check_attribute_support(
        self,
        quirk_schema: object,
        test_attr_def: str,
        support: t.CommonDict.DistributionDict,
    ) -> t.CommonDict.DistributionDict:
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
        # Type narrowing: parse_attribute returns r-like object
        # Use isinstance check for proper type narrowing instead of hasattr
        if isinstance(attr_result, r) and attr_result.is_success:
            support["attribute"] = 1

        return support

    def _check_objectclass_support(
        self,
        quirk_schema: object,
        test_oc_def: str,
        support: t.CommonDict.DistributionDict,
    ) -> t.CommonDict.DistributionDict:
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
        # Extract value from result: r.value if r.is_success else None
        if (
            isinstance(oc_result, r)
            and (oc_result.value if oc_result.is_success else None) is not None
        ):
            support["objectclass"] = 1

        return support

    def _check_schema_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.CommonDict.DistributionDict,
    ) -> t.CommonDict.DistributionDict:
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
        support: t.CommonDict.DistributionDict,
    ) -> t.CommonDict.DistributionDict:
        """Check ACL support."""
        # No fallback - check both attributes explicitly
        acl = getattr(quirk, "acl_quirk", None)
        if acl is None:
            acl = getattr(quirk, "_acl_quirk", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if acl and callable(getattr(acl, "parse", None)):
            acl_result = acl.parse(test_acl_def)
            # Extract value from result: r.value if r.is_success else None
            if (acl_result.value if acl_result.is_success else None) is not None:
                support["acl"] = 1
        return support

    def _check_entry_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.CommonDict.DistributionDict,
    ) -> t.CommonDict.DistributionDict:
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
