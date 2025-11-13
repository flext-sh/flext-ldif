"""Quirks conversion matrix for LDAP server translation.

This module provides the QuirksConversionMatrix facade that enables
conversion between LDAP server quirks (OUD, OID, OpenLDAP, etc.) using
a universal Entry model as the pivot point.

Conversion Pattern:
 Source → Write to LDIF → Parse with Target → Entry Model

All server conversions work through the universal Entry model, which stores
server-specific metadata. This simplifies conversions to: write→parse pipeline.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import ClassVar, Union, cast, override

from flext_core import FlextLogger, FlextResult, FlextService
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

# Module-level logger
logger = FlextLogger(__name__)


class FlextLdifConversion(
    FlextService[
        Union[
            "FlextLdifModels.Entry",
            "FlextLdifModels.SchemaAttribute",
            "FlextLdifModels.SchemaObjectClass",
            "FlextLdifModels.Acl",
        ]
    ],
):
    """Facade for universal, model-driven quirk-to-quirk conversion.

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
    dn_registry: FlextLdifModels.DnRegistry = Field(
        default_factory=FlextLdifModels.DnRegistry
    )

    def __init__(self) -> None:
        """Initialize the conversion facade with DN case registry."""
        super().__init__()

    @override
    def execute(
        self,
    ) -> FlextResult[
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    ]:
        """Execute conversion service health check.

        Returns:
            FlextResult with empty Entry model for health check

        Note:
            Returns empty Entry model to satisfy FlextService type constraints.
            This is a health check, actual conversions use convert() method.

        """
        try:
            # Return empty Entry for health check to satisfy type constraints
            empty_entry = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=health-check"),
                attributes=FlextLdifModels.LdifAttributes(attributes={}),
            )
            return FlextResult[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
            ].ok(empty_entry)
        except Exception as e:
            return FlextResult[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
            ].fail(
                f"Conversion service health check failed: {e}",
            )

    def convert(
        self,
        source: FlextLdifServersBase,
        target: FlextLdifServersBase,
        model_instance_or_data_type: FlextLdifTypes.ConvertibleModel | str,
        data: str | dict[str, object] | None = None,
    ) -> (
        FlextResult[FlextLdifTypes.ConvertibleModel]
        | FlextResult[str | dict[str, object]]
    ):
        """Convert a model from a source server format to a target server format.

        Supports both new strategy pattern (model-based) and legacy string-based conversions.
        Emits ConversionEvent for all conversions (MANDATORY - eventos obrigatórios).

        Args:
            source: Source quirk instance
            target: Target quirk instance
            model_instance_or_data_type: Either a model instance (new pattern) or data type string (legacy)
            data: Data to convert (legacy pattern only)

        Returns:
            FlextResult with converted model or string data

        """
        # Track conversion duration (MANDATORY - eventos obrigatórios)
        start_time = time.perf_counter()

        # Determine conversion type and get source/target format names
        source_format = getattr(source, "server_name", "unknown")
        target_format = getattr(target, "server_name", "unknown")

        if isinstance(model_instance_or_data_type, str):
            # Legacy string-based conversion
            conversion_operation = f"convert_{model_instance_or_data_type}"
        else:
            # Model-based conversion
            model_type = type(model_instance_or_data_type).__name__
            conversion_operation = f"convert_{model_type}"

        # Execute conversion
        result: (
            FlextResult[FlextLdifTypes.ConvertibleModel]
            | FlextResult[str | dict[str, object]]
        )
        if isinstance(model_instance_or_data_type, str) and data is not None:
            # Legacy string-based conversion
            result = cast(
                "FlextResult[FlextLdifTypes.ConvertibleModel] | FlextResult[str | dict[str, object]]",
                self._convert_legacy(
                    source,
                    target,
                    model_instance_or_data_type,
                    data,
                ),
            )
        elif data is None and not isinstance(model_instance_or_data_type, str):
            # New model-based conversion - type guard ensures it's a model
            result = self._convert_model(source, target, model_instance_or_data_type)
        else:
            result = FlextResult.fail(
                "Invalid arguments: provide either (model) or (data_type, data)",
            )

        # Calculate duration and emit ConversionEvent (MANDATORY - eventos obrigatórios)
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Emit ConversionEvent with results
        items_converted = 1 if result.is_success else 0
        items_failed = 0 if result.is_success else 1

        # Create conversion event config
        conversion_config = FlextLdifModels.ConversionEventConfig(
            conversion_operation=conversion_operation,
            source_format=source_format,
            target_format=target_format,
            items_processed=1,
            items_converted=items_converted,
            items_failed=items_failed,
            conversion_duration_ms=duration_ms,
            error_details=[
                FlextLdifModels.ErrorDetail(item=str(data), error=str(result.error))
            ]
            if result.is_failure
            else None,
        )
        FlextLdifUtilities.Events.log_and_emit_conversion_event(
            logger=logger,
            config=conversion_config,
            log_level="info" if result.is_success else "error",
        )

        return result

    def _convert_model(
        self,
        source: FlextLdifServersBase,
        target: FlextLdifServersBase,
        model_instance: FlextLdifTypes.ConvertibleModel,
    ) -> FlextResult[FlextLdifTypes.ConvertibleModel]:
        """Convert Entry model between source and target server formats with FlextLdifUtilities.

        Uses universal Entry model as pivot point via write→parse pipeline.
        Conversions are server-agnostic: write to LDIF, then parse with target quirk.

        This approach eliminates the need for normalize_to_rfc/denormalize_from_rfc
        and ensures all conversions go through the same parse/write codepath used
        in normal parsing and writing operations.
        """
        try:
            # Only Entry models can be converted (schema models are server-specific)
            if not isinstance(model_instance, FlextLdifModels.Entry):
                return FlextResult.fail(
                    f"Only Entry models can be converted between servers. "
                    f"Got: {type(model_instance).__name__}",
                )

            entry: FlextLdifModels.Entry = model_instance

            # Validate entry DN using FlextLdifUtilities.DN before conversion
            entry_dn = (
                str(FlextLdifUtilities.DN.get_dn_value(entry.dn)) if entry.dn else ""
            )
            if not FlextLdifUtilities.DN.validate(entry_dn):
                return FlextResult.fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )

            # Register entry DN for case consistency during conversion
            self.dn_registry.register_dn(entry_dn)

            # Step 1: Write Entry from source server format to RFC LDIF string
            # Use write() which routes to entry quirk internally
            write_result = source.write([entry])
            if write_result.is_failure:
                return FlextResult.fail(
                    f"Failed to write entry in source format: {write_result.error}",
                )

            ldif_string: str = write_result.unwrap()
            if not ldif_string or not ldif_string.strip():
                return FlextResult.fail("Write operation returned empty LDIF")

            # Step 2: Parse LDIF string with target server to get Entry in target format
            parse_result = target.parse(ldif_string)
            if parse_result.is_failure:
                return FlextResult.fail(
                    f"Failed to parse entry in target format: {parse_result.error}",
                )

            parse_response = parse_result.unwrap()
            # Extract entries from ParseResponse
            parsed_entries = parse_response.entries
            if not parsed_entries:
                return FlextResult.fail("Parse operation returned empty entry list")

            # FASE 3: Preserve validation metadata from source entry to target entry
            converted_entry = parsed_entries[0]
            converted_entry = FlextLdifUtilities.Metadata.preserve_validation_metadata(  # type: ignore[arg-type]
                source_model=entry,
                target_model=cast("FlextLdifModels.Entry", converted_entry),
                transformation={
                    "step": "convert_entry",
                    "source_server": source.server_type,
                    "target_server": target.server_type,
                    "changes": [
                        "Converted via write→parse pipeline",
                        f"DN registered: {entry_dn}",
                    ],
                },
            )

            # Return first parsed entry (conversion always produces one entry)
            return FlextResult.ok(converted_entry)

        except Exception as e:
            return FlextResult.fail(f"Entry conversion failed: {e}")

    def _convert_legacy(
        self,
        source: FlextLdifServersBase,
        target: FlextLdifServersBase,
        data_type: str,
        data: str | dict[str, object],
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | str
        | dict[str, object]
    ]:
        """Convert using legacy string-based pattern."""
        try:
            # Normalize data_type to lowercase for case-insensitive matching
            data_type_lower = data_type.lower()

            if data_type_lower == "attribute":
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str | dict[str, object]]",
                    self._convert_attribute(source, target, data),
                )
            if data_type_lower in {"objectclass", "objectclasses"}:
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str | dict[str, object]]",
                    self._convert_objectclass(source, target, data),
                )
            if data_type_lower == "acl":
                if isinstance(data, str):
                    acl_result = self._convert_acl(source, target, data)
                    # Widen return type for legacy method compatibility
                    if acl_result.is_success:
                        return cast(
                            "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str | dict[str, object]]",
                            FlextResult[str | dict[str, object]].ok(
                                acl_result.unwrap()
                            ),
                        )
                    return cast(
                        "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str | dict[str, object]]",
                        FlextResult[str | dict[str, object]].fail(
                            acl_result.error or "ACL conversion failed"
                        ),
                    )
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str | dict[str, object]]",
                    FlextResult[str | dict[str, object]].fail(
                        "ACL conversion requires string input"
                    ),
                )
            if data_type_lower == "entry":
                # _convert_entry doesn't take source/target/data arguments anymore
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str | dict[str, object]]",
                    self._convert_entry(),
                )
            return FlextResult.fail(f"Invalid data_type: {data_type}")
        except Exception as e:
            return FlextResult.fail(f"Legacy conversion failed: {e}")

    def _extract_and_register_dns(
        self,
        model: FlextLdifModels.Acl,
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
            if isinstance(subject_value, str) and "ldap:///" in subject_value:
                dn_part = subject_value.split("ldap:///", 1)[1].split("?", 1)[0]
                # Validate DN using FlextLdifUtilities before registering
                if dn_part and FlextLdifUtilities.DN.validate(dn_part):
                    self.dn_registry.register_dn(dn_part)

            # Plain DN (not in LDAP URL format)
            elif isinstance(subject_value, str) and (
                "=" in subject_value or "," in subject_value
            ):
                # Validate DN using FlextLdifUtilities.DN before registering
                if FlextLdifUtilities.DN.validate(subject_value):
                    self.dn_registry.register_dn(subject_value)

    def _normalize_dns_in_model(
        self,
        acl: FlextLdifModels.Acl,
    ) -> FlextResult[FlextLdifModels.Acl]:
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
        return FlextResult[FlextLdifModels.Acl].ok(acl)

    def _write_attribute_to_rfc(
        self,
        source: FlextLdifServersBase,
        source_attr: FlextLdifModels.SchemaAttribute | dict[str, object] | str,
    ) -> FlextResult[str | FlextLdifModels.SchemaAttribute | dict[str, object]]:
        """Write attribute to RFC string representation."""
        # If already a string, return as-is
        if isinstance(source_attr, str):
            return FlextResult.ok(source_attr)

        # Type narrowing: ensure source_attr is SchemaAttribute
        if not isinstance(source_attr, FlextLdifModels.SchemaAttribute):
            return FlextResult.ok(source_attr)  # Pass-through if not SchemaAttribute

        # Check if source is already a Schema object (direct usage)
        write_method = getattr(source, "write_attribute", None)
        if write_method is not None:
            write_result = write_method(source_attr)
        elif hasattr(source, "schema_quirk"):
            write_method = getattr(source.schema_quirk, "write_attribute", None)
            if write_method is not None:
                write_result = write_method(source_attr)
            else:
                return FlextResult.ok(source_attr)  # Return as-is if no writer
        else:
            return FlextResult.ok(source_attr)  # Return as-is if no writer

        if write_result.is_failure:
            return FlextResult.ok(source_attr)  # Return as-is on write error

        return FlextResult.ok(write_result.unwrap())

    def _convert_attribute(
        self,
        source: FlextLdifServersBase,
        target: FlextLdifServersBase,
        data: str | dict[str, object],
    ) -> FlextResult[FlextLdifModels.SchemaAttribute | str | dict[str, object]]:
        """Convert attribute from source to target quirk via write→parse pipeline.

        Pipeline: parse source → write as string → parse target
        """
        try:
            # Step 1: Parse source attribute using generic utility
            parse_result = FlextLdifUtilities.Parser.parse_with_quirk_fallback(
                source, data, "parse_attribute"
            )
            if parse_result.is_failure:
                return parse_result
            source_attr = parse_result.unwrap()

            # Step 2: Write to RFC string
            write_result = self._write_attribute_to_rfc(source, source_attr)
            if write_result.is_failure:
                return write_result
            rfc_value = write_result.unwrap()

            # If result is not a string, return as-is (pass-through)
            if not isinstance(rfc_value, str):
                return FlextResult.ok(rfc_value)

            # Step 3: Parse RFC string with target quirk using generic utility
            target_result = FlextLdifUtilities.Parser.parse_with_quirk_fallback(
                target, rfc_value, "parse_attribute"
            )
            if target_result.is_failure:
                return target_result
            parsed_attr = target_result.unwrap()

            # Type narrowing: write_attribute requires SchemaAttribute
            if not isinstance(parsed_attr, FlextLdifModels.SchemaAttribute):
                return FlextResult.ok(
                    parsed_attr
                )  # Return as-is if not SchemaAttribute

            # Step 4: Write target attribute to final format
            write_method = getattr(target, "write_attribute", None)
            if write_method is not None:
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | str | dict[str, object]]",
                    write_method(parsed_attr),
                )
            if hasattr(target, "schema_quirk"):
                write_method = getattr(target.schema_quirk, "write_attribute", None)
                if write_method is not None:
                    return cast(
                        "FlextResult[FlextLdifModels.SchemaAttribute | str | dict[str, object]]",
                        write_method(parsed_attr),
                    )
            # No schema writer available, return parsed attribute as-is
            return FlextResult.ok(parsed_attr)

        except (AttributeError, ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult.fail(f"Attribute conversion failed: {e}")

    def _write_objectclass_to_rfc(
        self,
        source: FlextLdifServersBase,
        source_oc: FlextLdifModels.SchemaObjectClass | dict[str, object] | str,
    ) -> FlextResult[str | FlextLdifModels.SchemaObjectClass | dict[str, object]]:
        """Write objectClass to RFC string representation."""
        # If already a string, return as-is
        if isinstance(source_oc, str):
            return FlextResult.ok(source_oc)

        # Check if source is already a Schema object (direct usage)
        # Type narrowing: ensure source_oc is SchemaObjectClass
        if not isinstance(source_oc, FlextLdifModels.SchemaObjectClass):
            return FlextResult.ok(source_oc)  # Pass-through if not SchemaObjectClass

        write_method = getattr(source, "write_objectclass", None)
        if write_method is not None:
            # Source is a Schema object, use it directly
            write_result = write_method(source_oc)
        elif hasattr(source, "schema_quirk"):
            write_method = getattr(source.schema_quirk, "write_objectclass", None)
            if write_method is not None:
                # Source is a server object, use its schema_quirk
                write_result = write_method(source_oc)
            else:
                return FlextResult.ok(source_oc)  # Return as-is if no writer
        else:
            return FlextResult.ok(source_oc)  # Return as-is if no writer

        if write_result.is_failure:
            return FlextResult.ok(source_oc)  # Return as-is on write error

        return FlextResult.ok(write_result.unwrap())

    def _convert_objectclass(
        self,
        source: FlextLdifServersBase,
        target: FlextLdifServersBase,
        data: str | dict[str, object],
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass | str | dict[str, object]]:
        """Convert objectClass from source to target quirk via write→parse pipeline.

        Pipeline: parse source → write as string → parse target
        """
        try:
            # Step 1: Parse source objectClass using generic utility
            parse_result = FlextLdifUtilities.Parser.parse_with_quirk_fallback(
                source, data, "parse_objectclass"
            )
            if parse_result.is_failure:
                return parse_result
            source_oc = parse_result.unwrap()

            # Step 2: Write to RFC string
            write_result = self._write_objectclass_to_rfc(source, source_oc)
            if write_result.is_failure:
                return write_result
            rfc_value = write_result.unwrap()

            # If result is not a string, return as-is (pass-through)
            if not isinstance(rfc_value, str):
                return FlextResult.ok(rfc_value)

            # Step 3: Parse RFC string with target quirk using generic utility
            target_result = FlextLdifUtilities.Parser.parse_with_quirk_fallback(
                target, rfc_value, "parse_objectclass"
            )
            if target_result.is_failure:
                return target_result
            parsed_oc = target_result.unwrap()

            # Step 4: Write target objectClass to final format
            if not hasattr(target, "schema") or not hasattr(
                target.schema_quirk,
                "write_objectclass",
            ):
                return FlextResult.ok(parsed_oc)

            # Type narrowing: write_objectclass requires SchemaObjectClass
            if not isinstance(parsed_oc, FlextLdifModels.SchemaObjectClass):
                return FlextResult.ok(
                    parsed_oc
                )  # Return as-is if not SchemaObjectClass

            return cast(
                "FlextResult[FlextLdifModels.SchemaObjectClass | str | dict[str, object]]",
                target.schema_quirk.write_objectclass(parsed_oc),
            )

        except (AttributeError, ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult.fail(f"ObjectClass conversion failed: {e}")

    def _convert_acl(
        self,
        source: FlextLdifServersBase,
        target: FlextLdifServersBase,
        data: str,
    ) -> FlextResult[str]:
        """Convert ACL from source to target quirk.

        Pipeline: parse source ACL → Pydantic model → write target format

        ACL models (FlextLdifModels.Acl) are server-agnostic universal models,
        so no RFC intermediate conversion is needed - we can write directly.

        Args:
            source: Source server quirk
            target: Target server quirk
            data: ACL string to convert

        Returns:
            FlextResult with converted ACL string

        """
        try:
            # Access nested ACL quirk components via Acl class attribute
            source_class = type(source)
            target_class = type(target)

            if not hasattr(source_class, "Acl"):
                return FlextResult[str].fail(
                    f"Source quirk {source_class.__name__} does not have Acl nested class",
                )
            if not hasattr(target_class, "Acl"):
                return FlextResult[str].fail(
                    f"Target quirk {target_class.__name__} does not have Acl nested class",
                )

            # Instantiate nested Acl classes
            source_acl = source_class.Acl()
            target_acl = target_class.Acl()

            # Step 1: Parse source ACL string → Pydantic model (server-agnostic)
            if not hasattr(source_acl, "parse"):
                return FlextResult[str].fail(
                    "Source quirk does not support ACL parsing",
                )
            parse_result = source_acl.parse(data)
            if parse_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to parse source ACL: {parse_result.error}",
                )
            acl_model: FlextLdifModels.Acl = parse_result.unwrap()

            # Step 2: Extract and register DNs from model
            self._extract_and_register_dns(acl_model, "acl")

            # Step 3: Normalize DN references in model (currently a pass-through for ACLs)
            normalize_result = self._normalize_dns_in_model(acl_model)
            if normalize_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to normalize DN references: {normalize_result.error}",
                )
            normalized_model: FlextLdifModels.Acl = normalize_result.unwrap()

            # Step 4: Write ACL model in target server format
            if not hasattr(target_acl, "write"):
                return FlextResult[str].fail(
                    "Target quirk does not support ACL writing",
                )
            write_result = target_acl.write(normalized_model)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write target format: {write_result.error}",
                )

            # Explicitly type the return
            return FlextResult[str].ok(write_result.unwrap())

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            return FlextResult[str].fail(f"ACL conversion failed: {e}")

    def _convert_entry(
        self,
    ) -> FlextResult[str | dict[str, object]]:
        """Convert entry from source to target quirk via RFC.

        DEPRECATED: Use model-based conversion with Entry objects instead.
        This legacy method relied on wrapper methods that are no longer available.

        The correct approach is:
        1. Parse entry with source server: source.parse_entry(ldif_string)
        2. Convert using write→parse pipeline: source.write_entry() → target.parse()
        """
        return FlextResult[str | dict[str, object]].fail(
            "Dict-based entry conversion is deprecated. "
            "Use Entry model conversion: convert(source, target, entry_model)",
        )

    def batch_convert(
        self,
        source: FlextLdifServersBase,
        target: FlextLdifServersBase,
        data_type: str,
        data_list: Sequence[str | dict[str, object]],
    ) -> FlextResult[list[str | dict[str, object]]]:
        """Convert multiple items from source to target quirk via RFC.

        This is a convenience method that applies convert() to a list of items.
        DN registry is shared across all conversions to ensure case consistency.
        Emits ConversionEvent with aggregated statistics (MANDATORY - eventos obrigatórios).

        Args:
            source: Source quirk instance (must satisfy QuirksPort protocol)
            target: Target quirk instance (must satisfy QuirksPort protocol)
            data_type: Type of data to convert
            data_list: List of items to convert

        Returns:
            FlextResult containing list of converted items

        Examples:
            >>> attributes = ["( 2.16... )", "( 2.16... )", ...]
            >>> result = matrix.batch_convert(oud, oid, "attribute", attributes)
            >>> if result.is_success:
            ...     converted = result.unwrap()
            ...     print(f"Converted {len(converted)} attributes")

        """
        # Track batch conversion duration (MANDATORY - eventos obrigatórios)
        start_time = time.perf_counter()

        # Get source/target format names
        source_format = getattr(source, "server_name", "unknown")
        target_format = getattr(target, "server_name", "unknown")
        conversion_operation = f"batch_convert_{data_type}"

        try:
            converted = []
            errors = []
            error_details = []

            for idx, item in enumerate(data_list):
                result = self.convert(source, target, data_type, item)
                if result.is_success:
                    unwrapped = result.unwrap()
                    # Type guard: convert returns ConvertibleModel or str | dict
                    if isinstance(unwrapped, (str, dict)):
                        converted.append(unwrapped)
                    # ConvertibleModel types not expected in batch_convert legacy API
                    else:
                        error_msg = "Unexpected model type in legacy batch convert"
                        errors.append(f"Item {idx}: {error_msg}")
                        error_details.append(
                            FlextLdifModels.ErrorDetail(
                                item=f"batch_item_{idx}",
                                error=error_msg,
                            )
                        )
                else:
                    error_msg = str(result.error)
                    errors.append(f"Item {idx}: {error_msg}")
                    error_details.append(
                        FlextLdifModels.ErrorDetail(
                            item=f"batch_item_{idx}",
                            error=error_msg,
                        )
                    )

            # Calculate duration and emit ConversionEvent (MANDATORY - eventos obrigatórios)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            items_processed = len(data_list)
            items_converted = len(converted)
            items_failed = len(errors)

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
            FlextLdifUtilities.Events.log_and_emit_conversion_event(
                logger=logger,
                config=conversion_config,
                log_level="warning" if errors else "info",
            )

            if errors:
                error_msg = (
                    f"Batch conversion completed with {len(errors)} errors:\n"
                    + "\n".join(errors[: self.MAX_ERRORS_TO_SHOW])
                )
                if len(errors) > self.MAX_ERRORS_TO_SHOW:
                    error_msg += (
                        f"\n... and {len(errors) - self.MAX_ERRORS_TO_SHOW} more errors"
                    )
                return FlextResult[list[str | dict[str, object]]].fail(error_msg)

            return FlextResult[list[str | dict[str, object]]].ok(converted)

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            # Emit ConversionEvent for exception case (MANDATORY - eventos obrigatórios)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Create conversion event config for exception case
            conversion_config = FlextLdifModels.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=len(data_list),
                items_converted=0,
                items_failed=len(data_list),
                conversion_duration_ms=duration_ms,
                error_details=[
                    FlextLdifModels.ErrorDetail(
                        item="batch_conversion", error=f"Batch conversion failed: {e}"
                    )
                ],
            )
            FlextLdifUtilities.Events.log_and_emit_conversion_event(
                logger=logger,
                config=conversion_config,
                log_level="error",
            )

            return FlextResult[list[str | dict[str, object]]].fail(
                f"Batch conversion failed: {e}",
            )

    def validate_oud_conversion(self) -> FlextResult[bool]:
        """Validate DN case consistency for OUD target conversion.

        This should be called after batch conversions to OUD to ensure
        no DN case conflicts exist that would cause OUD to reject the data.

        Returns:
            FlextResult[bool]: Validation result with any inconsistencies in metadata

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
            >>> oud = FlextLdifServersOud()
            >>> supported = matrix.get_supported_conversions(oud)
            >>> print(supported)
            {'attribute': True, FlextLdifConstants.DictKeys.OBJECTCLASS: True, 'acl': True, 'entry': True}

        """
        support = {
            "attribute": False,
            FlextLdifConstants.DictKeys.OBJECTCLASS: False,
            "acl": False,
            "entry": False,
        }

        # Check schema support via parse() public method
        # Use Oracle OID namespace for testing (recognized by OID/OUD/OpenLDAP quirks)
        test_attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclTest' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )

        # Test attribute support via parse() - if parse succeeds, quirk supports attributes
        if hasattr(quirk, "schema_quirk"):
            quirk_schema = quirk.schema_quirk
            attr_result = quirk_schema.parse(test_attr_def)
            if attr_result.is_success:
                support["attribute"] = True

            # Test objectClass support via parse() - if parse succeeds, quirk supports objectClasses
            oc_result = quirk_schema.parse(test_oc_def)
            if oc_result.is_success:
                support[FlextLdifConstants.DictKeys.OBJECTCLASS] = True

        # Check ACL support
        acl = getattr(quirk, "acl_quirk", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if acl and callable(getattr(acl, "parse", None)):
            acl_result = acl.parse(test_acl_def)
            if acl_result.is_success:
                support["acl"] = True

        # Check Entry support - use entry_quirk attribute (not entry)
        entry = getattr(quirk, "entry_quirk", None)
        if entry and callable(getattr(entry, "parse", None)):
            support["entry"] = True

        return support


__all__ = ["FlextLdifConversion"]
