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
import traceback
from collections.abc import Sequence
from typing import ClassVar, Self, Union, cast, override

from flext_core import FlextLogger, FlextResult, FlextService
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

# Type alias for source/target - can be server quirk instance or server type string
ServerQuirkOrType = Union["FlextLdifServersBase", str]

# Type alias for ConvertibleModel Union (used in return types)
# Use string literals for forward references to avoid import issues
if False:  # TYPE_CHECKING equivalent for runtime
    from flext_ldif.models import FlextLdifModels

ConvertibleModelUnion = Union[
    "FlextLdifModels.Entry",
    "FlextLdifModels.SchemaAttribute",
    "FlextLdifModels.SchemaObjectClass",
    "FlextLdifModels.Acl",
]

# Module-level logger
logger = FlextLogger(__name__)


class FlextLdifConversion(
    FlextService[
        Union[
            FlextLdifModels.Entry,
            FlextLdifModels.SchemaAttribute,
            FlextLdifModels.SchemaObjectClass,
            FlextLdifModels.Acl,
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
        default_factory=FlextLdifModels.DnRegistry,
    )

    def __new__(cls) -> Self:
        """Create service instance with matching signature for type checker."""
        return super().__new__(cls)

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
        if isinstance(quirk_or_type, str):
            server = FlextLdifServer()
            # Get base quirk from registry
            resolved = server.quirk(quirk_or_type)
            if resolved is None:
                msg = f"Unknown server type: {quirk_or_type}"
                raise ValueError(msg)
            return resolved
        return quirk_or_type

    @override
    def execute(
        self,
        **_kwargs: object,
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
                Union[
                    FlextLdifModels.Entry,
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                    FlextLdifModels.Acl,
                ]
            ].ok(empty_entry)
        except Exception as e:
            return FlextResult[
                Union[
                    FlextLdifModels.Entry,
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                    FlextLdifModels.Acl,
                ]
            ].fail(
                f"Conversion service health check failed: {e}",
            )

    def convert(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        model_instance: FlextLdifTypes.ConvertibleModel,
    ) -> FlextResult[FlextLdifTypes.ConvertibleModel]:
        """Convert a model from a source server format to a target server format.

        Model-based conversion only - no legacy string/dict support.
        Emits ConversionEvent for all conversions (MANDATORY - eventos obrigatórios).

        Args:
            source: Source quirk instance
            target: Target quirk instance
            model_instance: Model instance to convert (Entry, SchemaAttribute, SchemaObjectClass, or Acl)

        Returns:
            FlextResult with converted model

        """
        # Track conversion duration (MANDATORY - eventos obrigatórios)
        start_time = time.perf_counter()

        # Determine conversion type and get source/target format names
        if isinstance(source, str):
            source_format = source
        else:
            source_format = getattr(source, "server_name", "unknown")
        if isinstance(target, str):
            target_format = target
        else:
            target_format = getattr(target, "server_name", "unknown")

        # Model-based conversion only
        model_type = type(model_instance).__name__
        conversion_operation = f"convert_{model_type}"

        # Execute model-based conversion
        result = self._convert_model(source, target, model_instance)

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
                FlextLdifModels.ErrorDetail(
                    item=model_type,
                    error=str(result.error),
                ),
            ]
            if result.is_failure
            else None,
        )
        _ = FlextLdifUtilities.Events.log_and_emit_conversion_event(
            logger=logger,
            config=conversion_config,
            log_level="info" if result.is_success else "error",
        )

        return result

    def _convert_model(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        model_instance: FlextLdifTypes.ConvertibleModel,
    ) -> FlextResult[
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    ]:
        """Convert model between source and target server formats via write→parse pipeline.

        Supports Entry, SchemaAttribute, SchemaObjectClass, and Acl conversions.
        Uses write→parse pipeline for server-agnostic conversions.

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
            if isinstance(model_instance, FlextLdifModels.Entry):
                return self._convert_entry(source_quirk, target_quirk, model_instance)
            if isinstance(model_instance, FlextLdifModels.SchemaAttribute):
                return self._convert_schema_attribute(
                    source_quirk,
                    target_quirk,
                    model_instance,
                )
            if isinstance(model_instance, FlextLdifModels.SchemaObjectClass):
                return self._convert_schema_objectclass(
                    source_quirk,
                    target_quirk,
                    model_instance,
                )
            if isinstance(model_instance, FlextLdifModels.Acl):
                return self._convert_acl(source_quirk, target_quirk, model_instance)
            return FlextResult.fail(
                f"Unsupported model type for conversion: {type(model_instance).__name__}",
            )

        except Exception as e:
            return FlextResult.fail(f"Model conversion failed: {e}")

    def _convert_entry(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    ]:
        """Convert Entry model directly without serialization.

        Entry models are already RFC-compliant. Instead of Source.write() → Target.parse()
        (which fails because parsers expect their own format), we return the model directly.
        The target.write() will be called by the consumer to serialize to target format.

        Architecture: Entry RFC Model → Target.write() → Target LDIF format
        """
        try:
            # Validate entry DN using FlextLdifUtilities.DN before conversion
            entry_dn = (
                str(FlextLdifUtilities.DN.get_dn_value(entry.dn)) if entry.dn else ""
            )
            if not FlextLdifUtilities.DN.validate(entry_dn):
                return FlextResult[
                    Union[
                        FlextLdifModels.Entry,
                        FlextLdifModels.SchemaAttribute,
                        FlextLdifModels.SchemaObjectClass,
                        FlextLdifModels.Acl,
                    ]
                ].fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )

            # Register entry DN for case consistency during conversion
            _ = self.dn_registry.register_dn(entry_dn)

            # Clone the model to avoid mutating the original
            converted_entry = entry.model_copy(deep=True)

            # Get target server type
            target_server_type = getattr(target_quirk, "server_name", "unknown")

            # Update metadata to indicate target server
            if not converted_entry.metadata:
                converted_entry.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=target_server_type
                )

            # Add conversion tracking in metadata extensions
            if not converted_entry.metadata.extensions:
                converted_entry.metadata.extensions = {}

            source_server_type = getattr(source_quirk, "server_name", "unknown")
            converted_entry.metadata.extensions[
                FlextLdifConstants.MetadataKeys.CONVERTED_FROM_SERVER
            ] = source_server_type

            # Return RFC model - consumer will call target.write() to serialize
            return FlextResult[
                Union[
                    FlextLdifModels.Entry,
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                    FlextLdifModels.Acl,
                ]
            ].ok(converted_entry)

        except Exception as e:
            return FlextResult[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
            ].fail(f"Entry conversion failed: {e}")

    def _convert_schema_attribute(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        attribute: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    ]:
        """Convert SchemaAttribute model directly without serialization.

        SchemaAttribute models are already RFC-compliant. Instead of Source.write() → Target.parse()
        (which fails because parsers expect their own format), we return the model directly.
        The target.write() will be called by the consumer to serialize to target format.

        Architecture: SchemaAttribute RFC Model → Target.write() → Target LDIF format
        """
        try:
            # Clone the model to avoid mutating the original
            converted_attribute = attribute.model_copy(deep=True)

            # Get target server type
            target_server_type = getattr(target_quirk, "server_name", "unknown")

            # Update metadata to indicate target server
            if not converted_attribute.metadata:
                converted_attribute.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=target_server_type
                )

            # Add conversion tracking in metadata extensions
            if not converted_attribute.metadata.extensions:
                converted_attribute.metadata.extensions = {}

            source_server_type = getattr(source_quirk, "server_name", "unknown")
            converted_attribute.metadata.extensions[
                FlextLdifConstants.MetadataKeys.CONVERTED_FROM_SERVER
            ] = source_server_type

            # Return RFC model - consumer will call target.write() to serialize
            return FlextResult[
                Union[
                    FlextLdifModels.Entry,
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                    FlextLdifModels.Acl,
                ]
            ].ok(converted_attribute)

        except Exception as e:
            return FlextResult[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
            ].fail(f"SchemaAttribute conversion failed: {e}")

    def _convert_schema_objectclass(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    ]:
        """Convert SchemaObjectClass model directly without serialization.

        SchemaObjectClass models are already RFC-compliant. Instead of Source.write() → Target.parse()
        (which fails because parsers expect their own format), we return the model directly.
        The target.write() will be called by the consumer to serialize to target format.

        Architecture: SchemaObjectClass RFC Model → Target.write() → Target LDIF format
        """
        try:
            # Clone the model to avoid mutating the original
            converted_objectclass = objectclass.model_copy(deep=True)

            # Get target server type
            target_server_type = getattr(target_quirk, "server_name", "unknown")

            # Update metadata to indicate target server
            if not converted_objectclass.metadata:
                converted_objectclass.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=target_server_type
                )

            # Add conversion tracking in metadata extensions
            if not converted_objectclass.metadata.extensions:
                converted_objectclass.metadata.extensions = {}

            source_server_type = getattr(source_quirk, "server_name", "unknown")
            converted_objectclass.metadata.extensions[
                FlextLdifConstants.MetadataKeys.CONVERTED_FROM_SERVER
            ] = source_server_type

            # Return RFC model - consumer will call target.write() to serialize
            return FlextResult[
                Union[
                    FlextLdifModels.Entry,
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                    FlextLdifModels.Acl,
                ]
            ].ok(converted_objectclass)

        except Exception as e:
            return FlextResult[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
            ].fail(f"SchemaObjectClass conversion failed: {e}")

    def _convert_acl(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        acl: FlextLdifModels.Acl,
    ) -> FlextResult[
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    ]:
        """Convert Acl model directly without serialization.

        ACL models are already RFC-compliant. Instead of Source.write() → Target.parse()
        (which fails because parsers expect their own format), we return the model directly.
        The target.write() will be called by the consumer to serialize to target format.

        Architecture: ACL RFC Model → Target.write() → Target LDIF format
        """
        try:
            # Clone the model to avoid mutating the original
            converted_acl = acl.model_copy(deep=True)

            # Get target server type
            target_server_type = getattr(target_quirk, "server_name", "unknown")

            # Update metadata to indicate target server
            if not converted_acl.metadata:
                converted_acl.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=target_server_type
                )

            # Add conversion tracking in metadata extensions
            if not converted_acl.metadata.extensions:
                converted_acl.metadata.extensions = {}

            source_server_type = getattr(source_quirk, "server_name", "unknown")
            converted_acl.metadata.extensions[
                FlextLdifConstants.MetadataKeys.CONVERTED_FROM_SERVER
            ] = source_server_type

            # Return RFC model - consumer will call target.write() to serialize
            return FlextResult[
                Union[
                    FlextLdifModels.Entry,
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                    FlextLdifModels.Acl,
                ]
            ].ok(converted_acl)

        except Exception as e:
            tb_str = traceback.format_exc()
            logger.exception(f"ACL conversion exception\n{tb_str}")
            return FlextResult[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
            ].fail(f"Acl conversion failed: {e}")

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
        source: ServerQuirkOrType,
        source_attr: FlextLdifModels.SchemaAttribute | dict[str, object] | str,
    ) -> FlextResult[str | FlextLdifModels.SchemaAttribute | dict[str, object]]:
        """Write attribute to RFC string representation."""
        # If already a string, return as-is
        if isinstance(source_attr, str):
            return FlextResult.ok(source_attr)

        # Type narrowing: ensure source_attr is SchemaAttribute
        if not isinstance(source_attr, FlextLdifModels.SchemaAttribute):
            return FlextResult.ok(source_attr)  # Pass-through if not SchemaAttribute

        # Resolve quirk if it's a string
        source_quirk = self._resolve_quirk(source)

        # Check if source is already a Schema quirk (has write_attribute directly)
        if hasattr(source_quirk, "write_attribute"):
            write_method = source_quirk.write_attribute
            write_result = write_method(source_attr)
        # Check if source is a base quirk with schema_quirk attribute
        elif hasattr(source_quirk, "schema_quirk"):
            schema_quirk = source_quirk.schema_quirk
            write_method = getattr(schema_quirk, "write_attribute", None)
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
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        data: str | dict[str, object],
    ) -> FlextResult[FlextLdifModels.SchemaAttribute | str | dict[str, object]]:
        """Convert attribute from source to target quirk via write→parse pipeline.

        Pipeline: parse source → write as string → parse target
        """
        try:
            # Step 1: Parse source attribute
            # Ensure data is string for parsing
            if not isinstance(data, str):
                return FlextResult.fail("Attribute conversion requires string data")

            parse_result = self._parse_source_attribute(source, data)
            if parse_result.is_failure:
                error_msg = parse_result.error or "Failed to parse source attribute"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute | dict[str, object] | str
                ].fail(error_msg)
            source_attr = parse_result.unwrap()

            # Step 2: Write to RFC string
            rfc_result = self._write_attribute_to_rfc(source, source_attr)
            if rfc_result.is_failure:
                return rfc_result
            rfc_value = rfc_result.unwrap()

            # If result is not a string, return as-is (pass-through)
            if not isinstance(rfc_value, str):
                return FlextResult.ok(rfc_value)

            # Step 3: Parse RFC string with target quirk
            target_parse_result = self._parse_target_attribute(target, rfc_value)
            if target_parse_result.is_failure:
                error_msg = (
                    target_parse_result.error or "Failed to parse target attribute"
                )
                return FlextResult[
                    FlextLdifModels.SchemaAttribute | dict[str, object] | str
                ].fail(error_msg)
            parsed_attr = target_parse_result.unwrap()

            # Step 4: Write target attribute to final format
            return self._write_target_attribute(target, parsed_attr)

        except (AttributeError, ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult.fail(f"Attribute conversion failed: {e}")

    def _parse_source_attribute(
        self,
        source: ServerQuirkOrType,
        data: str | dict[str, object],
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse source attribute."""
        source_quirk = self._resolve_quirk(source)

        # Check if source is already a Schema quirk (has parse_attribute directly)
        if hasattr(source_quirk, "parse_attribute"):
            source_schema = source_quirk
        # Check if source is a base quirk with schema_quirk attribute
        elif hasattr(source_quirk, "schema_quirk"):
            source_schema = source_quirk.schema_quirk
        else:
            return FlextResult.fail(
                "Source quirk must be a Schema quirk or have schema_quirk attribute",
            )

        if not hasattr(source_schema, "parse_attribute"):
            return FlextResult.fail(
                "Source schema quirk must have parse_attribute method",
            )
        # Ensure data is string for parse_attribute
        if isinstance(data, str):
            parse_method = source_schema.parse_attribute
            return parse_method(data)
        return FlextResult.fail("parse_attribute requires string data")

    def _parse_target_attribute(
        self,
        target: ServerQuirkOrType,
        rfc_value: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse target attribute from RFC string."""
        target_quirk = self._resolve_quirk(target)

        # Check if target is already a Schema quirk (has parse_attribute directly)
        if hasattr(target_quirk, "parse_attribute"):
            target_schema = target_quirk
        # Check if target is a base quirk with schema_quirk attribute
        elif hasattr(target_quirk, "schema_quirk"):
            target_schema = target_quirk.schema_quirk
        else:
            return FlextResult.fail(
                "Target quirk must be a Schema quirk or have schema_quirk attribute",
            )

        if not hasattr(target_schema, "parse_attribute"):
            return FlextResult.fail(
                "Target schema quirk must have parse_attribute method",
            )
        parse_method = target_schema.parse_attribute
        return parse_method(rfc_value)

    def _write_target_attribute(
        self,
        target: ServerQuirkOrType,
        parsed_attr: FlextLdifModels.SchemaAttribute | object,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute | str | dict[str, object]]:
        """Write target attribute to final format."""
        # Type narrowing: write_attribute requires SchemaAttribute
        if not isinstance(parsed_attr, FlextLdifModels.SchemaAttribute):
            # Return as-is if not SchemaAttribute - cast to match return type
            return FlextResult[
                FlextLdifModels.SchemaAttribute | dict[str, object] | str
            ].ok(
                cast(
                    "FlextLdifModels.SchemaAttribute | dict[str, object] | str",
                    parsed_attr,
                ),
            )

        target_quirk = self._resolve_quirk(target)

        # Check if target is already a Schema quirk (has write_attribute directly)
        if hasattr(target_quirk, "write_attribute"):
            write_method = target_quirk.write_attribute
            write_result = write_method(parsed_attr)
            # write_attribute returns FlextResult[str] - deprecated, use model-based conversion
            if write_result.is_success:
                return FlextResult[
                    FlextLdifModels.SchemaAttribute | dict[str, object] | str
                ].fail(
                    "String-based attribute conversion is deprecated. Use model-based conversion.",
                )
            error_msg = write_result.error or "Failed to write attribute"
            return FlextResult[
                FlextLdifModels.SchemaAttribute | dict[str, object] | str
            ].fail(error_msg)

        # Check if target is a base quirk with schema_quirk attribute
        if hasattr(target_quirk, "schema_quirk"):
            write_method = getattr(target_quirk.schema_quirk, "write_attribute", None)
            if write_method is not None:
                write_result = write_method(parsed_attr)
                # write_attribute returns FlextResult[str] - convert to SchemaAttribute if needed
                if write_result.is_success:
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute | dict[str, object] | str
                    ].fail(
                        "String-based attribute conversion is deprecated. Use model-based conversion.",
                    )
                return FlextResult[
                    FlextLdifModels.SchemaAttribute | dict[str, object] | str
                ].fail(write_result.error or "Failed to write attribute")

        # No schema writer available, return parsed attribute as-is
        return FlextResult[
            FlextLdifModels.SchemaAttribute | dict[str, object] | str
        ].ok(
            cast(
                "FlextLdifModels.SchemaAttribute | dict[str, object] | str",
                parsed_attr,
            ),
        )

    def _write_objectclass_to_rfc(
        self,
        source: ServerQuirkOrType,
        source_oc: FlextLdifModels.SchemaObjectClass | dict[str, object] | str,
    ) -> FlextResult[str | FlextLdifModels.SchemaObjectClass | dict[str, object]]:
        """Write objectClass to RFC string representation."""
        # If already a string, return as-is
        if isinstance(source_oc, str):
            return FlextResult[
                str | FlextLdifModels.SchemaObjectClass | dict[str, object]
            ].ok(source_oc)

        # Check if source is already a Schema object (direct usage)
        # Type narrowing: ensure source_oc is SchemaObjectClass
        if not isinstance(source_oc, FlextLdifModels.SchemaObjectClass):
            # Pass-through if not SchemaObjectClass - cast to match return type
            return FlextResult[
                str | FlextLdifModels.SchemaObjectClass | dict[str, object]
            ].ok(
                cast(
                    "str | FlextLdifModels.SchemaObjectClass | dict[str, object]",
                    source_oc,
                ),
            )

        # Resolve quirk if it's a string
        source_quirk = self._resolve_quirk(source)

        # Check if source is already a Schema quirk (has write_objectclass directly)
        if hasattr(source_quirk, "write_objectclass"):
            write_method = source_quirk.write_objectclass
            write_result = write_method(source_oc)
        # Check if source is a base quirk with schema_quirk attribute
        elif hasattr(source_quirk, "schema_quirk"):
            schema_quirk = source_quirk.schema_quirk
            write_method = getattr(schema_quirk, "write_objectclass", None)
            if write_method is not None:
                write_result = write_method(source_oc)
            else:
                return FlextResult[
                    str | FlextLdifModels.SchemaObjectClass | dict[str, object]
                ].ok(
                    cast(
                        "str | FlextLdifModels.SchemaObjectClass | dict[str, object]",
                        source_oc,
                    ),
                )
        else:
            return FlextResult[
                str | FlextLdifModels.SchemaObjectClass | dict[str, object]
            ].ok(
                cast(
                    "str | FlextLdifModels.SchemaObjectClass | dict[str, object]",
                    source_oc,
                ),
            )

        if write_result.is_failure:
            return FlextResult[
                str | FlextLdifModels.SchemaObjectClass | dict[str, object]
            ].ok(
                cast(
                    "str | FlextLdifModels.SchemaObjectClass | dict[str, object]",
                    source_oc,
                ),
            )

        write_unwrapped = write_result.unwrap()
        return FlextResult[
            str | FlextLdifModels.SchemaObjectClass | dict[str, object]
        ].ok(
            cast(
                "str | FlextLdifModels.SchemaObjectClass | dict[str, object]",
                write_unwrapped,
            ),
        )

    def _convert_objectclass(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        data: str | dict[str, object],
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass | str | dict[str, object]]:
        """Convert objectClass from source to target quirk via write→parse pipeline.

        Pipeline: parse source → write as string → parse target
        """
        try:
            # Step 1: Parse source objectClass
            # Ensure data is string for parsing
            if not isinstance(data, str):
                return FlextResult.fail("ObjectClass conversion requires string data")

            parse_result = self._parse_source_objectclass(source, data)
            if parse_result.is_failure:
                error_msg = parse_result.error or "Failed to parse source objectClass"
                return FlextResult[
                    FlextLdifModels.SchemaObjectClass | str | dict[str, object]
                ].fail(error_msg)
            source_oc = parse_result.unwrap()

            # Step 2: Write to RFC string
            write_result = self._write_objectclass_to_rfc(source, source_oc)
            if write_result.is_failure:
                return write_result
            rfc_value = write_result.unwrap()

            # If result is not a string, return as-is (pass-through)
            if not isinstance(rfc_value, str):
                return FlextResult[
                    FlextLdifModels.SchemaObjectClass | str | dict[str, object]
                ].ok(
                    cast(
                        "FlextLdifModels.SchemaObjectClass | str | dict[str, object]",
                        rfc_value,
                    ),
                )

            # Step 3: Parse RFC string with target quirk
            target_result = self._parse_target_objectclass(target, rfc_value)
            if target_result.is_failure:
                error_msg = target_result.error or "Failed to parse target objectClass"
                return FlextResult[
                    FlextLdifModels.SchemaObjectClass | str | dict[str, object]
                ].fail(error_msg)
            parsed_oc = target_result.unwrap()

            # Step 4: Write target objectClass to final format
            return self._write_target_objectclass(target, parsed_oc)

        except (AttributeError, ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult.fail(f"ObjectClass conversion failed: {e}")

    def _parse_source_objectclass(
        self,
        source: ServerQuirkOrType,
        data: str | dict[str, object],
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse source objectClass."""
        source_quirk = self._resolve_quirk(source)

        # Check if source is already a Schema quirk (has parse_objectclass directly)
        if hasattr(source_quirk, "parse_objectclass"):
            source_schema = source_quirk
        # Check if source is a base quirk with schema_quirk attribute
        elif hasattr(source_quirk, "schema_quirk"):
            source_schema = source_quirk.schema_quirk
        else:
            return FlextResult.fail(
                "Source quirk must be a Schema quirk or have schema_quirk attribute",
            )

        if not hasattr(source_schema, "parse_objectclass"):
            return FlextResult.fail(
                "Source schema quirk must have parse_objectclass method",
            )
        # Ensure data is string for parse_objectclass
        if isinstance(data, str):
            parse_method = source_schema.parse_objectclass
            return parse_method(data)
        return FlextResult.fail("parse_objectclass requires string data")

    def _parse_target_objectclass(
        self,
        target: ServerQuirkOrType,
        rfc_value: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse target objectClass from RFC string."""
        target_quirk = self._resolve_quirk(target)

        # Check if target is already a Schema quirk (has parse_objectclass directly)
        if hasattr(target_quirk, "parse_objectclass"):
            target_schema = target_quirk
        # Check if target is a base quirk with schema_quirk attribute
        elif hasattr(target_quirk, "schema_quirk"):
            target_schema = target_quirk.schema_quirk
        else:
            return FlextResult.fail(
                "Target quirk must be a Schema quirk or have schema_quirk attribute",
            )

        if not hasattr(target_schema, "parse_objectclass"):
            return FlextResult.fail(
                "Target schema quirk must have parse_objectclass method",
            )
        parse_method = target_schema.parse_objectclass
        return parse_method(rfc_value)

    def _write_target_objectclass(
        self,
        target: ServerQuirkOrType,
        parsed_oc: FlextLdifModels.SchemaObjectClass | object,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass | str | dict[str, object]]:
        """Write target objectClass to final format."""
        # Type narrowing: write_objectclass requires SchemaObjectClass
        if not isinstance(parsed_oc, FlextLdifModels.SchemaObjectClass):
            # Return as-is if not SchemaObjectClass - cast to match return type
            return FlextResult[
                FlextLdifModels.SchemaObjectClass | str | dict[str, object]
            ].ok(
                cast(
                    "FlextLdifModels.SchemaObjectClass | str | dict[str, object]",
                    parsed_oc,
                ),
            )

        target_quirk = self._resolve_quirk(target)

        # Check if target is already a Schema quirk (has write_objectclass directly)
        if hasattr(target_quirk, "write_objectclass"):
            schema_quirk = target_quirk
        # Check if target is a base quirk with schema_quirk attribute
        elif hasattr(target_quirk, "schema_quirk"):
            schema_quirk = target_quirk.schema_quirk
        else:
            return FlextResult[
                FlextLdifModels.SchemaObjectClass | str | dict[str, object]
            ].ok(
                cast(
                    "FlextLdifModels.SchemaObjectClass | str | dict[str, object]",
                    parsed_oc,
                ),
            )

        # Check if schema_quirk has write_objectclass method
        if not hasattr(schema_quirk, "write_objectclass"):
            return FlextResult[
                FlextLdifModels.SchemaObjectClass | str | dict[str, object]
            ].ok(
                cast(
                    "FlextLdifModels.SchemaObjectClass | str | dict[str, object]",
                    parsed_oc,
                ),
            )

        # Type narrowing: write_objectclass requires SchemaObjectClass
        if not isinstance(parsed_oc, FlextLdifModels.SchemaObjectClass):
            return FlextResult[
                FlextLdifModels.SchemaObjectClass | str | dict[str, object]
            ].ok(
                cast(
                    "FlextLdifModels.SchemaObjectClass | str | dict[str, object]",
                    parsed_oc,
                ),
            )

        write_method = schema_quirk.write_objectclass
        write_result = write_method(parsed_oc)
        # write_objectclass returns FlextResult[str] - convert to union type
        if write_result.is_success:
            written_str = write_result.unwrap()
            return FlextResult[
                FlextLdifModels.SchemaObjectClass | str | dict[str, object]
            ].ok(
                cast(
                    "FlextLdifModels.SchemaObjectClass | str | dict[str, object]",
                    written_str,
                ),
            )
        error_msg = write_result.error or "Failed to write objectClass"
        return FlextResult[
            FlextLdifModels.SchemaObjectClass | str | dict[str, object]
        ].fail(error_msg)

    def batch_convert(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        model_list: Sequence[FlextLdifTypes.ConvertibleModel],
    ) -> FlextResult[list[FlextLdifTypes.ConvertibleModel]]:
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
        if isinstance(source, str):
            source_format = source
        else:
            source_format = getattr(source, "server_name", "unknown")
        if isinstance(target, str):
            target_format = target
        else:
            target_format = getattr(target, "server_name", "unknown")

        # Handle empty list case - succeed with empty result
        # No event emission for empty batches (no work done)
        if not model_list:
            return FlextResult[list[FlextLdifTypes.ConvertibleModel]].ok([])

        model_type = type(model_list[0]).__name__
        conversion_operation = f"batch_convert_{model_type}"

        try:
            converted: list[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
            ] = []
            errors: list[str] = []
            error_details: list[FlextLdifModels.ErrorDetail] = []

            for idx, model_item in enumerate(model_list):
                result = self.convert(source, target, model_item)
                if result.is_success:
                    unwrapped = result.unwrap()
                    # Type guard: ensure unwrapped is ConvertibleModel
                    if isinstance(
                        unwrapped,
                        (
                            FlextLdifModels.Entry,
                            FlextLdifModels.SchemaAttribute,
                            FlextLdifModels.SchemaObjectClass,
                            FlextLdifModels.Acl,
                        ),
                    ):
                        converted.append(unwrapped)
                    else:
                        errors.append(
                            f"Item {idx}: Converted model is not a valid ConvertibleModel type",
                        )
                else:
                    error_msg = str(result.error)
                    errors.append(f"Item {idx}: {error_msg}")
                    error_details.append(
                        FlextLdifModels.ErrorDetail(
                            item=f"batch_item_{idx}",
                            error=error_msg,
                        ),
                    )

            # Calculate duration and emit ConversionEvent (MANDATORY - eventos obrigatórios)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            items_processed = len(model_list)
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
            _ = FlextLdifUtilities.Events.log_and_emit_conversion_event(
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
                return FlextResult[list[FlextLdifTypes.ConvertibleModel]].fail(
                    error_msg,
                )

            # Type guard: converted is list of ConvertibleModel
            # Explicit cast to help type checker
            converted_typed = cast(
                "list[FlextLdifModels.Entry | FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | FlextLdifModels.Acl]",
                converted,
            )
            return FlextResult[
                list[
                    FlextLdifModels.Entry
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | FlextLdifModels.Acl
                ]
            ].ok(converted_typed)

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            # Emit ConversionEvent for exception case (MANDATORY - eventos obrigatórios)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Create conversion event config for exception case
            conversion_config = FlextLdifModels.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=len(model_list),
                items_converted=0,
                items_failed=len(model_list),
                conversion_duration_ms=duration_ms,
                error_details=[
                    FlextLdifModels.ErrorDetail(
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

            return FlextResult[list[FlextLdifTypes.ConvertibleModel]].fail(
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

        # Check schema support
        support = self._check_schema_support(quirk, support)

        # Check ACL support
        support = self._check_acl_support(quirk, support)

        # Check Entry support
        return self._check_entry_support(quirk, support)

    def _check_schema_support(
        self,
        quirk: FlextLdifServersBase,
        support: dict[str, bool],
    ) -> dict[str, bool]:
        """Check schema (attribute and objectClass) support."""
        # Check if quirk is already a Schema quirk (has parse_attribute directly)
        if hasattr(quirk, "parse_attribute") or hasattr(quirk, "parse_objectclass"):
            quirk_schema = quirk
        # Check if quirk is a base quirk with schema_quirk attribute
        elif hasattr(quirk, "schema_quirk"):
            quirk_schema = quirk.schema_quirk
        else:
            return support

        # Use quirk_schema for checks
        test_attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclTest' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )

        # Check attribute support
        if hasattr(quirk_schema, "can_handle_attribute") and hasattr(
            quirk_schema,
            "parse_attribute",
        ):
            can_handle_method = quirk_schema.can_handle_attribute
            if can_handle_method(test_attr_def):
                parse_method = quirk_schema.parse_attribute
                attr_result = parse_method(test_attr_def)
                if attr_result.is_success:
                    support["attribute"] = True

        # Check objectClass support
        if hasattr(quirk_schema, "can_handle_objectclass") and hasattr(
            quirk_schema,
            "parse_objectclass",
        ):
            can_handle_method = quirk_schema.can_handle_objectclass
            if can_handle_method(test_oc_def):
                parse_method = quirk_schema.parse_objectclass
                oc_result = parse_method(test_oc_def)
                if oc_result.is_success:
                    support[FlextLdifConstants.DictKeys.OBJECTCLASS] = True

        return support

    def _check_acl_support(
        self,
        quirk: FlextLdifServersBase,
        support: dict[str, bool],
    ) -> dict[str, bool]:
        """Check ACL support."""
        # No fallback - check both attributes explicitly
        acl = getattr(quirk, "acl_quirk", None)
        if acl is None:
            acl = getattr(quirk, "_acl_quirk", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if acl and callable(getattr(acl, "parse", None)):
            acl_result = acl.parse(test_acl_def)
            if acl_result.is_success:
                support["acl"] = True
        return support

    def _check_entry_support(
        self,
        quirk: FlextLdifServersBase,
        support: dict[str, bool],
    ) -> dict[str, bool]:
        """Check Entry support."""
        # No fallback - check both attributes explicitly
        entry = getattr(quirk, "entry_quirk", None)
        if entry is None:
            entry = getattr(quirk, "_entry_quirk", None)
        if not entry and hasattr(quirk, "parse") and hasattr(quirk, "can_handle_entry"):
            entry = quirk
        if entry and callable(getattr(entry, "parse", None)):
            support["entry"] = True
        return support


__all__ = ["FlextLdifConversion"]
