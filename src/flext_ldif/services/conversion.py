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
from typing import ClassVar, Self, override

from flext_core import FlextLogger, FlextResult, FlextRuntime, FlextService
from pydantic import Field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

# Type alias for source/target - can be server quirk instance or server type string
type ServerQuirkOrType = "FlextLdifServersBase" | str

# Type alias for ConvertibleModel Union (used in return types)
# Use string literals for forward references to avoid import issues
type ConvertibleModelUnion = (
    "FlextLdifModels.Entry"
    | "FlextLdifModels.SchemaAttribute"
    | "FlextLdifModels.SchemaObjectClass"
    | "FlextLdifModels.Acl"
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
    if isinstance(quirk, FlextLdifServersBase.Schema):
        return quirk

    # SECOND: Get schema from schema_quirk attribute
    return _get_schema_from_attribute(quirk)


def _validate_schema_quirk(
    quirk: FlextLdifServersBase,
) -> FlextLdifServersBase.Schema:
    """Validate and return quirk as Schema type."""
    if not isinstance(quirk, FlextLdifServersBase.Schema):
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
        if not isinstance(schema, FlextLdifServersBase.Schema):
            msg = f"Expected Schema quirk, got {type(schema)}"
            raise TypeError(msg)
        return schema
    msg = "Quirk must be a Schema quirk or have schema_quirk attribute"
    raise TypeError(msg)


class FlextLdifConversion(
    FlextService[
        (
            FlextLdifModels.Entry
            | FlextLdifModels.SchemaAttribute
            | FlextLdifModels.SchemaObjectClass
            | FlextLdifModels.Acl
        )
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
        if isinstance(quirk_or_type, str):
            server = FlextLdifServer()
            # Get base quirk from registry
            resolved_result = server.quirk(quirk_or_type)
            if resolved_result.is_failure:
                msg = f"Unknown server type: {quirk_or_type}"
                raise ValueError(msg)
            return resolved_result.unwrap()
        return quirk_or_type

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
                (
                    FlextLdifModels.Entry
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | FlextLdifModels.Acl
                )
            ].ok(empty_entry)
        except Exception as e:
            return FlextResult[
                (
                    FlextLdifModels.Entry
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | FlextLdifModels.Acl
                )
            ].fail(
                f"Conversion service health check failed: {e}",
            )

    def convert(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        model_instance: FlextLdifTypes.ConvertibleModel,
    ) -> FlextResult[ConvertibleModelUnion]:
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
    ) -> FlextResult[ConvertibleModelUnion]:
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

    def _analyze_metadata_for_conversion(
        self,
        source_metadata: (
            FlextLdifModels.QuirkMetadata
            | FlextLdifModelsDomains.QuirkMetadata
            | FlextLdifModelsMetadata.DynamicMetadata
            | None
        ),
        target_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str,
    ) -> dict[str, str | dict[str, str | FlextTypes.MetadataAttributeValue]]:
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
            str | dict[str, str | FlextTypes.MetadataAttributeValue],
        ] = {}

        if not source_metadata:
            return conversion_analysis

        # Type narrowing: check for QuirkMetadata attributes
        if not hasattr(source_metadata, "boolean_conversions"):
            return conversion_analysis

        # Analyze boolean conversions for target compatibility
        boolean_conversions = getattr(source_metadata, "boolean_conversions", {})
        if boolean_conversions and FlextRuntime.is_dict_like(boolean_conversions):
            for attr_name, conv_info in boolean_conversions.items():
                if FlextRuntime.is_dict_like(conv_info):
                    original_format = conv_info.get("format", "")
                    conversion_analysis[f"boolean_{attr_name}"] = {
                        "source_format": str(original_format),
                        "target_server": str(target_server_type),
                        "action": "convert_to_target_format",
                    }

        # Analyze attribute case for target compatibility
        original_attribute_case = getattr(
            source_metadata,
            "original_attribute_case",
            {},
        )
        if original_attribute_case:
            # Convert original_attribute_case to proper MetadataValue type
            # Explicit type narrowing from object to MetadataValue
            case_data: FlextTypes.MetadataAttributeValue
            if isinstance(original_attribute_case, (dict, list, str, int, float, bool)):
                case_data = original_attribute_case
            else:
                case_data = str(original_attribute_case)
            conversion_analysis["attribute_case"] = {
                "source_case": case_data,
                "target_server": str(target_server_type),
                "action": "apply_target_conventions",
            }

        # Analyze DN spacing for target compatibility
        original_format_details = getattr(
            source_metadata,
            "original_format_details",
            {},
        )
        if original_format_details and isinstance(original_format_details, dict):
            dn_spacing = original_format_details.get("dn_spacing")
            if dn_spacing:
                # Convert dn_spacing to proper MetadataValue type
                # Explicit type narrowing from object to MetadataValue
                spacing_data: FlextTypes.MetadataAttributeValue
                if isinstance(dn_spacing, (dict, list, str, int, float, bool)):
                    spacing_data = dn_spacing
                else:
                    spacing_data = str(dn_spacing) if dn_spacing is not None else ""
                conversion_analysis["dn_format"] = {
                    "source_dn": spacing_data,
                    "target_server": str(target_server_type),
                    "action": "normalize_for_target",
                }

        return conversion_analysis

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
                    (
                        FlextLdifModels.Entry
                        | FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | FlextLdifModels.Acl
                    )
                ].fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )

            # Register entry DN for case consistency during conversion
            _ = self.dn_registry.register_dn(entry_dn)

            # Clone the model to avoid mutating the original
            converted_entry = entry.model_copy(deep=True)

            # Get target server type and validate against valid server types
            target_server_type_raw: str = getattr(
                target_quirk,
                "server_name",
                "unknown",
            )

            # Normalize server type using constants (handles aliases and canonicalization)
            target_server_type_str = (
                str(target_server_type_raw)
                if target_server_type_raw != "unknown"
                else FlextLdifConstants.ServerTypes.RFC
            )
            # normalize_server_type returns canonical ServerTypeLiteral value (validated at runtime)
            validated_quirk_type = FlextLdifConstants.normalize_server_type(
                target_server_type_str,
            )

            # Use validated_quirk_type for analysis
            conversion_analysis = self._analyze_metadata_for_conversion(
                entry.metadata,
                validated_quirk_type,
            )

            # Store analysis in converted entry for downstream processing
            if not converted_entry.metadata:
                converted_entry.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=validated_quirk_type,
                )

            if conversion_analysis:
                if not converted_entry.metadata.extensions:
                    converted_entry.metadata.extensions = (
                        FlextLdifModelsMetadata.DynamicMetadata()
                    )
                # Store conversion analysis as string representation
                converted_entry.metadata.extensions["conversion_analysis"] = str(
                    conversion_analysis,
                )

            # Add conversion tracking in metadata extensions
            if not converted_entry.metadata.extensions:
                converted_entry.metadata.extensions = (
                    FlextLdifModelsMetadata.DynamicMetadata()
                )

            source_server_type = getattr(source_quirk, "server_name", "unknown")
            converted_entry.metadata.extensions[
                FlextLdifConstants.MetadataKeys.CONVERTED_FROM_SERVER
            ] = source_server_type

            # Return RFC model - consumer will call target.write() to serialize
            return FlextResult[
                (
                    FlextLdifModels.Entry
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | FlextLdifModels.Acl
                )
            ].ok(converted_entry)

        except Exception as e:
            logger.exception(
                "Failed to convert Entry model",
                error=str(e),
            )
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
        """Convert SchemaAttribute model via write_attribute→parse_attribute pipeline."""
        try:
            # Step 1: Get source schema quirk with proper type narrowing
            try:
                source_schema = _get_schema_quirk(source_quirk)
            except TypeError as e:
                return FlextResult.fail(f"Source quirk error: {e}")

            # Step 2: Write attribute from source format to LDIF string
            write_result = source_schema.write_attribute(attribute)
            if write_result.is_failure:
                return FlextResult.fail(
                    f"Failed to write attribute in source format: {write_result.error}",
                )

            ldif_string: str = write_result.unwrap()
            if not ldif_string or not ldif_string.strip():
                return FlextResult.fail("Write operation returned empty attribute LDIF")

            # Step 3: Get target schema quirk with proper type narrowing
            try:
                target_schema = _get_schema_quirk(target_quirk)
            except TypeError as e:
                return FlextResult.fail(f"Target quirk error: {e}")

            # Step 4: Parse LDIF string with target server to get attribute in target format
            parse_result = target_schema.parse_attribute(ldif_string)
            if parse_result.is_failure:
                return FlextResult.fail(
                    f"Failed to parse attribute in target format: {parse_result.error}",
                )

            converted_attribute = parse_result.unwrap()

            # Return as Union type to satisfy type checker
            return FlextResult[
                (
                    FlextLdifModels.Entry
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | FlextLdifModels.Acl
                )
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
        """Convert SchemaObjectClass model via write_objectclass→parse_objectclass pipeline."""
        try:
            # Step 1: Get source schema quirk with proper type narrowing
            try:
                source_schema = _get_schema_quirk(source_quirk)
            except TypeError as e:
                return FlextResult.fail(f"Source quirk error: {e}")

            # Step 2: Write objectclass from source format to LDIF string
            write_result = source_schema.write_objectclass(objectclass)
            if write_result.is_failure:
                return FlextResult.fail(
                    f"Failed to write objectclass in source format: {write_result.error}",
                )

            ldif_string: str = write_result.unwrap()
            if not ldif_string or not ldif_string.strip():
                return FlextResult.fail(
                    "Write operation returned empty objectclass LDIF",
                )

            # Step 3: Get target schema quirk with proper type narrowing
            try:
                target_schema = _get_schema_quirk(target_quirk)
            except TypeError as e:
                return FlextResult.fail(f"Target quirk error: {e}")

            # Step 4: Parse LDIF string with target server to get objectclass in target format
            parse_result = target_schema.parse_objectclass(ldif_string)
            if parse_result.is_failure:
                return FlextResult.fail(
                    f"Failed to parse objectclass in target format: {parse_result.error}",
                )

            converted_objectclass = parse_result.unwrap()

            # Return as Union type to satisfy type checker
            return FlextResult[
                (
                    FlextLdifModels.Entry
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | FlextLdifModels.Acl
                )
            ].ok(converted_objectclass)

        except Exception as e:
            return FlextResult[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
            ].fail(f"SchemaObjectClass conversion failed: {e}")

    def _get_acl_classes(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
    ) -> FlextResult[
        tuple[
            FlextLdifProtocols.Quirks.AclProtocol,
            FlextLdifProtocols.Quirks.AclProtocol,
        ]
    ]:
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

        # Create ACL quirks - they implement AclProtocol
        source_acl = source_class.Acl()
        target_acl = target_class.Acl()

        # Validate protocol compliance at runtime using isinstance
        if not isinstance(source_acl, FlextLdifProtocols.Quirks.AclProtocol):
            return FlextResult.fail(
                f"Source ACL quirk {source_class.__name__} does not implement AclProtocol",
            )
        if not isinstance(target_acl, FlextLdifProtocols.Quirks.AclProtocol):
            return FlextResult.fail(
                f"Target ACL quirk {target_class.__name__} does not implement AclProtocol",
            )

        # Both are now typed as AclProtocol - no cast needed
        return FlextResult.ok((source_acl, target_acl))

    def _write_acl_to_string(
        self,
        acl: FlextLdifModels.Acl,
        source_acl: FlextLdifProtocols.Quirks.AclProtocol,
    ) -> FlextResult[str]:
        """Write ACL to LDIF string."""
        # Acl model satisfies AclProtocol structurally - no cast needed
        # The write method accepts AclProtocol, and Acl model implements all required attributes
        write_result = source_acl.write(acl)
        if write_result.is_failure:
            return FlextResult.fail(
                f"Failed to write ACL in source format: {write_result.error}",
            )

        unwrapped = write_result.unwrap()
        if not isinstance(unwrapped, str):
            return FlextResult.fail(
                f"Write operation returned unexpected type: {type(unwrapped).__name__}, expected str",
            )

        ldif_string: str = unwrapped
        if not ldif_string or not ldif_string.strip():
            return FlextResult.fail("Write operation returned empty ACL LDIF")

        return FlextResult.ok(ldif_string)

    def _parse_acl_from_string(
        self,
        ldif_string: str,
        target_acl: FlextLdifProtocols.Quirks.AclProtocol,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse ACL from LDIF string."""
        parse_result = target_acl.parse(ldif_string)
        if parse_result.is_failure:
            return FlextResult.fail(
                f"Failed to parse ACL in target format: {parse_result.error}",
            )

        converted_acl = parse_result.unwrap()
        if not isinstance(converted_acl, FlextLdifModels.Acl):
            return FlextResult.fail(
                f"ACL conversion produced invalid type: {type(converted_acl).__name__}, expected Acl",
            )

        return FlextResult.ok(converted_acl)

    @staticmethod
    def _perms_dict_to_model(
        perms_dict: dict[str, bool | None],
    ) -> FlextLdifModels.AclPermissions:
        """Convert permissions dict to AclPermissions model.

        Args:
            perms_dict: Dict with permission mappings

        Returns:
            AclPermissions model with non-None values

        """
        # Remove None values for cleaner model
        clean_dict = {k: v for k, v in perms_dict.items() if v is not None}
        return FlextLdifModels.AclPermissions(**clean_dict)

    def _apply_permission_mapping(
        self,
        original_acl: FlextLdifModels.Acl,
        converted_acl: FlextLdifModels.Acl,
        orig_perms_dict: dict[str, bool],
        source_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | str
        | None,
        target_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | str
        | None,
        *,
        converted_has_permissions: bool = False,
    ) -> None:
        """Apply permission mapping based on server types.

        Args:
            original_acl: Original ACL model
            converted_acl: Converted ACL model (modified in-place)
            orig_perms_dict: Original permissions dict
            source_server_type: Source server type
            target_server_type: Target server type
            converted_has_permissions: Whether converted ACL has permissions

        """
        # Normalize server types for comparison (handles both str and ServerTypeLiteral)
        normalized_source = (
            FlextLdifConstants.normalize_server_type(source_server_type)
            if source_server_type
            else None
        )
        normalized_target = (
            FlextLdifConstants.normalize_server_type(target_server_type)
            if target_server_type
            else None
        )

        # Determine if we need to apply mapping based on server types
        needs_oid_to_oud_mapping = (
            normalized_source == FlextLdifConstants.ServerTypes.OID
            and normalized_target == FlextLdifConstants.ServerTypes.OUD
        )
        needs_oud_to_oid_mapping = (
            normalized_source == FlextLdifConstants.ServerTypes.OUD
            and normalized_target == FlextLdifConstants.ServerTypes.OID
        )

        logger.debug(
            "ACL mapping decision",
            needs_oid_to_oud_mapping=needs_oid_to_oud_mapping,
            needs_oud_to_oid_mapping=needs_oud_to_oid_mapping,
        )

        # For cross-server conversions, ALWAYS apply mapping regardless of converted_has_permissions
        # This ensures OID↔OUD permission mapping executes even if converted_acl already has permissions
        if needs_oid_to_oud_mapping:
            # OID → OUD: Map OID-specific permissions to OUD equivalents
            mapped_perms = FlextLdifUtilities.ACL.map_oid_to_oud_permissions(
                orig_perms_dict,
            )
            oid_to_oud_perms: dict[str, bool | None] = {
                "read": mapped_perms.get("read"),
                "write": mapped_perms.get("write"),
                "add": mapped_perms.get("add"),
                "delete": mapped_perms.get("delete"),
                "search": mapped_perms.get("search"),
                "compare": mapped_perms.get("compare"),
                "self_write": mapped_perms.get("selfwrite"),
                "proxy": mapped_perms.get("proxy"),
                "browse": mapped_perms.get("browse"),
                "auth": mapped_perms.get("auth"),
                "all": mapped_perms.get("all"),
            }
            converted_acl.permissions = self._perms_dict_to_model(oid_to_oud_perms)
        elif needs_oud_to_oid_mapping:
            # OUD → OID: Map OUD permissions to OID equivalents
            mapped_perms = FlextLdifUtilities.ACL.map_oud_to_oid_permissions(
                orig_perms_dict,
            )
            oud_to_oid_perms: dict[str, bool | None] = {
                "read": mapped_perms.get("read"),
                "write": mapped_perms.get("write"),
                "add": mapped_perms.get("add"),
                "delete": mapped_perms.get("delete"),
                "search": mapped_perms.get("search"),
                "compare": mapped_perms.get("compare"),
                "self_write": mapped_perms.get("selfwrite"),
                "proxy": mapped_perms.get("proxy"),
                "browse": mapped_perms.get("browse"),
                "auth": mapped_perms.get("auth"),
                "all": mapped_perms.get("all"),
            }
            converted_acl.permissions = self._perms_dict_to_model(oud_to_oid_perms)
        elif not converted_has_permissions and original_acl.permissions is not None:
            # No mapping needed but converted is empty - preserve original as-is
            converted_acl.permissions = original_acl.permissions.model_copy(deep=True)

    def _preserve_acl_metadata(
        self,
        original_acl: FlextLdifModels.Acl,
        converted_acl: FlextLdifModels.Acl,
        source_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | str
        | None = None,
        target_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | str
        | None = None,
    ) -> None:
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
        converted_has_permissions: bool = bool(
            converted_acl.permissions
            and any(
                getattr(converted_acl.permissions, field, False)
                for field in (
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
            ),
        )

        if original_acl.permissions:
            # Get original permissions as dict for mapping
            orig_perms_dict = original_acl.permissions.model_dump(exclude_unset=True)
            # Remove None values and fields that are False (only keep True permissions)
            orig_perms_dict = {
                k: v
                for k, v in orig_perms_dict.items()
                if v is True  # Only include explicitly True permissions
            }

            logger.debug(
                "ACL permission preservation",
                source_server_type=source_server_type,
                target_server_type=target_server_type,
                original_permissions=orig_perms_dict,
            )

            if orig_perms_dict:
                self._apply_permission_mapping(
                    original_acl,
                    converted_acl,
                    orig_perms_dict,
                    source_server_type,
                    target_server_type,
                    converted_has_permissions=converted_has_permissions,
                )

        # Preserve metadata from original ACL model for proper server-specific formatting
        # Metadata contains source_subject_type and other conversion hints needed by target writers
        if original_acl.metadata:
            if not converted_acl.metadata:
                converted_acl.metadata = original_acl.metadata.model_copy(deep=True)
            elif (
                original_acl.metadata.extensions and converted_acl.metadata is not None
            ):
                # Merge extensions from original metadata into converted metadata
                if not converted_acl.metadata.extensions:
                    converted_acl.metadata.extensions = (
                        FlextLdifModelsMetadata.DynamicMetadata()
                    )
                # Copy each key-value pair individually
                # Both metadata and extensions must exist and be non-empty
                converted_metadata = converted_acl.metadata
                original_metadata = original_acl.metadata
                if (
                    converted_metadata is not None
                    and converted_metadata.extensions is not None
                    and original_metadata is not None
                    and original_metadata.extensions is not None
                ):
                    # Use local variables to maintain type narrowing
                    converted_extensions = converted_metadata.extensions
                    original_extensions = original_metadata.extensions
                    for key, value in original_extensions.items():
                        # Type narrowing: value is MetadataValue
                        typed_value: FlextTypes.MetadataAttributeValue = value
                        converted_extensions[key] = typed_value

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
        """Convert Acl model via Entry RFC + Metadata pipeline.

        Architecture: Source Acl → Entry RFC + Metadata → Target Acl
        - Source writes Acl to Entry.metadata.acls (RFC format)
        - Target parses Entry.metadata.acls to extract Acl (preserves subject via metadata)
        """
        try:
            # Create a deep copy of the ACL model to avoid modifying the original
            acl = acl.model_copy(deep=True)

            # Step 1: Create Entry RFC with Acl in metadata.acls
            # This preserves the Acl model with all its fields (subject, permissions, etc.)
            entry_dn = FlextLdifModels.DistinguishedName(
                value="cn=acl-conversion,dc=example,dc=com",
            )
            entry_attributes = FlextLdifModels.LdifAttributes(attributes={})

            # Create metadata with ACL stored in metadata.acls
            # Get server_type and default to None (RFC) if not valid
            source_server_type: (
                FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None
            ) = None
            server_type_attr = getattr(source_quirk, "server_type", None)

            # Validate against VALID_SERVER_TYPES_RULE before using
            if isinstance(server_type_attr, str):
                # Check if it's one of the valid server types
                valid_types: tuple[str, ...] = tuple(
                    FlextLdifConstants.ValidationRules.VALID_SERVER_TYPES_RULE,
                )
                if server_type_attr in valid_types:
                    # Use normalize_server_type for proper type narrowing
                    source_server_type = FlextLdifConstants.normalize_server_type(
                        server_type_attr,
                    )

            metadata = FlextLdifModels.QuirkMetadata.create_for(
                source_server_type,
                extensions={},
            )
            metadata.acls = [acl]  # Store ACL in metadata.acls

            # Create Entry RFC with ACL in metadata
            rfc_entry = FlextLdifModels.Entry(
                dn=entry_dn,
                attributes=entry_attributes,
                metadata=metadata,
            )

            # Step 2: Convert Entry using Entry conversion (which preserves metadata.acls)
            entry_result = self._convert_entry(source_quirk, target_quirk, rfc_entry)
            if entry_result.is_failure:
                return entry_result

            converted_entry = entry_result.unwrap()
            if not isinstance(converted_entry, FlextLdifModels.Entry):
                return FlextResult.fail(
                    f"Entry conversion returned unexpected type: {type(converted_entry).__name__}",
                )

            # Step 3: Extract ACL from converted Entry metadata.acls
            if not converted_entry.metadata or not converted_entry.metadata.acls:
                return FlextResult.fail(
                    "Converted entry has no ACLs in metadata.acls",
                )

            # Get first ACL from metadata (should be the converted one)
            # Type narrowing: metadata.acls contains FlextLdifModelsDomains.Acl, convert to FlextLdifModels.Acl
            domain_acl = converted_entry.metadata.acls[0]
            # Convert domain Acl to public Acl model
            if not isinstance(domain_acl, FlextLdifModels.Acl):
                converted_acl = FlextLdifModels.Acl.model_validate(
                    domain_acl.model_dump(),
                )
            else:
                converted_acl = domain_acl

            # Get target server type for permission mapping
            target_server_type = getattr(target_quirk, "server_type", "unknown")

            # Preserve permissions and metadata from original ACL
            # Pass server types so permission mapping can be applied during preservation
            self._preserve_acl_metadata(
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
            return FlextResult.ok(converted_acl)

        except Exception as e:
            traceback.format_exc()
            logger.exception(
                "Failed to convert ACL model",
                error=str(e),
            )
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
        source_attr: FlextLdifModels.SchemaAttribute
        | FlextTypes.MetadataAttributeValue
        | str,
    ) -> FlextResult[
        str | FlextLdifModels.SchemaAttribute | FlextTypes.MetadataAttributeValue
    ]:
        """Write attribute to RFC string representation."""
        # If already a string, return as-is
        if isinstance(source_attr, str):
            return FlextResult.ok(source_attr)

        # Type narrowing: ensure source_attr is SchemaAttribute
        if not isinstance(source_attr, FlextLdifModels.SchemaAttribute):
            return FlextResult.ok(source_attr)  # Pass-through if not SchemaAttribute

        # Resolve quirk if it's a string
        source_quirk = self._resolve_quirk(source)

        # Get source schema quirk with proper type narrowing
        try:
            schema_quirk = _get_schema_quirk(source_quirk)
            write_result = schema_quirk.write_attribute(source_attr)
            if write_result.is_failure:
                return FlextResult.ok(source_attr)  # Return as-is on write error
            return FlextResult.ok(write_result.unwrap())
        except TypeError:
            return FlextResult.ok(source_attr)  # Return as-is if no writer

    def _convert_attribute(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        data: str | FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | str | FlextTypes.MetadataAttributeValue
    ]:
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
                    FlextLdifModels.SchemaAttribute | FlextTypes.MetadataAttributeValue | str
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
                    FlextLdifModels.SchemaAttribute | FlextTypes.MetadataAttributeValue | str
                ].fail(error_msg)
            parsed_attr = target_parse_result.unwrap()

            # Step 4: Write target attribute to final format
            return self._write_target_attribute(parsed_attr)

        except (AttributeError, ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult.fail(f"Attribute conversion failed: {e}")

    def _parse_source_attribute(
        self,
        source: ServerQuirkOrType,
        data: str | FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
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
            return parse_method(data)
        return FlextResult.fail("parse_attribute requires string data")

    def _parse_target_attribute(
        self,
        target: ServerQuirkOrType,
        rfc_value: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse target attribute from RFC string."""
        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            target_schema = _get_schema_quirk(target_quirk)
        except TypeError as e:
            return FlextResult.fail(f"Target quirk error: {e}")

        parse_method = target_schema.parse_attribute
        return parse_method(rfc_value)

    def _write_target_attribute(
        self,
        parsed_attr: FlextLdifModels.SchemaAttribute
        | str
        | FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | str | FlextTypes.MetadataAttributeValue
    ]:
        """Write target attribute to final format."""
        # Type narrowing: write_attribute requires SchemaAttribute
        if not isinstance(parsed_attr, FlextLdifModels.SchemaAttribute):
            # Return as-is if not SchemaAttribute - type narrowing for union type
            if isinstance(parsed_attr, dict):
                return FlextResult[
                    FlextLdifModels.SchemaAttribute | FlextTypes.MetadataAttributeValue | str
                ].ok(parsed_attr)
            if isinstance(parsed_attr, str):
                return FlextResult[
                    FlextLdifModels.SchemaAttribute | FlextTypes.MetadataAttributeValue | str
                ].ok(parsed_attr)
            msg = f"Expected SchemaAttribute | dict | str, got {type(parsed_attr)}"
            raise TypeError(msg)

        # Model-based conversion - return parsed attribute as-is
        # Schema quirks write via model conversion, not string-based
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextTypes.MetadataAttributeValue | str
        ].ok(parsed_attr)

    def _write_objectclass_to_rfc(
        self,
        source: ServerQuirkOrType,
        source_oc: FlextLdifModels.SchemaObjectClass
        | FlextTypes.MetadataAttributeValue
        | str,
    ) -> FlextResult[
        str | FlextLdifModels.SchemaObjectClass | FlextTypes.MetadataAttributeValue
    ]:
        """Write objectClass to RFC string representation."""
        # If already a string, return as-is
        if isinstance(source_oc, str):
            return FlextResult[
                str | FlextLdifModels.SchemaObjectClass | FlextTypes.MetadataAttributeValue
            ].ok(source_oc)

        # Check if source is already a Schema object (direct usage)
        # Type narrowing: ensure source_oc is SchemaObjectClass
        if not isinstance(source_oc, FlextLdifModels.SchemaObjectClass):
            # Pass-through if not SchemaObjectClass - type narrowing for union type
            if isinstance(source_oc, str):
                return FlextResult[
                    str
                    | FlextLdifModels.SchemaObjectClass
                    | FlextTypes.MetadataAttributeValue
                ].ok(source_oc)
            if isinstance(source_oc, dict):
                return FlextResult[
                    str
                    | FlextLdifModels.SchemaObjectClass
                    | FlextTypes.MetadataAttributeValue
                ].ok(source_oc)
            msg = f"Expected SchemaObjectClass | str | dict, got {type(source_oc)}"
            raise TypeError(msg)

        # Resolve quirk if it's a string
        source_quirk = self._resolve_quirk(source)

        # Get source schema quirk with proper type narrowing
        try:
            schema_quirk = _get_schema_quirk(source_quirk)
            write_result = schema_quirk.write_objectclass(source_oc)
            if write_result.is_failure:
                return FlextResult[
                    str
                    | FlextLdifModels.SchemaObjectClass
                    | FlextTypes.MetadataAttributeValue
                ].ok(source_oc)
            write_unwrapped = write_result.unwrap()
            # Type narrowing: write_objectclass returns str
            if not isinstance(write_unwrapped, str):
                msg = (
                    f"Expected str from write_objectclass, got {type(write_unwrapped)}"
                )
                raise TypeError(msg)
            return FlextResult[
                str | FlextLdifModels.SchemaObjectClass | FlextTypes.MetadataAttributeValue
            ].ok(write_unwrapped)
        except TypeError:
            return FlextResult[
                str | FlextLdifModels.SchemaObjectClass | FlextTypes.MetadataAttributeValue
            ].ok(source_oc)

    def _convert_objectclass(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        data: str | FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[
        FlextLdifModels.SchemaObjectClass | str | FlextTypes.MetadataAttributeValue
    ]:
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
                    FlextLdifModels.SchemaObjectClass
                    | str
                    | FlextTypes.MetadataAttributeValue
                ].fail(error_msg)
            source_oc = parse_result.unwrap()

            # Step 2: Write to RFC string
            write_result = self._write_objectclass_to_rfc(source, source_oc)
            if write_result.is_failure:
                return write_result
            rfc_value = write_result.unwrap()

            # If result is not a string, return as-is (pass-through)
            if not isinstance(rfc_value, str):
                # Type narrowing for union type
                if isinstance(rfc_value, FlextLdifModels.SchemaObjectClass):
                    return FlextResult[
                        FlextLdifModels.SchemaObjectClass
                        | str
                        | FlextTypes.MetadataAttributeValue
                    ].ok(rfc_value)
                if isinstance(rfc_value, dict):
                    return FlextResult[
                        FlextLdifModels.SchemaObjectClass
                        | str
                        | FlextTypes.MetadataAttributeValue
                    ].ok(rfc_value)
                msg = f"Expected SchemaObjectClass | str | dict, got {type(rfc_value)}"
                raise TypeError(msg)

            # Step 3: Parse RFC string with target quirk
            target_result = self._parse_target_objectclass(target, rfc_value)
            if target_result.is_failure:
                error_msg = target_result.error or "Failed to parse target objectClass"
                return FlextResult[
                    FlextLdifModels.SchemaObjectClass
                    | str
                    | FlextTypes.MetadataAttributeValue
                ].fail(error_msg)
            parsed_oc = target_result.unwrap()

            # Step 4: Write target objectClass to final format
            return self._write_target_objectclass(target, parsed_oc)

        except (AttributeError, ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult.fail(f"ObjectClass conversion failed: {e}")

    def _parse_source_objectclass(
        self,
        source: ServerQuirkOrType,
        data: str | FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
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
            return parse_method(data)
        return FlextResult.fail("parse_objectclass requires string data")

    def _parse_target_objectclass(
        self,
        target: ServerQuirkOrType,
        rfc_value: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse target objectClass from RFC string."""
        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            target_schema = _get_schema_quirk(target_quirk)
        except TypeError as e:
            return FlextResult.fail(f"Target quirk error: {e}")

        parse_method = target_schema.parse_objectclass
        return parse_method(rfc_value)

    def _write_target_objectclass(
        self,
        target: ServerQuirkOrType,
        parsed_oc: FlextLdifModels.SchemaObjectClass
        | str
        | FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[
        FlextLdifModels.SchemaObjectClass | str | FlextTypes.MetadataAttributeValue
    ]:
        """Write target objectClass to final format."""
        # Type narrowing: write_objectclass requires SchemaObjectClass
        if not isinstance(parsed_oc, FlextLdifModels.SchemaObjectClass):
            # Return as-is if not SchemaObjectClass - type narrowing for union type
            if isinstance(parsed_oc, str):
                return FlextResult[
                    FlextLdifModels.SchemaObjectClass
                    | str
                    | FlextTypes.MetadataAttributeValue
                ].ok(parsed_oc)
            if isinstance(parsed_oc, dict):
                return FlextResult[
                    FlextLdifModels.SchemaObjectClass
                    | str
                    | FlextTypes.MetadataAttributeValue
                ].ok(parsed_oc)
            msg = f"Expected SchemaObjectClass | str | dict, got {type(parsed_oc)}"
            raise TypeError(msg)

        target_quirk = self._resolve_quirk(target)

        # Get target schema quirk with proper type narrowing
        try:
            schema_quirk = _get_schema_quirk(target_quirk)
        except TypeError:
            # Return as-is if no writer available
            return FlextResult[
                FlextLdifModels.SchemaObjectClass | str | FlextTypes.MetadataAttributeValue
            ].ok(parsed_oc)

        # schema_quirk is already properly typed from _get_schema_quirk
        write_result = schema_quirk.write_objectclass(parsed_oc)
        # write_objectclass returns FlextResult[str] - convert to union type
        if write_result.is_success:
            written_str = write_result.unwrap()
            # Type narrowing: write_objectclass returns str
            if not isinstance(written_str, str):
                msg = f"Expected str from write_objectclass, got {type(written_str)}"
                raise TypeError(msg)
            return FlextResult[
                FlextLdifModels.SchemaObjectClass | str | FlextTypes.MetadataAttributeValue
            ].ok(written_str)
        error_msg = write_result.error or "Failed to write objectClass"
        return FlextResult[
            FlextLdifModels.SchemaObjectClass | str | FlextTypes.MetadataAttributeValue
        ].fail(error_msg)

    def batch_convert(
        self,
        source: ServerQuirkOrType,
        target: ServerQuirkOrType,
        model_list: Sequence[FlextLdifTypes.ConvertibleModel],
    ) -> FlextResult[list[ConvertibleModelUnion]]:
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
            return FlextResult[list[ConvertibleModelUnion]].ok([])

        model_type = type(model_list[0]).__name__
        conversion_operation = f"batch_convert_{model_type}"

        try:
            # Collect converted models (concrete types from convert method)
            converted: list[ConvertibleModelUnion] = []
            errors: list[str] = []
            error_details: list[FlextLdifModels.ErrorDetail] = []

            for idx, model_item in enumerate(model_list):
                result = self.convert(source, target, model_item)
                if result.is_success:
                    unwrapped = result.unwrap()
                    # convert() returns ConvertibleModel (protocol-based)
                    # so unwrapped is already typed correctly
                    converted.append(unwrapped)
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
                return FlextResult[list[ConvertibleModelUnion]].fail(
                    error_msg,
                )

            # converted already has correct type from declaration (line 1490)
            return FlextResult[list[ConvertibleModelUnion]].ok(converted)

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

            return FlextResult[list[ConvertibleModelUnion]].fail(
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
        return self._check_entry_support(quirk, support)

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
        # Check if quirk is already a Schema quirk (has parse_attribute directly)
        if hasattr(quirk, "parse_attribute") or hasattr(quirk, "parse_objectclass"):
            # Use isinstance with @runtime_checkable protocol for type narrowing
            if isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol):
                return quirk
            # Check structural compliance: has required SchemaProtocol methods
            if (
                hasattr(quirk, "parse")
                and hasattr(quirk, "write")
                and isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)
            ):
                return quirk
            return None
        # Check if quirk is a base quirk with schema_quirk attribute
        schema_quirk_raw = getattr(quirk, "schema_quirk", None)
        if schema_quirk_raw is not None:
            # Use isinstance with @runtime_checkable protocol for type narrowing
            if isinstance(schema_quirk_raw, FlextLdifProtocols.Quirks.SchemaProtocol):
                return schema_quirk_raw
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
        if isinstance(attr_result, FlextResult) and attr_result.is_success:
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
        if isinstance(oc_result, FlextResult) and oc_result.is_success:
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
            if acl_result.is_success:
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
