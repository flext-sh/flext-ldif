"""Base Quirk Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines base classes for implementing server-specific quirks that extend
RFC-compliant LDIF/LDAP parsing with vendor-specific features.

Quirks allow extending the RFC base without modifying core parser logic.

ARCHITECTURE:
    Base classes use Python 3.13+ abstract base classes (ABC) with
    decorators for explicit inheritance contracts, while also implementing
    all methods required by FlextLdifProtocols for structural typing
    validation.

    This dual approach provides:
    - Explicit inheritance contracts through ABC
    - Structural typing validation through protocols
    - isinstance() checks for protocol compliance
    - Type safety at development and runtime

PROTOCOL COMPLIANCE:
    All base classes and implementations MUST satisfy corresponding protocols:
    - FlextLdifServersBase.Schema -> SchemaProtocol (structural typing)
    - FlextLdifServersBase.Acl -> AclProtocol (structural typing)
    - FlextLdifServersBase.Entry -> EntryProtocol (structural typing)

    All method signatures must match protocol definitions exactly for type safety.
"""

from __future__ import annotations

from typing import ClassVar, Self, cast

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes
from pydantic import Field

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.models import m
from flext_ldif.servers._base.constants import QuirkMethodsMixin

logger = FlextLogger(__name__)


class FlextLdifServersBaseSchema(
    QuirkMethodsMixin,
    FlextService[(m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)],
):
    """Base class for schema quirks - FlextService V2 with enhanced usability.

    NOTE: This is an implementation detail - DO NOT import directly.
    Use FlextLdifServersBase.Schema instead.

    Schema quirks extend RFC 4512 schema parsing with server-specific features
    for attribute and objectClass processing.

    **FlextService V2 Integration:**
    - Inherits from FlextService for dependency injection,
      logging, and validation
    - Uses V2 patterns: .result property for direct access,
      .execute() for FlextResult
    - Auto-registration in DI container via FlextService
        - Type-safe with TDomainResult = SchemaAttribute | SchemaObjectClass

    **V2 Usage Patterns:**
        >>> schema = FlextLdifServersRfc.Schema()
        >>> # Parse attribute with direct access
        >>> attr = schema.parse_attribute(attr_def).result
        >>> # Or use execute() for FlextResult composition
        >>> result = schema.parse_attribute(attr_def)

    """

    # Protocol-required fields
    server_type: str = "rfc"
    """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')."""

    priority: int = 0
    """Quirk priority (lower number = higher priority).

        **STANDARDIZED CONSTANTS REQUIRED**: Each Schema implementation MUST define
        a Constants nested class with:
        - CANONICAL_NAME: Unique server identifier (e.g., "oid", "oud")
        - ALIASES: All valid names for this server including canonical
        - PRIORITY: Selection priority (lower = higher priority)
        - CAN_NORMALIZE_FROM: What source types this quirk can normalize
        - CAN_DENORMALIZE_TO: What target types this quirk can denormalize to

        **Protocol Compliance**: All implementations MUST satisfy
        p.Ldif.SchemaQuirkProtocol through structural typing.
        This means all public methods must match protocol signatures exactly.

        **Validation**: Use hasattr(quirk, "parse") and hasattr(quirk, "write")
        to check protocol compliance at runtime (structural typing).

        Common schema extension patterns:
        - Vendor-specific prefixes (e.g., vendor prefix + attribute name)
        - Enhanced schema features beyond RFC baseline
        - Configuration-specific attributes
        - Vendor-specific schema extensions
        - RFC 4512 compliant baseline (no extensions)
        """

    # Parent quirk reference for accessing server-level configuration
    parent_quirk: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description=("Reference to parent quirk instance for server-level access"),
    )

    # Auto-execute parameters (for __new__ pattern with auto_execute)
    # These fields are excluded from serialization and only processed by __new__
    attr_definition: str | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="Attribute definition for auto-execute pattern",
    )
    oc_definition: str | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="ObjectClass definition for auto-execute pattern",
    )
    attr_model: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="SchemaAttribute model for auto-execute pattern",
    )
    oc_model: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="SchemaObjectClass model for auto-execute pattern",
    )
    operation: str | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="Operation type for auto-execute pattern",
    )

    def __new__(
        cls,
        _schema_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: FlextTypes.GeneralValueType,
    ) -> Self:
        """Override __new__ to filter _parent_quirk before passing to FlextService.

        Business Rule: _parent_quirk is not a Pydantic field and must be filtered
        from kwargs before passing to FlextService.__new__ which expects only
        t.GeneralValueType values.

        Args:
            _schema_service: Injected schema service (optional, passed to __init__)
            _parent_quirk: Parent quirk reference (optional, filtered from kwargs)
            **kwargs: Additional initialization parameters

        Returns:
            Schema instance

        """
        # Filter _parent_quirk from kwargs to avoid type errors in FlextService.__new__
        # Business Rule: _schema_service is not a t.GeneralValueType, so it must be handled separately
        # Implication: _schema_service is passed to __init__ instead of __new__
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_quirk"}
        # Call FlextService.__new__ with filtered kwargs (without _schema_service)
        instance = super().__new__(cls, **filtered_kwargs)
        # Store _parent_quirk after instance creation using object.__setattr__
        if _parent_quirk is not None:
            object.__setattr__(instance, "_parent_quirk", _parent_quirk)
        # _schema_service will be set in __init__
        return instance

    def __init__(
        self,
        _schema_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: FlextTypes.GeneralValueType,
    ) -> None:
        """Initialize schema quirk service with optional DI service injection.

        Business Rule: _schema_service parameter name matches __new__ signature.
        Both use underscore prefix to indicate internal use and avoid Pydantic field conflicts.
        _schema_service is NOT passed to FlextService.__init__ because it's not a t.GeneralValueType.
        Instead, it's stored directly on the instance using object.__setattr__.

        Implication: FlextService.__init__ expects only t.GeneralValueType kwargs,
        so protocol types must be handled separately from Pydantic initialization.

        Args:
            _schema_service: Injected FlextLdifSchema service
                (optional, lazy-created if None)
            _parent_quirk: Reference to parent quirk instance (optional)
            **kwargs: Additional initialization parameters for FlextService

        Note:
            server_type and priority are no longer passed to nested classes.
            They should be accessed via _get_server_type() and Constants.PRIORITY
            from the parent server class.

        """
        # Business Rule: Filter _parent_quirk from kwargs to avoid type errors
        # Implication: _parent_quirk is handled separately, not via Pydantic fields
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_quirk"}
        super().__init__(**filtered_kwargs)
        self._schema_service = _schema_service  # Store for use by subclasses
        # Store _parent_quirk using object.__setattr__ to avoid Pydantic validation
        # (it's not a Pydantic field, just an internal reference)
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)
        # Note: server_type and priority descriptors are only available on parent server classes
        # Nested classes (Schema/Acl/Entry) access them via _get_server_type() when needed

    # =====================================================================
    # HOOKS for Customization - Override in subclasses to customize behavior
    # =====================================================================
    # _get_server_type(), _get_priority(), _get_parent_quirk_safe()
    # are inherited from QuirkMethodsMixin

    # Control auto-execution
    auto_execute: ClassVar[bool] = False

    # =====================================================================
    # Automatic Routing Methods - Moved to rfc.py.Schema
    # =====================================================================
    # Concrete implementations of routing methods are now in
    # FlextLdifServersRfc.Schema
    # Base class keeps only abstract methods and hooks

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Parse server-specific attribute definition (internal).

        Extracts attribute metadata (OID, NAME, DESC, SYNTAX, etc.)
        from RFC 4512 format and applies server-specific enhancements.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextResult with parsed SchemaAttribute model

        """
        del attr_definition  # Unused in base, required by protocol
        return FlextResult.fail("Must be implemented by subclass")

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Parse server-specific objectClass definition (internal).

        Extracts objectClass metadata (OID, NAME, SUP, MUST, MAY, etc.)
        from RFC 4512 format and applies server-specific enhancements.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed SchemaObjectClass model

        """
        _ = oc_definition  # Explicitly mark as intentionally unused in base
        return FlextResult.fail("Must be implemented by subclass")

    # =====================================================================
    # Concrete Routing Methods - Moved to rfc.py.Schema
    # =====================================================================
    # _route_write, _route_can_handle, _handle_parse_operation,
    # _handle_write_operation, _auto_detect_operation, _route_operation,
    # execute, __call__, __new__ are now concrete implementations in FlextLdifServersRfc.Schema

    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Hook called after parsing an attribute definition.

        Override in subclasses for server-specific post-processing of parsed attributes.

        Default behavior: returns attribute unchanged (pass-through).

        **When to use:**
        - Normalize attribute properties after parsing
        - Add server-specific metadata
        - Validate attribute constraints
        - Transform attribute format

        Args:
            attr: Parsed SchemaAttribute from parse_attribute()

        Returns:
            FlextResult[m.Ldif.SchemaAttribute] - modified or original attribute

        **Example:**
            def _hook_post_parse_attribute(self, attr):
                # OID-specific: normalize OID format
                if attr.oid:
                    attr.oid = normalize_oid(attr.oid)
                return FlextResult.ok(attr)

        """
        return FlextResult.ok(attr)

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Hook called after parsing an objectClass definition.

        Override in subclasses for server-specific post-processing of parsed objectClasses.

        Default behavior: returns objectClass unchanged (pass-through).

        **When to use:**
        - Normalize objectClass properties after parsing
        - Add server-specific metadata
        - Validate objectClass constraints
        - Transform objectClass format

        Args:
            oc: Parsed SchemaObjectClass from parse_objectclass()

        Returns:
            FlextResult[m.Ldif.SchemaObjectClass] - modified or original objectClass

        **Example:**
            def _hook_post_parse_objectclass(self, oc):
                # OID-specific: validate MUST/MAY attributes exist
                if oc.must:
                    for attr_name in oc.must:
                        if not self.validate_attribute_exists(attr_name):
                            return FlextResult.fail(f"Unknown attribute: {attr_name}")
                return FlextResult.ok(oc)

        """
        return FlextResult.ok(oc)

    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if this quirk can handle the attribute definition.

        Called BEFORE parsing to detect if this quirk should process the definition.
        Receives the raw attribute definition string (e.g., "( 2.5.4.3 NAME 'cn' ...)")
        OR SchemaAttribute model object (for convenience in tests).

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if this quirk can parse this attribute definition

        """
        _ = attr_definition  # Explicitly mark as intentionally unused in base
        return False  # CONSOLIDATED into parse(definition, model_type=None)  # CONSOLIDATED into parse(definition, model_type=None)

    # CONSOLIDATED into parse(definition, model_type=None)
    # See consolidated parse() method below

    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if this quirk can handle the objectClass definition.

        Called BEFORE parsing to detect if this quirk should process the definition.
        Receives the raw objectClass definition string (e.g., "( 2.5.6.6 NAME 'person' ...)")
        OR SchemaObjectClass model object (for convenience in tests).

        Args:
            oc_definition: ObjectClass definition string or model

        Returns:
            True if this quirk can parse this objectClass definition

        """
        _ = oc_definition  # Explicitly mark as intentionally unused in base
        return False  # CONSOLIDATED into parse(definition, model_type=None)

    # CONSOLIDATED into parse(definition, model_type=None)
    # See consolidated parse() method below

    # REMOVED: convert_attribute - Entry is always RFC with metadata
    # All conversion is handled by quirk_metadata in the model itself

    # REMOVED: convert_objectclass - See convert_attribute

    # REMOVED: convert_attribute - See convert_attribute

    # REMOVED: convert_objectclass - See convert_attribute

    # =====================================================================
    # Concrete Helper Methods - Moved to rfc.py.Schema
    # =====================================================================
    # create_metadata is now a concrete implementation in FlextLdifServersRfc.Schema

    def parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Parse attribute definition (public API).

        Delegates to _parse_attribute() for server-specific implementation.

        Args:
            attr_definition: Attribute definition string

        Returns:
            FlextResult with parsed SchemaAttribute model

        """
        return self._parse_attribute(attr_definition)

    def parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Parse objectClass definition (public API).

        Delegates to _parse_objectclass() for server-specific implementation.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed SchemaObjectClass model

        """
        return self._parse_objectclass(oc_definition)

    def route_parse(
        self,
        definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Route schema definition to appropriate parse method.

        Generic implementation that automatically detects if definition is
        attribute or objectclass and routes to the appropriate parser.
        This method is available to all server implementations.

        Args:
            definition: Schema definition string.

        Returns:
            FlextResult with SchemaAttribute or SchemaObjectClass.

        """
        # Business Rule: Schema type detection uses FlextLdifUtilities.Schema
        # via lazy import pattern. Type checker cannot infer exact types.
        # Implication: We use runtime hasattr checks and getattr for type safety.

        schema_util = FlextLdifUtilitiesSchema
        if schema_util is not None:
            detect_method = getattr(schema_util, "detect_schema_type", None)
            if detect_method is not None and callable(detect_method):
                schema_type = detect_method(definition)
            else:
                schema_type = "attribute"
        else:
            schema_type = "attribute"
        if schema_type == "objectclass":
            oc_result = self._parse_objectclass(definition)
            if oc_result.is_failure:
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass)
                ].fail(
                    oc_result.error or "Parse failed",
                )
            return FlextResult[(m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass)].ok(
                oc_result.value,
            )
        attr_result = self._parse_attribute(definition)
        if attr_result.is_failure:
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass)
            ].fail(
                attr_result.error or "Parse failed",
            )
        return FlextResult[(m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass)].ok(
            attr_result.value,
        )

    def parse(
        self,
        definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Parse schema definition (attribute or objectClass).

        Generic implementation that automatically routes to parse_attribute()
        or parse_objectclass() based on content. This method is available
        to all server implementations.

        Args:
            definition: Schema definition string (attribute or objectClass)

        Returns:
            FlextResult with SchemaAttribute or SchemaObjectClass model

        """
        return self.route_parse(definition)

    def write_attribute(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> FlextResult[str]:
        """Write attribute to RFC-compliant string format (public API).

        Delegates to _write_attribute() for server-specific implementation.

        Args:
            attr_data: SchemaAttribute model

        Returns:
            FlextResult with RFC-compliant attribute string

        """
        return self._write_attribute(attr_data)

    def write_objectclass(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write objectClass to RFC-compliant string format (public API).

        Delegates to _write_objectclass() for server-specific implementation.

        Args:
            oc_data: SchemaObjectClass model

        Returns:
            FlextResult with RFC-compliant objectClass string

        """
        return self._write_objectclass(oc_data)

    def _write_attribute(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> FlextResult[str]:
        """Write attribute data to RFC-compliant string format (internal).

        Args:
            attr_data: SchemaAttribute model to write

        Returns:
            FlextResult with RFC-compliant attribute string

        """
        _ = attr_data  # Explicitly mark as intentionally unused in base
        return FlextResult.fail(
            "Must be implemented by subclass",
        )  # Must be implemented by subclass

    def _write_objectclass(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write objectClass data to RFC-compliant string format (internal).

        Args:
            oc_data: SchemaObjectClass model

        Returns:
            FlextResult with RFC-compliant objectClass string

        """
        _ = oc_data  # Explicitly mark as intentionally unused in base
        return FlextResult.fail("Must be implemented by subclass")

    def _hook_validate_attributes(
        self,
        attributes: list[m.Ldif.SchemaAttribute],
        available_attrs: set[str],
    ) -> FlextResult[bool]:
        """Hook for server-specific attribute validation during schema extraction.

        Subclasses can override this to perform validation of attribute dependencies
        before objectClass extraction. This is called only when validate_dependencies=True.

        Default implementation: No validation (pass-through).

        Args:
            attributes: List of parsed SchemaAttribute models
            available_attrs: Set of lowercase attribute names available

        Returns:
            FlextResult[bool] - True if valid, fails with error if invalid

        Example Override (in OUD):
            def _hook_validate_attributes(self, attributes, available_attrs):
                # OUD-specific validation logic
                for attr in attributes:
                    if attr.requires_dependency not in available_attrs:
                        return FlextResult.fail("Missing dependency")
                return FlextResult.ok(True)

        """
        # Default: No validation needed
        _ = attributes
        _ = available_attrs
        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_and_track_oid(
        metadata_extensions: dict[str, list[str] | str | bool | None],
        oid_value: str | None,
        oid_name: str,
    ) -> None:
        """Validate OID and track result in metadata extensions.

        Uses c.Ldif.MetadataKeys for standardized metadata keys.

        Args:
            metadata_extensions: Metadata extensions dict to update
            oid_value: OID value to validate (optional)
            oid_name: Name of OID for error messages (e.g., "attribute", "syntax", "equality")

        """
        if not oid_value:
            return

        # Business Rule: OID validation uses FlextLdifUtilities.OID
        # via lazy import pattern. Type checker cannot infer exact types.
        # Implication: We use runtime hasattr checks and getattr for type safety.
        # Business Rule: Validate OID format using FlextLdifUtilities.OID
        # OID validation returns FlextResult[bool] indicating format validity
        # Use structural checks and cast to satisfy pyright strict mode
        oid_util = FlextLdifUtilitiesOID
        oid_validate_result: FlextResult[bool]
        if oid_util is not None:
            validate_method = getattr(oid_util, "validate_format", None)
            if validate_method is not None and callable(validate_method):
                validate_result_raw = validate_method(oid_value)
                # Type narrowing: validate_format returns FlextResult[bool]
                if isinstance(validate_result_raw, FlextResult):
                    oid_validate_result = validate_result_raw
                else:
                    oid_validate_result = FlextResult.ok(bool(validate_result_raw))
            else:
                oid_validate_result = FlextResult.ok(True)
        else:
            oid_validate_result = FlextResult.ok(True)
        if oid_validate_result.is_failure:
            metadata_extensions["syntax_validation_error"] = (
                f"{oid_name.capitalize()} OID validation failed: {oid_validate_result.error}"
            )
            metadata_extensions["syntax_oid_valid"] = False
        elif not oid_validate_result.value:
            metadata_extensions["syntax_validation_error"] = (
                f"Invalid {oid_name} OID format: {oid_value} "
                f"(must be numeric dot-separated format)"
            )
            metadata_extensions["syntax_oid_valid"] = False
        else:
            # OID is valid - track in metadata
            metadata_extensions["syntax_oid_valid"] = True

    @staticmethod
    def _extract_metadata_extensions(
        attr_definition: str,
    ) -> dict[str, list[str] | str | bool | None]:
        """Extract metadata extensions from attribute definition.

        Business Rule: Uses FlextLdifUtilities.Parser.extract_extensions.
        """
        parser_util = FlextLdifUtilitiesParser
        if parser_util is not None:
            return {}
        extract_method = getattr(parser_util, "extract_extensions", None)
        if extract_method is None or not callable(extract_method):
            return {}
        extensions_raw = extract_method(attr_definition)
        if isinstance(extensions_raw, dict):
            return cast("dict[str, list[str] | str | bool | None]", extensions_raw)
        return {}

    @staticmethod
    def _resolve_quirk_type(
        server_type: str | None,
    ) -> str:
        """Resolve server type to valid string, defaulting to RFC."""
        if not server_type:
            return FlextLdifUtilitiesServer.normalize_server_type("rfc")
        # Common server types - validation happens at runtime
        valid_types = {
            "rfc",
            "oid",
            "oud",
            "openldap",
            "openldap1",
            "ds389",
            "apache",
            "ad",
            "novell",
            "tivoli",
            "relaxed",
        }
        if server_type.lower() in valid_types:
            return FlextLdifUtilitiesServer.normalize_server_type(server_type)
        return FlextLdifUtilitiesServer.normalize_server_type("rfc")

    @staticmethod
    def _preserve_formatting(
        metadata: m.Ldif.QuirkMetadata,
        attr_definition: str,
    ) -> None:
        """Preserve schema formatting via FlextLdifUtilities.Metadata."""
        metadata_util = FlextLdifUtilitiesMetadata
        if metadata_util is None:
            return
        preserve_method = getattr(metadata_util, "preserve_schema_formatting", None)
        if preserve_method is not None and callable(preserve_method):
            _ = preserve_method(metadata, attr_definition)

    @staticmethod
    def build_attribute_metadata(
        attr_definition: str,
        syntax: str | None,
        syntax_validation_error: str | None,
        attribute_oid: str | None = None,
        equality_oid: str | None = None,
        ordering_oid: str | None = None,
        substr_oid: str | None = None,
        sup_oid: str | None = None,
        server_type: str | None = None,
    ) -> m.Ldif.QuirkMetadata | None:
        """Build metadata for attribute including extensions and OID validation.

        Business Rule: Tracks OID validation for attribute, syntax, matching
        rules (equality, ordering, substr), and SUP OID.

        Args:
            attr_definition: Original attribute definition
            syntax: Syntax OID (optional)
            syntax_validation_error: Validation error for syntax OID if any
            attribute_oid: Attribute OID (optional)
            equality_oid: Equality matching rule OID (optional)
            ordering_oid: Ordering matching rule OID (optional)
            substr_oid: Substring matching rule OID (optional)
            sup_oid: SUP OID (optional)
            server_type: Server type identifier (defaults to RFC)

        Returns:
            QuirkMetadata or None

        """
        metadata_extensions = FlextLdifServersBaseSchema._extract_metadata_extensions(
            attr_definition,
        )

        # Track syntax OID validation
        if syntax:
            metadata_extensions["syntax_oid_valid"] = syntax_validation_error is None
            if syntax_validation_error:
                metadata_extensions["syntax_validation_error"] = syntax_validation_error

        # Track OID validations using helper method
        FlextLdifServersBaseSchema.validate_and_track_oid(
            metadata_extensions,
            attribute_oid,
            "attribute",
        )
        for rule_name, rule_oid in [
            ("equality matching rule", equality_oid),
            ("ordering matching rule", ordering_oid),
            ("substring matching rule", substr_oid),
        ]:
            FlextLdifServersBaseSchema.validate_and_track_oid(
                metadata_extensions,
                rule_oid,
                rule_name,
            )
        FlextLdifServersBaseSchema.validate_and_track_oid(
            metadata_extensions,
            sup_oid,
            "SUP",
        )

        # Preserve original format
        metadata_extensions["original_format"] = attr_definition.strip()
        metadata_extensions["schema_original_string_complete"] = attr_definition

        # Create metadata
        quirk_type = FlextLdifServersBaseSchema._resolve_quirk_type(server_type)
        metadata = m.Ldif.QuirkMetadata(
            quirk_type=quirk_type,
            extensions=FlextLdifModelsMetadata.DynamicMetadata(**metadata_extensions)
            if metadata_extensions
            else FlextLdifModelsMetadata.DynamicMetadata(),
        )

        # Preserve formatting details
        FlextLdifServersBaseSchema._preserve_formatting(metadata, attr_definition)

        # Log preview
        preview_len = 100
        logger.debug(
            "Preserved schema formatting details",
            attr_definition_preview=attr_definition[:preview_len]
            if len(attr_definition) > preview_len
            else attr_definition,
        )

        return (
            metadata if metadata_extensions or metadata.schema_format_details else None
        )

    # =====================================================================
    # Concrete Template Methods - Moved to rfc.py.Schema
    # =====================================================================
    # extract_schemas_from_ldif is now a concrete implementation in FlextLdifServersRfc.Schema

    # REMOVED: should_filter_out_attribute - Roteamento interno, não deve ser abstrato

    # REMOVED: should_filter_out_objectclass - Roteamento interno, não deve ser abstrato

    def _handle_parse_operation(
        self,
        attr_definition: str | None,
        oc_definition: str | None,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Handle parse operation for schema quirk.

        Generic implementation that routes to parse_attribute() or
        parse_objectclass() based on provided parameters. This method is
        available to all server implementations.

        Args:
            attr_definition: Attribute definition string to parse (optional).
            oc_definition: ObjectClass definition string to parse (optional).

        Returns:
            FlextResult with parsed SchemaAttribute or SchemaObjectClass model,
            or error if parsing failed or no parameter provided.

        """
        if attr_definition:
            attr_result = self.parse_attribute(attr_definition)
            if attr_result.is_success:
                parsed_attr: m.Ldif.SchemaAttribute = attr_result.value
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].ok(
                    parsed_attr,
                )
            error_msg: str = attr_result.error or "Parse attribute failed"
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                error_msg,
            )
        if oc_definition:
            oc_result = self.parse_objectclass(oc_definition)
            if oc_result.is_success:
                parsed_oc: m.Ldif.SchemaObjectClass = oc_result.value
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].ok(
                    parsed_oc,
                )
            error_msg = oc_result.error or "Parse objectclass failed"
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                error_msg,
            )
        return FlextResult[
            (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
        ].fail(
            "No parse parameter provided",
        )

    def _handle_write_operation(
        self,
        attr_model: m.Ldif.SchemaAttribute | None,
        oc_model: m.Ldif.SchemaObjectClass | None,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Handle write operation for schema quirk.

        Generic implementation that routes to write_attribute() or
        write_objectclass() based on provided parameters. This method is
        available to all server implementations.

        Args:
            attr_model: SchemaAttribute model to write (optional).
            oc_model: SchemaObjectClass model to write (optional).

        Returns:
            FlextResult with LDIF string representation, or error if writing
            failed or no parameter provided.

        """
        if attr_model:
            write_result = self.write_attribute(attr_model)
            if write_result.is_success:
                written_text: str = write_result.value
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].ok(
                    written_text,
                )
            error_msg: str = write_result.error or "Write attribute failed"
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                error_msg,
            )
        if oc_model:
            write_oc_result = self.write_objectclass(oc_model)
            if write_oc_result.is_success:
                written_text = write_oc_result.value
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].ok(
                    written_text,
                )
            error_msg = write_oc_result.error or "Write objectclass failed"
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                error_msg,
            )
        return FlextResult[
            (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
        ].fail(
            "No write parameter provided",
        )

    def _auto_detect_operation(
        self,
        data: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass),
        operation: str | None,
    ) -> str | FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Auto-detect operation from data type.

        Generic implementation that detects whether to parse or write based on
        data type. Returns operation or error result. This method is available
        to all server implementations.

        Args:
            data: Data to process (str for parse, SchemaAttribute/SchemaObjectClass
                for write, or None).
            operation: Explicit operation to use (optional, auto-detected if None).

        Returns:
            ParseWriteOperationLiteral if operation can be determined, or
            FlextResult with error if data type is unknown.

        """
        if operation is not None:
            return operation

        if isinstance(data, str):
            # "parse" is a valid ParseWriteOperationLiteral
            return "parse"
        # data is SchemaAttribute | SchemaObjectClass (Union type covers both)
        return "write"

    def _route_operation(
        self,
        data: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass),
        operation: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Route data to appropriate parse or write handler.

        Generic implementation that routes data to _handle_parse_operation()
        or _handle_write_operation() based on operation type. This method is
        available to all server implementations.

        Args:
            data: Data to process (str, SchemaAttribute, or SchemaObjectClass).
            operation: Operation to perform ("parse" or "write").

        Returns:
            FlextResult with parsed model or written string, or error if
            operation/data type mismatch.

        """
        if operation == "parse":
            if not isinstance(data, str):
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].fail(f"parse operation requires str, got {type(data).__name__}")
            # Detect if attribute or objectClass definition
            # Business Rule: Schema type detection uses FlextLdifUtilitiesSchema

            schema_util = FlextLdifUtilitiesSchema
            if schema_util is not None:
                detect_method = getattr(schema_util, "detect_schema_type", None)
                if detect_method is not None and callable(detect_method):
                    schema_type = detect_method(data)
                else:
                    schema_type = "attribute"
            else:
                schema_type = "attribute"
            if schema_type == "objectClass":
                return self._handle_parse_operation(
                    attr_definition=None,
                    oc_definition=data,
                )
            return self._handle_parse_operation(
                attr_definition=data,
                oc_definition=None,
            )

        if operation == "write":
            if isinstance(data, m.Ldif.SchemaAttribute):
                return self._handle_write_operation(attr_model=data, oc_model=None)
            if isinstance(data, m.Ldif.SchemaObjectClass):
                return self._handle_write_operation(attr_model=None, oc_model=data)
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                f"write operation requires SchemaAttribute or SchemaObjectClass, got {type(data).__name__}",
            )

        # Should not reach here (Literal type ensures only parse or write)
        msg = f"Unknown operation: {operation}"
        raise AssertionError(msg)

    def execute(
        self,
        *,
        data: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None) = None,
        operation: str | None = None,
        **kwargs: dict[str, object],
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Execute schema operation with auto-detection: str→parse, Model→write.

        Generic implementation that auto-detects operation type and routes to
        appropriate handler. This method is available to all server implementations.

        Args:
            **kwargs: data (str | SchemaAttribute | SchemaObjectClass), operation (optional)

        Returns:
            FlextResult with parsed model or written string

        """
        # Extract from kwargs if not provided
        if data is None:
            data_raw = kwargs.get("data")
            if isinstance(
                data_raw,
                (
                    str,
                    m.Ldif.SchemaAttribute,
                    m.Ldif.SchemaObjectClass,
                ),
            ):
                data = data_raw

        if operation is None:
            operation_raw = kwargs.get("operation")
            # Type narrowing: check if operation_raw is a valid Literal value
            operation_typed: str | None = None
            if isinstance(operation_raw, str):
                if operation_raw == "parse":
                    operation_typed = "parse"
                elif operation_raw == "write":
                    operation_typed = "write"
            operation = operation_typed

        # Health check: no data provided
        if data is None:
            empty_str: str = ""
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].ok(
                empty_str,
            )

        # Auto-detect or validate operation
        # Type narrowing: ensure operation is ParseWriteOperationLiteral | None
        # Type narrowing: ParseWriteOperationLiteral is Literal["parse", "write"]
        # operation is already typed from above, just ensure it's the correct type

        # Business Rule: operation is already validated as ParseWriteOperationLiteral via isinstance check
        # Implication: No cast needed - type checker can infer the correct type from the guard
        # Type narrowing: use explicit literal values based on operation string
        operation_final: str | None = None
        if isinstance(operation, str) and operation in {"parse", "write"}:
            operation_final = "parse" if operation == "parse" else "write"
        detected_op = self._auto_detect_operation(data, operation_final)
        if isinstance(detected_op, FlextResult):
            return detected_op

        # Route to appropriate handler
        return self._route_operation(data, detected_op)

    def write(
        self,
        model: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write schema model to string format.

        Dispatches to write_attribute or write_objectclass based on model type.
        This satisfies p.Ldif.SchemaQuirkProtocol.

        Args:
            model: SchemaAttribute or SchemaObjectClass model to write

        Returns:
            FlextResult with string representation

        """
        if isinstance(model, m.Ldif.SchemaAttribute):
            return self.write_attribute(model)
        # model is SchemaObjectClass (Union type narrows after first check)
        return self.write_objectclass(model)
