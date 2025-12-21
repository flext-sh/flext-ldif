"""Schema Processing Service for FlextLdif.

Centralizes all schema parsing, validation, transformation, and detection logic
in a server-agnostic service using dependency injection via FlextLdifServer.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Self, override

from flext_core import r
from pydantic import PrivateAttr

from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m

# Removed: from flext_ldif.constants import c (prohibited in services/)
# Use FlextLdifUtilitiesServer helpers or direct string literals
from flext_ldif.services.server import FlextLdifServer


class FlextLdifSchema(FlextLdifServiceBase[FlextLdifModelsResults.SchemaServiceStatus]):
    """Unified schema validation, transformation, and detection service.

    Business Rule: Schema service centralizes all schema-related operations using
    dependency injection via FlextLdifServer. Service provides server-agnostic
    interface for schema parsing, validation, transformation, and detection.
    Schema entries are identified by specific objectClasses (attributeSchema,
    objectClassSchema, etc.). All operations use FlextResult for error handling.

    Implication: Schema service enables schema-aware LDIF processing without
    direct server knowledge. Schema entries can be filtered, validated, and
    manipulated separately from regular entries. This enables schema migration
    and validation workflows.

    Centralizes all schema-related operations that were previously scattered
    across server-specific nested Schema classes and separate detector service.

    Key Principles:
        - SRP: Each method has a single, well-defined responsibility
        - DI: Uses FlextLdifServer for server-specific behavior (never knows OID/OUD directly)
        - Utilities: Leverages u extensively for metadata operations
        - Metadata: Uses Entry + Metadata patterns conforming to FlextLdifConstants
        - No Server Knowledge: Never imports or references server types directly

    Methods:
        - parse_attribute(): Parse attribute definition
        - parse_objectclass(): Parse objectClass definition
        - validate_attribute(): Validate attribute syntax
        - validate_objectclass(): Validate objectClass syntax
        - write_attribute(): Write attribute to LDIF format
        - write_objectclass(): Write objectClass to LDIF format
        - is_schema(): Detect if entry is a schema definition

    Usage:
        from flext_ldif.services.schema import FlextLdifSchema
        from flext_ldif.services.server import FlextLdifServer

        registry = FlextLdifServer()
        schema_service = FlextLdifSchema(registry=registry)

        # Parse attribute
        result = schema_service.parse_attribute(attr_definition)
        if result.is_success:
            attr = result.value

        # Detect schema entry
        if schema_service.is_schema(entry):
            print("Entry is a schema definition")

    References:
        - RFC 4512: LDAP Schema Definitions
        - u: Schema utilities for metadata operations
        - FlextLdifConstants: Metadata keys and schema constants
        - FlextLdifServer: Server registry for DI

    """

    # ════════════════════════════════════════════════════════════════════════
    # DEPENDENCY INJECTION FIELDS (PrivateAttr for frozen model compatibility)
    # ════════════════════════════════════════════════════════════════════════

    _registry: FlextLdifServer = PrivateAttr(default_factory=FlextLdifServer)
    _server_type: str = PrivateAttr(
        default="rfc",
    )

    def __init__(
        self,
        *,
        registry: FlextLdifServer | None = None,
        server_type: str = "rfc",
    ) -> None:
        """Initialize schema service with dependency injection.

        Args:
            registry: FlextLdifServer instance for server-specific behavior.
                     If None, creates a new instance (default: None).
            server_type: Server type for schema operations (default: "rfc").

        Note:
            All server-specific operations are delegated to FlextLdifServer.
            This service never knows about OID, OUD, or other server types directly.

        """
        super().__init__()
        # Business Rule: Private attributes use object.__setattr__ for frozen model compatibility
        object.__setattr__(
            self,
            "_registry",
            registry if registry is not None else FlextLdifServer(),
        )
        object.__setattr__(self, "_server_type", server_type)

    # ════════════════════════════════════════════════════════════════════════
    # PROPERTIES
    # ════════════════════════════════════════════════════════════════════════

    @property
    def server_type(self) -> str:
        """Get configured server type."""
        return self._server_type

    # ════════════════════════════════════════════════════════════════════════
    # BUILDER PATTERN METHODS
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def builder(cls) -> Self:
        """Create fluent builder instance for method chaining.

        Returns:
            Service instance for method chaining

        Example:
            service = (
                FlextLdifSchema.builder()
                .with_server_type("oid")
                .build()
            )

        """
        return cls()

    def with_server_type(
        self,
        server_type: str,
    ) -> Self:
        """Set server type for schema operations (fluent builder).

        Args:
            server_type: Server type (e.g., "oid", "oud", "openldap", "rfc")

        Returns:
            Self for method chaining

        """
        # Business Rule: Private attributes use object.__setattr__ for frozen model compatibility
        object.__setattr__(self, "_server_type", server_type)
        return self

    def build(self) -> Self:
        """Build configured schema service instance.

        Returns:
            Fully configured service instance

        """
        return self

    # ════════════════════════════════════════════════════════════════════════
    # SERVICE EXECUTION
    # ════════════════════════════════════════════════════════════════════════

    @override
    def execute(
        self,
    ) -> r[FlextLdifModelsResults.SchemaServiceStatus]:
        """Execute schema service self-check.

        Returns:
            FlextResult containing service status

        """
        server_type_lit: c.Ldif.ServerTypes = c.Ldif.ServerTypes(self._server_type)
        return r[FlextLdifModelsResults.SchemaServiceStatus].ok(
            FlextLdifModelsResults.SchemaServiceStatus(
                service="SchemaService",
                server_type=server_type_lit.value,
                status="operational",
                rfc_compliance="RFC 4512",
                operations=[
                    "parse_attribute",
                    "parse_objectclass",
                    "validate_attribute",
                    "validate_objectclass",
                    "write_attribute",
                    "write_objectclass",
                    "is_schema",
                ],
            ),
        )

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA PARSING OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    def parse_attribute(
        self,
        attr_definition: str,
        *,
        server_type: str | None = None,
    ) -> r[m.Ldif.SchemaAttribute]:
        """Parse attribute type definition.

        Uses u.Parser for RFC parsing and FlextLdifServer
        for server-specific enhancements via dependency injection.

        Args:
            attr_definition: Attribute definition string
                (e.g., "( 2.5.4.3 NAME 'cn' SYNTAX ... )")
            server_type: Optional server type for server-specific parsing.
                        If None, uses RFC-compliant parsing (default: None).

        Returns:
            FlextResult with SchemaAttribute model including metadata

        """
        try:
            if not attr_definition or not attr_definition.strip():
                return r.fail("Attribute definition is empty")

            # Use utilities for RFC parsing - parse_attribute returns FlextResult
            parse_result = FlextLdifUtilitiesSchema.parse_attribute(attr_definition)
            if parse_result.is_failure:
                return r.fail(f"Parse failed: {parse_result.error}")

            parsed_dict = dict(parse_result.value)

            # Extract metadata_extensions before model_validate (not a direct field)
            metadata_extensions = parsed_dict.pop("metadata_extensions", {})
            parsed_dict.pop("syntax_validation", None)

            # Build SchemaAttribute from parsed dict (without metadata_extensions)
            attr_domain = m.Ldif.SchemaAttribute.model_validate(parsed_dict)

            # Build metadata from extensions if present
            if metadata_extensions and isinstance(metadata_extensions, dict):
                attr_domain.metadata = m.Ldif.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=m.Ldif.DynamicMetadata(**metadata_extensions),
                )

            # Apply server-specific enhancements via FlextLdifServer if requested
            if server_type:
                server_quirk = self._registry.schema(server_type)
                if server_quirk:
                    # Use server quirk for server-specific parsing
                    server_result = server_quirk.parse_attribute(attr_definition)
                    if server_result.is_success:
                        attr_domain = server_result.value

            # Type narrowing: attr_domain is already m.Ldif.SchemaAttribute
            attr: m.Ldif.SchemaAttribute = attr_domain

            # Metadata is already built by u.Parser
            # No additional metadata building needed here

            return r.ok(attr)

        except Exception as e:
            error_msg = f"Error parsing attribute: {e}"
            self.logger.exception(
                "Failed to parse attribute definition",
                error=str(e),
            )
            return r.fail(error_msg)

    def parse_objectclass(
        self,
        oc_definition: str,
        *,
        server_type: str | None = None,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse objectClass definition.

        Uses u.Parser for RFC parsing and FlextLdifServer
        for server-specific enhancements via dependency injection.

        Args:
            oc_definition: ObjectClass definition string
                (e.g., "( 2.5.6.6 NAME 'person' ... )")
            server_type: Optional server type for server-specific parsing.
                        If None, uses RFC-compliant parsing (default: None).

        Returns:
            FlextResult with SchemaObjectClass model including metadata

        """
        try:
            if not oc_definition or not oc_definition.strip():
                return r.fail("ObjectClass definition is empty")

            # Use utilities for RFC parsing - parse_objectclass returns dict directly
            parsed_dict = FlextLdifUtilitiesSchema.parse_objectclass(oc_definition)

            # Extract metadata_extensions before building (not a direct field)
            metadata_extensions = parsed_dict.pop("metadata_extensions", {})

            # Build SchemaObjectClass from parsed dict
            oid_value = str(parsed_dict["oid"]) if parsed_dict["oid"] else ""
            name_value = str(parsed_dict.get("name") or parsed_dict["oid"])
            desc_value = str(parsed_dict.get("desc")) if parsed_dict.get("desc") else None
            sup_value = parsed_dict.get("sup")
            kind_value = str(parsed_dict.get("kind", "STRUCTURAL"))
            must_value = parsed_dict.get("must")
            may_value = parsed_dict.get("may")

            oc_domain = m.Ldif.SchemaObjectClass(
                oid=oid_value,
                name=name_value,
                desc=desc_value,
                sup=sup_value,
                kind=kind_value,
                must=must_value,
                may=may_value,
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=m.Ldif.DynamicMetadata(**metadata_extensions),
                )
                if (metadata_extensions and isinstance(metadata_extensions, dict))
                else None,
            )

            # Apply server-specific enhancements via FlextLdifServer if requested
            if server_type:
                server_quirk = self._registry.schema(server_type)
                if server_quirk:
                    # Use server quirk for server-specific parsing
                    server_result = server_quirk.parse_objectclass(oc_definition)
                    if server_result.is_success:
                        oc_domain = server_result.value

            # Type narrowing: oc_domain is already m.Ldif.SchemaObjectClass
            oc: m.Ldif.SchemaObjectClass = oc_domain

            # Metadata is already built by u.Parser
            # No additional metadata building needed here

            return r.ok(oc)

        except Exception as e:
            error_msg = f"Error parsing objectClass: {e}"
            self.logger.exception(
                "Failed to parse objectClass definition",
                error=str(e),
            )
            return r.fail(error_msg)

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA VALIDATION OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    def validate_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> r[bool]:
        """Validate attribute model syntax and constraints.

        Uses u for validation operations.

        Args:
            attr: SchemaAttribute model to validate (guaranteed non-None by Pydantic)

        Returns:
            r[bool]: True if valid, error otherwise

        Note:
            - attr cannot be None (Pydantic Field(...) ensures this)
            - attr.name and attr.oid are required fields (Pydantic Field(...))
            - Validates syntax OID format using u.OID

        """
        try:
            # Validate required fields are not empty
            if not attr.oid or not attr.oid.strip():
                return r.fail("Attribute OID is required and cannot be empty")
            if not attr.name or not attr.name.strip():
                return r.fail(
                    "Attribute NAME is required and cannot be empty",
                )

            # Validate syntax OID format if present using utilities
            if attr.syntax:
                validation_result = FlextLdifUtilitiesOID.validate_format(attr.syntax)
                if validation_result.is_failure or not validation_result.value:
                    return r.fail(f"Invalid SYNTAX OID: {attr.syntax}")

            return r.ok(True)

        except Exception as e:
            error_msg = f"Error validating attribute: {e}"
            self.logger.exception(
                "Failed to validate attribute",
                error=str(e),
            )
            return r.fail(error_msg)

    def validate_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> r[bool]:
        """Validate objectClass model syntax and constraints.

        Uses FlextLdifConstants for validation constants.

        Args:
            oc: SchemaObjectClass model to validate (guaranteed non-None by Pydantic)

        Returns:
            r[bool]: True if valid, error otherwise

        Note:
            - oc cannot be None (Pydantic Field(...) ensures this)
            - oc.name and oc.oid are required fields (Pydantic Field(...))
            - Validates objectclass kind using schema constants

        """
        try:
            # Validate required fields are not empty
            if not oc.oid or not oc.oid.strip():
                return r.fail(
                    "ObjectClass OID is required and cannot be empty",
                )
            if not oc.name or not oc.name.strip():
                return r.fail(
                    "ObjectClass NAME is required and cannot be empty",
                )

            # Check objectclass kind using constants
            valid_kinds = {
                "ABSTRACT",
                "STRUCTURAL",
                "AUXILIARY",
            }
            if oc.kind not in valid_kinds:
                valid_kinds_str = "ABSTRACT, STRUCTURAL, or AUXILIARY"
                return r.fail(
                    f"Invalid objectclass kind: {oc.kind}. Must be {valid_kinds_str}",
                )

            return r.ok(True)

        except Exception as e:
            error_msg = f"Error validating objectclass: {e}"
            self.logger.exception(
                "Failed to validate objectClass",
                error=str(e),
            )
            return r.fail(error_msg)

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA WRITING OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    def write_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> r[str]:
        """Convert attribute model to LDIF format.

        Uses u.Writer for writing operations.

        Args:
            attr: SchemaAttribute model

        Returns:
            FlextResult with LDIF string

        """
        try:
            # Validate first
            validation = self.validate_attribute(attr)
            if not validation.is_success:
                return r.fail(validation.error or "Unknown error")

            # Use utilities to write
            return FlextLdifUtilitiesWriter.write_rfc_attribute(attr)

        except Exception as e:
            error_msg = f"Error writing attribute: {e}"
            self.logger.exception(
                "Failed to write attribute",
                error=str(e),
            )
            return r.fail(error_msg)

    def write_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> r[str]:
        """Convert objectClass model to LDIF format.

        Uses u.Writer for writing operations.

        Args:
            oc: SchemaObjectClass model

        Returns:
            FlextResult with LDIF string

        """
        try:
            # Validate first
            validation = self.validate_objectclass(oc)
            if not validation.is_success:
                return r.fail(validation.error or "Unknown error")

            # Use utilities to write
            return FlextLdifUtilitiesWriter.write_rfc_objectclass(oc)

        except Exception as e:
            error_msg = f"Error writing objectClass: {e}"
            self.logger.exception(
                "Failed to write objectClass",
                error=str(e),
            )
            return r.fail(error_msg)

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA DETECTION OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def is_schema(entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema definition.

        Schema entries are detected by presence of schema-related attributes
        (attributeTypes, objectClasses, ldapSyntaxes, or matchingRules)
        using case-insensitive matching.

        Uses schema field constants for schema field names.

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema definition

        Note:
            This method is static as it doesn't require server-specific behavior.
            It uses constants from FlextLdifConstants for schema field detection.

        """
        # Use string literals for schema field names (constants prohibited in services/)
        schema_attrs = {
            "attributetypes",
            "objectclasses",
            "ldapsyntaxes",
            "matchingrules",
        }
        # Type narrowing: ensure entry.attributes is not None
        if entry.attributes is None:
            return False
        entry_attrs = {attr.lower() for attr in entry.attributes.attributes}
        return bool(schema_attrs & entry_attrs)

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if attribute definition can be handled by this service.

        An attribute definition can be handled if it's not empty and contains
        parentheses (basic structural requirement for RFC attribute definitions).

        Args:
            attr_definition: Attribute definition string to check

        Returns:
            True if definition can be handled, False otherwise

        """
        if not attr_definition or not attr_definition.strip():
            return False
        return "(" in attr_definition and ")" in attr_definition

    # ════════════════════════════════════════════════════════════════════════
    # STRING REPRESENTATION
    # ════════════════════════════════════════════════════════════════════════

    def __repr__(self) -> str:
        """String representation."""
        return f"FlextLdifSchema[{self._server_type}]"


__all__ = [
    "FlextLdifSchema",
]
