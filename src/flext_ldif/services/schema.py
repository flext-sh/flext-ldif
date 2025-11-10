"""Schema Processing Service for FlextLdif.

Centralizes all schema parsing, validation, and transformation logic in a
server-agnostic service. Replaces nested Schema classes with a unified,
reusable service that works with any server configuration.

Architecture:
    - FlextLdifSchema: Core service for schema operations
    - Accepts server_type for server-specific behavior
    - Provides FlextResult[T] for railway-oriented error handling
    - Leverages existing utilities (Parser, Writer, Schema utilities)
    - Can be used standalone or integrated into servers

Benefits:
    - Single source of truth for schema logic
    - Server-agnostic (any server can use with different config)
    - Independently testable
    - No duplication across servers
    - Clean separation of concerns

Usage:
    from flext_ldif.services.schema import FlextLdifSchema

    schema_service = FlextLdifSchema("oud")

    # Parse attribute
    result = schema_service.parse_attribute(attr_definition)
    if result.is_success:
        attr = result.unwrap()

References:
    - RFC 4512: LDAP Schema Definitions
    - PHASE_2_SERVICE_LAYER.md: Service layer design
    - FlextLdifUtilities.Schema: Schema utilities

"""

from __future__ import annotations

from typing import override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifSchema(FlextService[FlextLdifModels.SchemaServiceStatus]):
    """Unified schema validation and transformation service.

    Centralizes all schema-related operations that were previously scattered
    across server-specific nested Schema classes.

    Provides a clean, server-agnostic interface for schema parsing, validation,
    and transformation using server configuration.

    FlextService V2 Integration:
    - Pydantic fields for service configuration
    - Builder pattern for complex workflows
    - execute() method returns service status
    - Direct methods for immediate operations

    Methods:
        - parse_attribute(): Parse attribute definition
        - parse_objectclass(): Parse objectClass definition
        - validate_attribute(): Validate attribute syntax
        - validate_objectclass(): Validate objectClass syntax
        - write_attribute(): Write attribute to LDIF format
        - write_objectclass(): Write objectClass to LDIF format
        - can_handle_attribute(): Check if server handles attribute
        - can_handle_objectclass(): Check if server handles objectClass

    """

    # OID validation configuration
    MIN_OID_PARTS: int = 2  # Minimum parts in OID (e.g., "1.2")

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS (for builder pattern)
    # ════════════════════════════════════════════════════════════════════════

    server_type: str = "rfc"

    @override
    def execute(self) -> FlextResult[FlextLdifModels.SchemaServiceStatus]:
        """Execute schema service self-check.

        Returns:
            FlextResult containing service status

        """
        return FlextResult[FlextLdifModels.SchemaServiceStatus].ok(
            FlextLdifModels.SchemaServiceStatus(
                service="SchemaService",
                server_type=self.server_type,
                status="operational",
                rfc_compliance="RFC 4512",
                operations=[
                    "parse_attribute",
                    "parse_objectclass",
                    "validate_attribute",
                    "validate_objectclass",
                    "write_attribute",
                    "write_objectclass",
                ],
            )
        )

    # ════════════════════════════════════════════════════════════════════════
    # FLUENT BUILDER PATTERN
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def builder(cls) -> FlextLdifSchema:
        """Create fluent builder for schema operations.

        Returns:
            Service instance for method chaining

        Example:
            schema = (FlextLdifSchema.builder()
                .with_server_type("oud")
                .build())

        """
        return cls()

    def with_server_type(self, server_type: str) -> FlextLdifSchema:
        """Set server type (fluent builder).

        Args:
            server_type: Server type (e.g., "oud", "oid", "rfc")

        Returns:
            Self for chaining

        """
        self.server_type = server_type
        return self

    def build(self) -> FlextLdifSchema:
        """Build and return schema service instance (fluent terminal).

        Returns:
            Configured schema service instance

        """
        return self

    # ════════════════════════════════════════════════════════════════════════
    # DIRECT SCHEMA OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    def parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse attribute type definition.

        Args:
            attr_definition: Attribute definition string
                (e.g., "( 2.5.4.3 NAME 'cn' SYNTAX ... )")

        Returns:
            FlextResult with SchemaAttribute model

        """
        try:
            if not attr_definition or not attr_definition.strip():
                return FlextResult.fail("Attribute definition is empty")

            # Use utilities to parse - parse_rfc_attribute returns FlextResult[SchemaAttribute]
            return FlextLdifUtilities.Parser.parse_rfc_attribute(attr_definition)

        except Exception as e:
            error_msg = f"Error parsing attribute: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse objectClass definition.

        Args:
            oc_definition: ObjectClass definition string
                (e.g., "( 2.5.6.6 NAME 'person' ... )")

        Returns:
            FlextResult with SchemaObjectClass model

        """
        try:
            if not oc_definition or not oc_definition.strip():
                return FlextResult.fail("ObjectClass definition is empty")

            # Use utilities to parse - parse_rfc_objectclass returns FlextResult[SchemaObjectClass]
            return FlextLdifUtilities.Parser.parse_rfc_objectclass(oc_definition)

        except Exception as e:
            error_msg = f"Error parsing objectClass: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def validate_attribute(
        self,
        attr: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[bool]:
        """Validate attribute model syntax and constraints.

        Args:
            attr: SchemaAttribute model to validate

        Returns:
            FlextResult[bool]: True if valid, error otherwise

        """
        try:
            if not attr:
                return FlextResult.fail("Attribute model is None")
            # Basic validation
            if not attr.name:
                return FlextResult.fail("Attribute has no NAME")
            if not attr.oid:
                return FlextResult.fail("Attribute has no OID")
            # Check syntax if present and validate OID format
            if attr.syntax and not self._is_valid_oid(attr.syntax):
                return FlextResult.fail(f"Invalid SYNTAX OID: {attr.syntax}")
            return FlextResult.ok(True)

        except Exception as e:
            error_msg = f"Error validating attribute: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def validate_objectclass(
        self,
        oc: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[bool]:
        """Validate objectClass model syntax and constraints.

        Args:
            oc: SchemaObjectClass model to validate

        Returns:
            FlextResult[bool]: True if valid, error otherwise

        """
        try:
            if not oc:
                return FlextResult.fail("ObjectClass model is None")

            # Basic validation
            if not oc.name:
                return FlextResult.fail("ObjectClass has no NAME")

            if not oc.oid:
                return FlextResult.fail("ObjectClass has no OID")

            # Check objectclass kind
            if oc.kind not in {"ABSTRACT", "STRUCTURAL", "AUXILIARY"}:
                return FlextResult.fail(f"Invalid objectClass KIND: {oc.kind}")

            return FlextResult.ok(True)

        except Exception as e:
            error_msg = f"Error validating objectClass: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def write_attribute(
        self,
        attr: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        """Convert attribute model to LDIF format.

        Args:
            attr: SchemaAttribute model

        Returns:
            FlextResult with LDIF string

        """
        try:
            # Validate first
            validation = self.validate_attribute(attr)
            if not validation.is_success:
                return FlextResult.fail(validation.error)

            # Use utilities to write - write_rfc_attribute returns FlextResult[str]
            return FlextLdifUtilities.Writer.write_rfc_attribute(attr)

        except Exception as e:
            error_msg = f"Error writing attribute: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def write_objectclass(
        self,
        oc: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Convert objectClass model to LDIF format.

        Args:
            oc: SchemaObjectClass model

        Returns:
            FlextResult with LDIF string

        """
        try:
            # Validate first
            validation = self.validate_objectclass(oc)
            if not validation.is_success:
                return FlextResult.fail(validation.error)

            # Use utilities to write - write_rfc_objectclass returns FlextResult[str]
            return FlextLdifUtilities.Writer.write_rfc_objectclass(oc)

        except Exception as e:
            error_msg = f"Error writing objectClass: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this service can handle the attribute definition.

        For now, all servers can handle RFC-compliant attributes.
        This can be overridden in server-specific implementations.

        Args:
            attr_definition: Attribute definition string

        Returns:
            True if service can handle, False otherwise

        """
        try:
            if not attr_definition or not attr_definition.strip():
                return False

            # Basic check: looks like an attribute definition
            return "(" in attr_definition and ")" in attr_definition

        except Exception:
            logger.exception("Error checking if can handle attribute")
            return False

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this service can handle the objectClass definition.

        For now, all servers can handle RFC-compliant objectClasses.
        This can be overridden in server-specific implementations.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            True if service can handle, False otherwise

        """
        try:
            if not oc_definition or not oc_definition.strip():
                return False

            # Basic check: looks like an objectClass definition
            return "(" in oc_definition and ")" in oc_definition

        except Exception:
            logger.exception("Error checking if can handle objectClass")
            return False

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    @staticmethod
    def _is_valid_oid(oid: str) -> bool:
        """Check if string is a valid OID format.

        Args:
            oid: OID string (e.g., "1.3.6.1.4.1.9999")

        Returns:
            True if valid OID format, False otherwise

        """
        if not oid:
            return False

        # OID should be digits separated by dots (minimum parts required)
        parts = oid.split(".")
        if len(parts) < FlextLdifSchema.MIN_OID_PARTS:
            return False

        return all(part.isdigit() for part in parts)

    def __repr__(self) -> str:
        """String representation."""
        return f"FlextLdifSchema[{self.server_type}]"


__all__ = [
    "FlextLdifSchema",
]
