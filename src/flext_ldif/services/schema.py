"""Schema Processing Service for FlextLdif."""

from __future__ import annotations

from typing import Self, override

from flext_core import r
from pydantic import PrivateAttr

from flext_ldif.base import s
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import u


class FlextLdifSchema(s[m.Ldif.LdifResults.SchemaServiceStatus]):
    """Unified schema validation, transformation, and detection service."""

    _registry: FlextLdifServer = PrivateAttr(default_factory=FlextLdifServer)
    _server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = PrivateAttr(
        default="rfc",
    )

    def __init__(
        self,
        *,
        registry: FlextLdifServer | None = None,
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = "rfc",
    ) -> None:
        """Initialize schema service with dependency injection."""
        super().__init__()

        object.__setattr__(
            self,
            "_registry",
            registry if registry is not None else FlextLdifServer(),
        )
        object.__setattr__(self, "_server_type", server_type)

    @property
    def server_type(self) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
        """Get configured server type."""
        return self._server_type

    @classmethod
    def builder(cls) -> Self:
        """Create fluent builder instance for method chaining."""
        return cls()

    def with_server_type(
        self,
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
    ) -> Self:
        """Set server type for schema operations (fluent builder)."""
        object.__setattr__(self, "_server_type", server_type)
        return self

    def build(self) -> Self:
        """Build configured schema service instance."""
        return self

    @override
    def execute(
        self,
    ) -> r[m.Ldif.LdifResults.SchemaServiceStatus]:
        """Execute schema service self-check."""
        return r[m.Ldif.LdifResults.SchemaServiceStatus].ok(
            m.Ldif.LdifResults.SchemaServiceStatus(
                service="SchemaService",
                server_type=self._server_type,
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

    def parse_attribute(
        self,
        attr_definition: str,
        *,
        _server_type: str | None = None,
    ) -> r[m.Ldif.SchemaAttribute]:
        """Parse attribute type definition."""
        try:
            if not attr_definition or not attr_definition.strip():
                return r[m.Ldif.SchemaAttribute].fail("Attribute definition is empty")

            parse_result = u.Ldif.Schema.parse_attribute(attr_definition)
            if parse_result.is_failure:
                return r[m.Ldif.SchemaAttribute].fail(
                    f"Parse failed: {parse_result.error}",
                )

            parsed_dict = dict(parse_result.value)

            metadata_extensions = parsed_dict.pop("metadata_extensions", {})
            parsed_dict.pop("syntax_validation", None)

            attr_domain = m.Ldif.SchemaAttribute.model_validate(parsed_dict)

            if metadata_extensions and isinstance(metadata_extensions, dict):
                attr_domain.metadata = m.Ldif.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=m.Ldif.DynamicMetadata.from_dict({}),
                )

            attr: m.Ldif.SchemaAttribute = attr_domain

            return r[m.Ldif.SchemaAttribute].ok(attr)

        except Exception as e:
            error_msg = f"Error parsing attribute: {e}"
            self.logger.exception(
                "Failed to parse attribute definition",
                error=str(e),
            )
            return r[m.Ldif.SchemaAttribute].fail(error_msg)

    def parse_objectclass(
        self,
        oc_definition: str,
        *,
        _server_type: str | None = None,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse objectClass definition."""
        try:
            if not oc_definition or not oc_definition.strip():
                return r[m.Ldif.SchemaObjectClass].fail(
                    "ObjectClass definition is empty",
                )

            parsed_dict = u.Ldif.Schema.parse_objectclass(oc_definition)

            metadata_extensions = parsed_dict.pop("metadata_extensions", {})

            oc_dict = {
                "oid": str(parsed_dict["oid"]) if parsed_dict["oid"] else "",
                "name": str(parsed_dict.get("name") or parsed_dict["oid"]),
                "desc": str(parsed_dict.get("desc"))
                if parsed_dict.get("desc")
                else None,
                "sup": parsed_dict.get("sup"),
                "kind": str(parsed_dict.get("kind", "STRUCTURAL")),
                "must": parsed_dict.get("must"),
                "may": parsed_dict.get("may"),
            }

            oc_domain = m.Ldif.SchemaObjectClass.model_validate(oc_dict)

            if metadata_extensions and isinstance(metadata_extensions, dict):
                oc_domain.metadata = m.Ldif.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=m.Ldif.DynamicMetadata.from_dict({}),
                )

            oc: m.Ldif.SchemaObjectClass = oc_domain

            return r[m.Ldif.SchemaObjectClass].ok(oc)

        except Exception as e:
            error_msg = f"Error parsing objectClass: {e}"
            self.logger.exception(
                "Failed to parse objectClass definition",
                error=str(e),
            )
            return r[m.Ldif.SchemaObjectClass].fail(error_msg)

    def validate_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> r[bool]:
        """Validate attribute model syntax and constraints."""
        try:
            if not attr.oid or not attr.oid.strip():
                return r[bool].fail("Attribute OID is required and cannot be empty")
            if not attr.name or not attr.name.strip():
                return r[bool].fail(
                    "Attribute NAME is required and cannot be empty",
                )

            if attr.syntax:
                validation_result = u.Ldif.OID.validate_format(attr.syntax)
                if validation_result.is_failure or not validation_result.value:
                    return r[bool].fail(f"Invalid SYNTAX OID: {attr.syntax}")

            return r[bool].ok(value=True)

        except Exception as e:
            error_msg = f"Error validating attribute: {e}"
            self.logger.exception(
                "Failed to validate attribute",
                error=str(e),
            )
            return r[bool].fail(error_msg)

    def validate_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> r[bool]:
        """Validate objectClass model syntax and constraints."""
        try:
            if not oc.oid or not oc.oid.strip():
                return r[bool].fail(
                    "ObjectClass OID is required and cannot be empty",
                )
            if not oc.name or not oc.name.strip():
                return r[bool].fail(
                    "ObjectClass NAME is required and cannot be empty",
                )

            valid_kinds = {
                "ABSTRACT",
                "STRUCTURAL",
                "AUXILIARY",
            }
            if oc.kind not in valid_kinds:
                valid_kinds_str = "ABSTRACT, STRUCTURAL, or AUXILIARY"
                return r[bool].fail(
                    f"Invalid objectclass kind: {oc.kind}. Must be {valid_kinds_str}",
                )

            return r[bool].ok(value=True)

        except Exception as e:
            error_msg = f"Error validating objectclass: {e}"
            self.logger.exception(
                "Failed to validate objectClass",
                error=str(e),
            )
            return r[bool].fail(error_msg)

    def write_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> r[str]:
        """Convert attribute model to LDIF format."""
        try:
            validation = self.validate_attribute(attr)
            if not validation.is_success:
                return r[str].fail(validation.error or "Unknown error")

            return u.Ldif.Writer.write_rfc_attribute(attr)

        except Exception as e:
            error_msg = f"Error writing attribute: {e}"
            self.logger.exception(
                "Failed to write attribute",
                error=str(e),
            )
            return r[str].fail(error_msg)

    def write_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> r[str]:
        """Convert objectClass model to LDIF format."""
        try:
            validation = self.validate_objectclass(oc)
            if not validation.is_success:
                return r[str].fail(validation.error or "Unknown error")

            return u.Ldif.Writer.write_rfc_objectclass(oc)

        except Exception as e:
            error_msg = f"Error writing objectClass: {e}"
            self.logger.exception(
                "Failed to write objectClass",
                error=str(e),
            )
            return r[str].fail(error_msg)

    @staticmethod
    def is_schema(entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema definition."""
        schema_attrs = {
            "attributetypes",
            "objectclasses",
            "ldapsyntaxes",
            "matchingrules",
        }

        if entry.attributes is None:
            return False
        entry_attrs = {attr.lower() for attr in entry.attributes.attributes}
        return bool(schema_attrs & entry_attrs)

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if attribute definition can be handled by this service."""
        if not attr_definition or not attr_definition.strip():
            return False
        return "(" in attr_definition and ")" in attr_definition

    def __repr__(self) -> str:
        """String representation."""
        return f"FlextLdifSchema[{self._server_type}]"


__all__ = [
    "FlextLdifSchema",
]
