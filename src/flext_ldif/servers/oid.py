"""Oracle Internet Directory (OID) Quirks."""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import m
from flext_ldif.servers._oid import (
    FlextLdifServersOidAcl,
    FlextLdifServersOidConstants,
    FlextLdifServersOidEntry,
    FlextLdifServersOidSchema,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOid(FlextLdifServersRfc):
    """Oracle OID server quirks - implements object."""

    @classmethod
    def get_schema_filterable_fields(cls) -> frozenset[str]:
        """Get schema fields that support OID filtering."""
        return cls.Constants.SCHEMA_FILTERABLE_FIELDS

    @classmethod
    def get_schema_dn(cls) -> str:
        """Get the RFC-normalized schema DN (RFC 4512 standard)."""
        return FlextLdifServersRfc.Constants.SCHEMA_DN

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
    ) -> FlextResult[
        dict[
            str,
            list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass] | int,
        ]
    ]:
        """Extract and parse all schema definitions from LDIF content."""
        schema_class = getattr(type(self), "Schema", None)
        if not schema_class:
            return FlextResult[
                dict[
                    str,
                    list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass] | int,
                ]
            ].fail(
                "Schema nested class not available",
            )

        schema_quirk = schema_class()
        result = schema_quirk.extract_schemas_from_ldif(ldif_content)

        if result.is_success:
            data = result.value

            converted_data: dict[
                str,
                list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass] | int,
            ] = {
                "attributes": data.get("attributes", []),
                "objectclasses": data.get("objectclasses", []),
                "total_attributes": len(data.get("attributes", [])),
                "total_objectclasses": len(data.get("objectclasses", [])),
            }
            return FlextResult[
                dict[
                    str,
                    list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass] | int,
                ]
            ].ok(converted_data)
        return FlextResult[
            dict[
                str,
                list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass] | int,
            ]
        ].fail(
            result.error or "Failed to extract schemas",
        )

    class Constants(FlextLdifServersOidConstants):
        """OID server constants."""

    class Acl(FlextLdifServersOidAcl):
        """OID ACL quirk."""

    class Schema(FlextLdifServersOidSchema):
        """OID Schema quirk."""

    class Entry(FlextLdifServersOidEntry):
        """OID Entry quirk."""
