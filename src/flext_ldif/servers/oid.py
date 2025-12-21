"""Oracle Internet Directory (OID) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements Oracle OID-specific extensions as quirks on top of RFC-compliant
base parsers. This wraps existing OID parser logic as composable quirks.

OID-specific features:
- Oracle OID attribute types (2.16.840.1.113894.* namespace)
- Oracle orclaci and orclentrylevelaci ACLs
- Oracle-specific schema attributes
- Oracle operational attributes
"""

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
    """Oracle OID server quirks - implements object.

    Extends RFC 4512 schema parsing with Oracle OID-specific features:
    - Oracle OID namespace (2.16.840.1.113894.*)
    - Oracle-specific syntaxes
    - Oracle attribute extensions
    - RFC compliance normalizations (OID proprietary → RFC standard)

    **Protocol Compliance**: Fully implements
    object
    All methods match protocol signatures exactly for type safety.

    **Validation**: Verify protocol compliance with:
        # Removed: from flext_ldif.protocols import FlextLdifProtocols, p (use structural typing)
        quirk = FlextLdifServersOid()
        # Protocol compliance verified via structural typing
        if not isinstance(quirk, object
            raise TypeError("Quirk does not satisfy SchemaProtocol")

    Example:
        quirk = FlextLdifServersOid()
        if quirk.schema_quirk.can_handle_attribute(attr_def):
            result = quirk.schema_quirk._parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.value

    """

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    # === PUBLIC INTERFACE FOR SCHEMA CONFIGURATION ===

    @classmethod
    def get_schema_filterable_fields(cls) -> frozenset[str]:
        """Get schema fields that support OID filtering.

        Returns:
            frozenset of schema field names (attributetypes, objectclasses, etc.)

        """
        return cls.Constants.SCHEMA_FILTERABLE_FIELDS

    @classmethod
    def get_schema_dn(cls) -> str:
        """Get the RFC-normalized schema DN (RFC 4512 standard).

        Returns:
            Schema DN in RFC format (cn=schema)
            OID's quirk DN (cn=subschemasubentry) is normalized during parsing

        """
        # Return RFC standard DN (inherited from parent)
        return FlextLdifServersRfc.Constants.SCHEMA_DN

    # REMOVED: get_categorization_rules (25 lines dead code - never called)
    # Categorization rules are passed via FlextLdif.migrate() directly

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
    ) -> FlextResult[
        dict[
            str,
            list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass] | int,
        ]
    ]:
        """Extract and parse all schema definitions from LDIF content.

        Delegates to the Schema nested class implementation.

        Returns:
            FlextResult containing extracted attributes and objectclasses

        """
        # Instantiate Schema nested class
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
        # Type narrowing: convert Union[dict[str, list[str], str]] to specific types
        if result.is_success:
            data = result.value
            # Return schema extraction result with metadata
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
