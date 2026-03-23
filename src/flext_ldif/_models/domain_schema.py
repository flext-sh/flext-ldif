from __future__ import annotations

from typing import Annotated

from pydantic import Field

from flext_ldif import FlextLdifModelsBase, c


class SchemaDiscovery(FlextLdifModelsBase):
    """Schema discovery operation configuration and state.

    Used to configure and track schema discovery operations across
    LDAP directories and servers.
    """

    server_type: Annotated[
        c.Ldif.LiteralTypes.ServerTypeLiteral,
        Field(default="rfc", description="LDAP server type for discovery"),
    ]
    naming_contexts: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="Naming contexts to discover schema from",
        ),
    ]
    include_operational: Annotated[
        bool,
        Field(default=False, description="Include operational attributes in discovery"),
    ]
    max_entries: Annotated[
        int | None,
        Field(
            default=None,
            description="Maximum entries to sample for schema discovery",
        ),
    ]


class SchemaLookup(FlextLdifModelsBase):
    """Schema element lookup configuration and results.

    Used for looking up specific schema elements by OID, name,
    or other criteria across different LDAP servers.
    """

    search_term: Annotated[
        str,
        Field(description="Term to search for (OID, name, description)"),
    ]
    search_type: Annotated[
        c.Ldif.LiteralTypes.ServerTypeLiteral,
        Field(default="rfc", description="Server type context for lookup"),
    ]
    element_type: Annotated[
        str | None,
        Field(
            default=None,
            description="Type of element to lookup (attribute, objectclass, syntax)",
        ),
    ]


__all__ = ["SchemaDiscovery", "SchemaLookup"]
