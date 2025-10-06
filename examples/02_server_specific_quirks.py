#!/usr/bin/env python3
"""Example 2: Server-Specific Quirks.

Demonstrates:
- RFC-first architecture with quirks
- MANDATORY quirk_registry parameter
- Server-specific parsing (OID, OUD, OpenLDAP)
- Generic transformation pipeline
"""

from __future__ import annotations

from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc.rfc_schema_parser import FlextLdifRfcSchemaParser


def main() -> None:
    """Server-specific quirks example."""
    # ⚠️ MANDATORY: Initialize quirk registry first
    # Auto-discovers all standard quirks (OID, OUD, OpenLDAP, etc.)
    quirk_registry = FlextLdifQuirksRegistry()

    # Example 1: Parse OID schema with OID-specific quirks
    oid_schema_content = """
dn: cn=schema
objectClass: top
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( 1.2.3.4.5 NAME 'customAttr' DESC 'OID custom attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""

    oid_parser = FlextLdifRfcSchemaParser(
        params={"content": oid_schema_content},
        quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
        server_type="oid",  # Selects OID-specific quirks
    )

    oid_result = oid_parser.execute()
    if oid_result.is_success:
        oid_result.unwrap()

    # Example 2: Parse OpenLDAP schema with OpenLDAP quirks
    openldap_parser = FlextLdifRfcSchemaParser(
        params={"content": oid_schema_content},
        quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
        server_type="openldap",  # Selects OpenLDAP 2.x quirks
    )

    openldap_result = openldap_parser.execute()
    if openldap_result.is_success:
        openldap_result.unwrap()

    # Example 3: Parse pure RFC 4512 (no server-specific quirks)
    rfc_parser = FlextLdifRfcSchemaParser(
        params={"content": oid_schema_content},
        quirk_registry=quirk_registry,  # ⚠️ MANDATORY even for pure RFC
        server_type=None,  # None = no server-specific quirks, pure RFC baseline
    )

    rfc_result = rfc_parser.execute()
    if rfc_result.is_success:
        rfc_result.unwrap()

    # Example 4: Unknown server type (falls back to RFC baseline)
    unknown_parser = FlextLdifRfcSchemaParser(
        params={"content": oid_schema_content},
        quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
        server_type="my_custom_ldap_v5",  # Unknown server = RFC baseline
    )

    unknown_result = unknown_parser.execute()
    if unknown_result.is_success:
        unknown_result.unwrap()


if __name__ == "__main__":
    main()
