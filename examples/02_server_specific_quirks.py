#!/usr/bin/env python3
"""Example 2: Server-Specific Quirks.

Demonstrates:
- RFC-first architecture with quirks
- MANDATORY quirk_registry parameter
- Server-specific parsing (OID, OUD, OpenLDAP)
- Generic transformation pipeline
"""

from __future__ import annotations

from flext_ldif.quirks.registry import QuirkRegistryService
from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService


def main() -> None:
    """Server-specific quirks example."""
    # ⚠️ MANDATORY: Initialize quirk registry first
    # Auto-discovers all standard quirks (OID, OUD, OpenLDAP, etc.)
    quirk_registry = QuirkRegistryService()

    print("=== RFC-First Architecture with Quirks ===\n")

    # Example 1: Parse OID schema with OID-specific quirks
    print("1. Oracle Internet Directory (OID) Quirks:")
    oid_schema_content = """
dn: cn=schema
objectClass: top
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( 1.2.3.4.5 NAME 'customAttr' DESC 'OID custom attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""

    oid_parser = RfcSchemaParserService(
        params={"content": oid_schema_content},
        quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
        server_type="oid",  # Selects OID-specific quirks
    )

    oid_result = oid_parser.execute()
    if oid_result.is_success:
        schema = oid_result.unwrap()
        print(
            f"  ✅ Parsed {len(schema.get('attributes', {}))} attributes with OID quirks"
        )
    else:
        print(f"  ⚠️ OID parsing: {oid_result.error}")

    # Example 2: Parse OpenLDAP schema with OpenLDAP quirks
    print("\n2. OpenLDAP 2.x Quirks:")
    openldap_parser = RfcSchemaParserService(
        params={"content": oid_schema_content},
        quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
        server_type="openldap",  # Selects OpenLDAP 2.x quirks
    )

    openldap_result = openldap_parser.execute()
    if openldap_result.is_success:
        schema = openldap_result.unwrap()
        print(
            f"  ✅ Parsed {len(schema.get('attributes', {}))} attributes with OpenLDAP quirks"
        )
    else:
        print(f"  ⚠️ OpenLDAP parsing: {openldap_result.error}")

    # Example 3: Parse pure RFC 4512 (no server-specific quirks)
    print("\n3. Pure RFC 4512 (Generic):")
    rfc_parser = RfcSchemaParserService(
        params={"content": oid_schema_content},
        quirk_registry=quirk_registry,  # ⚠️ MANDATORY even for pure RFC
        server_type=None,  # None = no server-specific quirks, pure RFC baseline
    )

    rfc_result = rfc_parser.execute()
    if rfc_result.is_success:
        schema = rfc_result.unwrap()
        print(
            f"  ✅ Parsed {len(schema.get('attributes', {}))} attributes with pure RFC"
        )
    else:
        print(f"  ⚠️ RFC parsing: {rfc_result.error}")

    # Example 4: Unknown server type (falls back to RFC baseline)
    print("\n4. Unknown Server Type (Generic Fallback):")
    unknown_parser = RfcSchemaParserService(
        params={"content": oid_schema_content},
        quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
        server_type="my_custom_ldap_v5",  # Unknown server = RFC baseline
    )

    unknown_result = unknown_parser.execute()
    if unknown_result.is_success:
        schema = unknown_result.unwrap()
        print(
            f"  ✅ Parsed {len(schema.get('attributes', {}))} attributes (RFC fallback)"
        )
    else:
        print(f"  ⚠️ Unknown server parsing: {unknown_result.error}")

    print("\n=== Supported Servers ===")
    print("Complete Implementations (4): OID, OUD, OpenLDAP 1.x/2.x")
    print("Stub Implementations (5): AD, Apache DS, 389DS, Novell, Tivoli")
    print("Generic: ANY unknown server uses pure RFC baseline")


if __name__ == "__main__":
    main()
