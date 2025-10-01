#!/usr/bin/env python3
"""Example 5: Server Migration.

Demonstrates:
- Generic transformation pipeline (Source → RFC → Target)
- OID to OUD migration
- MANDATORY quirk_registry usage
- Works with ANY LDAP server combination
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdifAPI, FlextLdifModels
from flext_ldif.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.quirks.registry import QuirkRegistryService


def simple_migration_example() -> None:
    """Simple migration using API."""
    print("=== Simple Migration Example ===\n")

    api = FlextLdifAPI()

    # Create OID-specific entry
    oid_entry = FlextLdifModels.Entry(
        dn="cn=OID User,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person", "inetOrgPerson"],
            "cn": ["OID User"],
            "sn": ["User"],
            "mail": ["oid@example.com"],
            # OID-specific attributes could be here
        },
    )

    print("1. Source entry (OID format):")
    print(f"   DN: {oid_entry.dn}")
    print(f"   Attributes: {len(oid_entry.attributes)}")

    # Write OID entry
    write_result = api.write([oid_entry])
    if write_result.is_success:
        ldif_content = write_result.unwrap()
        print(f"\n2. OID LDIF output ({len(ldif_content)} bytes):")
        print(ldif_content[:200] + "...")


def pipeline_migration_example() -> None:
    """Advanced migration using pipeline."""
    print("\n=== Pipeline Migration Example ===\n")

    # ⚠️ MANDATORY: Initialize quirk registry
    quirk_registry = QuirkRegistryService()

    # Create sample OID LDIF files
    oid_dir = Path("examples/oid_source")
    oud_dir = Path("examples/oud_target")

    oid_dir.mkdir(exist_ok=True)
    oud_dir.mkdir(exist_ok=True)

    # Sample OID LDIF content
    oid_ldif = """dn: cn=OID Test User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: OID Test User
sn: User
mail: oid.test@example.com

dn: cn=schema
objectClass: top
objectClass: ldapSubentry
objectClass: subschema
cn: schema
"""

    # Write sample OID file
    (oid_dir / "sample_oid.ldif").write_text(oid_ldif)

    print("1. Generic Transformation Pipeline: OID → RFC → OUD")
    print(f"   Source: {oid_dir}")
    print(f"   Target: {oud_dir}")

    # Initialize migration pipeline
    migration = FlextLdifMigrationPipeline(
        input_dir=oid_dir,
        output_dir=oud_dir,
        source_server_type="oid",  # Oracle Internet Directory
        target_server_type="oud",  # Oracle Unified Directory
        quirk_registry=quirk_registry,
    )

    print("\n2. Executing migration...")

    # Execute migration: OID → RFC → OUD
    result = migration.execute()

    if result.is_success:
        data = result.unwrap()
        print("\n✅ Migration completed:")
        print(f"   Entries migrated: {data.get('entries_migrated', 0)}")
        print(f"   Schema files: {len(data.get('schema_files', []))}")
        print(f"   Output files: {len(data.get('output_files', []))}")

        # Show output files
        if data.get("output_files"):
            print("\n   Generated files:")
            for output_file in data["output_files"]:
                print(f"      - {output_file}")
    else:
        print(f"\n❌ Migration failed: {result.error}")


def main() -> None:
    """Run migration examples."""
    simple_migration_example()
    pipeline_migration_example()

    print("\n=== Supported Migration Paths ===")
    print("Complete implementations:")
    print("  • OID ↔ OUD")
    print("  • OID ↔ OpenLDAP 1.x/2.x")
    print("  • OUD ↔ OpenLDAP 1.x/2.x")
    print("  • Any combination of 4 complete servers")
    print(
        "\nGeneric transformation works with ANY LDAP server (N implementations, not N²)"
    )


if __name__ == "__main__":
    main()
