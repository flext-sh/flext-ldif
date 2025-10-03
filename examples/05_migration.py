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

from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.migration_pipeline import LdifMigrationPipelineService
from flext_ldif.quirks.registry import QuirkRegistryService


def simple_migration_example() -> None:
    """Simple migration using API."""
    api = FlextLdif()

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

    # Write OID entry
    write_result = api.write([oid_entry])
    if write_result.is_success:
        write_result.unwrap()


def pipeline_migration_example() -> None:
    """Advanced migration using pipeline."""
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

    # Initialize migration pipeline
    migration = LdifMigrationPipelineService(
        params={
            "input_dir": str(oid_dir),
            "output_dir": str(oud_dir),
        },
        source_server_type="oid",  # Oracle Internet Directory
        target_server_type="oud",  # Oracle Unified Directory
        quirk_registry=quirk_registry,
    )

    # Execute migration: OID → RFC → OUD
    result = migration.execute()

    if result.is_success:
        data = result.unwrap()

        # Show output files
        if data.get("output_files"):
            for _output_file in data["output_files"]:
                pass


def main() -> None:
    """Run migration examples."""
    simple_migration_example()
    pipeline_migration_example()


if __name__ == "__main__":
    main()
