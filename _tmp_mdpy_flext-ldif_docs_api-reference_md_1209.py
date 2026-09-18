# from flext-ldif_docs/api-reference.md:1209
from flext_ldif import FlextLdifMigration
from pathlib import Path

# Migrate OID → OUD using generic transformation pipeline
migration = FlextLdifMigration(
    input_dir=Path("source_oid_ldif"),
    output_dir=Path("target_oud_ldif"),
    source_server_type="oid",  # Oracle Internet Directory
    target_server_type="oud",  # Oracle Unified Directory
)

# Execute migration: OID → RFC → OUD
result = migration.execute()
if result.success:
    data = result.unwrap()
    u.Cli.print(f"✅ Migrated {data['entries_migrated']} entries")
    u.Cli.print(f"✅ Processed {len(data['schema_files'])} schema files")
    u.Cli.print(f"✅ Generated {len(data['output_files'])} output files")
else:
    u.Cli.print(f"❌ Migration failed: {result.error}")

# Works with ANY server combination (N implementations, not N²)
# Examples: OID→OUD, OpenLDAP→389DS, AD→OUD, OUD→OpenLDAP, etc.```
### Railway-Oriented Pipeline

