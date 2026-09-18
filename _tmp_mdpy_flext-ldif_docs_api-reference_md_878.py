# from flext-ldif_docs/api-reference.md:878
# ✅ CORRECT: v1.0+ flat imports with MANDATORY server_registry
from flext_ldif import ServerRegistryService

# Initialize registry FIRST (auto-discovers all standard servers)
server_registry = ServerRegistryService()

# Parse with OID servers
oid_parser = RfcSchemaParserService(
    params={
        "file_path": "oid_schema.ldif",
        "parse_attributes": True,
        "parse_objectclasses": True,
    },
    server_registry=server_registry,  # ⚠️ MANDATORY parameter
    server_type="oid",  # Selects OID-specific servers
)

result = oid_parser.execute()
if result.success:
    schema_data = result.unwrap()
    u.Cli.print(f"Attributes: {len(schema_data['attributes'])}")
    u.Cli.print(f"ObjectClasses: {len(schema_data['objectclasses'])}")

# ✅ CORRECT: Parse pure RFC 4512 (still requires server_registry)
rfc_parser = RfcSchemaParserService(
    params={"file_path": "standard_schema.ldif"},
    server_registry=server_registry,  # ⚠️ MANDATORY even for pure RFC
    server_type=None,  # None = no server-specific servers, pure RFC baseline
)

# ❌ INCORRECT: Omitting server_registry (will cause errors)
# parser = RfcSchemaParserService(params={"file_path": "schema.ldif"})```
**Why server_registry is MANDATORY**:

1. **Enforces RFC-first architecture** - Zero bypass paths guarantee
1. **Enables generic transformation** - Source → RFC → Target pipeline requires registry
1. **Auto-discovery** - ServerRegistryService automatically discovers all standard servers
1. **Future-proof** - New servers can be added without API changes

## Migration Pipeline API

### FlextLdifMigration

Generic LDIF migration between different LDAP servers.

