# from flext-ldif_docs/api-reference.md:1235
from flext_ldif import ldif
from pathlib import Path

Path("directory.ldif").write_text(
    "dn: cn=John Doe,dc=example,dc=com\nobjectClass: person\ncn: John Doe\n"
)

api = ldif()

# Composable pipeline with explicit error handling
result = (
    # Parse LDIF file
    api
    .parse_file(Path("directory.ldif"))
    # Validate all entries
    .flat_map(lambda entries: api.validate_entries(entries).map(lambda _: entries))
    # Filter person entries
    .flat_map(api.filter_persons)
    # Generate statistics
    .flat_map(
        lambda persons: api.get_entry_statistics(persons).map(
            lambda stats: {"persons": persons, "stats": stats}
        )
    )
    # Write filtered entries
    .flat_map(
        lambda data: api.write_file(data["persons"], Path("persons.ldif")).map(
            lambda _: data["stats"]
        )
    )
    # Add error context
    .map_error(lambda error: f"Processing failed: {error}")
)

# Handle final result
if result.success:
    stats = result.unwrap()
    u.Cli.print(f"✅ Pipeline completed: {stats}")
else:
    u.Cli.print(f"❌ Pipeline failed: {result.error}")```
### Supported LDAP Servers

**Complete Implementations** (4 servers):

