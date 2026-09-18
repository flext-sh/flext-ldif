# from flext-ldif/docs/api-reference.md:666
from flext_cli import u

# Successful operation
result = api.parse_file("valid.ldif")
if result.success:
    entries = result.unwrap()
    # Process entries
else:
    error_message = result.error
    u.Cli.print(f"Parse failed: {error_message}")

# Safe value extraction with defaults
entries = result.unwrap_or([])  # Empty list if failed

# Railway-oriented composition
final_result = (
    api
    .parse_file("input.ldif")
    .flat_map(api.validate_entries)
    .flat_map(lambda entries: api.filter_persons(entries))
    .flat_map(lambda persons: api.write_file(persons, "persons.ldif"))
)```
### Exception Types

