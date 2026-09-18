# from flext-ldif/docs/api-reference.md:711
# ❌ OLD (CLI - no longer available):
# python -m flext_ldif parse directory.ldif

# ✅ NEW (Library API):
from flext_ldif import ldif
from pathlib import Path

api = ldif()
result = api.parse_file(Path("directory.ldif"))
if result.success:
    entries = result.unwrap()
    u.Cli.print(f"Parsed {len(entries)} entries")

# ❌ OLD (CLI - no longer available):
# python -m flext_ldif analyze directory.ldif

# ✅ NEW (Library API):
result = api.parse_file(Path("directory.ldif"))
if result.success:
    entries = result.unwrap()
    stats_result = api.get_entry_statistics(entries)
    if stats_result.success:
        stats = stats_result.unwrap()
        u.Cli.print(f"Statistics: {stats}")

# ❌ OLD (CLI - no longer available):
# python -m flext_ldif filter --type person directory.ldif

# ✅ NEW (Library API):
result = api.parse_file(Path("directory.ldif"))
if result.success:
    entries = result.unwrap()
    persons_result = api.filter_persons(entries)
    if persons_result.success:
        persons = persons_result.unwrap()
        u.Cli.print(f"Found {len(persons)} person entries")```
## Advanced Usage Patterns

### Pipeline Processing

