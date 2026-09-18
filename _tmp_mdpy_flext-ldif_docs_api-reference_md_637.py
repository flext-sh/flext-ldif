# from flext-ldif_docs/api-reference.md:637
from flext_ldif import FlextLdifSettings

# Initialize configuration
settings = FlextLdifSettings(
    max_entries=100000, strict_validation=True, encoding="utf-8"
)

# Access global configuration
u.Cli.print(f"Max entries: {settings.max_entries}")```
### Instance Configuration

