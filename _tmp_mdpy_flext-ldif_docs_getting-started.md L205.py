# from flext-ldif/docs/getting-started.md:205
from flext_ldif import FlextLdifSettings

# Get global configuration
settings = FlextLdifSettings()

# Access configuration settings
u.Cli.print(f"Max entries: {settings.max_entries}")
u.Cli.print(f"Strict validation: {settings.strict_validation}")```
## Command Line Interface

### CLI Installation and Usage

FLEXT-LDIF provides a command-line interface for common operations:

