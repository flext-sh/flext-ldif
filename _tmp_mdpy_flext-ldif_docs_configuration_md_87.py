# from flext-ldif_docs/configuration.md:87
# Create configuration with custom settings
settings = FlextLdifModels.Config(
    max_entries=100000, strict_validation=True, encoding="utf-8", log_level="DEBUG"
)

# Use configuration with API
from flext_ldif import ldif

api = ldif(settings=settings)

# Access configuration values
u.Cli.print(f"Max entries: {settings.max_entries}")
u.Cli.print(f"Strict validation: {settings.strict_validation}")```
## Global Configuration

### Initialization

