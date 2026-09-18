# from flext-ldif/docs/configuration.md:105
from flext_ldif import FlextLdif, FlextLdifSettings

# Initialize configuration and use it with the public facade
settings = FlextLdifSettings(
    max_entries=50000, strict_validation=True, encoding="utf-8", log_level="INFO"
)
api = FlextLdif(settings=settings)

u.Cli.print(f"Global max entries: {settings.max_entries}")```
### Environment Variables

FLEXT-LDIF supports configuration through environment variables:

