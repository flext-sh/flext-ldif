# from flext-ldif/docs/getting-started.md:188
from flext_ldif import ldif, FlextLdifSettings

# Create configuration
settings = FlextLdifSettings(
    ldif_max_entries=10000,  # Limit number of entries processed
    ldif_strict_validation=True,  # Enable strict RFC 2849 validation
    ldif_ignore_unknown_attributes=False,  # Process all attributes
    ldif_encoding="utf-8",  # Character encoding
)

# Initialize API with configuration
api = ldif(settings=settings)```
### Advanced Configuration

Access additional configuration options:

