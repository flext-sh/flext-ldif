# from flext-ldif_docs/configuration.md:389
from flext_ldif import FlextLdifSettings

# ✅ Good: Type-safe configuration
settings = FlextLdifSettings(ldif_max_entries=50000, ldif_strict_validation=True)

# ❌ Avoid: Raw dictionaries without validation
config_dict = {
    "max_entries": "50000",  # Should be int
    "strict_validation": "yes",  # Should be bool
}```
### 2. Validate Configuration Early

Validate configuration at application startup:

