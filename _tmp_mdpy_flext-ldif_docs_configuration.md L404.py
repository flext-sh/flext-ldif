# from flext-ldif/docs/configuration.md:404
from __future__ import annotations

import os
from flext_ldif import ldif, p, r, FlextLdifSettings


def initialize_application_config() -> p.Result[ldif]:
    """Initialize application with validated configuration."""
    try:
        settings = FlextLdifSettings(
            ldif_max_entries=int(os.getenv("MAX_ENTRIES", "50000")),
            ldif_strict_validation=os.getenv("STRICT_VALIDATION", "").lower() == "true",
        )
        api = ldif(settings=settings)
        return r[ldif].ok(api)
    except Exception as e:
        return r[ldif].fail(f"Configuration initialization failed: {e}")```
### 3. Use Environment-Specific Profiles

Create profiles for different deployment environments:

