# from flext-ldif_docs/configuration.md:132
from __future__ import annotations

import os
from flext_ldif import FlextLdifSettings, ldif


def load_config_from_environment() -> FlextLdifSettings:
    """Load configuration from environment variables."""
    return FlextLdifSettings(
        max_entries=int(os.getenv("FLEXT_LDIF_MAX_ENTRIES", "0")) or None,
        strict_validation=os.getenv("FLEXT_LDIF_STRICT_VALIDATION", "").lower()
        == "true",
        encoding=os.getenv("FLEXT_LDIF_ENCODING", "utf-8"),
        buffer_size=int(os.getenv("FLEXT_LDIF_BUFFER_SIZE", "8192")),
        log_level=os.getenv("FLEXT_LDIF_LOG_LEVEL", "INFO"),
    )


# Use environment-based configuration
settings = load_config_from_environment()
api = ldif(settings=settings)```
## Configuration Scenarios

### Development Configuration

Optimized for development and testing:

