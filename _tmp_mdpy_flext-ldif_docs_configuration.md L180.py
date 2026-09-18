# from flext-ldif/docs/configuration.md:180
from __future__ import annotations


def create_production_config() -> FlextLdifModels.Config:
    """Create configuration optimized for production."""
    return FlextLdifModels.Config(
        max_entries=None,  # No artificial limits
        strict_validation=False,  # More permissive for real-world data
        ignore_unknown_attributes=True,  # Handle varied schemas
        encoding="utf-8",
        buffer_size=16384,  # Larger buffer for performance
        log_level="INFO",  # Standard logging
    )


# Production API instance
prod_api = ldif(settings=create_production_config())```
### Migration Configuration

Optimized for large-scale LDAP migrations:

