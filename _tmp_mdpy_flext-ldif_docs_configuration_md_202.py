# from flext-ldif_docs/configuration.md:202
from __future__ import annotations


def create_migration_config() -> FlextLdifModels.Config:
    """Create configuration optimized for enterprise migrations."""
    return FlextLdifModels.Config(
        max_entries=None,  # Handle large exports
        strict_validation=False,  # Accommodate legacy data
        ignore_unknown_attributes=True,  # Handle custom schemas
        encoding="utf-8",
        buffer_size=32768,  # Maximum performance
        log_level="INFO",
    )


# Migration API instance
migration_api = ldif(settings=create_migration_config())```
## Advanced Configuration

### Configuration Validation

