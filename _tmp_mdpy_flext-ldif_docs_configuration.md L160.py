# from flext-ldif/docs/configuration.md:160
from __future__ import annotations


def create_development_config() -> FlextLdifModels.Config:
    """Create configuration optimized for development."""
    return FlextLdifModels.Config(
        max_entries=10000,  # Limit for faster testing
        strict_validation=True,  # Catch issues early
        ignore_unknown_attributes=False,  # Strict validation
        log_level="DEBUG",  # Verbose logging
    )


# Development API instance
dev_api = ldif(settings=create_development_config())```
### Production Configuration

Optimized for production environments:

