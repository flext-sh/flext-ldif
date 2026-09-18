# from flext-ldif_docs/configuration.md:357
from __future__ import annotations

from flext_cli import u


def log_configuration(settings: FlextLdifModels.Config) -> None:
    """Log configuration settings for debugging."""
    logger = u.fetch_logger(__name__)

    logger.info(
        "LDIF configuration initialized",
        extra={
            "max_entries": settings.max_entries,
            "strict_validation": settings.strict_validation,
            "encoding": settings.encoding,
            "buffer_size": settings.buffer_size,
            "log_level": settings.log_level,
        },
    )


# Log configuration during initialization
settings = FlextLdifModels.Config(max_entries=50000)
log_configuration(settings)
api = ldif(settings=settings)```
## Configuration Best Practices

### 1. Use Type-Safe Configuration

Always use the Pydantic-based configuration models:

