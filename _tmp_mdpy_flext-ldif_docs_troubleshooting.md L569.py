# from flext-ldif/docs/troubleshooting.md:569
from __future__ import annotations

from flext_ldif import FlextLdif, FlextLdifModels, ldif, u


def enable_debug_mode() -> FlextLdif:
    """Enable comprehensive debug mode."""
    # Configure debug logging
    logger = u.fetch_logger(__name__)
    logger.set_level("DEBUG")

    # Create debug configuration
    debug_config = FlextLdifModels.Config(
        strict_validation=True, ignore_unknown_attributes=False, log_level="DEBUG"
    )

    api = ldif(settings=debug_config)

    u.Cli.print("🐛 Debug mode enabled:")
    u.Cli.print("  - Strict validation active")
    u.Cli.print("  - All attributes processed")
    u.Cli.print("  - Verbose logging enabled")

    return api```
## Getting Help

### Support Resources

- **Documentation**: Complete documentation
- **API Reference**: API documentation
- **Examples**: Usage examples
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext-ldif/issues)

### Creating Support Requests

When creating support requests, include:

