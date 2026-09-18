# from flext-ldif/docs/configuration.md:287
from __future__ import annotations


class ConfigurationProfiles:
    """Predefined configuration profiles for common use cases."""

    @staticmethod
    def minimal() -> FlextLdifModels.Config:
        """Minimal configuration for basic LDIF processing."""
        return FlextLdifModels.Config(
            max_entries=1000, strict_validation=False, ignore_unknown_attributes=True
        )

    @staticmethod
    def standard() -> FlextLdifModels.Config:
        """Standard configuration for general use."""
        return FlextLdifModels.Config(
            max_entries=50000,
            strict_validation=True,
            ignore_unknown_attributes=True,
            buffer_size=8192,
        )

    @staticmethod
    def enterprise() -> FlextLdifModels.Config:
        """Enterprise configuration for large-scale processing."""
        return FlextLdifModels.Config(
            max_entries=None,
            strict_validation=False,
            ignore_unknown_attributes=True,
            buffer_size=32768,
            log_level="INFO",
        )

    @staticmethod
    def testing() -> FlextLdifModels.Config:
        """Testing configuration with strict validation."""
        return FlextLdifModels.Config(
            max_entries=100,
            strict_validation=True,
            ignore_unknown_attributes=False,
            log_level="DEBUG",
        )


# Use predefined profiles
api = ldif(settings=ConfigurationProfiles.enterprise())```
## Integration with FLEXT Configuration

### FlextContainer Integration

