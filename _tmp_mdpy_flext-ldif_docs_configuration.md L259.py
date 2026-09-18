# from flext-ldif/docs/configuration.md:259
from __future__ import annotations


def create_inherited_config(
    base_config: FlextLdifModels.Config, overrides: dict
) -> FlextLdifModels.Config:
    """Create new configuration inheriting from base with overrides."""
    base_dict = base_config.model_dump()
    base_dict.update(overrides)
    return FlextLdifModels.Config(**base_dict)


# Base configuration
base_config = FlextLdifModels.Config(
    max_entries=50000, strict_validation=True, encoding="utf-8"
)

# Specialized configuration for specific use case
specialized_config = create_inherited_config(
    base_config,
    {
        "max_entries": 100000,  # Override for larger files
        "log_level": "DEBUG",  # Add debugging
    },
)```
### Configuration Profiles

