# FLEXT-LDIF Configuration

<!-- TOC START -->
- [Configuration Overview](#configuration-overview)
- [Configuration Models](#configuration-models)
  - [FlextLdifModels.Config](#flextldifmodelsconfig)
  - [Configuration Usage](#configuration-usage)
- [Global Configuration](#global-configuration)
  - [Initialization](#initialization)
  - [Environment Variables](#environment-variables)
  - [Environment Configuration Loading](#environment-configuration-loading)
- [Configuration Scenarios](#configuration-scenarios)
  - [Development Configuration](#development-configuration)
  - [Production Configuration](#production-configuration)
  - [Migration Configuration](#migration-configuration)
- [Advanced Configuration](#advanced-configuration)
  - [Configuration Validation](#configuration-validation)
  - [Configuration Inheritance](#configuration-inheritance)
  - [Configuration Profiles](#configuration-profiles)
- [Integration with FLEXT Configuration](#integration-with-flext-configuration)
  - [FlextContainer Integration](#flextcontainer-integration)
  - [Configuration Logging](#configuration-logging)
- [Configuration Best Practices](#configuration-best-practices)
  - [1. Use Type-Safe Configuration](#1-use-type-safe-configuration)
  - [2. Validate Configuration Early](#2-validate-configuration-early)
  - [3. Use Environment-Specific Profiles](#3-use-environment-specific-profiles)
  - [4. Document Configuration Changes](#4-document-configuration-changes)
- [Configuration Reference](#configuration-reference)
  - [Complete Configuration Options](#complete-configuration-options)
  - [Environment Variable Mapping](#environment-variable-mapping)
<!-- TOC END -->

**Version**: 0.12.0-dev | **Updated**: April 14, 2026

This document covers configuration options for FLEXT-LDIF, including settings management, environment configuration, and integration with FLEXT ecosystem configuration patterns.

## Configuration Overview

FLEXT-LDIF provides flexible configuration management through multiple layers:

1. **Default Configuration**: Built-in sensible defaults
1. **Global Configuration**: Process-wide settings
1. **Instance Configuration**: Per-API instance settings
1. **Operation Configuration**: Per-operation overrides

## Configuration Models

### FlextLdifModels.Config

Core configuration class with validation:

```python notest
from flext_ldif import FlextLdifModels


class Config(m.BaseModel):
    """LDIF processing configuration with Pydantic validation."""

    max_entries: int | None = u.Field(
        None,
        description="Maximum number of entries to process (None = unlimited)",
        ge=1,
    )

    strict_validation: bool = u.Field(
        False, description="Enable strict RFC 2849 validation"
    )

    ignore_unknown_attributes: bool = u.Field(
        True, description="Ignore attributes not in standard LDAP schema"
    )

    encoding: str = u.Field("utf-8", description="Character encoding for LDIF files")

    line_separator: str = u.Field("\\n", description="Line separator for LDIF output")

    buffer_size: int = u.Field(
        8192, description="Buffer size for file operations", ge=1024
    )

    log_level: str = u.Field("INFO", description="Logging level for LDIF operations")
```

### Configuration Usage

```python notest
# Create configuration with custom settings
settings = FlextLdifModels.Config(
    max_entries=100000, strict_validation=True, encoding="utf-8", log_level="DEBUG"
)

# Use configuration with API
from flext_ldif import ldif

api = ldif(settings=settings)

# Access configuration values
u.Cli.print(f"Max entries: {settings.max_entries}")
u.Cli.print(f"Strict validation: {settings.strict_validation}")
```

## Global Configuration

### Initialization

```python notest
from flext_ldif import FlextLdif, FlextLdifSettings

# Initialize configuration and use it with the public facade
settings = FlextLdifSettings(
    max_entries=50000, strict_validation=True, encoding="utf-8", log_level="INFO"
)
api = FlextLdif(settings=settings)

u.Cli.print(f"Global max entries: {settings.max_entries}")
```

### Environment Variables

FLEXT-LDIF supports configuration through environment variables:

```bash
# LDIF processing limits
export FLEXT_LDIF_MAX_ENTRIES=100000
export FLEXT_LDIF_STRICT_VALIDATION=true

# File handling
export FLEXT_LDIF_ENCODING=utf-8
export FLEXT_LDIF_BUFFER_SIZE=16384

# Logging
export FLEXT_LDIF_LOG_LEVEL=DEBUG
```

### Environment Configuration Loading

```python notest
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
api = ldif(settings=settings)
```

## Configuration Scenarios

### Development Configuration

Optimized for development and testing:

```python notest
def create_development_config() -> FlextLdifModels.Config:
    """Create configuration optimized for development."""
    return FlextLdifModels.Config(
        max_entries=10000,  # Limit for faster testing
        strict_validation=True,  # Catch issues early
        ignore_unknown_attributes=False,  # Strict validation
        log_level="DEBUG",  # Verbose logging
    )


# Development API instance
dev_api = ldif(settings=create_development_config())
```

### Production Configuration

Optimized for production environments:

```python notest
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
prod_api = ldif(settings=create_production_config())
```

### Migration Configuration

Optimized for large-scale LDAP migrations:

```python notest
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
migration_api = ldif(settings=create_migration_config())
```

## Advanced Configuration

### Configuration Validation

```python notest
from flext_ldif import FlextLdifModels, c


def validate_configuration(config_dict: dict) -> p.Result[FlextLdifModels.Config]:
    """Validate configuration with detailed error handling."""
    try:
        settings = FlextLdifModels.Config(**config_dict)
        return r[FlextLdifModels.Config].ok(settings)
    except c.ValidationError as e:
        error_details = "; ".join([
            f"{err['loc'][0]}: {err['msg']}" for err in e.errors()
        ])
        return r[FlextLdifModels.Config].fail(
            f"Configuration validation failed: {error_details}"
        )


# Validate configuration before use
config_data = {
    "max_entries": "invalid",  # Should be int or None
    "strict_validation": True,
    "encoding": "utf-8",
}

validation_result = validate_configuration(config_data)
if validation_result.success:
    settings = validation_result.unwrap()
    api = ldif(settings=settings)
else:
    u.Cli.print(f"Configuration error: {validation_result.error}")
```

### Configuration Inheritance

```python notest
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
)
```

### Configuration Profiles

```python notest
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
api = ldif(settings=ConfigurationProfiles.enterprise())
```

## Integration with FLEXT Configuration

### FlextContainer Integration

```python notest
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import d
from flext_core import FlextDispatcher
from flext_core import e
from flext_core import h
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r, p
from flext_core import u
from flext_core import s
from flext_core import t
from flext_core import u
from flext_ldif import FlextLdifSettings

# Register configuration in container
container = FlextContainer.get_global()
settings = FlextLdifModels.Config(max_entries=100000)

registration_result = container.bind("ldif_config", settings)
if registration_result.success:
    u.Cli.print("Configuration registered in container")

# Retrieve configuration from container
config_result = container.resolve("ldif_config")
if config_result.success:
    retrieved_config = config_result.unwrap()
    api = ldif(settings=retrieved_config)
```

### Configuration Logging

```python notest
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import d
from flext_core import FlextDispatcher
from flext_core import e
from flext_core import h
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r, p
from flext_core import u
from flext_core import s
from flext_core import t
from flext_core import u


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
api = ldif(settings=settings)
```

## Configuration Best Practices

### 1. Use Type-Safe Configuration

Always use the Pydantic-based configuration models:

```python notest
from flext_ldif import FlextLdifSettings

# ✅ Good: Type-safe configuration
settings = FlextLdifSettings(ldif_max_entries=50000, ldif_strict_validation=True)

# ❌ Avoid: Raw dictionaries without validation
config_dict = {
    "max_entries": "50000",  # Should be int
    "strict_validation": "yes",  # Should be bool
}
```

### 2. Validate Configuration Early

Validate configuration at application startup:

```python notest
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
        return r[ldif].fail(f"Configuration initialization failed: {e}")
```

### 3. Use Environment-Specific Profiles

Create profiles for different deployment environments:

```python notest
def get_environment_config(environment: str) -> FlextLdifModels.Config:
    """Get configuration based on deployment environment."""
    profiles = {
        "development": ConfigurationProfiles.testing(),
        "staging": ConfigurationProfiles.standard(),
        "production": ConfigurationProfiles.enterprise(),
    }

    return profiles.get(environment, ConfigurationProfiles.standard())


# Use environment-based configuration
env = os.getenv("ENVIRONMENT", "development")
settings = get_environment_config(env)
api = ldif(settings=settings)
```

### 4. Document Configuration Changes

Keep configuration changes documented and version controlled:

```python notest
# Configuration changelog
CONFIGURATION_CHANGELOG = {
    "0.9.9": {
        "added": ["buffer_size", "log_level"],
        "changed": ["max_entries default from 10000 to None"],
        "deprecated": [],
    }
}


def get_config_version() -> str:
    """Get current configuration version."""
    return "0.9.9"
```

## Configuration Reference

### Complete Configuration Options

| Option                      | Type   | Default   | Description                                 |                                               |
| --------------------------- | ------ | --------- | ------------------------------------------- | --------------------------------------------- |
| `max_entries`               | `int \ | None`     | `None`                                      | Maximum entries to process (None = unlimited) |
| `strict_validation`         | `bool` | `False`   | Enable strict RFC 2849 validation           |                                               |
| `ignore_unknown_attributes` | `bool` | `True`    | Ignore non-standard attributes              |                                               |
| `encoding`                  | `str`  | `"utf-8"` | Character encoding for files                |                                               |
| `line_separator`            | `str`  | `"\\n"`   | Line separator for output                   |                                               |
| `buffer_size`               | `int`  | `8192`    | File operation buffer size                  |                                               |
| `log_level`                 | `str`  | `"INFO"`  | Logging level (DEBUG, INFO, WARNING, ERROR) |                                               |

### Environment Variable Mapping

| Environment Variable              | Configuration Option        | Example  |
| --------------------------------- | --------------------------- | -------- |
| `FLEXT_LDIF_MAX_ENTRIES`          | `max_entries`               | `100000` |
| `FLEXT_LDIF_STRICT_VALIDATION`    | `strict_validation`         | `true`   |
| `FLEXT_LDIF_IGNORE_UNKNOWN_ATTRS` | `ignore_unknown_attributes` | `false`  |
| `FLEXT_LDIF_ENCODING`             | `encoding`                  | `utf-8`  |
| `FLEXT_LDIF_BUFFER_SIZE`          | `buffer_size`               | `16384`  |
| `FLEXT_LDIF_LOG_LEVEL`            | `log_level`                 | `DEBUG`  |

______________________________________________________________________

This configuration guide provides comprehensive coverage of FLEXT-LDIF configuration options while maintaining integration with FLEXT ecosystem patterns and professional configuration management practices.
