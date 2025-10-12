# FLEXT-LDIF Configuration

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

This document covers configuration options for FLEXT-LDIF, including settings management, environment configuration, and integration with FLEXT ecosystem configuration patterns.

## Configuration Overview

FLEXT-LDIF provides flexible configuration management through multiple layers:

1. **Default Configuration**: Built-in sensible defaults
2. **Global Configuration**: Process-wide settings
3. **Instance Configuration**: Per-API instance settings
4. **Operation Configuration**: Per-operation overrides

## Configuration Models

### FlextLdifModels.Config

Core configuration class with validation:

```python
from flext_ldif import FlextLdifModels

class Config(BaseModel):
    """LDIF processing configuration with Pydantic validation."""

    max_entries: int | None = Field(
        None,
        description="Maximum number of entries to process (None = unlimited)",
        ge=1
    )

    strict_validation: bool = Field(
        False,
        description="Enable strict RFC 2849 validation"
    )

    ignore_unknown_attributes: bool = Field(
        True,
        description="Ignore attributes not in standard LDAP schema"
    )

    encoding: str = Field(
        "utf-8",
        description="Character encoding for LDIF files"
    )

    line_separator: str = Field(
        "\\n",
        description="Line separator for LDIF output"
    )

    buffer_size: int = Field(
        8192,
        description="Buffer size for file operations",
        ge=1024
    )

    log_level: str = Field(
        "INFO",
        description="Logging level for LDIF operations"
    )
```

### Configuration Usage

```python
# Create configuration with custom settings
config = FlextLdifModels.Config(
    max_entries=100000,
    strict_validation=True,
    encoding='utf-8',
    log_level='DEBUG'
)

# Use configuration with API
from flext_ldif import FlextLdif
api = FlextLdif(config=config)

# Access configuration values
print(f"Max entries: {config.max_entries}")
print(f"Strict validation: {config.strict_validation}")
```

## Global Configuration

### Initialization

```python
from flext_ldif import initialize_ldif_config, get_ldif_config

# Initialize global configuration
initialize_ldif_config({
    'max_entries': 50000,
    'strict_validation': True,
    'encoding': 'utf-8',
    'log_level': 'INFO'
})

# Access global configuration
global_config = get_ldif_config()
print(f"Global max entries: {global_config.max_entries}")
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

```python
import os
from flext_ldif import FlextLdifModels

def load_config_from_environment() -> FlextLdifModels.Config:
    """Load configuration from environment variables."""
    return FlextLdifModels.Config(
        max_entries=int(os.getenv('FLEXT_LDIF_MAX_ENTRIES', '0')) or None,
        strict_validation=os.getenv('FLEXT_LDIF_STRICT_VALIDATION', '').lower() == 'true',
        encoding=os.getenv('FLEXT_LDIF_ENCODING', 'utf-8'),
        buffer_size=int(os.getenv('FLEXT_LDIF_BUFFER_SIZE', '8192')),
        log_level=os.getenv('FLEXT_LDIF_LOG_LEVEL', 'INFO')
    )

# Use environment-based configuration
config = load_config_from_environment()
api = FlextLdif(config=config)
```

## Configuration Scenarios

### Development Configuration

Optimized for development and testing:

```python
def create_development_config() -> FlextLdifModels.Config:
    """Create configuration optimized for development."""
    return FlextLdifModels.Config(
        max_entries=10000,          # Limit for faster testing
        strict_validation=True,      # Catch issues early
        ignore_unknown_attributes=False,  # Strict validation
        log_level='DEBUG'           # Verbose logging
    )

# Development API instance
dev_api = FlextLdif(config=create_development_config())
```

### Production Configuration

Optimized for production environments:

```python
def create_production_config() -> FlextLdifModels.Config:
    """Create configuration optimized for production."""
    return FlextLdifModels.Config(
        max_entries=None,           # No artificial limits
        strict_validation=False,    # More permissive for real-world data
        ignore_unknown_attributes=True,  # Handle varied schemas
        encoding='utf-8',
        buffer_size=16384,          # Larger buffer for performance
        log_level='INFO'            # Standard logging
    )

# Production API instance
prod_api = FlextLdif(config=create_production_config())
```

### Migration Configuration

Optimized for large-scale LDAP migrations:

```python
def create_migration_config() -> FlextLdifModels.Config:
    """Create configuration optimized for enterprise migrations."""
    return FlextLdifModels.Config(
        max_entries=None,           # Handle large exports
        strict_validation=False,    # Accommodate legacy data
        ignore_unknown_attributes=True,  # Handle custom schemas
        encoding='utf-8',
        buffer_size=32768,          # Maximum performance
        log_level='INFO'
    )

# Migration API instance
migration_api = FlextLdif(config=create_migration_config())
```

## Advanced Configuration

### Configuration Validation

```python
from pydantic import ValidationError
from flext_ldif import FlextLdifModels

def validate_configuration(config_dict: dict) -> FlextCore.Result[FlextLdifModels.Config]:
    """Validate configuration with detailed error handling."""
    try:
        config = FlextLdifModels.Config(**config_dict)
        return FlextCore.Result[FlextLdifModels.Config].ok(config)
    except ValidationError as e:
        error_details = "; ".join([f"{err['loc'][0]}: {err['msg']}" for err in e.errors()])
        return FlextCore.Result[FlextLdifModels.Config].fail(f"Configuration validation failed: {error_details}")

# Validate configuration before use
config_data = {
    'max_entries': 'invalid',  # Should be int or None
    'strict_validation': True,
    'encoding': 'utf-8'
}

validation_result = validate_configuration(config_data)
if validation_result.is_success:
    config = validation_result.unwrap()
    api = FlextLdif(config=config)
else:
    print(f"Configuration error: {validation_result.error}")
```

### Configuration Inheritance

```python
def create_inherited_config(
    base_config: FlextLdifModels.Config,
    overrides: dict
) -> FlextLdifModels.Config:
    """Create new configuration inheriting from base with overrides."""
    base_dict = base_config.model_dump()
    base_dict.update(overrides)
    return FlextLdifModels.Config(**base_dict)

# Base configuration
base_config = FlextLdifModels.Config(
    max_entries=50000,
    strict_validation=True,
    encoding='utf-8'
)

# Specialized configuration for specific use case
specialized_config = create_inherited_config(base_config, {
    'max_entries': 100000,  # Override for larger files
    'log_level': 'DEBUG'    # Add debugging
})
```

### Configuration Profiles

```python
class ConfigurationProfiles:
    """Predefined configuration profiles for common use cases."""

    @staticmethod
    def minimal() -> FlextLdifModels.Config:
        """Minimal configuration for basic LDIF processing."""
        return FlextLdifModels.Config(
            max_entries=1000,
            strict_validation=False,
            ignore_unknown_attributes=True
        )

    @staticmethod
    def standard() -> FlextLdifModels.Config:
        """Standard configuration for general use."""
        return FlextLdifModels.Config(
            max_entries=50000,
            strict_validation=True,
            ignore_unknown_attributes=True,
            buffer_size=8192
        )

    @staticmethod
    def enterprise() -> FlextLdifModels.Config:
        """Enterprise configuration for large-scale processing."""
        return FlextLdifModels.Config(
            max_entries=None,
            strict_validation=False,
            ignore_unknown_attributes=True,
            buffer_size=32768,
            log_level='INFO'
        )

    @staticmethod
    def testing() -> FlextLdifModels.Config:
        """Testing configuration with strict validation."""
        return FlextLdifModels.Config(
            max_entries=100,
            strict_validation=True,
            ignore_unknown_attributes=False,
            log_level='DEBUG'
        )

# Use predefined profiles
api = FlextLdif(config=ConfigurationProfiles.enterprise())
```

## Integration with FLEXT Configuration

### FlextCore.Container Integration

```python
from flext_core import FlextCore
from flext_ldif import FlextLdifConfig

# Register configuration in container
container = FlextCore.Container.get_global()
config = FlextLdifModels.Config(max_entries=100000)

registration_result = container.register("ldif_config", config)
if registration_result.is_success:
    print("Configuration registered in container")

# Retrieve configuration from container
config_result = container.get("ldif_config")
if config_result.is_success:
    retrieved_config = config_result.unwrap()
    api = FlextLdif(config=retrieved_config)
```

### Configuration Logging

```python
from flext_core import FlextCore

def log_configuration(config: FlextLdifModels.Config) -> None:
    """Log configuration settings for debugging."""
    logger = FlextCore.Logger(__name__)

    logger.info("LDIF configuration initialized", extra={
        'max_entries': config.max_entries,
        'strict_validation': config.strict_validation,
        'encoding': config.encoding,
        'buffer_size': config.buffer_size,
        'log_level': config.log_level
    })

# Log configuration during initialization
config = FlextLdifModels.Config(max_entries=50000)
log_configuration(config)
api = FlextLdif(config=config)
```

## Configuration Best Practices

### 1. Use Type-Safe Configuration

Always use the Pydantic-based configuration models:

```python
# ✅ Good: Type-safe configuration
config = FlextLdifModels.Config(
    max_entries=50000,
    strict_validation=True
)

# ❌ Avoid: Raw dictionaries without validation
config_dict = {
    'max_entries': '50000',  # Should be int
    'strict_validation': 'yes'  # Should be bool
}
```

### 2. Validate Configuration Early

Validate configuration at application startup:

```python
def initialize_application_config() -> FlextCore.Result[FlextLdif]:
    """Initialize application with validated configuration."""
    try:
        config = FlextLdifModels.Config(
            max_entries=int(os.getenv('MAX_ENTRIES', '50000')),
            strict_validation=os.getenv('STRICT_VALIDATION', '').lower() == 'true'
        )
        api = FlextLdif(config=config)
        return FlextCore.Result[FlextLdif].ok(api)
    except Exception as e:
        return FlextCore.Result[FlextLdif].fail(f"Configuration initialization failed: {e}")
```

### 3. Use Environment-Specific Profiles

Create profiles for different deployment environments:

```python
def get_environment_config(environment: str) -> FlextLdifModels.Config:
    """Get configuration based on deployment environment."""
    profiles = {
        'development': ConfigurationProfiles.testing(),
        'staging': ConfigurationProfiles.standard(),
        'production': ConfigurationProfiles.enterprise()
    }

    return profiles.get(environment, ConfigurationProfiles.standard())

# Use environment-based configuration
env = os.getenv('ENVIRONMENT', 'development')
config = get_environment_config(env)
api = FlextLdif(config=config)
```

### 4. Document Configuration Changes

Keep configuration changes documented and version controlled:

```python
# Configuration changelog
CONFIGURATION_CHANGELOG = {
    "0.9.9": {
        "added": ["buffer_size", "log_level"],
        "changed": ["max_entries default from 10000 to None"],
        "deprecated": []
    }
}

def get_config_version() -> str:
    """Get current configuration version."""
    return "0.9.9"
```

## Configuration Reference

### Complete Configuration Options

| Option                      | Type          | Default   | Description                                   |
| --------------------------- | ------------- | --------- | --------------------------------------------- |
| `max_entries`               | `int \| None` | `None`    | Maximum entries to process (None = unlimited) |
| `strict_validation`         | `bool`        | `False`   | Enable strict RFC 2849 validation             |
| `ignore_unknown_attributes` | `bool`        | `True`    | Ignore non-standard attributes                |
| `encoding`                  | `str`         | `"utf-8"` | Character encoding for files                  |
| `line_separator`            | `str`         | `"\\n"`   | Line separator for output                     |
| `buffer_size`               | `int`         | `8192`    | File operation buffer size                    |
| `log_level`                 | `str`         | `"INFO"`  | Logging level (DEBUG, INFO, WARNING, ERROR)   |

### Environment Variable Mapping

| Environment Variable              | Configuration Option        | Example  |
| --------------------------------- | --------------------------- | -------- |
| `FLEXT_LDIF_MAX_ENTRIES`          | `max_entries`               | `100000` |
| `FLEXT_LDIF_STRICT_VALIDATION`    | `strict_validation`         | `true`   |
| `FLEXT_LDIF_IGNORE_UNKNOWN_ATTRS` | `ignore_unknown_attributes` | `false`  |
| `FLEXT_LDIF_ENCODING`             | `encoding`                  | `utf-8`  |
| `FLEXT_LDIF_BUFFER_SIZE`          | `buffer_size`               | `16384`  |
| `FLEXT_LDIF_LOG_LEVEL`            | `log_level`                 | `DEBUG`  |

---

This configuration guide provides comprehensive coverage of FLEXT-LDIF configuration options while maintaining integration with FLEXT ecosystem patterns and professional configuration management practices.
