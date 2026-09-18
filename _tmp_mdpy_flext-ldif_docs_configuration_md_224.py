# from flext-ldif_docs/configuration.md:224
from __future__ import annotations

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
    u.Cli.print(f"Configuration error: {validation_result.error}")```
### Configuration Inheritance

