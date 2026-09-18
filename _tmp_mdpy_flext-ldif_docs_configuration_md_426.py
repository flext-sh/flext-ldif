# from flext-ldif_docs/configuration.md:426
from __future__ import annotations


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
api = ldif(settings=settings)```
### 4. Document Configuration Changes

Keep configuration changes documented and version controlled:

