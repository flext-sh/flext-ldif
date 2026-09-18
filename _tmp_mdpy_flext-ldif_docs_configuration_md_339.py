# from flext-ldif_docs/configuration.md:339
from flext_cli import u

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
    api = ldif(settings=retrieved_config)```
### Configuration Logging

