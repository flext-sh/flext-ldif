# from flext-ldif/docs/api-reference.md:649
from flext_ldif import FlextLdifModels, ldif

# Create instance-specific configuration
instance_config = FlextLdifModels.Config(
    max_entries=10000,  # Override global setting
    strict_validation=False,
)

# Use with API instance
api = ldif(settings=instance_config)```
## Error Handling

### r Integration

All API operations return r for composable error handling:

