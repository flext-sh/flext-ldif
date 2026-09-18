# from flext-ldif_docs/api-reference.md:571
# Create custom configuration
settings = FlextLdifModels.Config(
    max_entries=50000,
    strict_validation=True,
    ignore_unknown_attributes=False,
    encoding="utf-8",
)

# Use configuration with API
api = ldif(settings=settings)```
### FlextLdifModels.Factory

Factory methods for creating domain objects.

