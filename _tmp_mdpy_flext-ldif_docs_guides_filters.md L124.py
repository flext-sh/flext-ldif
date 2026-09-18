# from flext-ldif/docs/guides/filters.md:124
# Check if entry is schema
is_schema = FlextLdifFilters.is_schema(entry)

# Filter schema by OID whitelist
result = FlextLdifFilters.filter_schema_by_oids(
    entries=schema_entries,
    allowed_oids={"attributes": ["2.5.4.*"], "objectclasses": ["2.5.6.*"]},
)```
## Quick Reference

Most common use cases:

