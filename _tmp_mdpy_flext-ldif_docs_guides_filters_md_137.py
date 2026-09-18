# from flext-ldif_docs/guides/filters.md:137
# Filter entries by DN pattern
result = FlextLdifFilters.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.by_objectclass(entries, ("person", "inetOrgPerson"))

# Combine multiple conditions (builder)
filtered_result = (
    FlextLdifFilters
    .builder()
    .with_entries(entries)
    .with_dn_pattern("*,ou=users,*")
    .with_objectclass("person")
    .build()
)

# Check if schema entry
is_schema = FlextLdifFilters.is_schema(entry)

# Extract ACL entries
result = FlextLdifFilters.extract_acl_entries(entries)
acl_entries = result.unwrap()

# Categorize entry
category, reason = FlextLdifFilters.categorize(entry, rules)```
## See Also

- API Reference
- Getting Started
