# from flext-ldif/docs/guides/filters.md:91
# Filter by DN pattern
result = FlextLdifFilters.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.by_objectclass(entries, ("person", "inetOrgPerson"))

# Filter by attributes
result = FlextLdifFilters.by_attributes(entries, ["mail"], match_all=False)

# Filter by base DN
included, excluded = FlextLdifFilters.by_base_dn(entries, "dc=example,dc=com")

# Extract ACL entries
result = FlextLdifFilters.extract_acl_entries(entries)

# Categorize entry
category, reason = FlextLdifFilters.categorize(entry, rules)```
### Pattern 5: Transformation (Remove Attributes/ObjectClasses)

