# from flext-ldif/docs/guides/filters.md:79
filtered_result = (
    FlextLdifFilters
    .builder()
    .with_entries(my_entries)
    .with_dn_pattern("*,ou=users,dc=example,dc=com")
    .with_objectclass("person")
    .with_required_attributes(["cn", "mail"])
    .build()  # Returns t.SequenceOf[Entry] directly
)```
### Pattern 4: Public Classmethod Helpers (Most Direct)

