# FLEXT LDIF Filters Service - Universal Entry Filtering and Categorization Engine

## Features

| Feature | Description |
|---------|-------------|
| DN pattern matching | Wildcard/fnmatch syntax |
| ObjectClass-based filtering | With required attributes |
| Attribute presence/absence filtering | Include/exclude by attribute |
| Entry transformation | Attribute and objectClass removal |
| Entry categorization | 6-category: users/groups/hierarchy/schema/ACL |
| Schema entry detection | Filtering by OID patterns |
| ACL attribute detection | Extraction capabilities |
| Exclusion metadata | Marking with reason tracking |
| Fluent builder pattern | Complex multi-condition filtering |
| Multiple API patterns | Static, classmethod, builder, helpers |
| Server-agnostic design | Works with any LDAP server |

## Usage Examples

### Pattern 1: Direct Classmethod API (Simplified)

```python
# Filter entries by DN pattern
result = FlextLdifFilters.by_dn(
    entries=my_entries,
    pattern="*,ou=users,dc=example,dc=com",
    mode="include"
)
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.by_objectclass(
    entries=my_entries,
    objectclass=("person", "inetOrgPerson"),
    required_attributes=["cn", "mail"]
)

# Filter by attribute presence
result = FlextLdifFilters.by_attributes(
    entries=my_entries,
    attributes=["mail"],
    match_all=False,  # Has ANY attribute
    mode="include"
)
```

### Pattern 2: Classmethod for Composable/Chainable Operations

```python
result = (
    FlextLdifFilters.filter(
        entries=my_entries,
        criteria="dn",
        pattern="*,ou=users,*"
    )
    .map(lambda e: e[:10])  # Take first 10
    .and_then(lambda e: FlextLdifFilters.filter(e, criteria="objectclass", objectclass="person"))
)
```

### Pattern 3: Fluent Builder Pattern

```python
filtered_result = (
    FlextLdifFilters.builder()
    .with_entries(my_entries)
    .with_dn_pattern("*,ou=users,dc=example,dc=com")
    .with_objectclass("person")
    .with_required_attributes(["cn", "mail"])
    .build()  # Returns list[Entry] directly
)
```

### Pattern 4: Public Classmethod Helpers (Most Direct)

```python
# Filter by DN pattern
result = FlextLdifFilters.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.by_objectclass(
    entries, ("person", "inetOrgPerson")
)

# Filter by attributes
result = FlextLdifFilters.by_attributes(
    entries, ["mail"], match_all=False
)

# Filter by base DN
included, excluded = FlextLdifFilters.by_base_dn(
    entries, "dc=example,dc=com"
)

# Extract ACL entries
result = FlextLdifFilters.extract_acl_entries(entries)

# Categorize entry
category, reason = FlextLdifFilters.categorize(entry, rules)
```

### Pattern 5: Transformation (Remove Attributes/ObjectClasses)

```python
# Remove temporary attributes
result = FlextLdifFilters.remove_attributes(
    entry=my_entry,
    attributes=["tempAttribute", "debugInfo"]
)

# Remove unwanted objectClasses
result = FlextLdifFilters.remove_objectclasses(
    entry=my_entry,
    objectclasses=["temporaryClass"]
)
```

### Pattern 6: Schema & Advanced Operations

```python
# Check if entry is schema
is_schema = FlextLdifFilters.is_schema(entry)

# Filter schema by OID whitelist
result = FlextLdifFilters.filter_schema_by_oids(
    entries=schema_entries,
    allowed_oids={
        "attributes": ["2.5.4.*"],
        "objectclasses": ["2.5.6.*"]
    }
)
```

## Quick Reference

Most common use cases:

```python
# Filter entries by DN pattern
result = FlextLdifFilters.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.by_objectclass(
    entries, ("person", "inetOrgPerson")
)

# Combine multiple conditions (builder)
filtered_result = (
    FlextLdifFilters.builder()
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
category, reason = FlextLdifFilters.categorize(entry, rules)
```

## See Also

- [API Reference](api-reference.md)
- [Getting Started](getting-started.md)
