# FLEXT LDIF Sorting Service - Universal Sorting Engine

Flexible sorting for LDIF entries, attributes, ACL & schemas.
Supports hierarchy, DN, custom predicate, and schema OID sorting.

## DN Handling (RFC 4514 Compliance)

- Hierarchical sorting uses `FlextLdifUtilities.DN.norm()` for DN normalization
- DN depth calculation with fallback to `FlextLdifUtilities.DN.get_depth()`
- Alphabetical DN sorting uses RFC 4514 normalized form for canonical ordering
- All DN comparisons are case-insensitive and RFC 4514 compliant

## What It Sorts (sort_target parameter)

| Target | Description |
|--------|-------------|
| `"entries"` | Sort the entry list itself by DN/hierarchy/custom |
| `"attributes"` | Sort attributes WITHIN each entry (no entry reordering) |
| `"acl"` | Sort ACL values WITHIN entries (acl, aci, olcAccess) |
| `"schema"` | Sort schema entries by OID (for schema exports) |
| `"combined"` | Sort everything at once (entries + attrs + ACL) |

## How It Sorts Entries (sort_by parameter)

| Strategy | Description |
|----------|-------------|
| `"hierarchy"` | Depth-first: shallow entries first, then alphabetical. Order: dc=com, ou=users,dc=com, cn=john,ou=users,... |
| `"alphabetical"` | Full DN alphabetical (case-insensitive) |
| `"dn"` | Alias for alphabetical |
| `"schema"` | For schema entries: attributeTypes before objectClasses, each sorted by extracted OID number |
| `"custom"` | Use custom_predicate function to extract sort key |

## Usage Examples

### Pattern 1: Execute Method (V1 Style)

```python
result = FlextLdifSorting(
    entries=my_entries,
    sort_by="hierarchy"
).execute()

if result.is_success:
    sorted_entries = result.unwrap()
```

### Pattern 2: Classmethod for Composable/Chainable Operations

```python
result = (
    FlextLdifSorting.sort(my_entries, by="hierarchy")
    .map(lambda e: e[:10])  # Take first 10
    .and_then(lambda e: FlextLdifSorting.sort(e, by="alphabetical"))
)
```

### Pattern 3: Fluent Builder Pattern

```python
sorted_entries = (
    FlextLdifSorting.builder()
    .with_entries(my_entries)
    .with_strategy("hierarchy")
    .with_attribute_sorting(order=["cn", "sn", "mail"])
    .build()  # Returns list[Entry] directly
)
```

### Pattern 4: Public Classmethod Helpers (Most Direct)

```python
# Sort entries by hierarchy
result = FlextLdifSorting.by_hierarchy(my_entries)
sorted_entries = result.unwrap()

# Sort entries alphabetically by DN
result = FlextLdifSorting.by_dn(my_entries)

# Sort entries by custom predicate
result = FlextLdifSorting.by_custom(
    my_entries,
    lambda e: FlextLdifUtilities.DN.get_dn_value(e.dn).count(",")
)

# Sort attributes in entries
result = FlextLdifSorting.sort_attributes_in_entries(
    my_entries,
    order=["cn", "sn", "mail"]
)

# Sort ACL values in entries
result = FlextLdifSorting.sort_acl_in_entries(my_entries)

# Sort schema entries by OID
result = FlextLdifSorting.by_schema(schema_entries)
```

## Attribute & ACL Sorting Options

### When sort_target="attributes":

- `sort_attributes=True` - Sort alphabetically (default)
- `attribute_order=[...]` - Custom order: `["cn", "sn", "mail"]` (remaining attrs sorted alphabetically)

### When sort_target="acl":

- `acl_attributes=[...]` - Which attrs to sort (default: `["acl", "aci", "olcAccess"]`)

## Complex Sorting Examples

```python
# Sort ONLY attributes, preserving entry order
sorted_entries = FlextLdifSorting(
    entries=my_entries,
    sort_target="attributes"
).execute().unwrap()

# Sort ONLY ACL values within entries
sorted_entries = FlextLdifSorting(
    entries=my_entries,
    sort_target="acl"
).execute().unwrap()

# Sort EVERYTHING at once
sorted_entries = FlextLdifSorting(
    entries=my_entries,
    sort_target="combined",
    sort_by="hierarchy",
    sort_attributes=True,
    attribute_order=["objectClass", "cn", "sn", "mail"],
    sort_acl=True
).execute().unwrap()

# Custom sorting: sort by DN length
sorted_entries = FlextLdifSorting(
    entries=my_entries,
    sort_by="custom",
    custom_predicate=lambda e: len(FlextLdifUtilities.DN.get_dn_value(e.dn))
).execute().unwrap()

# Custom sorting: sort by CN attribute value
result = FlextLdifSorting.by_custom(
    my_entries,
    lambda e: e.attributes.attributes.get("cn", [""])[0].lower()
)
```

## Public Classmethod API

| Method | Returns | Description |
|--------|---------|-------------|
| `sort(entries, target=..., by=..., predicate=...)` | `FlextResult[list[Entry]]` | For chaining |
| `by_hierarchy(entries)` | `FlextResult[list[Entry]]` | Depth-first + alphabetical |
| `by_dn(entries)` | `FlextResult[list[Entry]]` | Alphabetical by full DN |
| `by_schema(entries)` | `FlextResult[list[Entry]]` | Schema entries by OID |
| `by_custom(entries, predicate)` | `FlextResult[list[Entry]]` | Custom sort function |
| `sort_attributes_in_entries(entries, order=None)` | `FlextResult[list[Entry]]` | Sort attrs within entries |
| `sort_acl_in_entries(entries, acl_attrs=None)` | `FlextResult[list[Entry]]` | Sort ACL values |
| `builder()` | `FlextLdifSorting` | Fluent builder, terminal: `.build()` |

## Quick Reference

Most common use cases:

```python
# Just sort entries by hierarchy
sorted = FlextLdifSorting.by_hierarchy(entries).unwrap()

# Just sort entries alphabetically
sorted = FlextLdifSorting.by_dn(entries).unwrap()

# Sort entries + sort attributes + sort ACL
sorted = FlextLdifSorting(
    entries=entries,
    sort_target="combined",
    sort_by="hierarchy",
    sort_attributes=True,
    sort_acl=True
).execute().unwrap()

# Sort with custom logic
sorted = FlextLdifSorting.by_custom(
    entries,
    lambda e: FlextLdifUtilities.DN.get_dn_value(e.dn).count(",")
).unwrap()
```

## See Also

- [API Reference](api-reference.md)
- [Filters Documentation](FILTERS.md)
