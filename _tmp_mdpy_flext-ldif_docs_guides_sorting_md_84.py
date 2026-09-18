# from flext-ldif_docs/guides/sorting.md:84
# Sort entries by hierarchy
result = FlextLdifSorting.by_hierarchy(my_entries)
sorted_entries = result.unwrap()

# Sort entries alphabetically by DN
result = FlextLdifSorting.by_dn(my_entries)

# Sort entries by custom predicate
result = FlextLdifSorting.by_custom(
    my_entries, lambda e: FlextLdifUtilities.DN.get_dn_value(e.dn).count(",")
)

# Sort attributes in entries
result = FlextLdifSorting.sort_attributes_in_entries(
    my_entries, order=["cn", "sn", "mail"]
)

# Sort ACL values in entries
result = FlextLdifSorting.sort_acl_in_entries(my_entries)

# Sort schema entries by OID
result = FlextLdifSorting.by_schema(schema_entries)```
## Attribute & ACL Sorting Options

### When sort_target="attributes"

- `sort_attributes=True` - Sort alphabetically (default)
- `attribute_order=[...]` - Custom order: `["cn", "sn", "mail"]` (remaining attrs sorted alphabetically)

### When sort_target="acl"

- `acl_attributes=[...]` - Which attrs to sort (default: `["acl", "aci", "olcAccess"]`)

## Complex Sorting Examples

