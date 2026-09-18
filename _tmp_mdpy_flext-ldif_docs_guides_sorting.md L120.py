# from flext-ldif/docs/guides/sorting.md:120
# Sort ONLY attributes, preserving entry order
sorted_entries = (
    FlextLdifSorting(entries=my_entries, sort_target="attributes").execute().unwrap()
)

# Sort ONLY ACL values within entries
sorted_entries = (
    FlextLdifSorting(entries=my_entries, sort_target="acl").execute().unwrap()
)

# Sort EVERYTHING at once
sorted_entries = (
    FlextLdifSorting(
        entries=my_entries,
        sort_target="combined",
        sort_by="hierarchy",
        sort_attributes=True,
        attribute_order=["objectClass", "cn", "sn", "mail"],
        sort_acl=True,
    )
    .execute()
    .unwrap()
)

# Custom sorting: sort by DN length
sorted_entries = (
    FlextLdifSorting(
        entries=my_entries,
        sort_by="custom",
        custom_predicate=lambda e: len(FlextLdifUtilities.DN.get_dn_value(e.dn)),
    )
    .execute()
    .unwrap()
)

# Custom sorting: sort by CN attribute value
result = FlextLdifSorting.by_custom(
    my_entries, lambda e: e.attributes.attributes.get("cn", [""])[0].lower()
)```
## Public Classmethod API

| Method                                             | Returns              | Description                          |
| -------------------------------------------------- | -------------------- | ------------------------------------ |
| `sort(entries, target=..., by=..., predicate=...)` | `r[Sequence[Entry]]` | For chaining                         |
| `by_hierarchy(entries)`                            | `r[Sequence[Entry]]` | Depth-first + alphabetical           |
| `by_dn(entries)`                                   | `r[Sequence[Entry]]` | Alphabetical by full DN              |
| `by_schema(entries)`                               | `r[Sequence[Entry]]` | Schema entries by OID                |
| `by_custom(entries, predicate)`                    | `r[Sequence[Entry]]` | Custom sort function                 |
| `sort_attributes_in_entries(entries, order=None)`  | `r[Sequence[Entry]]` | Sort attrs within entries            |
| `sort_acl_in_entries(entries, acl_attrs=None)`     | `r[Sequence[Entry]]` | Sort ACL values                      |
| `builder()`                                        | `FlextLdifSorting`   | Fluent builder, terminal: `.build()` |

## Quick Reference

Most common use cases:

