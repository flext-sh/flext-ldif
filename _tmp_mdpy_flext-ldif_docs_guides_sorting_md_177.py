# from flext-ldif_docs/guides/sorting.md:177
# Just sort entries by hierarchy
sorted = FlextLdifSorting.by_hierarchy(entries).unwrap()

# Just sort entries alphabetically
sorted = FlextLdifSorting.by_dn(entries).unwrap()

# Sort entries + sort attributes + sort ACL
sorted = (
    FlextLdifSorting(
        entries=entries,
        sort_target="combined",
        sort_by="hierarchy",
        sort_attributes=True,
        sort_acl=True,
    )
    .execute()
    .unwrap()
)

# Sort with custom logic
sorted = FlextLdifSorting.by_custom(
    entries, lambda e: FlextLdifUtilities.DN.get_dn_value(e.dn).count(",")
).unwrap()```
## See Also

- API Reference
- Filters Documentation
