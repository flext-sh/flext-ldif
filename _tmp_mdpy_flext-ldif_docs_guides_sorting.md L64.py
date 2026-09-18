# from flext-ldif/docs/guides/sorting.md:64
result = (
    FlextLdifSorting
    .sort(my_entries, by="hierarchy")
    .map(lambda e: e[:10])  # Take first 10
    .and_then(lambda e: FlextLdifSorting.sort(e, by="alphabetical"))
)```
### Pattern 3: Fluent Builder Pattern

