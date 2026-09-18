# from flext-ldif_docs/guides/sorting.md:73
sorted_entries = (
    FlextLdifSorting
    .builder()
    .with_entries(my_entries)
    .with_strategy("hierarchy")
    .with_attribute_sorting(order=["cn", "sn", "mail"])
    .build()  # Returns t.SequenceOf[Entry] directly
)```
### Pattern 4: Public Classmethod Helpers (Most Direct)

