# from flext-ldif_docs/guides/integration.md:466
from __future__ import annotations


def categorize_ldif_entries(entries) -> t.JsonMapping:
    """Categorize LDIF entries by type."""
    categories = {
        "persons": [e for e in entries if e.is_person()],
        "groups": [e for e in entries if e.is_group()],
        "organizational_units": [
            e for e in entries if e.has_object_class("organizationalUnit")
        ],
        "other": [],
    }

    # Find entries that don't fit standard categories
    categorized = set(
        categories["persons"]
        + categories["groups"]
        + categories["organizational_units"]
    )
    categories["other"] = [e for e in entries if e not in categorized]

    return categories```
## Performance Considerations

### Current Implementation Limitations

- **Memory Usage**: Entire LDIF file loaded into memory during processing
- **Single-threaded**: No parallel processing support
- **No Streaming**: Cannot process files larger than available memory
- **No Progress Reporting**: Long operations provide no feedback

### Recommended Usage Patterns

