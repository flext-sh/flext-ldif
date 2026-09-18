# from flext-ldif/docs/guides/filters.md:61
from __future__ import annotations

from flext_ldif import FlextLdifFilters

my_entries: list = []
result = (
    FlextLdifFilters
    .filter(entries=my_entries, criteria="dn", pattern="*,ou=users,*")
    .map(lambda e: e[:10])  # Take first 10
    .and_then(
        lambda e: FlextLdifFilters.filter(
            e, criteria="objectclass", objectclass="person"
        )
    )
)```
### Pattern 3: Fluent Builder Pattern

