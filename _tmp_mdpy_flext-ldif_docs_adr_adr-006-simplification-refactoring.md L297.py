# from flext-ldif/docs/adr/adr-006-simplification-refactoring.md:297
from __future__ import annotations

from typing import Literal


def parse(
    self,
    source: str | Path | t.SequenceOf[str | Path],
    *,
    mode: Literal["single", "batch", "paginate"] = "single",
    server_type: str = "rfc",
    page_size: int = 1000,
) -> p.Result[Sequence[Entry] | Callable]:
    """Parse LDIF with pattern matching mode dispatch."""
    match mode:
        case "batch":
            return self._client.parse_batch(source, server_type)
        case "paginate":
            return self._client.parse_paginated(source, server_type, page_size)
        case "single":
            return self._client.parse_ldif(source, server_type)
        case _:
            return r.fail(f"Invalid mode: {mode}")```
**Benefits**:

- Clearer intent
- Type safety with `Literal`
- Reduced line count
- Easier to test

### **8. Reorganize Tests**

**Action**: Flatten test structure to mirror module structure

**Before**:```
tests/unit/
├── rfc/
├── services/
├── acl/
├── schema/
├── entry/
└── ...```
**After**:

