# from flext-ldif/docs/adr/adr-006-simplification-refactoring.md:259
from __future__ import annotations

from flext_core import s


class FlextLdifDetector(s):
    """Server detection service with automatic logging."""

    def execute(self, content: str) -> p.Result[dict]:
        self.logger.info("Detecting server type", extra={"size": len(content)})
        # self.logger available automatically from s```
**Benefits**:

- Automatic logger injection
- Context management
- Operation tracking
- Consistent service interface

### **7. Simplify with Python 3.13+ Pattern Matching**

**Action**: Replace if/else chains with pattern matching

**Before** (170 lines with nested if/else):

