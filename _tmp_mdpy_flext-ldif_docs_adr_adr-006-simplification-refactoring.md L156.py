# from flext-ldif/docs/adr/adr-006-simplification-refactoring.md:156
from flext_core import FlextProcessors

processor = FlextProcessors()  # Direct usage
result = processor.batch_process(entries, func)```
### **3. Remove Wrapper Methods**

**Action**: Delete 600+ lines of delegation methods from `api.py`

**Methods to Remove**:

- `get_entry_dn()` → Use `entry.dn.value` directly
- `get_entry_attributes()` → Use `entry.attributes.to_ldap3()` directly
- `get_entry_objectclasses()` → Use `entry.get_attribute_values("objectClass")` directly
- `create_entry()` → Use `FlextLdifModels.Entry.create()` directly

**Rationale**:

- No added value - pure delegation
- Forces indirection (must have `ldif` instance)
- Domain models already provide these operations

**Before**:

