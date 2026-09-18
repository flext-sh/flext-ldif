# from flext-ldif/docs/adr/adr-006-simplification-refactoring.md:185
dn = entry.dn.value  # Direct
attrs = entry.attributes.to_ldap3()  # Direct```
### **4. Remove Property Accessors**

**Action**: Delete 100+ lines of property wrappers

**Properties to Remove**:

- `@property def models()` → Import `FlextLdifModels` directly
- `@property def settings()` → Import `FlextLdifSettings` directly
- `@property def constants()` → Import `FlextLdifConstants` directly
- `@property def processors()` → Import `FlextProcessors` from flext-core

**Rationale**:

- Unnecessary indirection
- Python convention: direct imports over property access

### **5. Leverage d**

**Action**: Apply flext-core decorators to key operations

**Decorators to Apply**:

- `@d.log_operation()` - Automatic operation logging
- `@d.track_performance()` - Performance metrics
- `@d.retry()` - Automatic retry logic
- `@d.railway()` - Railway error handling

**Example**:

