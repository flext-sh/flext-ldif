# from flext-ldif_docs/adr/adr-006-simplification-refactoring.md:180
dn = ldif.get_entry_dn(entry)  # Wrapper
attrs = ldif.get_entry_attributes(entry)  # Wrapper```
**After**:

