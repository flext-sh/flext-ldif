# from flext-ldif/docs/development.md:135
from __future__ import annotations

from flext_ldif import p, r, FlextLdifModels


# LDIF-specific validation
def validate_ldif_structure(
    entries: t.SequenceOf[FlextLdifModels.Entry],
) -> p.Result[bool]:
    """Validate LDIF entries for common issues."""
    for entry in entries:
        # Check DN format
        if not entry.dn.value:
            return r[bool].fail("Empty DN found")

        # Check required attributes
        if "objectClass" not in entry.attributes.data:
            return r[bool].fail(f"Missing objectClass in {entry.dn.value}")

    return r[bool].ok(value=True)```
#### Memory-Conscious Processing

