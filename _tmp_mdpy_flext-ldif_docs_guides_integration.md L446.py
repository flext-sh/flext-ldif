# from flext-ldif/docs/guides/integration.md:446
from __future__ import annotations


def robust_ldif_processing(content: str) -> p.Result[m.Dict]:
    """Process LDIF with format-specific error handling."""
    api = ldif()

    result = api.parse_string(content)
    if result.failure:
        error_msg = result.error
        if "LDIF" in error_msg or "parse" in error_msg.lower():
            return r[m.Dict].fail(f"LDIF format error: {error_msg}")
        return r[m.Dict].fail(f"Processing error: {error_msg}")

    return r[m.Dict].ok({"entries": result.unwrap()})```
### 3. LDIF Entry Type Processing

Use LDIF-specific entry type methods:

