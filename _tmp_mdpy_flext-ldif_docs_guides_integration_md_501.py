# from flext-ldif_docs/guides/integration.md:501
from __future__ import annotations


# ✅ Good: Small to medium LDIF files
def process_small_ldif(file_path: Path) -> p.Result[m.Dict]:
    """Process LDIF files under 100MB."""
    if file_path.stat().st_size > 100 * 1024 * 1024:
        return r[m.Dict].fail("File too large for current implementation")

    api = ldif()
    return api.parse_file(file_path)


# ⚠️ Consider: External tools for large files
def process_large_ldif(file_path: Path) -> p.Result[str]:
    """For large LDIF files, use external tools first."""
    # Use grep, awk, or other streaming tools to pre-process
    # Then use FLEXT-LDIF for final processing of smaller chunks
    return r[str].fail("Large file processing not yet implemented")```
______________________________________________________________________

This integration guide focuses on LDIF-specific patterns within the FLEXT ecosystem. For general FLEXT patterns, see [flext-core documentation](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/README.md).
