# from flext-ldif_docs/guides/integration.md:64
from __future__ import annotations

from pathlib import Path


def process_ldif_with_memory_check(file_path: Path) -> p.Result[m.Dict]:
    """Process LDIF with memory size validation."""
    api = ldif()

    # Check file size before processing (custom parser loads into memory)
    file_size = file_path.stat().st_size
    max_size = 100 * 1024 * 1024  # 100MB limit for memory-bound parser

    if file_size > max_size:
        return r[m.Dict].fail(
            f"File too large ({file_size} bytes). "
            f"Current implementation limited to {max_size} bytes."
        )

    return api.parse_file(file_path)```
## Enterprise Directory Migration Integration

### FLEXT Oracle Unified Directory Migration

