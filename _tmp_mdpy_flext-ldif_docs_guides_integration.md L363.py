# from flext-ldif/docs/guides/integration.md:363
from __future__ import annotations

from flext_ldif import ldif
from pathlib import Path
import psutil
import os


def process_multiple_ldif_files(file_paths: t.SequenceOf[Path]) -> p.Result[m.Dict]:
    """Process multiple LDIF files with memory monitoring."""
    api = ldif()
    all_entries = []
    processing_stats = {}
    process = psutil.Process(os.getpid())

    initial_memory = process.memory_info().rss

    for file_path in file_paths:
        # Memory check before each file
        current_memory = process.memory_info().rss
        memory_increase = current_memory - initial_memory

        if memory_increase > 500 * 1024 * 1024:  # 500MB increase limit
            return r[m.Dict].fail(
                f"Memory usage too high ({memory_increase} bytes). "
                f"Processed {len(processing_stats)} files before limit."
            )

        result = api.parse_file(file_path)
        if result.success:
            entries = result.unwrap()
            all_entries.extend(entries)
            processing_stats[str(file_path)] = {
                "entries": len(entries),
                "memory_after": current_memory,
            }
        else:
            return r[m.Dict].fail(f"Failed to process {file_path}: {result.error}")

    final_memory = process.memory_info().rss
    total_memory_used = final_memory - initial_memory

    return r[m.Dict].ok({
        "total_entries": len(all_entries),
        "files_processed": len(processing_stats),
        "file_stats": processing_stats,
        "memory_usage": {
            "initial_memory": initial_memory,
            "final_memory": final_memory,
            "total_increase": total_memory_used,
        },
        "entries": all_entries,
    })```
## LDIF Integration Best Practices

### 1. Memory-Aware Processing

Always check file sizes before processing with current implementation:

