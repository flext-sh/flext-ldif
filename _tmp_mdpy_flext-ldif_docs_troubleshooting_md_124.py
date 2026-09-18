# from flext-ldif_docs/troubleshooting.md:124
from __future__ import annotations

from flext_ldif import ldif, FlextLdifModels, p, r, m
import pathlib


def process_large_file_safely(file_path: str) -> p.Result[m.Dict]:
    """Process large LDIF files with memory management."""
    import psutil

    # Check available memory
    available_memory_gb = psutil.virtual_memory().available / (1024**3)
    file_size_gb = pathlib.Path(file_path).stat().st_size / (1024**3)

    u.Cli.print(f"File size: {file_size_gb:.2f} GB")
    u.Cli.print(f"Available memory: {available_memory_gb:.2f} GB")

    if file_size_gb > available_memory_gb * 0.5:
        return r[m.Dict].fail(
            f"File too large for available memory. "
            f"File: {file_size_gb:.2f}GB, Available: {available_memory_gb:.2f}GB"
        )

    # Configure for large files
    settings = FlextLdifModels.Config(
        max_entries=50000,  # Limit entries
        buffer_size=16384,  # Smaller buffer
    )

    api = ldif(settings=settings)
    return api.parse_file(file_path)


def chunk_process_file(file_path: str, chunk_size: int = 10000) -> p.Result[m.Dict]:
    """Process file in chunks to manage memory."""
    results = {"total_entries": 0, "processed_chunks": 0}

    try:
        with pathlib.Path(file_path).open("r", encoding="utf-8") as f:
            current_chunk = []
            current_entry = []

            for line in f:
                if line.startswith("dn:") and current_entry:
                    # Process completed entry
                    current_chunk.append("\n".join(current_entry))
                    current_entry = [line.strip()]

                    if len(current_chunk) >= chunk_size:
                        # Process chunk
                        chunk_result = process_chunk(current_chunk)
                        if chunk_result.success:
                            results["total_entries"] += len(current_chunk)
                            results["processed_chunks"] += 1
                        current_chunk = []
                else:
                    current_entry.append(line.strip())

            # Process final chunk
            if current_chunk:
                chunk_result = process_chunk(current_chunk)
                if chunk_result.success:
                    results["total_entries"] += len(current_chunk)
                    results["processed_chunks"] += 1

        return r[m.Dict].ok(results)
    except Exception as e:
        return r[m.Dict].fail(f"Chunk processing failed: {e}")


def process_chunk(chunk_entries: list[str]) -> p.Result[bool]:
    """Process a chunk of LDIF entries."""
    chunk_content = "\n\n".join(chunk_entries)
    api = ldif()
    result = api.parse_string(chunk_content)
    return result.map(lambda _: None)```
### Validation Errors

#### Strict Validation Failures

**Symptom**: Validation fails with strict mode enabled.

