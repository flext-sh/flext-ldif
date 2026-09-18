# from flext-ldif/docs/troubleshooting.md:279
from __future__ import annotations
import pathlib


def benchmark_processing(file_path: str) -> None:
    """Benchmark LDIF processing performance."""
    import time

    file_size_mb = pathlib.Path(file_path).stat().st_size / (1024 * 1024)
    u.Cli.print(f"File size: {file_size_mb:.2f} MB")

    api = ldif()

    # Benchmark parsing
    start_time = time.time()
    parse_result = api.parse_file(file_path)
    parse_time = time.time() - start_time

    if parse_result.success:
        entries = parse_result.unwrap()
        u.Cli.print(f"Parsed {len(entries)} entries in {parse_time:.2f} seconds")
        u.Cli.print(f"Processing rate: {len(entries) / parse_time:.1f} entries/second")
        u.Cli.print(f"Throughput: {file_size_mb / parse_time:.2f} MB/second")

        # Benchmark validation
        start_time = time.time()
        validation_result = api.validate_entries(entries)
        validation_time = time.time() - start_time

        if validation_result.success:
            u.Cli.print(f"Validated in {validation_time:.2f} seconds")
        else:
            u.Cli.print(f"Validation failed: {validation_result.error}")
    else:
        u.Cli.print(f"Parsing failed: {parse_result.error}")```
**Optimization**:

