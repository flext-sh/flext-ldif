# from flext-ldif/docs/development.md:204
from __future__ import annotations

import psutil
import os
import pathlib


def test_memory_usage():
    """Monitor memory usage during LDIF processing."""
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss

    api = ldif()
    result = api.parse_file("test_data.ldif")

    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory

    # Memory increase should be reasonable for file size
    file_size = pathlib.Path("test_data.ldif").stat().st_size
    assert memory_increase < file_size * 3  # Allow 3x overhead```
## Performance Considerations

### Current Limitations

1. **Memory Usage**: Entire file loaded into memory
1. **Single-threaded**: No parallel processing
1. **No Progress Reporting**: Long operations provide no feedback
1. **No Streaming**: Cannot process files larger than available memory

### Performance Guidelines

