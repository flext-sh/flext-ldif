# ADR-004: Memory-Bound Processing Architecture


<!-- TOC START -->
- No sections found
<!-- TOC END -->

**Status**: Accepted

**Date**: 2025-10-10

**Context**:
FLEXT-LDIF processes LDIF files containing directory data that can range from small configuration files to large enterprise directory exports. The system needs to handle files efficiently while maintaining type safety and RFC compliance.

Key requirements:

- Support enterprise-scale directory operations
- Maintain 100% type safety with Pydantic models
- Ensure RFC compliance for all parsing operations
- Provide predictable performance characteristics
- Support both small files (KB) and large files (GB)

Available implementation approaches:

- **Streaming Parser**: Process files incrementally without full memory load
- **Memory-Bound Parser**: Load entire file into memory for processing
- **Hybrid Approach**: Stream parsing with memory checkpoints

**Decision**:
Implement a **memory-bound processing architecture** that loads entire LDIF files into memory during processing.

**Key Design Decisions**:

1. **Complete File Loading**: Use `content.splitlines()` to load entire file into memory
2. **File Size Warnings**: Recommend 100MB limit with explicit warnings
3. **Single-Threaded Processing**: Focus on correctness over parallelism
4. **Memory Usage Transparency**: Document memory requirements clearly

**Implementation**:

```python
# Memory-bound file processing
def parse_ldif_file(self, file_path: Path) -> FlextResult[list[Entry]]:
    """Parse LDIF file with memory-bound architecture."""

    # Check file size and warn
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    if file_size_mb > 100:
        logger.warning(f"Large file detected: {file_size_mb:.1f}MB")

    # Load entire file into memory
    with file_path.open('r', encoding='utf-8') as f:
        content = f.read()

    # Process in memory
    lines = content.splitlines()
    return self._parse_lines(lines)
```

**Consequences**:

**Positive**:

- **Simplicity**: Straightforward implementation and debugging
- **Type Safety**: Full Pydantic validation on complete data structures
- **RFC Compliance**: Easy to ensure complete parsing compliance
- **Performance**: Fast processing for files under memory limits
- **Correctness**: Complete file context available for validation

**Negative**:

- **Memory Limits**: Cannot process files larger than available RAM
- **Scalability**: Not suitable for very large enterprise directories
- **Resource Usage**: High memory consumption during processing
- **Error Recovery**: All-or-nothing processing (no partial recovery)

**Neutral**:

- **Current Use Cases**: Suitable for typical directory migration scenarios
- **Clear Limitations**: Well-documented constraints guide usage

**Alternatives Considered**:

1. **Streaming Parser**: Process files incrementally without full memory load
   - **Rejected**: Would complicate type validation and RFC compliance checking
   - **Complexity**: Much harder to maintain complete file context for validation
   - **Performance**: Similar memory usage for validation of complex schemas

2. **Chunked Processing**: Process file in configurable chunks
   - **Rejected**: Would break RFC compliance for cross-chunk validations
   - **Complexity**: Significant architectural complexity for marginal benefits

3. **Memory-Mapped Files**: Use OS memory mapping for large files
   - **Rejected**: Still loads entire file into virtual memory, doesn't solve RAM limits
   - **Platform Dependencies**: Memory mapping behavior varies by OS

**Related ADRs**:

- ADR-006 - Future streaming parser implementation

**Notes**:
The memory-bound architecture is appropriate for the current use case of directory migrations where files are typically under 100MB. The clear memory limits and warnings guide users to appropriate file sizes. Future versions will implement streaming parsers for larger files while maintaining the same API.

**Current Limits**:

- **Recommended Maximum**: 100MB per file
- **Absolute Maximum**: Limited by available system RAM
- **Monitoring**: File size warnings but no automatic chunking
- **Future Evolution**: Streaming parser planned for Phase 2
