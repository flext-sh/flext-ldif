# FLEXT-LDIF Troubleshooting

<!-- TOC START -->
- [Common Issues and Solutions](#common-issues-and-solutions)
  - [Parse Errors](#parse-errors)
  - [Memory Issues](#memory-issues)
  - [Validation Errors](#validation-errors)
  - [Performance Issues](#performance-issues)
  - [Integration Issues](#integration-issues)
- [Diagnostic Tools](#diagnostic-tools)
  - [Health Check Utility](#health-check-utility)
  - [Debug Mode Configuration](#debug-mode-configuration)
- [Getting Help](#getting-help)
  - [Support Resources](#support-resources)
  - [Creating Support Requests](#creating-support-requests)
  - [Emergency Contacts](#emergency-contacts)
<!-- TOC END -->

**Version**: 0.12.0-dev | **Updated**: April 14, 2026

This document provides solutions to common issues encountered when using FLEXT-LDIF, including error diagnosis, performance problems, and integration issues.

## Common Issues and Solutions

### Parse Errors

#### Invalid LDIF Format

**Symptom**: Parse operations fail with format-related error messages.

```python
from flext_ldif import ldif

if (
    result := ldif.parse_string(
        "dn: cn=test,dc=example,dc=com\nobjectClass: inetOrgPerson\ncn: test"
    )
).failure:
    u.Cli.print(result.error)
```

**Solution**:

```python
from __future__ import annotations


def diagnose_ldif_format(content: str) -> None:
    """Diagnose LDIF format issues."""
    lines = content.strip().split("\n")

    u.Cli.print(f"Total lines: {len(lines)}")
    u.Cli.print("First few lines:")
    for i, line in enumerate(lines[:5]):
        u.Cli.print(f"{i + 1}: '{line}'")

    # Check for common issues
    if not any(line.startswith("dn:") for line in lines):
        u.Cli.print("❌ No DN found - LDIF entries must start with 'dn:'")

    # Check line folding issues
    for i, line in enumerate(lines):
        if line.startswith(" ") and i == 0:
            u.Cli.print(f"❌ Line {i + 1} starts with space but is first line")

    # Check character encoding
    try:
        content.encode("utf-8")
        u.Cli.print("✓ UTF-8 encoding valid")
    except UnicodeError as e:
        u.Cli.print(f"❌ Encoding issue: {e}")
```

#### Character Encoding Issues

**Symptom**: Parse fails with encoding-related errors.

```python
# Common encoding error
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 123
```

**Solution**:

```python
from __future__ import annotations

from flext_ldif import ldif, p, r


def handle_encoding_issues(file_path: str) -> p.Result[str]:
    """Handle various character encodings."""
    encodings_to_try = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]

    for encoding in encodings_to_try:
        try:
            with open(file_path, "r", encoding=encoding) as f:
                content = f.read()
            u.Cli.print(f"✓ Successfully read with {encoding} encoding")
            return r[str].ok(content)
        except UnicodeDecodeError:
            u.Cli.print(f"✗ Failed with {encoding} encoding")
            continue

    return r[str].fail("Unable to decode file with any supported encoding")


# Usage with custom encoding
def parse_with_encoding_detection(file_path: str) -> p.Result[list]:
    """Parse LDIF with automatic encoding detection."""
    content_result = handle_encoding_issues(file_path)
    if content_result.failure:
        return r[list].fail(content_result.error)

    api = ldif()
    return api.parse_string(content_result.unwrap())
```

### Memory Issues

#### Out of Memory Errors

**Symptom**: Application crashes or becomes unresponsive with large LDIF files.

```python
# Memory error when processing large files
MemoryError: Unable to allocate array
```

**Solution**:

```python
from __future__ import annotations

from flext_ldif import ldif, FlextLdifModels, p, r, m, t


def process_large_file_safely(file_path: str) -> p.Result[m.Dict]:
    """Process large LDIF files with memory management."""
    import psutil
    import os

    # Check available memory
    available_memory_gb = psutil.virtual_memory().available / (1024**3)
    file_size_gb = os.path.getsize(file_path) / (1024**3)

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
        with open(file_path, "r", encoding="utf-8") as f:
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
    return result.map(lambda _: None)
```

### Validation Errors

#### Strict Validation Failures

**Symptom**: Validation fails with strict mode enabled.

```python
result = api.validate_entries(entries)
# Error: "Entry validation failed: unknown attribute 'customAttribute'"
```

**Solution**:

```python
from __future__ import annotations

from flext_ldif import ldif, FlextLdifModels, p, r


def handle_validation_errors(entries: list) -> p.Result[list]:
    """Handle validation errors with detailed reporting."""
    # Try with strict validation first
    strict_config = FlextLdifModels.Config(strict_validation=True)
    strict_api = ldif(settings=strict_config)

    strict_result = strict_api.validate_entries(entries)
    if strict_result.success:
        u.Cli.print("✓ All entries pass strict validation")
        return r[list].ok(entries)

    u.Cli.print(f"✗ Strict validation failed: {strict_result.error}")

    # Try with permissive validation
    permissive_config = FlextLdifModels.Config(
        strict_validation=False, ignore_unknown_attributes=True
    )
    permissive_api = ldif(settings=permissive_config)

    permissive_result = permissive_api.validate_entries(entries)
    if permissive_result.success:
        u.Cli.print("✓ Entries pass permissive validation")
        u.Cli.print("⚠️  Consider reviewing data quality")
        return r[list].ok(entries)

    return r[list].fail(f"Validation failed: {permissive_result.error}")


def analyze_entry_issues(entries: list) -> None:
    """Analyze common entry validation issues."""
    for i, entry in enumerate(entries):
        u.Cli.print(f"\nEntry {i + 1}: {entry.dn}")

        # Check DN format
        if not entry.dn or "=" not in entry.dn:
            u.Cli.print("  ❌ Invalid DN format")

        # Check object classes
        object_classes = entry.get_object_classes()
        if not object_classes:
            u.Cli.print("  ❌ Missing object class")

        # Check required attributes for person entries
        if "person" in object_classes:
            if not entry.get_attribute_values("cn"):
                u.Cli.print("  ❌ Person missing required 'cn' attribute")
            if not entry.get_attribute_values("sn"):
                u.Cli.print("  ❌ Person missing required 'sn' attribute")

        # Check for empty attributes
        for attr_name, attr_values in entry.attributes.items():
            if not attr_values or any(not v.strip() for v in attr_values):
                u.Cli.print(f"  ⚠️  Empty values in attribute '{attr_name}'")
```

### Performance Issues

#### Slow Processing

**Symptom**: LDIF processing takes significantly longer than expected.

**Diagnosis**:

```python
from __future__ import annotations


def benchmark_processing(file_path: str) -> None:
    """Benchmark LDIF processing performance."""
    import time
    import os

    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
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
        u.Cli.print(f"Parsing failed: {parse_result.error}")
```

**Optimization**:

```python
from __future__ import annotations


def optimize_processing_config() -> FlextLdifModels.Config:
    """Create optimized configuration for performance."""
    return FlextLdifModels.Config(
        max_entries=None,  # No artificial limits
        strict_validation=False,  # Faster processing
        ignore_unknown_attributes=True,  # Skip unknown attributes
        buffer_size=32768,  # Larger buffer for I/O
    )


def process_with_optimization(file_path: str) -> p.Result[m.Dict]:
    """Process LDIF with performance optimizations."""
    settings = optimize_processing_config()
    api = ldif(settings=settings)

    return api.parse_file(file_path).map(
        lambda entries: {"entry_count": len(entries), "processing_optimized": True}
    )
```

### Integration Issues

#### FlextContainer Registration Problems

**Symptom**: Services fail to register or retrieve from FlextContainer.

```python
# Error: "Service registration failed"
container = FlextContainer.get_global()
result = container.bind("ldif_api", api)
# result.failure == True
```

**Solution**:

```python
from __future__ import annotations


def debug_container_issues() -> None:
    """Debug FlextContainer registration issues."""

    from flext_ldif import ldif

    container = FlextContainer.get_global()

    # Check container status
    u.Cli.print(f"Container type: {type(container)}")

    # Try registration with error handling
    api = ldif()
    registration_result = container.bind("ldif_api", api)

    if registration_result.success:
        u.Cli.print("✓ Service registered successfully")

        # Test retrieval
        retrieval_result = container.resolve("ldif_api")
        if retrieval_result.success:
            retrieved_api = retrieval_result.unwrap()
            u.Cli.print(f"✓ Service retrieved: {type(retrieved_api)}")
        else:
            u.Cli.print(f"✗ Retrieval failed: {retrieval_result.error}")
    else:
        u.Cli.print(f"✗ Registration failed: {registration_result.error}")


def safe_service_registration() -> p.Result[ldif]:
    """Safely register LDIF service with error handling."""
    container = FlextContainer.get_global()

    # Create API instance
    api = ldif()

    # Attempt registration
    registration_result = container.bind("ldif_api", api)
    if registration_result.failure:
        return r[ldif].fail(f"Failed to register LDIF API: {registration_result.error}")

    # Verify registration by retrieving
    retrieval_result = container.resolve("ldif_api")
    if retrieval_result.failure:
        return r[ldif].fail(f"Failed to retrieve LDIF API: {retrieval_result.error}")

    return r[ldif].ok(retrieval_result.unwrap())
```

#### r Chain Errors

**Symptom**: Railway-oriented programming chains fail unexpectedly.

```python
# Error in chain composition
result = (
    api
    .parse_file(file_path)
    .flat_map(api.validate_entries)  # Error: expects bool, gets list
    .flat_map(api.filter_persons)
)
```

**Solution**:

```python
from __future__ import annotations


def correct_railway_chaining(file_path: str) -> p.Result[list]:
    """Demonstrate correct r chaining."""
    api = ldif()

    return (
        # Parse file
        api
        .parse_file(file_path)
        # Validate entries (return original entries on success)
        .flat_map(
            lambda entries: api.validate_entries(entries).map(lambda _: entries)
        )  # Discard bool, return entries
        # Filter persons
        .flat_map(api.filter_persons)
        # Add error context
        .map_error(lambda error: f"Processing chain failed: {error}")
    )


def debug_railway_chain(file_path: str) -> p.Result[list]:
    """Debug railway-oriented programming chains."""
    api = ldif()

    # Step 1: Parse
    u.Cli.print("Step 1: Parsing file...")
    parse_result = api.parse_file(file_path)
    if parse_result.failure:
        u.Cli.print(f"❌ Parse failed: {parse_result.error}")
        return parse_result

    entries = parse_result.unwrap()
    u.Cli.print(f"✓ Parsed {len(entries)} entries")

    # Step 2: Validate
    u.Cli.print("Step 2: Validating entries...")
    validation_result = api.validate_entries(entries)
    if validation_result.failure:
        u.Cli.print(f"❌ Validation failed: {validation_result.error}")
        return r[list].fail(validation_result.error)

    u.Cli.print("✓ Validation passed")

    # Step 3: Filter
    u.Cli.print("Step 3: Filtering persons...")
    filter_result = api.filter_persons(entries)
    if filter_result.failure:
        u.Cli.print(f"❌ Filtering failed: {filter_result.error}")
        return filter_result

    persons = filter_result.unwrap()
    u.Cli.print(f"✓ Found {len(persons)} person entries")

    return r[list].ok(persons)
```

## Diagnostic Tools

### Health Check Utility

```python
from __future__ import annotations


def run_health_check() -> t.JsonMapping:
    """Run comprehensive health check for FLEXT-LDIF."""
    results = {"status": "healthy", "checks": {}, "warnings": [], "errors": []}

    # Check imports
    try:
        from flext_ldif import ldif, FlextLdifModels

        results["checks"]["imports"] = "✓ All imports successful"
    except ImportError as e:
        results["checks"]["imports"] = f"❌ Import failed: {e}"
        results["status"] = "unhealthy"
        results["errors"].append(f"Import error: {e}")

    # Check API initialization
    try:
        api = ldif()
        results["checks"]["api_init"] = "✓ API initializes successfully"
    except Exception as e:
        results["checks"]["api_init"] = f"❌ API initialization failed: {e}"
        results["status"] = "unhealthy"
        results["errors"].append(f"API initialization error: {e}")

    # Check basic functionality
    try:
        test_ldif = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""
        parse_result = api.parse_string(test_ldif)
        if parse_result.success:
            results["checks"]["basic_parsing"] = "✓ Basic parsing works"
        else:
            results["checks"]["basic_parsing"] = (
                f"⚠️ Basic parsing issue: {parse_result.error}"
            )
            results["warnings"].append(f"Basic parsing issue: {parse_result.error}")
    except Exception as e:
        results["checks"]["basic_parsing"] = f"❌ Basic parsing failed: {e}"
        results["errors"].append(f"Basic parsing error: {e}")

    # Check container integration
    try:
        container = FlextContainer.get_global()
        reg_result = container.bind("health_check_api", api)
        if reg_result.success:
            results["checks"]["container_integration"] = "✓ Container integration works"
        else:
            results["checks"]["container_integration"] = (
                f"⚠️ Container issue: {reg_result.error}"
            )
            results["warnings"].append(
                f"Container integration issue: {reg_result.error}"
            )
    except Exception as e:
        results["checks"]["container_integration"] = (
            f"❌ Container integration failed: {e}"
        )
        results["errors"].append(f"Container integration error: {e}")

    return results


def print_health_check_report() -> None:
    """Print formatted health check report."""
    results = run_health_check()

    u.Cli.print("=== FLEXT-LDIF Health Check ===")
    u.Cli.print(f"Overall Status: {results['status'].upper()}")
    u.Cli.print()

    u.Cli.print("Checks:")
    for check, result in results["checks"].items():
        u.Cli.print(f"  {check}: {result}")

    if results["warnings"]:
        u.Cli.print("\nWarnings:")
        for warning in results["warnings"]:
            u.Cli.print(f"  ⚠️ {warning}")

    if results["errors"]:
        u.Cli.print("\nErrors:")
        for error in results["errors"]:
            u.Cli.print(f"  ❌ {error}")

    u.Cli.print()
    u.Cli.print("For additional help, see: docs/troubleshooting.md")
```

### Debug Mode Configuration

```python
from __future__ import annotations

from flext_ldif import FlextLdif, FlextLdifModels, ldif, u


def enable_debug_mode() -> FlextLdif:
    """Enable comprehensive debug mode."""

    # Configure debug logging
    logger = u.fetch_logger(__name__)
    logger.set_level("DEBUG")

    # Create debug configuration
    debug_config = FlextLdifModels.Config(
        strict_validation=True, ignore_unknown_attributes=False, log_level="DEBUG"
    )

    api = ldif(settings=debug_config)

    u.Cli.print("🐛 Debug mode enabled:")
    u.Cli.print("  - Strict validation active")
    u.Cli.print("  - All attributes processed")
    u.Cli.print("  - Verbose logging enabled")

    return api
```

## Getting Help

### Support Resources

- **Documentation**: Complete documentation
- **API Reference**: API documentation
- **Examples**: Usage examples
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext-ldif/issues)

### Creating Support Requests

When creating support requests, include:

```python
from __future__ import annotations


def generate_support_info() -> t.JsonMapping:
    """Generate information for support requests."""
    import sys
    import platform
    from flext_ldif import __version__ as ldif_version

    return {
        "flext_ldif_version": ldif_version,
        "python_version": sys.version,
        "platform": platform.platform(),
        "health_check": run_health_check(),
        "reproduction_steps": "Include steps to reproduce the issue",
        "expected_behavior": "Describe expected behavior",
        "actual_behavior": "Describe actual behavior",
    }
```

### Emergency Contacts

For critical production issues:

1. Check health status: `run_health_check()`
1. Review logs for error patterns
1. Attempt with debug configuration
1. Document issue with support information
1. Contact FLEXT support team with detailed report

______________________________________________________________________

This troubleshooting guide provides comprehensive solutions for common FLEXT-LDIF issues while maintaining integration with FLEXT ecosystem support patterns.
