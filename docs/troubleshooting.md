# FLEXT-LDIF Troubleshooting

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

This document provides solutions to common issues encountered when using FLEXT-LDIF, including error diagnosis, performance problems, and integration issues.

## Common Issues and Solutions

### Parse Errors

#### Invalid LDIF Format

**Symptom**: Parse operations fail with format-related error messages.

```python
result = api.parse_string(ldif_content)
if result.is_failure:
    print(f"Parse error: {result.error}")
    # Common error: "Invalid LDIF format: missing DN"
```

**Solution**:

```python
def diagnose_ldif_format(content: str) -> None:
    """Diagnose LDIF format issues."""
    lines = content.strip().split('\n')

    print(f"Total lines: {len(lines)}")
    print("First few lines:")
    for i, line in enumerate(lines[:5]):
        print(f"{i+1}: '{line}'")

    # Check for common issues
    if not any(line.startswith('dn:') for line in lines):
        print("❌ No DN found - LDIF entries must start with 'dn:'")

    # Check line folding issues
    for i, line in enumerate(lines):
        if line.startswith(' ') and i == 0:
            print(f"❌ Line {i+1} starts with space but is first line")

    # Check character encoding
    try:
        content.encode('utf-8')
        print("✓ UTF-8 encoding valid")
    except UnicodeError as e:
        print(f"❌ Encoding issue: {e}")
```

#### Character Encoding Issues

**Symptom**: Parse fails with encoding-related errors.

```python
# Common encoding error
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 123
```

**Solution**:

```python
def handle_encoding_issues(file_path: str) -> FlextResult[str]:
    """Handle various character encodings."""
    encodings_to_try = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']

    for encoding in encodings_to_try:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            print(f"✓ Successfully read with {encoding} encoding")
            return FlextResult[str].ok(content)
        except UnicodeDecodeError:
            print(f"✗ Failed with {encoding} encoding")
            continue

    return FlextResult[str].fail("Unable to decode file with any supported encoding")

# Usage with custom encoding
def parse_with_encoding_detection(file_path: str) -> FlextResult[list]:
    """Parse LDIF with automatic encoding detection."""
    content_result = handle_encoding_issues(file_path)
    if content_result.is_failure:
        return FlextResult[list].fail(content_result.error)

    api = FlextLdif()
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
def process_large_file_safely(file_path: str) -> FlextResult[t.Dict]:
    """Process large LDIF files with memory management."""
    import psutil
    import os

    # Check available memory
    available_memory_gb = psutil.virtual_memory().available / (1024**3)
    file_size_gb = os.path.getsize(file_path) / (1024**3)

    print(f"File size: {file_size_gb:.2f} GB")
    print(f"Available memory: {available_memory_gb:.2f} GB")

    if file_size_gb > available_memory_gb * 0.5:
        return FlextResult[t.Dict].fail(
            f"File too large for available memory. "
            f"File: {file_size_gb:.2f}GB, Available: {available_memory_gb:.2f}GB"
        )

    # Configure for large files
    config = FlextLdifModels.Config(
        max_entries=50000,  # Limit entries
        buffer_size=16384   # Smaller buffer
    )

    api = FlextLdif(config=config)
    return api.parse_file(file_path)

def chunk_process_file(file_path: str, chunk_size: int = 10000) -> FlextResult[t.Dict]:
    """Process file in chunks to manage memory."""
    results = {'total_entries': 0, 'processed_chunks': 0}

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            current_chunk = []
            current_entry = []

            for line in f:
                if line.startswith('dn:') and current_entry:
                    # Process completed entry
                    current_chunk.append('\n'.join(current_entry))
                    current_entry = [line.strip()]

                    if len(current_chunk) >= chunk_size:
                        # Process chunk
                        chunk_result = process_chunk(current_chunk)
                        if chunk_result.is_success:
                            results['total_entries'] += len(current_chunk)
                            results['processed_chunks'] += 1
                        current_chunk = []
                else:
                    current_entry.append(line.strip())

            # Process final chunk
            if current_chunk:
                chunk_result = process_chunk(current_chunk)
                if chunk_result.is_success:
                    results['total_entries'] += len(current_chunk)
                    results['processed_chunks'] += 1

        return FlextResult[t.Dict].ok(results)
    except Exception as e:
        return FlextResult[t.Dict].fail(f"Chunk processing failed: {e}")

def process_chunk(chunk_entries: t.StringList) -> FlextResult[bool]:
    """Process a chunk of LDIF entries."""
    chunk_content = '\n\n'.join(chunk_entries)
    api = FlextLdif()
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
def handle_validation_errors(entries: list) -> FlextResult[list]:
    """Handle validation errors with detailed reporting."""
    # Try with strict validation first
    strict_config = FlextLdifModels.Config(strict_validation=True)
    strict_api = FlextLdif(config=strict_config)

    strict_result = strict_api.validate_entries(entries)
    if strict_result.is_success:
        print("✓ All entries pass strict validation")
        return FlextResult[list].ok(entries)

    print(f"✗ Strict validation failed: {strict_result.error}")

    # Try with permissive validation
    permissive_config = FlextLdifModels.Config(
        strict_validation=False,
        ignore_unknown_attributes=True
    )
    permissive_api = FlextLdif(config=permissive_config)

    permissive_result = permissive_api.validate_entries(entries)
    if permissive_result.is_success:
        print("✓ Entries pass permissive validation")
        print("⚠️  Consider reviewing data quality")
        return FlextResult[list].ok(entries)

    return FlextResult[list].fail(f"Validation failed: {permissive_result.error}")

def analyze_entry_issues(entries: list) -> None:
    """Analyze common entry validation issues."""
    for i, entry in enumerate(entries):
        print(f"\nEntry {i+1}: {entry.dn}")

        # Check DN format
        if not entry.dn or '=' not in entry.dn:
            print("  ❌ Invalid DN format")

        # Check object classes
        object_classes = entry.get_object_classes()
        if not object_classes:
            print("  ❌ Missing object class")

        # Check required attributes for person entries
        if 'person' in object_classes:
            if not entry.get_attribute_values('cn'):
                print("  ❌ Person missing required 'cn' attribute")
            if not entry.get_attribute_values('sn'):
                print("  ❌ Person missing required 'sn' attribute")

        # Check for empty attributes
        for attr_name, attr_values in entry.attributes.items():
            if not attr_values or any(not v.strip() for v in attr_values):
                print(f"  ⚠️  Empty values in attribute '{attr_name}'")
```

### Performance Issues

#### Slow Processing

**Symptom**: LDIF processing takes significantly longer than expected.

**Diagnosis**:

```python
def benchmark_processing(file_path: str) -> None:
    """Benchmark LDIF processing performance."""
    import time
    import os

    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    print(f"File size: {file_size_mb:.2f} MB")

    api = FlextLdif()

    # Benchmark parsing
    start_time = time.time()
    parse_result = api.parse_file(file_path)
    parse_time = time.time() - start_time

    if parse_result.is_success:
        entries = parse_result.unwrap()
        print(f"Parsed {len(entries)} entries in {parse_time:.2f} seconds")
        print(f"Processing rate: {len(entries) / parse_time:.1f} entries/second")
        print(f"Throughput: {file_size_mb / parse_time:.2f} MB/second")

        # Benchmark validation
        start_time = time.time()
        validation_result = api.validate_entries(entries)
        validation_time = time.time() - start_time

        if validation_result.is_success:
            print(f"Validated in {validation_time:.2f} seconds")
        else:
            print(f"Validation failed: {validation_result.error}")
    else:
        print(f"Parsing failed: {parse_result.error}")
```

**Optimization**:

```python
def optimize_processing_config() -> FlextLdifModels.Config:
    """Create optimized configuration for performance."""
    return FlextLdifModels.Config(
        max_entries=None,           # No artificial limits
        strict_validation=False,    # Faster processing
        ignore_unknown_attributes=True,  # Skip unknown attributes
        buffer_size=32768          # Larger buffer for I/O
    )

def process_with_optimization(file_path: str) -> FlextResult[t.Dict]:
    """Process LDIF with performance optimizations."""
    config = optimize_processing_config()
    api = FlextLdif(config=config)

    return (
        api.parse_file(file_path)
        .map(lambda entries: {
            'entry_count': len(entries),
            'processing_optimized': True
        })
    )
```

### Integration Issues

#### FlextContainer Registration Problems

**Symptom**: Services fail to register or retrieve from FlextContainer.

```python
# Error: "Service registration failed"
container = FlextContainer.get_global()
result = container.register("ldif_api", api)
# result.is_failure == True
```

**Solution**:

```python
def debug_container_issues() -> None:
    """Debug FlextContainer registration issues."""

    from flext_ldif import FlextLdif

    container = FlextContainer.get_global()

    # Check container status
    print(f"Container type: {type(container)}")

    # Try registration with error handling
    api = FlextLdif()
    registration_result = container.register("ldif_api", api)

    if registration_result.is_success:
        print("✓ Service registered successfully")

        # Test retrieval
        retrieval_result = container.get("ldif_api")
        if retrieval_result.is_success:
            retrieved_api = retrieval_result.unwrap()
            print(f"✓ Service retrieved: {type(retrieved_api)}")
        else:
            print(f"✗ Retrieval failed: {retrieval_result.error}")
    else:
        print(f"✗ Registration failed: {registration_result.error}")

def safe_service_registration() -> FlextResult[FlextLdif]:
    """Safely register LDIF service with error handling."""
    container = FlextContainer.get_global()

    # Create API instance
    api = FlextLdif()

    # Attempt registration
    registration_result = container.register("ldif_api", api)
    if registration_result.is_failure:
        return FlextResult[FlextLdif].fail(
            f"Failed to register LDIF API: {registration_result.error}"
        )

    # Verify registration by retrieving
    retrieval_result = container.get("ldif_api")
    if retrieval_result.is_failure:
        return FlextResult[FlextLdif].fail(
            f"Failed to retrieve LDIF API: {retrieval_result.error}"
        )

    return FlextResult[FlextLdif].ok(retrieval_result.unwrap())
```

#### FlextResult Chain Errors

**Symptom**: Railway-oriented programming chains fail unexpectedly.

```python
# Error in chain composition
result = (
    api.parse_file(file_path)
    .flat_map(api.validate_entries)  # Error: expects bool, gets list
    .flat_map(api.filter_persons)
)
```

**Solution**:

```python
def correct_railway_chaining(file_path: str) -> FlextResult[list]:
    """Demonstrate correct FlextResult chaining."""
    api = FlextLdif()

    return (
        # Parse file
        api.parse_file(file_path)

        # Validate entries (return original entries on success)
        .flat_map(lambda entries:
            api.validate_entries(entries)
            .map(lambda _: entries))  # Discard bool, return entries

        # Filter persons
        .flat_map(api.filter_persons)

        # Add error context
        .map_error(lambda error: f"Processing chain failed: {error}")
    )

def debug_railway_chain(file_path: str) -> FlextResult[list]:
    """Debug railway-oriented programming chains."""
    api = FlextLdif()

    # Step 1: Parse
    print("Step 1: Parsing file...")
    parse_result = api.parse_file(file_path)
    if parse_result.is_failure:
        print(f"❌ Parse failed: {parse_result.error}")
        return parse_result

    entries = parse_result.unwrap()
    print(f"✓ Parsed {len(entries)} entries")

    # Step 2: Validate
    print("Step 2: Validating entries...")
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        print(f"❌ Validation failed: {validation_result.error}")
        return FlextResult[list].fail(validation_result.error)

    print("✓ Validation passed")

    # Step 3: Filter
    print("Step 3: Filtering persons...")
    filter_result = api.filter_persons(entries)
    if filter_result.is_failure:
        print(f"❌ Filtering failed: {filter_result.error}")
        return filter_result

    persons = filter_result.unwrap()
    print(f"✓ Found {len(persons)} person entries")

    return FlextResult[list].ok(persons)
```

## Diagnostic Tools

### Health Check Utility

```python
def run_health_check() -> dict[str, object]:
    """Run comprehensive health check for FLEXT-LDIF."""
    results = {
        'status': 'healthy',
        'checks': {},
        'warnings': [],
        'errors': []
    }

    # Check imports
    try:
        from flext_ldif import FlextLdif, FlextLdifModels

        results['checks']['imports'] = '✓ All imports successful'
    except ImportError as e:
        results['checks']['imports'] = f'❌ Import failed: {e}'
        results['status'] = 'unhealthy'
        results['errors'].append(f'Import error: {e}')

    # Check API initialization
    try:
        api = FlextLdif()
        results['checks']['api_init'] = '✓ API initializes successfully'
    except Exception as e:
        results['checks']['api_init'] = f'❌ API initialization failed: {e}'
        results['status'] = 'unhealthy'
        results['errors'].append(f'API initialization error: {e}')

    # Check basic functionality
    try:
        test_ldif = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""
        parse_result = api.parse_string(test_ldif)
        if parse_result.is_success:
            results['checks']['basic_parsing'] = '✓ Basic parsing works'
        else:
            results['checks']['basic_parsing'] = f'⚠️ Basic parsing issue: {parse_result.error}'
            results['warnings'].append(f'Basic parsing issue: {parse_result.error}')
    except Exception as e:
        results['checks']['basic_parsing'] = f'❌ Basic parsing failed: {e}'
        results['errors'].append(f'Basic parsing error: {e}')

    # Check container integration
    try:
        container = FlextContainer.get_global()
        reg_result = container.register("health_check_api", api)
        if reg_result.is_success:
            results['checks']['container_integration'] = '✓ Container integration works'
        else:
            results['checks']['container_integration'] = f'⚠️ Container issue: {reg_result.error}'
            results['warnings'].append(f'Container integration issue: {reg_result.error}')
    except Exception as e:
        results['checks']['container_integration'] = f'❌ Container integration failed: {e}'
        results['errors'].append(f'Container integration error: {e}')

    return results

def print_health_check_report() -> None:
    """Print formatted health check report."""
    results = run_health_check()

    print("=== FLEXT-LDIF Health Check ===")
    print(f"Overall Status: {results['status'].upper()}")
    print()

    print("Checks:")
    for check, result in results['checks'].items():
        print(f"  {check}: {result}")

    if results['warnings']:
        print("\nWarnings:")
        for warning in results['warnings']:
            print(f"  ⚠️ {warning}")

    if results['errors']:
        print("\nErrors:")
        for error in results['errors']:
            print(f"  ❌ {error}")

    print()
    print("For additional help, see: docs/troubleshooting.md")
```

### Debug Mode Configuration

```python
def enable_debug_mode() -> FlextLdif:
    """Enable comprehensive debug mode."""


    # Configure debug logging
    logger = FlextLogger(__name__)
    logger.set_level('DEBUG')

    # Create debug configuration
    debug_config = FlextLdifModels.Config(
        strict_validation=True,
        ignore_unknown_attributes=False,
        log_level='DEBUG'
    )

    api = FlextLdif(config=debug_config)

    print("🐛 Debug mode enabled:")
    print("  - Strict validation active")
    print("  - All attributes processed")
    print("  - Verbose logging enabled")

    return api
```

## Getting Help

### Support Resources

- **Documentation**: [Complete documentation](../docs/)
- **API Reference**: [API documentation](api-reference.md)
- **Examples**: [Usage examples](examples/)
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext-ldif/issues)

### Creating Support Requests

When creating support requests, include:

```python
def generate_support_info() -> dict[str, object]:
    """Generate information for support requests."""
    import sys
    import platform
    from flext_ldif import __version__ as ldif_version

    return {
        'flext_ldif_version': ldif_version,
        'python_version': sys.version,
        'platform': platform.platform(),
        'health_check': run_health_check(),
        'reproduction_steps': "Include steps to reproduce the issue",
        'expected_behavior': "Describe expected behavior",
        'actual_behavior': "Describe actual behavior"
    }
```

### Emergency Contacts

For critical production issues:

1. Check health status: `run_health_check()`
2. Review logs for error patterns
3. Attempt with debug configuration
4. Document issue with support information
5. Contact FLEXT support team with detailed report

---

This troubleshooting guide provides comprehensive solutions for common FLEXT-LDIF issues while maintaining integration with FLEXT ecosystem support patterns.
