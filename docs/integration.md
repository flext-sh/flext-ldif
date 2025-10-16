# FLEXT-LDIF Ecosystem Integration

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

LDIF-specific integration patterns for using FLEXT-LDIF within the FLEXT ecosystem. For general FLEXT patterns, see [flext-core documentation](../../flext-core/README.md).

## LDIF Processing Integration

### Core LDIF Operations with FlextResult

```python
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import FlextHandlers
from flext_core import FlextLogger
from flext_core import FlextMixins
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import FlextProtocols
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import FlextTypes
from flext_core import FlextUtilities
from flext_ldif import FlextLdif

def process_directory_export(file_path: str) -> FlextResult[FlextTypes.Dict]:
    """Process LDIF directory export with railway programming."""
    api = FlextLdif()

    return (
        # Parse LDIF file (memory-bound operation)
        api.parse_file(file_path)

        # Validate entries and continue with entries on success
        .flat_map(lambda entries:
            api.validate_entries(entries).map(lambda _: entries))

        # Filter person entries for directory processing
        .flat_map(api.filter_persons)

        # Generate LDIF-specific statistics
        .flat_map(lambda persons:
            api.get_entry_statistics(persons)
            .map(lambda stats: {'persons': persons, 'stats': stats}))

        # Add LDIF-specific error context
        .map_error(lambda error: f"LDIF directory processing failed: {error}")
    )
```

### Memory-Aware LDIF Processing

```python
import os
from pathlib import Path

def process_ldif_with_memory_check(file_path: Path) -> FlextResult[FlextTypes.Dict]:
    """Process LDIF with memory size validation."""
    api = FlextLdif()

    # Check file size before processing (custom parser loads into memory)
    file_size = file_path.stat().st_size
    max_size = 100 * 1024 * 1024  # 100MB limit for memory-bound parser

    if file_size > max_size:
        return FlextResult[FlextTypes.Dict].fail(
            f"File too large ({file_size} bytes). "
            f"Current implementation limited to {max_size} bytes."
        )

    return api.parse_file(file_path)
```

## Enterprise Directory Migration Integration

### ALGAR Oracle Unified Directory Migration

```python
from flext_ldif import FlextLdif, FlextLdifModels
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import FlextHandlers
from flext_core import FlextLogger
from flext_core import FlextMixins
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import FlextProtocols
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import FlextTypes
from flext_core import FlextUtilities
from pathlib import Path

class ALGAROUDMigrationService:
    """ALGAR Oracle Unified Directory LDIF processing."""

    def __init__(self) -> None:
        self.logger = FlextLogger(__name__)

        # Configure for enterprise migration with legacy data accommodation
        migration_config = FlextLdifModels.Config(
            max_entries=None,  # No entry limits for enterprise data
            strict_validation=False,  # Accommodate legacy LDIF variations
            ignore_unknown_attributes=True,  # Handle custom schema attributes
            encoding='utf-8'
        )

        self._ldif_api = FlextLdif(config=migration_config)

    def process_oud_export(self, export_file: Path) -> FlextResult[FlextTypes.Dict]:
        """Process Oracle Unified Directory LDIF export."""
        self.logger.info("Starting OUD LDIF processing", extra={
            'export_file': str(export_file),
            'migration_phase': 'ldif_processing'
        })

        return (
            # Parse enterprise LDIF export
            self._ldif_api.parse_file(export_file)

            # Categorize entries for migration-specific processing
            .flat_map(self._categorize_ldif_entries)

            # Apply ALGAR-specific directory transformations
            .flat_map(self._apply_migration_transformations)

            # Generate migration-specific report
            .map(self._generate_migration_report)

            # Log LDIF processing completion
            .map(self._log_ldif_completion)
        )

    def _categorize_ldif_entries(self, entries) -> FlextResult[FlextTypes.Dict]:
        """Categorize LDIF entries for migration processing."""
        try:
            users = []
            groups = []
            organizational_units = []
            other = []

            for entry in entries:
                if entry.is_person():
                    users.append(entry)
                elif entry.is_group():
                    groups.append(entry)
                elif entry.has_object_class('organizationalUnit'):
                    organizational_units.append(entry)
                else:
                    other.append(entry)

            return FlextResult[FlextTypes.Dict].ok({
                'users': users,
                'groups': groups,
                'organizational_units': organizational_units,
                'other': other,
                'total': len(entries)
            })
        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"LDIF entry categorization failed: {e}")

    def _apply_migration_transformations(self, categorized: dict) -> FlextResult[FlextTypes.Dict]:
        """Apply ALGAR-specific LDIF entry transformations."""
        # LDIF-specific transformations for OUD migration

        self.logger.info("Applying LDIF migration transformations", extra={
            'user_count': len(categorized['users']),
            'group_count': len(categorized['groups']),
            'ou_count': len(categorized['organizational_units']),
            'other_count': len(categorized['other'])
        })

        # Apply ALGAR business rules to LDIF entries
        transformed_users = self._transform_user_entries(categorized['users'])
        transformed_groups = self._transform_group_entries(categorized['groups'])

        return FlextResult[FlextTypes.Dict].ok({
            'users': transformed_users,
            'groups': transformed_groups,
            'organizational_units': categorized['organizational_units'],
            'other': categorized['other'],
            'total': categorized['total']
        })

    def _transform_user_entries(self, user_entries):
        """Transform user LDIF entries for ALGAR migration."""
        # LDIF-specific user entry transformations
        return user_entries

    def _transform_group_entries(self, group_entries):
        """Transform group LDIF entries for ALGAR migration."""
        # LDIF-specific group entry transformations
        return group_entries

    def _generate_migration_report(self, processed_data: dict) -> dict[str, object]:
        """Generate LDIF migration processing report."""
        return {
            'ldif_migration_summary': {
                'total_entries_processed': processed_data['total'],
                'users_processed': len(processed_data['users']),
                'groups_processed': len(processed_data['groups']),
                'organizational_units': len(processed_data['organizational_units']),
                'other_entries': len(processed_data['other'])
            },
            'ldif_processing_status': 'completed',
            'processed_data': processed_data
        }

    def _log_ldif_completion(self, report: dict) -> dict[str, object]:
        """Log LDIF migration processing completion."""
        self.logger.info("OUD LDIF processing completed", extra={
            'ldif_summary': report['ldif_migration_summary'],
            'migration_phase': 'ldif_processing_complete'
        })
        return report
```

## LDIF-Specific Service Integration

### LDIF API Service Integration

```python
from flext_api import FlextAPIService
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import FlextHandlers
from flext_core import FlextLogger
from flext_core import FlextMixins
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import FlextProtocols
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import FlextTypes
from flext_core import FlextUtilities
from flext_ldif import FlextLdif

class LdifAPIService(FlextAPIService):
    """REST API service for LDIF processing operations."""

    def __init__(self) -> None:
        super().__init__()
        self._ldif_api = FlextLdif()

    def parse_ldif_endpoint(self, file_content: str) -> FlextResult[FlextTypes.Dict]:
        """API endpoint for LDIF parsing with memory awareness."""
        # Check content size before processing
        content_size = len(file_content.encode('utf-8'))
        max_size = 50 * 1024 * 1024  # 50MB for API operations

        if content_size > max_size:
            return FlextResult[FlextTypes.Dict].fail({
                'status': 'error',
                'message': f'LDIF content too large ({content_size} bytes). Maximum: {max_size} bytes.',
                'error_type': 'memory_limit_exceeded'
            })

        return (
            self._ldif_api.parse_string(file_content)
            .map(lambda entries: {
                'status': 'success',
                'entry_count': len(entries),
                'memory_usage': f'{content_size} bytes processed',
                'entries': [self._serialize_ldif_entry(entry) for entry in entries[:100]]  # Limit response size
            })
            .map_error(lambda error: {
                'status': 'error',
                'message': f'LDIF parsing failed: {error}',
                'error_type': 'ldif_parse_error'
            })
        )

    def _serialize_ldif_entry(self, entry) -> dict[str, object]:
        """Serialize LDIF entry for API response."""
        return {
            'dn': entry.dn,
            'object_classes': entry.get_object_classes(),
            'is_person': entry.is_person(),
            'is_group': entry.is_group(),
            'attribute_count': len(entry.attributes)
        }
```

### LDIF CLI Service Integration

```python
from flext_cli import FlextCliService
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import FlextHandlers
from flext_core import FlextLogger
from flext_core import FlextMixins
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import FlextProtocols
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import FlextTypes
from flext_core import FlextUtilities
from flext_ldif import FlextLdif
from pathlib import Path

class LdifCLIService(FlextCliService):
    """CLI service for LDIF operations with memory monitoring."""

    def __init__(self) -> None:
        super().__init__()
        self._ldif_api = FlextLdif()

    def parse_command(self, input_file: str, output_format: str = 'summary') -> FlextResult[None]:
        """CLI command for parsing LDIF files with size checking."""
        file_path = Path(input_file)

        # Check file size before processing
        if not file_path.exists():
            return FlextResult[None].fail(f"LDIF file not found: {input_file}")

        file_size = file_path.stat().st_size
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            return FlextResult[None].fail(
                f"LDIF file too large ({file_size} bytes). "
                f"Current implementation limited to 100MB."
            )

        return (
            self._ldif_api.parse_file(file_path)
            .flat_map(lambda entries: self._output_ldif_results(entries, output_format))
            .map_error(lambda error: f"LDIF CLI parse failed: {error}")
        )

    def _output_ldif_results(self, entries, format_type: str) -> FlextResult[None]:
        """Output LDIF parsing results in specified format."""
        if format_type == 'summary':
            print(f"LDIF Processing Summary:")
            print(f"  Total entries: {len(entries)}")

            # Get LDIF-specific statistics
            stats_result = self._ldif_api.get_entry_statistics(entries)
            if stats_result.is_success:
                stats = stats_result.unwrap()
                print(f"  Object class distribution: {stats}")

            # Count person and group entries
            persons = [e for e in entries if e.is_person()]
            groups = [e for e in entries if e.is_group()]
            print(f"  Person entries: {len(persons)}")
            print(f"  Group entries: {len(groups)}")

            return FlextResult[None].ok(None)
        elif format_type == 'json':
            import json
            output = json.dumps([
                {
                    'dn': entry.dn,
                    'object_classes': entry.get_object_classes(),
                    'is_person': entry.is_person(),
                    'is_group': entry.is_group()
                }
                for entry in entries
            ], indent=2)
            print(output)
            return FlextResult[None].ok(None)
        else:
            return FlextResult[None].fail(f"Unsupported LDIF output format: {format_type}")
```

## LDIF Data Pipeline Integration

### Batch LDIF Processing

```python
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import FlextHandlers
from flext_core import FlextLogger
from flext_core import FlextMixins
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import FlextProtocols
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import FlextTypes
from flext_core import FlextUtilities
from flext_ldif import FlextLdif
from pathlib import Path
import psutil
import os

def process_multiple_ldif_files(file_paths: list[Path]) -> FlextResult[FlextTypes.Dict]:
    """Process multiple LDIF files with memory monitoring."""
    api = FlextLdif()
    all_entries = []
    processing_stats = {}
    process = psutil.Process(os.getpid())

    initial_memory = process.memory_info().rss

    for file_path in file_paths:
        # Memory check before each file
        current_memory = process.memory_info().rss
        memory_increase = current_memory - initial_memory

        if memory_increase > 500 * 1024 * 1024:  # 500MB increase limit
            return FlextResult[FlextTypes.Dict].fail(
                f"Memory usage too high ({memory_increase} bytes). "
                f"Processed {len(processing_stats)} files before limit."
            )

        result = api.parse_file(file_path)
        if result.is_success:
            entries = result.unwrap()
            all_entries.extend(entries)
            processing_stats[str(file_path)] = {
                'entries': len(entries),
                'memory_after': current_memory
            }
        else:
            return FlextResult[FlextTypes.Dict].fail(f"Failed to process {file_path}: {result.error}")

    final_memory = process.memory_info().rss
    total_memory_used = final_memory - initial_memory

    return FlextResult[FlextTypes.Dict].ok({
        'total_entries': len(all_entries),
        'files_processed': len(processing_stats),
        'file_stats': processing_stats,
        'memory_usage': {
            'initial_memory': initial_memory,
            'final_memory': final_memory,
            'total_increase': total_memory_used
        },
        'entries': all_entries
    })
```

## LDIF Integration Best Practices

### 1. Memory-Aware Processing

Always check file sizes before processing with current implementation:

```python
def safe_ldif_processing(file_path: Path) -> FlextResult[list]:
    """Process LDIF with memory safety checks."""
    file_size = file_path.stat().st_size
    max_size = 100 * 1024 * 1024  # 100MB limit

    if file_size > max_size:
        return FlextResult[list].fail(
            f"File too large for current implementation: {file_size} bytes"
        )

    api = FlextLdif()
    return api.parse_file(file_path)
```

### 2. LDIF-Specific Error Handling

Handle LDIF format errors specifically:

```python
def robust_ldif_processing(content: str) -> FlextResult[FlextTypes.Dict]:
    """Process LDIF with format-specific error handling."""
    api = FlextLdif()

    result = api.parse_string(content)
    if result.is_failure:
        error_msg = result.error
        if "LDIF" in error_msg or "parse" in error_msg.lower():
            return FlextResult[FlextTypes.Dict].fail(f"LDIF format error: {error_msg}")
        else:
            return FlextResult[FlextTypes.Dict].fail(f"Processing error: {error_msg}")

    return FlextResult[FlextTypes.Dict].ok({'entries': result.unwrap()})
```

### 3. LDIF Entry Type Processing

Use LDIF-specific entry type methods:

```python
def categorize_ldif_entries(entries) -> dict[str, object]:
    """Categorize LDIF entries by type."""
    categories = {
        'persons': [e for e in entries if e.is_person()],
        'groups': [e for e in entries if e.is_group()],
        'organizational_units': [e for e in entries if e.has_object_class('organizationalUnit')],
        'other': []
    }

    # Find entries that don't fit standard categories
    categorized = set(categories['persons'] + categories['groups'] + categories['organizational_units'])
    categories['other'] = [e for e in entries if e not in categorized]

    return categories
```

## Performance Considerations

### Current Implementation Limitations

- **Memory Usage**: Entire LDIF file loaded into memory during processing
- **Single-threaded**: No parallel processing support
- **No Streaming**: Cannot process files larger than available memory
- **No Progress Reporting**: Long operations provide no feedback

### Recommended Usage Patterns

```python
# ✅ Good: Small to medium LDIF files
def process_small_ldif(file_path: Path) -> FlextResult[FlextTypes.Dict]:
    """Process LDIF files under 100MB."""
    if file_path.stat().st_size > 100 * 1024 * 1024:
        return FlextResult[FlextTypes.Dict].fail("File too large for current implementation")

    api = FlextLdif()
    return api.parse_file(file_path)

# ⚠️ Consider: External tools for large files
def process_large_ldif(file_path: Path) -> FlextResult[str]:
    """For large LDIF files, use external tools first."""
    # Use grep, awk, or other streaming tools to pre-process
    # Then use FLEXT-LDIF for final processing of smaller chunks
    return FlextResult[str].fail("Large file processing not yet implemented")
```

---

This integration guide focuses on LDIF-specific patterns within the FLEXT ecosystem. For general FLEXT patterns, see [flext-core documentation](../../flext-core/README.md).
