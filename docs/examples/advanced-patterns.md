# Advanced LDIF Processing Patterns

**Version**: 0.9.0 | **Updated**: September 17, 2025

This document demonstrates advanced patterns for using FLEXT-LDIF in complex scenarios, including enterprise integration, custom processing pipelines, and performance optimization techniques.

## Enterprise Integration Patterns

### Service-Oriented Processing

```python
from flext_ldif import FlextLDIFAPI, FlextLDIFModels
from flext_core import FlextResult, FlextLogger, FlextContainer
from typing import Protocol
from pathlib import Path

class DirectoryProcessor:
    """Enterprise-grade directory processing service."""

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        self._logger = FlextLogger(__name__)
        self._container = FlextContainer.get_global()
        self._ldif_api = FlextLDIFAPI(config=config)

    def process_enterprise_export(self, export_path: Path) -> FlextResult[dict]:
        """Process enterprise directory export with comprehensive reporting."""
        self._logger.info("Starting enterprise export processing", extra={
            'export_file': str(export_path),
            'operation': 'enterprise_processing'
        })

        return (
            # Parse large enterprise export
            self._parse_with_monitoring(export_path)

            # Apply enterprise validation rules
            .flat_map(self._apply_enterprise_validation)

            # Categorize entries by business rules
            .flat_map(self._categorize_entries)

            # Generate comprehensive report
            .map(self._generate_enterprise_report)

            # Log completion
            .map(self._log_processing_completion)
        )

    def _parse_with_monitoring(self, file_path: Path) -> FlextResult[list]:
        """Parse with progress monitoring for large files."""
        import os
        import time

        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        self._logger.info(f"Processing file: {file_size_mb:.2f}MB", extra={
            'file_size_mb': file_size_mb,
            'stage': 'parsing'
        })

        start_time = time.time()
        result = self._ldif_api.parse_file(file_path)
        processing_time = time.time() - start_time

        if result.is_success:
            entries = result.unwrap()
            self._logger.info("Parsing completed", extra={
                'entries_parsed': len(entries),
                'processing_time_seconds': processing_time,
                'entries_per_second': len(entries) / processing_time if processing_time > 0 else 0
            })

        return result

    def _apply_enterprise_validation(self, entries: list) -> FlextResult[list]:
        """Apply enterprise-specific validation rules."""
        validation_rules = [
            self._validate_required_attributes,
            self._validate_email_formats,
            self._validate_dn_structure
        ]

        valid_entries = []
        validation_errors = []

        for entry in entries:
            entry_valid = True
            for rule in validation_rules:
                rule_result = rule(entry)
                if rule_result.is_failure:
                    validation_errors.append({
                        'entry_dn': entry.dn,
                        'error': rule_result.error
                    })
                    entry_valid = False
                    break

            if entry_valid:
                valid_entries.append(entry)

        if validation_errors:
            self._logger.warning("Validation issues found", extra={
                'error_count': len(validation_errors),
                'valid_entries': len(valid_entries),
                'total_entries': len(entries)
            })

        return FlextResult[list].ok(valid_entries)

    def _validate_required_attributes(self, entry) -> FlextResult[None]:
        """Validate required attributes for different entry types."""
        if entry.is_person():
            required_attrs = ['cn', 'sn', 'mail']
            for attr in required_attrs:
                if not entry.get_attribute_values(attr):
                    return FlextResult[None].fail(f"Person entry missing required attribute: {attr}")

        return FlextResult[None].ok(None)

    def _validate_email_formats(self, entry) -> FlextResult[None]:
        """Validate email format compliance."""
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        emails = entry.get_attribute_values('mail')
        for email in emails:
            if not re.match(email_pattern, email):
                return FlextResult[None].fail(f"Invalid email format: {email}")

        return FlextResult[None].ok(None)

    def _validate_dn_structure(self, entry) -> FlextResult[None]:
        """Validate DN structure compliance."""
        dn = entry.dn
        if not dn or '=' not in dn:
            return FlextResult[None].fail("Invalid DN structure")

        # Check DN depth for organizational compliance
        dn_components = [comp.strip() for comp in dn.split(',')]
        if len(dn_components) < 3:  # Minimum: cn=user,ou=unit,dc=domain
            return FlextResult[None].fail("DN structure too shallow")

        return FlextResult[None].ok(None)

    def _categorize_entries(self, entries: list) -> FlextResult[dict]:
        """Categorize entries for enterprise processing."""
        categories = {
            'users': [],
            'groups': [],
            'organizational_units': [],
            'other': []
        }

        for entry in entries:
            if entry.is_person():
                categories['users'].append(entry)
            elif entry.is_group():
                categories['groups'].append(entry)
            elif 'organizationalUnit' in entry.get_object_classes():
                categories['organizational_units'].append(entry)
            else:
                categories['other'].append(entry)

        return FlextResult[dict].ok(categories)

    def _generate_enterprise_report(self, categorized: dict) -> dict:
        """Generate comprehensive enterprise processing report."""
        report = {
            'summary': {
                'total_entries': sum(len(entries) for entries in categorized.values()),
                'users': len(categorized['users']),
                'groups': len(categorized['groups']),
                'organizational_units': len(categorized['organizational_units']),
                'other': len(categorized['other'])
            },
            'user_analysis': self._analyze_users(categorized['users']),
            'group_analysis': self._analyze_groups(categorized['groups']),
            'ou_analysis': self._analyze_organizational_units(categorized['organizational_units']),
            'categorized_data': categorized
        }

        return report

    def _analyze_users(self, users: list) -> dict:
        """Analyze user entries for enterprise insights."""
        departments = {}
        email_domains = {}

        for user in users:
            # Department analysis
            dept_values = user.get_attribute_values('department')
            for dept in dept_values:
                departments[dept] = departments.get(dept, 0) + 1

            # Email domain analysis
            emails = user.get_attribute_values('mail')
            for email in emails:
                if '@' in email:
                    domain = email.split('@')[1]
                    email_domains[domain] = email_domains.get(domain, 0) + 1

        return {
            'total_users': len(users),
            'department_distribution': departments,
            'email_domain_distribution': email_domains
        }

    def _analyze_groups(self, groups: list) -> dict:
        """Analyze group entries."""
        group_sizes = {}
        group_types = {}

        for group in groups:
            # Group size analysis
            members = group.get_attribute_values('member')
            size_category = 'small' if len(members) < 10 else 'medium' if len(members) < 50 else 'large'
            group_sizes[size_category] = group_sizes.get(size_category, 0) + 1

            # Group type analysis (based on naming patterns)
            group_name = group.get_attribute_values('cn')[0] if group.get_attribute_values('cn') else 'unknown'
            if 'REDACTED_LDAP_BIND_PASSWORD' in group_name.lower():
                group_type = 'REDACTED_LDAP_BIND_PASSWORDistrative'
            elif 'dept' in group_name.lower() or 'department' in group_name.lower():
                group_type = 'departmental'
            else:
                group_type = 'functional'

            group_types[group_type] = group_types.get(group_type, 0) + 1

        return {
            'total_groups': len(groups),
            'size_distribution': group_sizes,
            'type_distribution': group_types
        }

    def _analyze_organizational_units(self, ous: list) -> dict:
        """Analyze organizational unit structure."""
        ou_hierarchy = {}

        for ou in ous:
            ou_name = ou.get_attribute_values('ou')[0] if ou.get_attribute_values('ou') else 'unknown'
            dn_components = ou.dn.split(',')
            depth = len(dn_components)

            hierarchy_level = 'top' if depth <= 3 else 'mid' if depth <= 5 else 'deep'
            ou_hierarchy[hierarchy_level] = ou_hierarchy.get(hierarchy_level, 0) + 1

        return {
            'total_organizational_units': len(ous),
            'hierarchy_distribution': ou_hierarchy
        }

    def _log_processing_completion(self, report: dict) -> dict:
        """Log processing completion with summary."""
        self._logger.info("Enterprise processing completed", extra={
            'total_entries': report['summary']['total_entries'],
            'users': report['summary']['users'],
            'groups': report['summary']['groups'],
            'organizational_units': report['summary']['organizational_units'],
            'operation': 'enterprise_processing_complete'
        })

        return report
```

### Batch Processing Pipeline

```python
from flext_ldif import FlextLDIFAPI
from flext_core import FlextResult
from pathlib import Path
from typing import Iterator
import time

class BatchLdifProcessor:
    """Batch processor for multiple LDIF files."""

    def __init__(self) -> None:
        self._ldif_api = FlextLDIFAPI()

    def process_directory_batch(self, directory_path: Path) -> FlextResult[dict]:
        """Process all LDIF files in a directory."""
        ldif_files = list(directory_path.glob("*.ldif"))

        if not ldif_files:
            return FlextResult[dict].fail(f"No LDIF files found in {directory_path}")

        return (
            FlextResult[list[Path]].ok(ldif_files)
            .flat_map(self._process_files_sequentially)
            .map(self._generate_batch_report)
        )

    def _process_files_sequentially(self, file_paths: list[Path]) -> FlextResult[list[dict]]:
        """Process files one by one to manage memory usage."""
        results = []

        for file_path in file_paths:
            print(f"Processing: {file_path.name}")

            file_result = self._process_single_file(file_path)
            if file_result.is_success:
                results.append(file_result.unwrap())
            else:
                # Continue processing other files even if one fails
                results.append({
                    'file_path': str(file_path),
                    'status': 'failed',
                    'error': file_result.error,
                    'entries': []
                })

        return FlextResult[list[dict]].ok(results)

    def _process_single_file(self, file_path: Path) -> FlextResult[dict]:
        """Process a single LDIF file with timing."""
        start_time = time.time()

        result = (
            self._ldif_api.parse_file(file_path)
            .flat_map(self._ldif_api.validate_entries)
            .flat_map(lambda entries: self._ldif_api.get_entry_statistics(entries)
                      .map(lambda stats: {'entries': entries, 'stats': stats}))
            .map(lambda data: {
                'file_path': str(file_path),
                'status': 'success',
                'processing_time': time.time() - start_time,
                'entry_count': len(data['entries']),
                'statistics': data['stats'],
                'entries': data['entries']
            })
        )

        return result

    def _generate_batch_report(self, file_results: list[dict]) -> dict:
        """Generate comprehensive batch processing report."""
        successful_files = [r for r in file_results if r['status'] == 'success']
        failed_files = [r for r in file_results if r['status'] == 'failed']

        total_entries = sum(r['entry_count'] for r in successful_files if 'entry_count' in r)
        total_processing_time = sum(r['processing_time'] for r in successful_files if 'processing_time' in r)

        return {
            'batch_summary': {
                'total_files': len(file_results),
                'successful_files': len(successful_files),
                'failed_files': len(failed_files),
                'total_entries_processed': total_entries,
                'total_processing_time': total_processing_time,
                'average_entries_per_second': total_entries / total_processing_time if total_processing_time > 0 else 0
            },
            'file_results': file_results,
            'failed_files': [{'file': r['file_path'], 'error': r['error']} for r in failed_files]
        }

def parallel_batch_processing(directory_path: Path, max_workers: int = 4) -> FlextResult[dict]:
    """Process LDIF files in parallel using thread pool."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from pathlib import Path

    ldif_files = list(directory_path.glob("*.ldif"))

    if not ldif_files:
        return FlextResult[dict].fail(f"No LDIF files found in {directory_path}")

    results = []
    failed_files = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all files for processing
        future_to_file = {
            executor.submit(process_file_worker, file_path): file_path
            for file_path in ldif_files
        }

        # Collect results as they complete
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                result = future.result()
                if result.is_success:
                    results.append(result.unwrap())
                else:
                    failed_files.append({
                        'file_path': str(file_path),
                        'error': result.error
                    })
            except Exception as e:
                failed_files.append({
                    'file_path': str(file_path),
                    'error': f"Processing exception: {e}"
                })

    return FlextResult[dict].ok({
        'parallel_summary': {
            'total_files': len(ldif_files),
            'successful_files': len(results),
            'failed_files': len(failed_files),
            'total_entries': sum(r.get('entry_count', 0) for r in results)
        },
        'results': results,
        'failures': failed_files
    })

def process_file_worker(file_path: Path) -> FlextResult[dict]:
    """Worker function for parallel processing."""
    api = FlextLDIFAPI()
    start_time = time.time()

    return (
        api.parse_file(file_path)
        .flat_map(api.validate_entries)
        .map(lambda entries: {
            'file_path': str(file_path),
            'entry_count': len(entries),
            'processing_time': time.time() - start_time,
            'status': 'completed'
        })
    )
```

## Custom Processing Patterns

### Data Transformation Pipeline

```python
from flext_ldif import FlextLDIFAPI, FlextLDIFModels
from flext_core import FlextResult
from typing import Callable, Any
from abc import ABC, abstractmethod

class LdifTransformer(ABC):
    """Abstract base class for LDIF transformations."""

    @abstractmethod
    def transform(self, entries: list) -> FlextResult[list]:
        """Transform LDIF entries."""
        pass

class EmailNormalizationTransformer(LdifTransformer):
    """Normalize email addresses to lowercase."""

    def transform(self, entries: list) -> FlextResult[list]:
        """Normalize email attributes to lowercase."""
        try:
            transformed_entries = []

            for entry in entries:
                # Create new entry with normalized emails
                new_attributes = entry.attributes.copy()

                if 'mail' in new_attributes:
                    new_attributes['mail'] = [email.lower() for email in new_attributes['mail']]

                transformed_entry = FlextLDIFModels.Factory.create_entry(
                    entry.dn,
                    new_attributes
                )
                transformed_entries.append(transformed_entry)

            return FlextResult[list].ok(transformed_entries)
        except Exception as e:
            return FlextResult[list].fail(f"Email normalization failed: {e}")

class DnStandardizationTransformer(LdifTransformer):
    """Standardize DN formats."""

    def __init__(self, target_base_dn: str = "dc=company,dc=com") -> None:
        self.target_base_dn = target_base_dn

    def transform(self, entries: list) -> FlextResult[list]:
        """Standardize DN formats to target base DN."""
        try:
            transformed_entries = []

            for entry in entries:
                # Extract RDN (relative DN)
                rdn_parts = entry.dn.split(',')[0]  # Get first component

                # Create new standardized DN
                new_dn = f"{rdn_parts},{self.target_base_dn}"

                transformed_entry = FlextLDIFModels.Factory.create_entry(
                    new_dn,
                    entry.attributes
                )
                transformed_entries.append(transformed_entry)

            return FlextResult[list].ok(transformed_entries)
        except Exception as e:
            return FlextResult[list].fail(f"DN standardization failed: {e}")

class AttributeMappingTransformer(LdifTransformer):
    """Map attribute names to different schemas."""

    def __init__(self, attribute_mapping: dict[str, str]) -> None:
        self.attribute_mapping = attribute_mapping

    def transform(self, entries: list) -> FlextResult[list]:
        """Transform attribute names according to mapping."""
        try:
            transformed_entries = []

            for entry in entries:
                new_attributes = {}

                for attr_name, attr_values in entry.attributes.items():
                    # Use mapped name if available, otherwise keep original
                    mapped_name = self.attribute_mapping.get(attr_name, attr_name)
                    new_attributes[mapped_name] = attr_values

                transformed_entry = FlextLDIFModels.Factory.create_entry(
                    entry.dn,
                    new_attributes
                )
                transformed_entries.append(transformed_entry)

            return FlextResult[list].ok(transformed_entries)
        except Exception as e:
            return FlextResult[list].fail(f"Attribute mapping failed: {e}")

class TransformationPipeline:
    """Pipeline for applying multiple transformations."""

    def __init__(self, transformers: list[LdifTransformer]) -> None:
        self.transformers = transformers

    def apply_transformations(self, entries: list) -> FlextResult[list]:
        """Apply all transformations in sequence."""
        current_result = FlextResult[list].ok(entries)

        for transformer in self.transformers:
            current_result = current_result.flat_map(transformer.transform)
            if current_result.is_failure:
                return current_result

        return current_result

# Usage example
def create_migration_pipeline() -> TransformationPipeline:
    """Create transformation pipeline for LDAP migration."""
    transformers = [
        EmailNormalizationTransformer(),
        DnStandardizationTransformer("dc=newcompany,dc=com"),
        AttributeMappingTransformer({
            'employeeNumber': 'employeeID',
            'departmentNumber': 'deptID'
        })
    ]

    return TransformationPipeline(transformers)

def process_with_transformations(ldif_content: str) -> FlextResult[str]:
    """Process LDIF with transformation pipeline."""
    api = FlextLDIFAPI()
    pipeline = create_migration_pipeline()

    return (
        # Parse original LDIF
        api.parse_string(ldif_content)

        # Apply transformations
        .flat_map(pipeline.apply_transformations)

        # Convert back to LDIF string
        .flat_map(api.write_string)
    )

# Example usage
migration_ldif = """dn: cn=John Doe,ou=People,dc=oldcompany,dc=com
cn: John Doe
mail: JOHN.DOE@OLDCOMPANY.COM
employeeNumber: 12345
departmentNumber: 100
"""

result = process_with_transformations(migration_ldif)
if result.is_success:
    transformed_ldif = result.unwrap()
    print("Transformed LDIF:")
    print(transformed_ldif)
```

## Performance Optimization Patterns

### Memory-Efficient Processing

```python
from flext_ldif import FlextLDIFAPI, FlextLDIFModels
from flext_core import FlextResult
import psutil
import os
from typing import Generator, Iterator

class MemoryEfficientProcessor:
    """Process large LDIF files with memory optimization."""

    def __init__(self, memory_limit_mb: int = 512) -> None:
        self.memory_limit_mb = memory_limit_mb
        self._ldif_api = FlextLDIFAPI()

    def process_large_file_chunked(self, file_path: str) -> FlextResult[dict]:
        """Process large LDIF file with memory constraints (conceptual - not yet implemented)."""
        return (
            self._check_memory_constraints(file_path)
            .flat_map(lambda _: self._process_in_chunks(file_path))
            .map(self._consolidate_chunk_results)
        )

    def _check_memory_constraints(self, file_path: str) -> FlextResult[None]:
        """Check if file can be processed within memory constraints."""
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        available_memory_mb = psutil.virtual_memory().available / (1024 * 1024)

        if file_size_mb > self.memory_limit_mb:
            return FlextResult[None].ok(None)  # Will use chunked processing

        if file_size_mb * 3 > available_memory_mb:  # Rough estimate including processing overhead
            return FlextResult[None].fail(
                f"Insufficient memory: file {file_size_mb:.1f}MB, "
                f"available {available_memory_mb:.1f}MB"
            )

        return FlextResult[None].ok(None)

    def _process_in_chunks(self, file_path: str) -> FlextResult[list[dict]]:
        """Process file in chunks (conceptual - requires streaming implementation)."""
        chunk_results = []
        chunk_size = 1000  # entries per chunk

        try:
            for chunk_entries in self._read_file_in_chunks(file_path, chunk_size):
                chunk_result = self._process_chunk(chunk_entries)
                if chunk_result.is_success:
                    chunk_results.append(chunk_result.unwrap())
                else:
                    return FlextResult[list[dict]].fail(
                        f"Chunk processing failed: {chunk_result.error}"
                    )

            return FlextResult[list[dict]].ok(chunk_results)
        except Exception as e:
            return FlextResult[list[dict]].fail(f"Chunked processing failed: {e}")

    def _read_file_in_chunks(self, file_path: str, chunk_size: int) -> Generator[list[str], None, None]:
        """Read LDIF file in chunks."""
        current_chunk = []
        current_entry_lines = []

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip()

                if line.startswith('dn:') and current_entry_lines:
                    # Complete previous entry
                    entry_content = '\n'.join(current_entry_lines)
                    current_chunk.append(entry_content)

                    if len(current_chunk) >= chunk_size:
                        yield current_chunk
                        current_chunk = []

                    # Start new entry
                    current_entry_lines = [line]
                elif line or current_entry_lines:  # Skip empty lines between entries
                    current_entry_lines.append(line)

            # Handle final entry and chunk
            if current_entry_lines:
                entry_content = '\n'.join(current_entry_lines)
                current_chunk.append(entry_content)

            if current_chunk:
                yield current_chunk

    def _process_chunk(self, chunk_entries: list[str]) -> FlextResult[dict]:
        """Process a chunk of LDIF entries."""
        chunk_content = '\n\n'.join(chunk_entries)

        return (
            self._ldif_api.parse_string(chunk_content)
            .flat_map(self._ldif_api.validate_entries)
            .map(lambda entries: {
                'entry_count': len(entries),
                'chunk_size': len(chunk_entries),
                'processed_entries': entries
            })
        )

    def _consolidate_chunk_results(self, chunk_results: list[dict]) -> dict:
        """Consolidate results from all chunks."""
        total_entries = sum(chunk['entry_count'] for chunk in chunk_results)
        total_chunks = len(chunk_results)

        # Memory usage info
        memory_info = psutil.Process().memory_info()

        return {
            'processing_summary': {
                'total_entries': total_entries,
                'total_chunks': total_chunks,
                'average_entries_per_chunk': total_entries / total_chunks if total_chunks > 0 else 0,
                'peak_memory_mb': memory_info.rss / (1024 * 1024)
            },
            'chunk_details': chunk_results
        }

class StreamingProcessor:
    """Stream-based LDIF processor for very large files."""

    def __init__(self) -> None:
        self._ldif_api = FlextLDIFAPI()

    def process_streaming(self, file_path: str, processor_func: Callable) -> FlextResult[dict]:
        """Process LDIF file using streaming approach."""
        processed_count = 0
        error_count = 0
        results = []

        try:
            for entry_batch in self._stream_entries(file_path, batch_size=100):
                batch_result = self._process_entry_batch(entry_batch, processor_func)

                if batch_result.is_success:
                    batch_data = batch_result.unwrap()
                    processed_count += batch_data['processed']
                    error_count += batch_data['errors']
                    results.extend(batch_data['results'])
                else:
                    error_count += len(entry_batch)

            return FlextResult[dict].ok({
                'streaming_summary': {
                    'processed_entries': processed_count,
                    'error_count': error_count,
                    'success_rate': processed_count / (processed_count + error_count) if processed_count + error_count > 0 else 0
                },
                'results': results
            })
        except Exception as e:
            return FlextResult[dict].fail(f"Streaming processing failed: {e}")

    def _stream_entries(self, file_path: str, batch_size: int) -> Generator[list, None, None]:
        """Stream LDIF entries in batches."""
        current_batch = []

        for entry_content in self._read_entries_one_by_one(file_path):
            current_batch.append(entry_content)

            if len(current_batch) >= batch_size:
                yield current_batch
                current_batch = []

        if current_batch:
            yield current_batch

    def _read_entries_one_by_one(self, file_path: str) -> Generator[str, None, None]:
        """Read LDIF entries one by one."""
        current_entry_lines = []

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip()

                if line.startswith('dn:') and current_entry_lines:
                    # Yield completed entry
                    yield '\n'.join(current_entry_lines)
                    current_entry_lines = [line]
                elif line or current_entry_lines:
                    current_entry_lines.append(line)

            # Yield final entry
            if current_entry_lines:
                yield '\n'.join(current_entry_lines)

    def _process_entry_batch(self, entry_batch: list[str], processor_func: Callable) -> FlextResult[dict]:
        """Process a batch of entries with custom processor function."""
        processed = 0
        errors = 0
        results = []

        for entry_content in entry_batch:
            try:
                parse_result = self._ldif_api.parse_string(entry_content)
                if parse_result.is_success:
                    entries = parse_result.unwrap()
                    if entries:  # Should be exactly one entry
                        entry = entries[0]
                        processor_result = processor_func(entry)
                        if processor_result:
                            results.append(processor_result)
                        processed += 1
                    else:
                        errors += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

        return FlextResult[dict].ok({
            'processed': processed,
            'errors': errors,
            'results': results
        })

# Example usage of advanced patterns
def example_enterprise_processing():
    """Example of business LDIF processing with FlextResult patterns."""
    processor = DirectoryProcessor()

    # Configure for enterprise processing
    enterprise_config = FlextLDIFModels.Config(
        max_entries=None,  # No limits
        strict_validation=False,  # Accommodate legacy data
        ignore_unknown_attributes=True
    )

    processor = DirectoryProcessor(enterprise_config)

    # Process enterprise export (would use real file path)
    # result = processor.process_enterprise_export(Path("enterprise_export.ldif"))

def example_memory_efficient_processing():
    """Example of memory-constrained processing (current limitation)."""
    processor = MemoryEfficientProcessor(memory_limit_mb=256)

    # Process large file with memory constraints
    # result = processor.process_large_file_chunked("large_directory.ldif")

def example_streaming_processing():
    """Example of streaming processing."""
    processor = StreamingProcessor()

    def extract_user_info(entry):
        """Custom processor function to extract user information."""
        if entry.is_person():
            return {
                'dn': entry.dn,
                'name': entry.get_attribute_values('cn')[0] if entry.get_attribute_values('cn') else 'Unknown',
                'email': entry.get_attribute_values('mail')[0] if entry.get_attribute_values('mail') else None
            }
        return None

    # Process with streaming approach
    # result = processor.process_streaming("very_large_file.ldif", extract_user_info)
```

These patterns demonstrate FLEXT-LDIF processing capabilities while maintaining integration with FLEXT ecosystem patterns. Note: The library currently uses memory-bound processing suitable for files under 100MB. Streaming and chunked processing patterns shown are conceptual designs for future implementation.