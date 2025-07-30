# 🚀 FLEXT LDIF Examples

Comprehensive examples demonstrating FLEXT LDIF library usage patterns.

## 📚 Table of Contents

- [🔧 Basic Usage](#-basic-usage)
- [🏗️ Advanced Parsing](#️-advanced-parsing)
- [✅ Validation Examples](#-validation-examples)
- [📝 Writing and Export](#-writing-and-export)
- [🎯 Domain Operations](#-domain-operations)
- [🔍 Filtering and Search](#-filtering-and-search)
- [🏢 Enterprise Patterns](#-enterprise-patterns)
- [🚨 Error Handling](#-error-handling)
- [⚡ Performance Examples](#-performance-examples)
- [🔄 Migration Examples](#-migration-examples)

## 🔧 Basic Usage

### Simple LDIF Parsing

```python
from flext_ldif import parse_ldif, write_ldif, validate_ldif

# Sample LDIF content
ldif_content = """
dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
sn: Doe
givenName: John
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
mail: john.doe@example.com
telephoneNumber: +1-555-123-4567
title: Software Engineer
department: Engineering

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
sn: Smith
givenName: Jane
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
mail: jane.smith@example.com
telephoneNumber: +1-555-987-6543
title: Product Manager
department: Product

dn: cn=Engineering,ou=groups,dc=example,dc=com
cn: Engineering
objectClass: groupOfNames
description: Engineering Department
member: cn=John Doe,ou=people,dc=example,dc=com
"""

# Parse LDIF
entries = parse_ldif(ldif_content)
print(f"Parsed {len(entries)} entries")

# Validate LDIF
is_valid = validate_ldif(ldif_content)
print(f"LDIF is valid: {is_valid}")

# Write back to LDIF
output = write_ldif(entries)
print("Generated LDIF:")
print(output)
```

### Working with Individual Entries

```python
from flext_ldif import FlextLdifEntry

# Create entry programmatically
entry_data = {
    "dn": "cn=Alice Johnson,ou=people,dc=example,dc=com",
    "attributes": {
        "cn": ["Alice Johnson"],
        "sn": ["Johnson"],
        "givenName": ["Alice"],
        "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
        "mail": ["alice.johnson@example.com"],
        "title": ["Senior Developer"],
        "department": ["Engineering"]
    }
}

entry = FlextLdifEntry.model_validate(entry_data)

# Access entry properties
print(f"DN: {entry.dn}")
print(f"Name: {entry.get_single_attribute('cn')}")
print(f"Object Classes: {entry.get_object_classes()}")
print(f"Email: {entry.get_attribute_values('mail')}")

# Check entry characteristics
if entry.has_object_class("person"):
    print("This is a person entry")

if entry.has_attribute("title"):
    print(f"Job title: {entry.get_single_attribute('title')}")

# Convert to LDIF format
ldif_output = entry.to_ldif()
print("LDIF representation:")
print(ldif_output)
```

## 🏗️ Advanced Parsing

### Using FlextLdifParser with Error Handling

```python
from flext_ldif import FlextLdifParser
from pathlib import Path

parser = FlextLdifParser()

# Parse from string with detailed error handling
ldif_content = """
dn: cn=Test User,dc=example,dc=com
cn: Test User
objectClass: person
invalid-attribute-format
"""

result = parser.parse_ldif_content(ldif_content)
if result.success:
    entries = result.data
    print(f"Successfully parsed {len(entries)} entries")
else:
    print(f"Parse error: {result.error}")

# Parse from file
try:
    file_result = parser.parse_ldif_file(Path("/path/to/users.ldif"))
    if file_result.success:
        print(f"Loaded {len(file_result.data)} entries from file")
except FileNotFoundError:
    print("LDIF file not found")
```

### Creating Entries from LDIF Blocks

```python
from flext_ldif import FlextLdifEntry

ldif_block = """
dn: cn=Bob Wilson,ou=contractors,dc=example,dc=com
cn: Bob Wilson
sn: Wilson
givenName: Bob
objectClass: person
objectClass: organizationalPerson
mail: bob.wilson@contractor.com
telephoneNumber: +1-555-456-7890
title: Consultant
contractorID: CTR-2024-001
"""

# Create entry from LDIF text
entry = FlextLdifEntry.from_ldif_block(ldif_block)

print(f"Created entry: {entry.dn}")
print(f"Contractor ID: {entry.get_single_attribute('contractorID')}")
```

## ✅ Validation Examples

### Entry Validation

```python
from flext_ldif import FlextLdifValidator, FlextLdifEntry

validator = FlextLdifValidator()

# Create a valid entry
valid_entry = FlextLdifEntry.model_validate({
    "dn": "cn=Valid User,dc=example,dc=com",
    "attributes": {
        "cn": ["Valid User"],
        "objectClass": ["person"],
        "mail": ["valid@example.com"]
    }
})

# Validate entry
result = validator.validate_entry(valid_entry)
if result.success:
    print("Entry is valid")
else:
    print(f"Validation failed: {result.error}")

# Domain validation
try:
    valid_entry.validate_domain_rules()
    print("Domain rules passed")
except ValueError as e:
    print(f"Domain validation failed: {e}")
```

### Batch Validation

```python
from flext_ldif import parse_ldif, FlextLdifValidator

# Parse multiple entries
entries = parse_ldif(ldif_content)

validator = FlextLdifValidator()

# Validate all entries
result = validator.validate_entries(entries)
if result.success:
    print("All entries are valid")
else:
    print(f"Validation failed: {result.error}")

# Validate individual entries with detailed reporting
for i, entry in enumerate(entries):
    result = validator.validate_entry(entry)
    if not result.success:
        print(f"Entry {i} validation failed: {result.error}")
        print(f"  DN: {entry.dn}")
```

### Custom Validation Rules

```python
def validate_email_format(entry: FlextLdifEntry) -> bool:
    """Custom validation for email format"""
    emails = entry.get_attribute_values("mail")
    for email in emails:
        if "@" not in email or "." not in email:
            return False
    return True

def validate_required_attributes(entry: FlextLdifEntry) -> bool:
    """Ensure required attributes are present"""
    required = ["cn", "objectClass"]
    return all(entry.has_attribute(attr) for attr in required)

# Apply custom validations
for entry in entries:
    if not validate_email_format(entry):
        print(f"Invalid email in entry: {entry.dn}")

    if not validate_required_attributes(entry):
        print(f"Missing required attributes in entry: {entry.dn}")
```

## 📝 Writing and Export

### Writing to Files

```python
from flext_ldif import FlextLdifWriter, parse_ldif
from pathlib import Path

# Parse some entries
entries = parse_ldif(ldif_content)

writer = FlextLdifWriter()

# Write FlextLdifEntry objects to file
result = writer.write_flext_entries_to_file(
    Path("/tmp/employees.ldif"),
    entries
)

if result.success:
    print("LDIF file written successfully")
else:
    print(f"Write failed: {result.error}")

# Write dictionary format entries
dict_entries = [
    {
        "dn": "cn=New User,dc=example,dc=com",
        "cn": ["New User"],
        "objectClass": ["person"],
        "mail": ["newuser@example.com"]
    }
]

result = writer.write_entries_to_file(
    Path("/tmp/new_users.ldif"),
    dict_entries
)
```

### Formatting Options

```python
from flext_ldif import write_ldif

# Basic writing
output = write_ldif(entries)

# Write to specific file
write_ldif(entries, "/tmp/export.ldif")

# Custom formatting (using individual entry methods)
formatted_entries = []
for entry in entries:
    # Add comments or modify format
    ldif_text = f"# Entry for {entry.get_single_attribute('cn')}\n"
    ldif_text += entry.to_ldif()
    ldif_text += "\n"
    formatted_entries.append(ldif_text)

with open("/tmp/formatted.ldif", "w") as f:
    f.write("\n".join(formatted_entries))
```

## 🎯 Domain Operations

### Working with Distinguished Names

```python
from flext_ldif import FlextLdifDistinguishedName

# Create DN
dn = FlextLdifDistinguishedName.model_validate({
    "value": "cn=John Doe,ou=Engineering,ou=Departments,dc=company,dc=com"
})

print(f"Full DN: {dn.value}")
print(f"RDN: {dn.get_rdn()}")  # cn=John Doe
print(f"Depth: {dn.get_depth()}")  # 4

# Navigate hierarchy
parent = dn.get_parent_dn()
if parent:
    print(f"Parent: {parent.value}")  # ou=Engineering,ou=Departments,dc=company,dc=com

# Check relationships
dept_dn = FlextLdifDistinguishedName.model_validate({
    "value": "ou=Engineering,ou=Departments,dc=company,dc=com"
})

if dn.is_child_of(dept_dn):
    print("User is in Engineering department")

# DN comparison and sorting
dns = [
    "cn=Alice,ou=Engineering,dc=company,dc=com",
    "ou=Engineering,dc=company,dc=com",
    "cn=Bob,ou=Engineering,dc=company,dc=com",
    "dc=company,dc=com"
]

dn_objects = [
    FlextLdifDistinguishedName.model_validate({"value": dn_str})
    for dn_str in dns
]

# Sort by depth (parents first)
sorted_dns = sorted(dn_objects, key=lambda x: x.get_depth())
for dn_obj in sorted_dns:
    print(f"Depth {dn_obj.get_depth()}: {dn_obj.value}")
```

### Working with Attributes

```python
from flext_ldif import FlextLdifAttributes

# Create attributes
attrs = FlextLdifAttributes.model_validate({
    "attributes": {
        "cn": ["John Doe"],
        "mail": ["john@example.com", "j.doe@example.com"],
        "objectClass": ["person", "organizationalPerson"],
        "telephoneNumber": ["+1-555-123-4567"]
    }
})

print(f"Attribute names: {attrs.get_attribute_names()}")
print(f"Total values: {attrs.get_total_values()}")

# Add values (returns new instance - immutable)
new_attrs = attrs.add_value("mail", "john.doe@company.com")
print(f"Original emails: {attrs.get_values('mail')}")
print(f"New emails: {new_attrs.get_values('mail')}")

# Remove values
final_attrs = new_attrs.remove_value("mail", "j.doe@example.com")
print(f"Final emails: {final_attrs.get_values('mail')}")

# Check attribute existence
if attrs.has_attribute("telephoneNumber"):
    phones = attrs.get_values("telephoneNumber")
    print(f"Phone numbers: {phones}")

# Get primary values
primary_email = attrs.get_single_value("mail")
print(f"Primary email: {primary_email}")
```

## 🔍 Filtering and Search

### Using Specifications

```python
from flext_ldif import FlextLdifProcessor
from flext_ldif.domain.specifications import (
    FlextLdifPersonSpecification,
    FlextLdifValidSpecification
)

processor = FlextLdifProcessor()

# Parse entries
result = processor.parse_ldif_content(ldif_content)
if result.success:
    entries = result.data

    # Filter person entries
    person_entries = processor.filter_person_entries(entries)
    print(f"Found {len(person_entries)} person entries")

    # Filter valid entries
    valid_entries = processor.filter_valid_entries(entries)
    print(f"Found {len(valid_entries)} valid entries")

    # Use specifications directly
    person_spec = FlextLdifPersonSpecification()
    valid_spec = FlextLdifValidSpecification()

    for entry in entries:
        if person_spec.is_satisfied_by(entry):
            print(f"Person: {entry.get_single_attribute('cn')}")

        if not valid_spec.is_satisfied_by(entry):
            print(f"Invalid entry: {entry.dn}")
```

### Custom Filtering

```python
from flext_ldif import parse_ldif

entries = parse_ldif(ldif_content)

# Filter by object class
def filter_by_object_class(entries, object_class):
    return [
        entry for entry in entries
        if entry.has_object_class(object_class)
    ]

# Filter by attribute presence
def filter_by_attribute(entries, attribute_name):
    return [
        entry for entry in entries
        if entry.has_attribute(attribute_name)
    ]

# Filter by DN pattern
def filter_by_dn_pattern(entries, pattern):
    return [
        entry for entry in entries
        if pattern in str(entry.dn)
    ]

# Apply filters
inetorgperson_entries = filter_by_object_class(entries, "inetOrgPerson")
entries_with_email = filter_by_attribute(entries, "mail")
engineering_entries = filter_by_dn_pattern(entries, "ou=Engineering")

print(f"inetOrgPerson entries: {len(inetorgperson_entries)}")
print(f"Entries with email: {len(entries_with_email)}")
print(f"Engineering entries: {len(engineering_entries)}")
```

### Search Operations

```python
from flext_ldif import FlextLdifUtils

# Hierarchical sorting
sorted_entries = FlextLdifUtils.sort_entries_hierarchically(entries)
print("Hierarchically sorted entries:")
for entry in sorted_entries:
    print(f"  {entry.dn}")

# Find specific entry
target_dn = "cn=John Doe,ou=people,dc=example,dc=com"
found_entry = FlextLdifUtils.find_entry_by_dn(entries, target_dn)
if found_entry:
    print(f"Found entry: {found_entry.get_single_attribute('cn')}")

# Filter by object class
person_entries = FlextLdifUtils.filter_by_objectclass(entries, "person")
print(f"Person entries: {len(person_entries)}")
```

## 🏢 Enterprise Patterns

### Batch Processing

```python
from flext_ldif import FlextLdifProcessor
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def process_ldif_files(directory: Path) -> dict:
    """Process multiple LDIF files in a directory"""
    processor = FlextLdifProcessor()
    results = {
        "processed": 0,
        "errors": 0,
        "total_entries": 0,
        "files": []
    }

    for ldif_file in directory.glob("*.ldif"):
        logger.info(f"Processing {ldif_file}")

        try:
            # Parse file
            parse_result = processor.parse_ldif_file(ldif_file)
            if not parse_result.success:
                logger.error(f"Parse failed for {ldif_file}: {parse_result.error}")
                results["errors"] += 1
                continue

            entries = parse_result.data

            # Validate entries
            validation_result = processor.validate_entries(entries)
            if not validation_result.success:
                logger.warning(f"Validation issues in {ldif_file}: {validation_result.error}")

            # Filter valid entries
            valid_entries = processor.filter_valid_entries(entries)

            results["processed"] += 1
            results["total_entries"] += len(valid_entries)
            results["files"].append({
                "file": str(ldif_file),
                "entries": len(entries),
                "valid_entries": len(valid_entries)
            })

            logger.info(f"Processed {len(valid_entries)}/{len(entries)} valid entries")

        except Exception as e:
            logger.error(f"Error processing {ldif_file}: {e}")
            results["errors"] += 1

    return results

# Usage
directory = Path("/data/ldif_files")
results = process_ldif_files(directory)
print(f"Processed {results['processed']} files with {results['total_entries']} total entries")
```

### Data Transformation Pipeline

```python
from flext_ldif import parse_ldif, FlextLdifEntry
from typing import List, Callable

class LDIFTransformationPipeline:
    """Pipeline for transforming LDIF data"""

    def __init__(self):
        self.transformations: List[Callable[[FlextLdifEntry], FlextLdifEntry]] = []

    def add_transformation(self, transform_func: Callable[[FlextLdifEntry], FlextLdifEntry]):
        """Add a transformation function to the pipeline"""
        self.transformations.append(transform_func)

    def process(self, entries: List[FlextLdifEntry]) -> List[FlextLdifEntry]:
        """Apply all transformations to entries"""
        result = entries.copy()

        for transform in self.transformations:
            result = [transform(entry) for entry in result]

        return result

# Example transformations
def normalize_email_addresses(entry: FlextLdifEntry) -> FlextLdifEntry:
    """Convert email addresses to lowercase"""
    emails = entry.get_attribute_values("mail")
    if emails:
        normalized_emails = [email.lower() for email in emails]
        new_attrs = entry.attributes
        for email in emails:
            new_attrs = new_attrs.remove_value("mail", email)
        for email in normalized_emails:
            new_attrs = new_attrs.add_value("mail", email)

        return FlextLdifEntry.model_validate({
            "dn": entry.dn,
            "attributes": new_attrs
        })
    return entry

def add_display_name(entry: FlextLdifEntry) -> FlextLdifEntry:
    """Add displayName attribute from cn"""
    if entry.has_attribute("cn") and not entry.has_attribute("displayName"):
        cn_value = entry.get_single_attribute("cn")
        if cn_value:
            new_attrs = entry.attributes.add_value("displayName", cn_value)
            return FlextLdifEntry.model_validate({
                "dn": entry.dn,
                "attributes": new_attrs
            })
    return entry

# Use pipeline
pipeline = LDIFTransformationPipeline()
pipeline.add_transformation(normalize_email_addresses)
pipeline.add_transformation(add_display_name)

entries = parse_ldif(ldif_content)
transformed_entries = pipeline.process(entries)

print(f"Transformed {len(transformed_entries)} entries")
```

### Error Handling and Monitoring

```python
from flext_ldif import FlextLdifProcessor, FlextLdifError
import logging
from typing import Dict, Any
from datetime import datetime

class LDIFProcessingMonitor:
    """Monitor LDIF processing operations"""

    def __init__(self):
        self.stats = {
            "processed": 0,
            "errors": 0,
            "start_time": None,
            "error_details": []
        }
        self.logger = logging.getLogger(__name__)

    def start_processing(self):
        """Start processing timer"""
        self.stats["start_time"] = datetime.now()
        self.logger.info("LDIF processing started")

    def record_success(self, entry_count: int):
        """Record successful processing"""
        self.stats["processed"] += entry_count
        self.logger.info(f"Successfully processed {entry_count} entries")

    def record_error(self, error: Exception, context: str = ""):
        """Record processing error"""
        self.stats["errors"] += 1
        error_detail = {
            "timestamp": datetime.now().isoformat(),
            "error": str(error),
            "type": type(error).__name__,
            "context": context
        }
        self.stats["error_details"].append(error_detail)
        self.logger.error(f"Processing error in {context}: {error}")

    def get_summary(self) -> Dict[str, Any]:
        """Get processing summary"""
        if self.stats["start_time"]:
            duration = datetime.now() - self.stats["start_time"]
            self.stats["duration_seconds"] = duration.total_seconds()

        return self.stats.copy()

def robust_ldif_processing(ldif_content: str) -> Dict[str, Any]:
    """Robust LDIF processing with comprehensive error handling"""
    monitor = LDIFProcessingMonitor()
    monitor.start_processing()

    processor = FlextLdifProcessor()
    results = {
        "entries": [],
        "valid_entries": [],
        "person_entries": [],
        "success": False
    }

    try:
        # Parse content
        parse_result = processor.parse_ldif_content(ldif_content)
        if not parse_result.success:
            raise FlextLdifError(f"Parse failed: {parse_result.error}")

        entries = parse_result.data
        results["entries"] = entries
        monitor.record_success(len(entries))

        # Validate entries
        try:
            validation_result = processor.validate_entries(entries)
            if validation_result.success:
                results["valid_entries"] = entries
            else:
                # Get individual validation results
                valid_entries = processor.filter_valid_entries(entries)
                results["valid_entries"] = valid_entries
                monitor.logger.warning(f"Some entries failed validation: {validation_result.error}")

        except Exception as e:
            monitor.record_error(e, "validation")
            # Continue with unvalidated entries
            results["valid_entries"] = entries

        # Filter person entries
        try:
            person_entries = processor.filter_person_entries(results["valid_entries"])
            results["person_entries"] = person_entries
        except Exception as e:
            monitor.record_error(e, "person_filtering")

        results["success"] = True

    except Exception as e:
        monitor.record_error(e, "main_processing")
        results["success"] = False

    # Add monitoring stats to results
    results["stats"] = monitor.get_summary()

    return results

# Usage
ldif_data = """
dn: cn=Test User,dc=example,dc=com
cn: Test User
objectClass: person
mail: test@example.com
"""

results = robust_ldif_processing(ldif_data)
if results["success"]:
    print(f"Processing successful: {len(results['entries'])} entries")
    print(f"Valid entries: {len(results['valid_entries'])}")
    print(f"Person entries: {len(results['person_entries'])}")
else:
    print("Processing failed")

print(f"Processing stats: {results['stats']}")
```

## 🚨 Error Handling

### Comprehensive Error Handling

```python
from flext_ldif import (
    parse_ldif,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
    FlextLdifEntry
)

def safe_ldif_processing(ldif_content: str):
    """Demonstrate comprehensive error handling"""

    try:
        # Attempt to parse LDIF
        entries = parse_ldif(ldif_content)
        print(f"Successfully parsed {len(entries)} entries")

        # Process each entry safely
        for i, entry in enumerate(entries):
            try:
                # Validate domain rules
                entry.validate_domain_rules()

                # Process entry
                process_entry_safely(entry)

            except ValueError as e:
                print(f"Entry {i} domain validation failed: {e}")
                continue
            except Exception as e:
                print(f"Unexpected error processing entry {i}: {e}")
                continue

    except FlextLdifParseError as e:
        print(f"LDIF parsing failed: {e}")
        # Try to recover or provide fallback
        return handle_parse_error(ldif_content, e)

    except FlextLdifValidationError as e:
        print(f"LDIF validation failed: {e}")
        return handle_validation_error(e)

    except FlextLdifError as e:
        print(f"General FLEXT LDIF error: {e}")
        return handle_general_error(e)

    except Exception as e:
        print(f"Unexpected error: {e}")
        return handle_unexpected_error(e)

def process_entry_safely(entry: FlextLdifEntry):
    """Safely process a single entry"""
    try:
        # Check required attributes
        if not entry.has_attribute("cn"):
            raise ValueError("Entry missing required cn attribute")

        # Validate email format if present
        emails = entry.get_attribute_values("mail")
        for email in emails:
            if "@" not in email:
                raise ValueError(f"Invalid email format: {email}")

        # Validate object classes
        object_classes = entry.get_object_classes()
        if not object_classes:
            raise ValueError("Entry missing objectClass")

        print(f"Entry validated: {entry.get_single_attribute('cn')}")

    except Exception as e:
        print(f"Entry processing error: {e}")
        raise

def handle_parse_error(content: str, error: FlextLdifParseError):
    """Handle parsing errors with recovery attempts"""
    print("Attempting to recover from parse error...")

    # Try to clean up common issues
    lines = content.strip().split('\n')
    cleaned_lines = []

    for line in lines:
        # Skip empty lines and comments
        if line.strip() and not line.startswith('#'):
            # Basic cleanup
            if ':' in line:
                cleaned_lines.append(line)

    if cleaned_lines:
        try:
            # Retry with cleaned content
            cleaned_content = '\n'.join(cleaned_lines)
            return parse_ldif(cleaned_content)
        except Exception:
            print("Recovery attempt failed")

    return []

def handle_validation_error(error: FlextLdifValidationError):
    """Handle validation errors"""
    print(f"Validation error details: {error}")
    # Could implement partial validation or error reporting
    return None

def handle_general_error(error: FlextLdifError):
    """Handle general FLEXT LDIF errors"""
    print(f"General error details: {error}")
    return None

def handle_unexpected_error(error: Exception):
    """Handle unexpected errors"""
    print(f"Unexpected error details: {error}")
    import traceback
    traceback.print_exc()
    return None

# Example usage with problematic LDIF
problematic_ldif = """
dn: cn=Good Entry,dc=example,dc=com
cn: Good Entry
objectClass: person

dn: invalid-dn-format
cn: Bad Entry
objectClass: person

dn: cn=Another Good Entry,dc=example,dc=com
cn: Another Good Entry
objectClass: person
mail: invalid-email-format
"""

safe_ldif_processing(problematic_ldif)
```

## ⚡ Performance Examples

### Large File Processing

```python
from flext_ldif import FlextLdifParser, FlextLdifProcessor
from pathlib import Path
import time
from typing import Iterator

def process_large_ldif_file(file_path: Path, batch_size: int = 1000):
    """Process large LDIF files in batches"""

    def ldif_entry_generator(file_path: Path) -> Iterator[str]:
        """Generator to read LDIF entries one by one"""
        with open(file_path, 'r') as f:
            entry_lines = []
            for line in f:
                line = line.strip()
                if line.startswith('dn:'):
                    if entry_lines:
                        # Yield previous entry
                        yield '\n'.join(entry_lines)
                    entry_lines = [line]
                elif line and not line.startswith('#'):
                    entry_lines.append(line)
                elif not line and entry_lines:
                    # Empty line - end of entry
                    yield '\n'.join(entry_lines)
                    entry_lines = []

            # Yield last entry if exists
            if entry_lines:
                yield '\n'.join(entry_lines)

    processor = FlextLdifProcessor()
    processed_count = 0
    batch = []

    start_time = time.time()

    for entry_text in ldif_entry_generator(file_path):
        batch.append(entry_text)

        if len(batch) >= batch_size:
            # Process batch
            batch_ldif = '\n\n'.join(batch)
            result = processor.parse_ldif_content(batch_ldif)

            if result.success:
                processed_count += len(result.data)
                print(f"Processed batch: {processed_count} total entries")

            batch = []

    # Process remaining entries
    if batch:
        batch_ldif = '\n\n'.join(batch)
        result = processor.parse_ldif_content(batch_ldif)
        if result.success:
            processed_count += len(result.data)

    end_time = time.time()
    processing_time = end_time - start_time

    print(f"Processed {processed_count} entries in {processing_time:.2f} seconds")
    print(f"Rate: {processed_count / processing_time:.2f} entries/second")

# Example usage
# process_large_ldif_file(Path("/data/large_directory.ldif"))
```

### Memory-Efficient Processing

```python
from flext_ldif import FlextLdifProcessor
import gc
from typing import Callable, Any

class MemoryEfficientProcessor:
    """Memory-efficient LDIF processor for large datasets"""

    def __init__(self, batch_size: int = 500):
        self.batch_size = batch_size
        self.processor = FlextLdifProcessor()

    def process_with_callback(
        self,
        ldif_content: str,
        entry_callback: Callable[[Any], None]
    ):
        """Process LDIF with callback for each entry to minimize memory usage"""

        # Split content into entries
        entries_text = ldif_content.split('\n\n')
        batch = []

        for i, entry_text in enumerate(entries_text):
            if entry_text.strip():
                batch.append(entry_text.strip())

            # Process batch when full
            if len(batch) >= self.batch_size or i == len(entries_text) - 1:
                if batch:
                    batch_content = '\n\n'.join(batch)
                    result = self.processor.parse_ldif_content(batch_content)

                    if result.success:
                        for entry in result.data:
                            entry_callback(entry)

                    # Clear batch and force garbage collection
                    batch = []
                    gc.collect()

# Usage example
def process_entry(entry):
    """Process individual entry"""
    print(f"Processing: {entry.get_single_attribute('cn')}")
    # Do something with entry

processor = MemoryEfficientProcessor(batch_size=100)

large_ldif_content = """
# Large LDIF content here...
"""

processor.process_with_callback(large_ldif_content, process_entry)
```

## 🔄 Migration Examples

### From Python-ldap

```python
# Before (python-ldap)
import ldap

conn = ldap.initialize("ldap://localhost")
conn.simple_bind_s("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "password")

# Search
results = conn.search_s(
    "ou=people,dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(objectClass=person)"
)

for dn, attrs in results:
    print(f"DN: {dn}")
    print(f"CN: {attrs.get('cn', [b''])[0].decode()}")

# After (FLEXT LDIF for file-based operations)
from flext_ldif import parse_ldif

# Assuming LDIF export from LDAP server
with open("export.ldif", "r") as f:
    ldif_content = f.read()

entries = parse_ldif(ldif_content)

for entry in entries:
    if entry.has_object_class("person"):
        print(f"DN: {entry.dn}")
        print(f"CN: {entry.get_single_attribute('cn')}")
```

### From ldif3 Library

```python
# Before (ldif3)
import ldif3

with open("input.ldif", "rb") as f:
    parser = ldif3.LDIFParser(f)
    for dn, entry in parser.parse():
        print(f"DN: {dn}")
        print(f"Attributes: {entry}")

# After (FLEXT LDIF)
from flext_ldif import FlextLdifParser
from pathlib import Path

parser = FlextLdifParser()
result = parser.parse_ldif_file(Path("input.ldif"))

if result.success:
    for entry in result.data:
        print(f"DN: {entry.dn}")
        print(f"CN: {entry.get_single_attribute('cn')}")
        print(f"Mail: {entry.get_attribute_values('mail')}")
```

### From Custom LDIF Parser

```python
# Before (custom parsing)
def parse_custom_ldif(content):
    entries = []
    lines = content.split('\n')
    current_entry = {}
    current_dn = None

    for line in lines:
        if line.startswith('dn:'):
            if current_entry:
                entries.append((current_dn, current_entry))
            current_dn = line[3:].strip()
            current_entry = {}
        elif ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            if key in current_entry:
                current_entry[key].append(value)
            else:
                current_entry[key] = [value]

    if current_entry:
        entries.append((current_dn, current_entry))

    return entries

# After (FLEXT LDIF)
from flext_ldif import parse_ldif

entries = parse_ldif(content)
# Now you have proper FlextLdifEntry objects with validation and methods
```

---

These examples demonstrate the comprehensive capabilities of FLEXT LDIF library, from basic usage to enterprise-grade processing patterns. The library provides both simple interfaces for common tasks and powerful features for complex LDIF processing requirements.
