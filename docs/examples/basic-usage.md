# Basic LDIF Usage Examples

**Version**: 0.9.0 | **Updated**: September 17, 2025

This document provides practical examples of basic FLEXT-LDIF usage patterns, demonstrating core functionality with working code samples.

## Getting Started Examples

### Simple LDIF Parsing

```python
from flext_ldif import FlextLDIFAPI
from pathlib import Path

# Initialize the API
api = FlextLDIFAPI()

# Basic LDIF content
sample_ldif = """dn: cn=John Doe,ou=People,dc=example,dc=com
cn: John Doe
sn: Doe
objectClass: person
objectClass: organizationalPerson
mail: john.doe@example.com

dn: cn=Jane Smith,ou=People,dc=example,dc=com
cn: Jane Smith
sn: Smith
objectClass: person
objectClass: organizationalPerson
mail: jane.smith@example.com
"""

# Parse LDIF string
result = api.parse_string(sample_ldif)
if result.is_success:
    entries = result.unwrap()
    print(f"Successfully parsed {len(entries)} entries")

    for entry in entries:
        print(f"DN: {entry.dn}")
        print(f"Name: {entry.get_attribute_values('cn')[0]}")
        print("---")
else:
    print(f"Parse failed: {result.error}")
```

### File Operations

```python
from flext_ldif import FlextLDIFAPI
from pathlib import Path

def process_ldif_file(input_file: str, output_file: str) -> None:
    """Basic file processing example."""
    api = FlextLDIFAPI()

    # Parse LDIF file
    input_path = Path(input_file)
    parse_result = api.parse_file(input_path)

    if parse_result.is_success:
        entries = parse_result.unwrap()
        print(f"Parsed {len(entries)} entries from {input_file}")

        # Validate entries
        validation_result = api.validate_entries(entries)
        if validation_result.is_success:
            print("All entries are valid")

            # Write to new file
            output_path = Path(output_file)
            write_result = api.write_file(entries, output_path)

            if write_result.is_success:
                print(f"Successfully wrote entries to {output_file}")
            else:
                print(f"Write failed: {write_result.error}")
        else:
            print(f"Validation failed: {validation_result.error}")
    else:
        print(f"Parse failed: {parse_result.error}")

# Usage
process_ldif_file("directory.ldif", "processed_directory.ldif")
```

## Configuration Examples

### Basic Configuration

```python
from flext_ldif import FlextLDIFAPI, FlextLDIFModels

# Create custom configuration
config = FlextLDIFModels.Config(
    max_entries=1000,           # Limit processing to 1000 entries
    strict_validation=True,     # Enable strict RFC 2849 validation
    encoding='utf-8'           # Specify character encoding
)

# Use configuration with API
api = FlextLDIFAPI(config=config)

# Process with custom settings
ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

result = api.parse_string(ldif_content)
print(f"Parsing with custom config: {'success' if result.is_success else 'failed'}")
```

### Environment-Based Configuration

```python
import os
from flext_ldif import FlextLDIFAPI, FlextLDIFModels

def create_config_from_environment() -> FlextLDIFModels.Config:
    """Create configuration from environment variables."""
    return FlextLDIFModels.Config(
        max_entries=int(os.getenv('LDIF_MAX_ENTRIES', '10000')),
        strict_validation=os.getenv('LDIF_STRICT_VALIDATION', 'false').lower() == 'true',
        encoding=os.getenv('LDIF_ENCODING', 'utf-8')
    )

# Use environment-based configuration
config = create_config_from_environment()
api = FlextLDIFAPI(config=config)
```

## Entry Manipulation

### Working with Entries

```python
from flext_ldif import FlextLDIFAPI

api = FlextLDIFAPI()

# Parse sample data
sample_ldif = """dn: cn=Alice Johnson,ou=People,dc=company,dc=com
cn: Alice Johnson
sn: Johnson
objectClass: person
objectClass: employee
mail: alice.johnson@company.com
department: Engineering

dn: cn=Bob Wilson,ou=People,dc=company,dc=com
cn: Bob Wilson
sn: Wilson
objectClass: person
objectClass: employee
mail: bob.wilson@company.com
department: Marketing
"""

result = api.parse_string(sample_ldif)
if result.is_success:
    entries = result.unwrap()

    for entry in entries:
        print(f"Employee: {entry.dn}")

        # Access attributes safely
        names = entry.get_attribute_values('cn')
        if names:
            print(f"  Name: {names[0]}")

        emails = entry.get_attribute_values('mail')
        if emails:
            print(f"  Email: {emails[0]}")

        departments = entry.get_attribute_values('department')
        if departments:
            print(f"  Department: {departments[0]}")

        # Check object classes
        object_classes = entry.get_object_classes()
        print(f"  Object Classes: {', '.join(object_classes)}")

        # Check entry types
        if entry.is_person():
            print("  Type: Person entry")

        print("---")
```

### Creating New Entries

```python
from flext_ldif import FlextLDIFModels

def create_person_entry(name: str, surname: str, email: str) -> FlextLDIFModels.Entry:
    """Create a new person entry."""
    dn = f"cn={name} {surname},ou=People,dc=example,dc=com"

    attributes = {
        'cn': [f"{name} {surname}"],
        'sn': [surname],
        'objectClass': ['person', 'organizationalPerson'],
        'mail': [email]
    }

    return FlextLDIFModels.Factory.create_entry(dn, attributes)

def create_group_entry(group_name: str, members: list[str]) -> FlextLDIFModels.Entry:
    """Create a new group entry."""
    dn = f"cn={group_name},ou=Groups,dc=example,dc=com"

    attributes = {
        'cn': [group_name],
        'objectClass': ['groupOfNames'],
        'member': members
    }

    return FlextLDIFModels.Factory.create_entry(dn, attributes)

# Create new entries
person = create_person_entry("David", "Brown", "david.brown@example.com")
group = create_group_entry("Administrators", ["cn=David Brown,ou=People,dc=example,dc=com"])

# Convert to LDIF
api = FlextLDIFAPI()
entries = [person, group]

ldif_result = api.write_string(entries)
if ldif_result.is_success:
    ldif_output = ldif_result.unwrap()
    print("Generated LDIF:")
    print(ldif_output)
```

## Filtering Examples

### Filter by Object Class

```python
from flext_ldif import FlextLDIFAPI

def demonstrate_filtering():
    """Demonstrate entry filtering capabilities."""
    api = FlextLDIFAPI()

    # Sample directory data
    directory_ldif = """dn: cn=John Doe,ou=People,dc=company,dc=com
cn: John Doe
objectClass: person
objectClass: employee

dn: cn=Developers,ou=Groups,dc=company,dc=com
cn: Developers
objectClass: groupOfNames
member: cn=John Doe,ou=People,dc=company,dc=com

dn: ou=People,dc=company,dc=com
ou: People
objectClass: organizationalUnit

dn: ou=Groups,dc=company,dc=com
ou: Groups
objectClass: organizationalUnit
"""

    # Parse directory
    result = api.parse_string(directory_ldif)
    if result.is_success:
        all_entries = result.unwrap()
        print(f"Total entries: {len(all_entries)}")

        # Filter person entries
        persons_result = api.filter_persons(all_entries)
        if persons_result.is_success:
            persons = persons_result.unwrap()
            print(f"Person entries: {len(persons)}")

        # Filter group entries
        groups_result = api.filter_groups(all_entries)
        if groups_result.is_success:
            groups = groups_result.unwrap()
            print(f"Group entries: {len(groups)}")

        # Filter organizational units
        ou_result = api.filter_by_objectclass(all_entries, "organizationalUnit")
        if ou_result.is_success:
            org_units = ou_result.unwrap()
            print(f"Organizational units: {len(org_units)}")

            for ou in org_units:
                ou_names = ou.get_attribute_values('ou')
                if ou_names:
                    print(f"  - {ou_names[0]}")

demonstrate_filtering()
```

### Custom Filtering Logic

```python
from flext_ldif import FlextLDIFAPI
from typing import Callable

def custom_filter_entries(
    entries: list,
    filter_func: Callable[[any], bool]
) -> list:
    """Apply custom filtering logic to entries."""
    return [entry for entry in entries if filter_func(entry)]

def filter_by_email_domain(entries: list, domain: str) -> list:
    """Filter entries by email domain."""
    def has_email_domain(entry):
        emails = entry.get_attribute_values('mail')
        return any(email.endswith(f'@{domain}') for email in emails)

    return custom_filter_entries(entries, has_email_domain)

def filter_by_department(entries: list, department: str) -> list:
    """Filter entries by department."""
    def in_department(entry):
        departments = entry.get_attribute_values('department')
        return department in departments

    return custom_filter_entries(entries, in_department)

# Usage example
api = FlextLDIFAPI()

company_ldif = """dn: cn=alice@company.com,ou=People,dc=company,dc=com
cn: Alice
mail: alice@company.com
department: Engineering

dn: cn=bob@external.com,ou=People,dc=company,dc=com
cn: Bob
mail: bob@external.com
department: Marketing
"""

result = api.parse_string(company_ldif)
if result.is_success:
    entries = result.unwrap()

    # Filter by company email domain
    company_emails = filter_by_email_domain(entries, 'company.com')
    print(f"Company email addresses: {len(company_emails)}")

    # Filter by engineering department
    engineers = filter_by_department(entries, 'Engineering')
    print(f"Engineering staff: {len(engineers)}")
```

## Error Handling Examples

### Basic Error Handling

```python
from flext_ldif import FlextLDIFAPI

def safe_ldif_processing(content: str) -> dict:
    """Safely process LDIF with comprehensive error handling."""
    api = FlextLDIFAPI()

    # Parse with error handling
    parse_result = api.parse_string(content)
    if parse_result.is_failure:
        return {
            'status': 'error',
            'stage': 'parsing',
            'message': parse_result.error,
            'entries': []
        }

    entries = parse_result.unwrap()

    # Validate with error handling
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        return {
            'status': 'warning',
            'stage': 'validation',
            'message': validation_result.error,
            'entries': entries  # Return entries despite validation issues
        }

    return {
        'status': 'success',
        'stage': 'complete',
        'message': f'Successfully processed {len(entries)} entries',
        'entries': entries
    }

# Test with valid content
valid_ldif = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

result = safe_ldif_processing(valid_ldif)
print(f"Valid LDIF result: {result['status']} - {result['message']}")

# Test with invalid content
invalid_ldif = "invalid ldif content without proper structure"

result = safe_ldif_processing(invalid_ldif)
print(f"Invalid LDIF result: {result['status']} - {result['message']}")
```

### Railway-Oriented Error Handling

```python
from flext_ldif import FlextLDIFAPI
from flext_core import FlextResult

def railway_processing_example(file_path: str) -> FlextResult[dict]:
    """Demonstrate railway-oriented programming with FLEXT-LDIF."""
    api = FlextLDIFAPI()

    return (
        # Parse file
        api.parse_file(file_path)

        # Validate entries (continue with entries on success)
        .flat_map(lambda entries:
            api.validate_entries(entries).map(lambda _: entries))

        # Filter person entries
        .flat_map(api.filter_persons)

        # Generate statistics
        .flat_map(lambda persons:
            api.get_entry_statistics(persons)
            .map(lambda stats: {
                'person_count': len(persons),
                'statistics': stats,
                'persons': persons
            }))

        # Add processing context
        .map(lambda data: {
            **data,
            'processed_file': file_path,
            'processing_status': 'completed'
        })

        # Handle errors with context
        .map_error(lambda error: f"Processing {file_path} failed: {error}")
    )

# Usage with temporary file
from pathlib import Path
import tempfile

def test_railway_processing():
    """Test railway-oriented processing."""
    # Create temporary LDIF file
    test_content = """dn: cn=Test User,ou=People,dc=test,dc=com
cn: Test User
sn: User
objectClass: person
mail: test.user@test.com

dn: cn=Another User,ou=People,dc=test,dc=com
cn: Another User
sn: User
objectClass: person
mail: another.user@test.com
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.ldif', delete=False) as f:
        f.write(test_content)
        temp_file = f.name

    try:
        # Process with railway pattern
        result = railway_processing_example(temp_file)

        if result.is_success:
            data = result.unwrap()
            print(f"✓ Processing successful:")
            print(f"  - File: {data['processed_file']}")
            print(f"  - Persons: {data['person_count']}")
            print(f"  - Status: {data['processing_status']}")
        else:
            print(f"✗ Processing failed: {result.error}")

    finally:
        # Cleanup
        Path(temp_file).unlink()

test_railway_processing()
```

## Statistics and Analytics

### Basic Statistics

```python
from flext_ldif import FlextLDIFAPI

def analyze_directory_structure():
    """Analyze LDIF directory structure and generate statistics."""
    api = FlextLDIFAPI()

    # Sample organizational directory
    org_ldif = """dn: dc=company,dc=com
dc: company
objectClass: domain

dn: ou=People,dc=company,dc=com
ou: People
objectClass: organizationalUnit

dn: ou=Groups,dc=company,dc=com
ou: Groups
objectClass: organizationalUnit

dn: cn=John Doe,ou=People,dc=company,dc=com
cn: John Doe
objectClass: person
objectClass: employee
department: Engineering

dn: cn=Jane Smith,ou=People,dc=company,dc=com
cn: Jane Smith
objectClass: person
objectClass: employee
department: Marketing

dn: cn=Engineers,ou=Groups,dc=company,dc=com
cn: Engineers
objectClass: groupOfNames
member: cn=John Doe,ou=People,dc=company,dc=com
"""

    # Parse directory
    result = api.parse_string(org_ldif)
    if result.is_success:
        entries = result.unwrap()
        print(f"Directory Analysis:")
        print(f"Total entries: {len(entries)}")

        # Get object class statistics
        stats_result = api.get_entry_statistics(entries)
        if stats_result.is_success:
            stats = stats_result.unwrap()
            print("\nObject Class Distribution:")
            for object_class, count in stats.items():
                print(f"  {object_class}: {count}")

        # Analyze by entry type
        persons = api.filter_persons(entries).unwrap_or([])
        groups = api.filter_groups(entries).unwrap_or([])

        print(f"\nEntry Type Analysis:")
        print(f"  Persons: {len(persons)}")
        print(f"  Groups: {len(groups)}")
        print(f"  Other: {len(entries) - len(persons) - len(groups)}")

        # Department analysis for persons
        departments = {}
        for person in persons:
            dept_values = person.get_attribute_values('department')
            for dept in dept_values:
                departments[dept] = departments.get(dept, 0) + 1

        if departments:
            print(f"\nDepartment Distribution:")
            for dept, count in departments.items():
                print(f"  {dept}: {count}")

analyze_directory_structure()
```

These basic usage examples demonstrate the core functionality of FLEXT-LDIF while following FLEXT ecosystem patterns and providing practical, working code samples.