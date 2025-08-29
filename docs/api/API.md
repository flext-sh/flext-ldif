# FLEXT-LDIF API Reference

**Version**: 0.9.0
**Status**: Active Development
**Integration**: FLEXT Ecosystem Compatible

API documentation for the FLEXT-LDIF library.

---

## 🚀 Quick Start Guide

### Installation & Setup

```bash
# Install from source (current)
git clone https://github.com/flext-sh/flext-ldif.git
cd flext-ldif
poetry install

# Verify installation
poetry run python -c "from flext_ldif import FlextLdifAPI; print('✅ Installation successful')"
```

### Basic Usage Pattern

```python
from flext_ldif import FlextLdifAPI

# Initialize with default configuration
api = FlextLdifAPI()

# Parse LDIF content
ldif_content = """
dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
objectClass: inetOrgPerson
mail: john.doe@example.com
"""

# Process with error handling
result = api.parse(ldif_content)
if result.is_success:
    entries = result.value
    print(f"✅ Parsed {len(entries)} entries")

    # Validate entries
    validation = api.validate(entries)
    print(f"✅ Validation: {'PASSED' if validation.is_success else 'FAILED'}")

    # Generate output
    output = api.write(entries)
    if output.is_success:
        print(f"✅ Generated LDIF:\n{output.value}")
else:
    print(f"❌ Parse failed: {result.error}")
```

---

## 🏗️ Core Architecture

### Application Layer

#### FlextLdifAPI

**Primary application service providing unified LDIF operations**

```python
from flext_ldif import FlextLdifAPI, FlextLdifConfig

# Configuration options
config = FlextLdifConfig(
    max_entries=10000,           # Maximum entries to process
    strict_validation=True,      # Enable strict business rule validation
    input_encoding="utf-8",      # Input file encoding
    output_encoding="utf-8",     # Output file encoding
    allow_empty_attributes=False # Allow attributes with empty values
)

# Initialize API with configuration
api = FlextLdifAPI(config)
```

##### Core Operations

**`parse(content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]`**

Parse LDIF content into domain objects.

```python
# Parse string content
result = api.parse(ldif_string)

# Parse with type safety
from flext_ldif.models import LDIFContent
typed_content = LDIFContent(ldif_string)
result = api.parse(typed_content)

# Handle results
if result.is_success:
    entries = result.value
    print(f"Parsed {len(entries)} entries")
    for entry in entries:
        print(f"  - {entry.dn.value}")
else:
    print(f"Parse error: {result.error}")
    print(f"Error details: {result.error_details}")  # Additional context
```

**`parse_file(file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]`**

Parse LDIF files with proper encoding handling.

```python
from pathlib import Path

# Parse file
result = api.parse_file("data/sample.ldif")
# or
result = api.parse_file(Path("data/sample.ldif"))

# Handle large files
config = FlextLdifConfig(max_entries=50000)  # Increase limit
api = FlextLdifAPI(config)
result = api.parse_file("data/large_export.ldif")
```

**`validate(entries: list[FlextLdifEntry]) -> FlextResult[bool]`**

Validate entries against business rules and LDIF compliance.

```python
validation_result = api.validate(entries)

if validation_result.is_success:
    print("✅ All entries valid")
else:
    print(f"❌ Validation failed: {validation_result.error}")
    # Get specific validation errors
    for entry in entries:
        try:
            entry.validate_domain_rules()
        except ValueError as e:
            print(f"  Entry {entry.dn.value}: {e}")
```

**`write(entries: list[FlextLdifEntry]) -> FlextResult[str]`**

Generate LDIF output from domain objects.

```python
# Generate LDIF string
output_result = api.write(entries)

if output_result.is_success:
    ldif_content = output_result.value
    print(ldif_content)

    # Write to file
    with open("output.ldif", "w", encoding="utf-8") as f:
        f.write(ldif_content)
else:
    print(f"Write error: {output_result.error}")
```

**`write_file(entries: list[FlextLdifEntry], file_path: str | Path) -> FlextResult[bool]`**

Write entries directly to file.

```python
# Write to file with error handling
result = api.write_file(entries, "output/processed.ldif")

if result.is_success:
    print("✅ File written successfully")
else:
    print(f"❌ Write failed: {result.error}")
```

---

## 🏛️ Domain Layer

### Domain Entities

#### FlextLdifEntry

**Main domain entity representing LDIF entries**

```python
from flext_ldif import FlextLdifEntry, FlextLdifDistinguishedName, FlextLdifAttributes

# Create entry from data
entry = FlextLdifEntry.model_validate({
    "dn": FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com"),
    "attributes": FlextLdifAttributes(attributes={
        "cn": ["John Doe"],
        "objectClass": ["person", "inetOrgPerson"],
        "mail": ["john.doe@example.com", "j.doe@example.com"],
        "sn": ["Doe"],
        "givenName": ["John"],
        "telephoneNumber": ["+1-555-123-4567"]
    })
})
```

##### Properties

- **`dn: FlextLdifDistinguishedName`** - Distinguished name (immutable)
- **`attributes: FlextLdifAttributes`** - Entry attributes (immutable)

##### Domain Methods

**`validate_domain_rules() -> None`**

Validate entry against business rules.

```python
try:
    entry.validate_domain_rules()
    print("✅ Entry valid")
except ValueError as e:
    print(f"❌ Validation error: {e}")
    # Common validation errors:
    # - Empty DN
    # - Missing required objectClass
    # - Invalid attribute names
    # - Malformed attribute values
```

**`get_object_classes() -> list[str]`**

Get all objectClass values.

```python
classes = entry.get_object_classes()
print(f"Object classes: {classes}")  # ['person', 'inetOrgPerson']

# Check for structural object classes
structural_classes = [cls for cls in classes if cls in ['person', 'organizationalPerson', 'inetOrgPerson']]
```

**`has_object_class(object_class: str) -> bool`**

Check for specific object class.

```python
if entry.has_object_class("person"):
    print("This is a person entry")

if entry.has_object_class("inetOrgPerson"):
    print("Has internet person attributes")
```

**`get_attribute_values(name: str) -> list[str]`**

Get all values for an attribute.

```python
# Get email addresses
emails = entry.get_attribute_values("mail")
print(f"Email addresses: {emails}")

# Get empty list for missing attributes
phones = entry.get_attribute_values("mobile")  # Returns []
```

**`has_attribute(name: str) -> bool`**

Check if attribute exists.

```python
if entry.has_attribute("mail"):
    primary_email = entry.get_attribute_values("mail")[0]
    print(f"Primary email: {primary_email}")
```

**`get_single_attribute_value(name: str) -> str | None`**

Get first value of attribute.

```python
cn = entry.get_single_attribute_value("cn")
if cn:
    print(f"Common name: {cn}")

# Returns None for missing attributes
mobile = entry.get_single_attribute_value("mobile")  # None
```

**`to_ldif() -> str`**

Convert to LDIF format (infrastructure method).

```python
ldif_output = entry.to_ldif()
print(ldif_output)
# Output:
# dn: cn=John Doe,ou=people,dc=example,dc=com
# cn: John Doe
# objectClass: person
# objectClass: inetOrgPerson
# mail: john.doe@example.com
# mail: j.doe@example.com
# sn: Doe
# givenName: John
# telephoneNumber: +1-555-123-4567
```

##### Change Type Detection

**`is_add_operation() -> bool`**
**`is_modify_operation() -> bool`**
**`is_delete_operation() -> bool`**

```python
# Check LDIF operation type
if entry.is_add_operation():
    print("Adding new entry")
elif entry.is_modify_operation():
    print("Modifying existing entry")
elif entry.is_delete_operation():
    print("Deleting entry")
else:
    print("Standard entry (no changetype)")
```

##### Factory Methods

**`from_ldif_block(ldif_block: str) -> FlextLdifEntry`**

Create entry from LDIF text.

```python
ldif_block = """
dn: cn=Test User,ou=people,dc=example,dc=com
cn: Test User
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com
"""

entry = FlextLdifEntry.from_ldif_block(ldif_block)
print(f"Created entry: {entry.dn.value}")
```

### Value Objects

#### FlextLdifDistinguishedName

**Immutable value object for Distinguished Names**

```python
from flext_ldif import FlextLdifDistinguishedName

# Create DN
dn = FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com")

# DN validation happens automatically
try:
    invalid_dn = FlextLdifDistinguishedName(value="invalid-dn-format")
except ValueError as e:
    print(f"DN validation error: {e}")
```

##### Properties

- **`value: str`** - The DN string value

##### Methods

**`get_rdn() -> str`**

Get relative distinguished name.

```python
rdn = dn.get_rdn()  # "cn=John Doe"
print(f"RDN: {rdn}")
```

**`get_parent_dn() -> FlextLdifDistinguishedName | None`**

Get parent DN.

```python
parent = dn.get_parent_dn()
if parent:
    print(f"Parent DN: {parent.value}")  # "ou=people,dc=example,dc=com"
else:
    print("This is a root DN")
```

**`is_child_of(parent: FlextLdifDistinguishedName) -> bool`**

Check parent-child relationship.

```python
parent_dn = FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com")
child_dn = FlextLdifDistinguishedName(value="cn=John,ou=people,dc=example,dc=com")

if child_dn.is_child_of(parent_dn):
    print("✅ Child relationship confirmed")
```

**`get_depth() -> int`**

Get DN depth (component count).

```python
depth = dn.get_depth()  # 4 components
print(f"DN depth: {depth}")

# Useful for hierarchical sorting
entries_by_depth = sorted(entries, key=lambda e: e.dn.get_depth())
```

**`get_components() -> list[str]`**

Get DN components.

```python
components = dn.get_components()
# ["cn=John Doe", "ou=people", "dc=example", "dc=com"]
```

#### FlextLdifAttributes

**Immutable value object for LDIF attributes**

```python
from flext_ldif import FlextLdifAttributes

# Create attributes
attrs = FlextLdifAttributes(attributes={
    "cn": ["John Doe"],
    "mail": ["john@example.com", "j.doe@example.com"],
    "objectClass": ["person", "inetOrgPerson"]
})
```

##### Properties

- **`attributes: dict[str, list[str]]`** - Attribute dictionary

##### Methods

**`get_values(name: str) -> list[str]`**

Get all values for attribute.

```python
emails = attrs.get_values("mail")
print(f"Emails: {emails}")  # ['john@example.com', 'j.doe@example.com']

missing = attrs.get_values("phone")  # Returns []
```

**`get_single_value(name: str) -> str | None`**

Get first value or None.

```python
cn = attrs.get_single_value("cn")  # "John Doe"
phone = attrs.get_single_value("phone")  # None
```

**`has_attribute(name: str) -> bool`**

Check attribute existence.

```python
if attrs.has_attribute("mail"):
    print("Has email address")
```

**`add_value(name: str, value: str) -> FlextLdifAttributes`**

Return new instance with added value (immutable).

```python
new_attrs = attrs.add_value("telephoneNumber", "+1-555-123-4567")
# Original attrs unchanged, new_attrs has phone number

# Chain operations
updated_attrs = attrs.add_value("mobile", "+1-555-987-6543") \
                    .add_value("fax", "+1-555-123-4568")
```

**`remove_value(name: str, value: str) -> FlextLdifAttributes`**

Return new instance with removed value.

```python
# Remove secondary email
new_attrs = attrs.remove_value("mail", "j.doe@example.com")
# new_attrs only has "john@example.com"
```

**`get_attribute_names() -> list[str]`**

Get all attribute names.

```python
names = attrs.get_attribute_names()  # ["cn", "mail", "objectClass"]
print(f"Attributes: {', '.join(names)}")
```

**`get_total_values() -> int`**

Get total value count across all attributes.

```python
total = attrs.get_total_values()  # Sum of all value counts
print(f"Total attribute values: {total}")
```

**`is_empty() -> bool`**

Check if no attributes defined.

```python
if attrs.is_empty():
    print("No attributes defined")
```

---

## 🔧 Infrastructure Layer

### Service Classes

#### FlextLdifParserService

**Domain service for LDIF parsing operations**

```python
from flext_ldif.services import FlextLdifParserService
from flext_ldif import FlextLdifConfig

# Configure parser
config = FlextLdifConfig(
    max_entries=5000,
    strict_validation=True,
    input_encoding="utf-8"
)

parser = FlextLdifParserService(config)
```

**`parse(content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]`**

```python
result = parser.parse(ldif_content)
if result.is_failure:
    print(f"Parse error: {result.error}")
    return

entries = result.value
print(f"Parsed {len(entries)} entries")
```

**`parse_file(file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]`**

```python
from pathlib import Path

result = parser.parse_file(Path("data/export.ldif"))
if result.is_success:
    entries = result.value
    print(f"Loaded {len(entries)} entries from file")
```

#### FlextLdifValidatorService

**Domain service for LDIF validation**

```python
from flext_ldif.services import FlextLdifValidatorService

validator = FlextLdifValidatorService(config)
```

**`validate(entries: list[FlextLdifEntry]) -> FlextResult[bool]`**

```python
result = validator.validate(entries)
if result.is_success:
    print("✅ All entries valid")
else:
    print(f"❌ Validation failed: {result.error}")
```

**`validate_entry(entry: FlextLdifEntry) -> FlextResult[bool]`**

```python
for entry in entries:
    result = validator.validate_entry(entry)
    if result.is_failure:
        print(f"Entry {entry.dn.value}: {result.error}")
```

#### FlextLdifWriterService

**Domain service for LDIF output generation**

```python
from flext_ldif.services import FlextLdifWriterService

writer = FlextLdifWriterService(config)
```

**`write(entries: list[FlextLdifEntry]) -> FlextResult[str]`**

```python
result = writer.write(entries)
if result.is_success:
    ldif_output = result.value
    print("✅ LDIF generated successfully")
else:
    print(f"❌ Write error: {result.error}")
```

**`write_file(entries: list[FlextLdifEntry], file_path: str | Path) -> FlextResult[bool]`**

```python
result = writer.write_file(entries, "output/processed.ldif")
if result.is_success:
    print("✅ File written successfully")
```

---

## 🔌 FLEXT Ecosystem Integration

### FLEXT-Core Integration

#### Dependency Injection

```python
from flext_core import get_flext_container
from flext_ldif import FlextLdifAPI

# Use DI container
container = FlextContainer.get_global()

# Register LDIF services
from flext_ldif.services import register_ldif_services
register_ldif_services(container)

# Get API instance from container
api = container.get(FlextLdifAPI)
```

#### FlextResult Pattern

```python
from flext_core import FlextResult

# All service methods return FlextResult
result: FlextResult[list[FlextLdifEntry]] = api.parse(content)

# Pattern matching style
match result:
    case result if result.is_success:
        entries = result.value
        print(f"Success: {len(entries)} entries")
    case result if result.is_failure:
        print(f"Error: {result.error}")

# Railway-oriented programming
def process_ldif_pipeline(content: str) -> FlextResult[str]:
    return (api.parse(content)
              .bind(lambda entries: api.validate(entries))
              .bind(lambda _: api.write(entries)))
```

#### Logging Integration

```python
from flext_core import FlextLogger

logger = FlextLogger(__name__)

# LDIF operations are automatically logged
result = api.parse(ldif_content)
# Logs: "Parsing LDIF content" (DEBUG)
# Logs: "Successfully parsed N entries" (INFO)
```

### FLEXT-Observability Integration

#### Monitoring and Tracing

```python
from flext_observability import flext_monitor_function, flext_create_trace

@flext_monitor_function("ldif_processing")
def process_ldif_file(file_path: str) -> FlextResult[list[FlextLdifEntry]]:
    with flext_create_trace("parse_ldif_file") as trace:
        api = FlextLdifAPI()
        result = api.parse_file(file_path)

        if result.is_success:
            trace.set_attribute("entries_count", len(result.value))
            trace.set_status("success")
        else:
            trace.set_status("error", result.error)

        return result
```

#### Performance Monitoring

```python
from flext_observability import FlextObservabilityMonitor

# Monitor LDIF operations
monitor = FlextObservabilityMonitor("ldif_operations")

# API automatically creates metrics
api = FlextLdifAPI()
result = api.parse(large_ldif_content)
# Creates metrics: ldif_parse_duration, ldif_entries_processed, etc.
```

### Future Integrations (Roadmap)

#### FLEXT-LDAP Integration (Phase 1)

```python
# Planned integration
from flext_ldap import FlextLdapConnection
from flext_ldif import FlextLdifAPI

# LDAP-aware LDIF processing
connection = FlextLdapConnection("ldap://directory.example.com")
api = FlextLdifAPI(ldap_connection=connection)

# Schema validation against LDAP server
result = api.parse_with_schema_validation(ldif_content)

# Import from LDAP to LDIF
ldif_result = api.export_from_ldap("ou=people,dc=example,dc=com")

# Import LDIF to LDAP
import_result = api.import_to_ldap(entries, base_dn="ou=people,dc=example,dc=com")
```

#### Singer Ecosystem Integration (Phase 2)

```python
# Planned Singer SDK integration
from flext_tap_ldif import FlextLdifTap
from flext_target_ldif import FlextLdifTarget

# Extract LDIF data for pipelines
tap = FlextLdifTap(config={
    "file_path": "data/users.ldif",
    "batch_size": 1000
})

# Discover streams
streams = tap.discover_streams()
print(f"Discovered {len(streams)} streams")

# Extract records
for stream in streams:
    for record in tap.read_stream(stream):
        print(f"Record: {record}")

# Load to LDIF format
target = FlextLdifTarget(config={
    "output_path": "output/processed.ldif",
    "format": "standard"
})

target.process_records(records)
```

---

## 🧪 Testing Integration

### Test Utilities

```python
from tests.conftest import (
    ldif_test_data,           # Sample LDIF data fixture
    flext_ldif_api,           # Configured API instance
    sample_entries,           # Pre-created test entries
    invalid_ldif_data,        # Invalid LDIF samples
    large_ldif_dataset        # Performance test data
)

def test_ldif_parsing(ldif_test_data, flext_ldif_api):
    result = flext_ldif_api.parse(ldif_test_data)
    assert result.is_success
    assert len(result.value) > 0

    # Validate all entries
    for entry in result.value:
        entry.validate_domain_rules()  # Should not raise
```

### Test Categories

```bash
# Run specific test categories
pytest -m unit                 # Unit tests
pytest -m integration          # Integration tests
pytest -m e2e                  # End-to-end tests
pytest -m ldif                 # LDIF-specific tests
pytest -m parser               # Parser tests

# Performance tests
pytest -m performance          # Benchmark tests
pytest tests/test_large_files.py -v  # Large file handling
```

---

## 🚨 Error Handling

### Exception Hierarchy

```python
from flext_ldif.exceptions import (
    FlextLdifError,              # Base exception
    FlextLdifParseError,         # Parsing failures
    FlextLdifValidationError,    # Validation failures
    FlextLdifEntryError,         # Entry-specific errors
    FlextLdifConfigurationError  # Configuration errors
)

# Exception handling patterns
try:
    result = api.parse(ldif_content)
    if result.is_failure:
        # Handle via FlextResult pattern (preferred)
        print(f"Parse failed: {result.error}")
    else:
        entries = result.value

except FlextLdifParseError as e:
    # Direct exception handling
    print(f"Parse error: {e}")
    print(f"Line number: {e.line_number}")
    print(f"Content: {e.content_snippet}")

except FlextLdifValidationError as e:
    print(f"Validation error: {e}")
    print(f"Field: {e.field_name}")
    print(f"Value: {e.field_value}")

except FlextLdifError as e:
    print(f"General LDIF error: {e}")
```

### Error Context

```python
# FlextResult provides rich error context
result = api.parse(invalid_content)
if result.is_failure:
    print(f"Error: {result.error}")
    print(f"Details: {result.error_details}")
    print(f"Context: {result.context}")

    # Access underlying exception if available
    if result.exception:
        print(f"Exception type: {type(result.exception).__name__}")
```

---

## 📊 Configuration Reference

### FlextLdifConfig

```python
from flext_ldif import FlextLdifConfig

config = FlextLdifConfig(
    # Processing limits
    max_entries=10000,                    # Maximum entries to process
    max_attribute_values=100,             # Maximum values per attribute
    max_dn_length=512,                    # Maximum DN length

    # Validation settings
    strict_validation=True,               # Enable strict business rules
    allow_empty_attributes=False,         # Allow empty attribute values
    validate_object_classes=True,         # Validate objectClass requirements

    # Encoding settings
    input_encoding="utf-8",               # Input file encoding
    output_encoding="utf-8",              # Output file encoding
    line_separator="\n",                  # Line separator for output

    # Performance settings
    buffer_size=8192,                     # I/O buffer size
    enable_streaming=False,               # Enable streaming for large files
    parse_timeout=30.0,                   # Parse timeout in seconds

    # LDIF format settings
    wrap_lines=True,                      # Wrap long lines at 76 chars
    sort_attributes=False,                # Sort attributes in output
    include_empty_lines=True,             # Include empty lines in output

    # Integration settings
    enable_observability=True,            # Enable monitoring integration
    log_level="INFO",                     # Logging level
    metric_prefix="flext_ldif"            # Metric name prefix
)

api = FlextLdifAPI(config)
```

### Environment Variables

```bash
# Configuration via environment variables
export FLEXT_LDIF_MAX_ENTRIES=50000
export FLEXT_LDIF_STRICT_VALIDATION=true
export FLEXT_LDIF_INPUT_ENCODING=utf-8
export FLEXT_LDIF_LOG_LEVEL=DEBUG
export FLEXT_LDIF_ENABLE_OBSERVABILITY=true

# Feature flags
export FLEXT_LDIF_ENABLE_STREAMING=true
export FLEXT_LDIF_ENABLE_SCHEMA_VALIDATION=true
```

---

## 🔍 Type Safety

### Type Definitions

```python
from flext_ldif.models import (
    LDIFContent,                 # Union[str, bytes] for LDIF content
    LDIFLines,                   # list[str] for LDIF lines
    FlextLdifDNDict,             # TypedDict for DN structure
    FlextLdifAttributesDict,     # TypedDict for attributes
    FlextLdifEntryDict           # TypedDict for entry structure
)

from flext_core import FlextResult

# Type-safe operations
def process_ldif(content: LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
    api = FlextLdifAPI()
    return api.parse(content)

# Type checking with mypy
result: FlextResult[list[FlextLdifEntry]] = process_ldif(ldif_content)
```

### Generic Usage

```python
from typing import TypeVar, Generic

T = TypeVar('T')

def process_ldif_with_transform(
    content: LDIFContent,
    transform: Callable[[FlextLdifEntry], T]
) -> FlextResult[list[T]]:
    """Process LDIF with custom transformation."""
    api = FlextLdifAPI()
    parse_result = api.parse(content)

    if parse_result.is_failure:
        return FlextResult[None].fail(parse_result.error)

    transformed = [transform(entry) for entry in parse_result.value]
    return FlextResult[None].ok(transformed)
```

---

## 📋 Best Practices

### 1. Use FlextResult Pattern

```python
# ✅ Recommended: Check result status
def safe_parse(content: str) -> list[FlextLdifEntry]:
    api = FlextLdifAPI()
    result = api.parse(content)

    if result.is_success:
        return result.value
    else:
        logger.error(f"Parse failed: {result.error}")
        return []

# ❌ Avoid: Assuming success
def unsafe_parse(content: str) -> list[FlextLdifEntry]:
    api = FlextLdifAPI()
    return api.parse(content).value  # May be None!
```

### 2. Leverage Domain Validation

```python
# ✅ Use domain rules
def validate_person_entry(entry: FlextLdifEntry) -> bool:
    try:
        entry.validate_domain_rules()
        return entry.has_object_class("person")
    except ValueError:
        return False

# ✅ Use specifications for complex business logic
from flext_ldif.domain.specifications import FlextLdifPersonSpecification

person_spec = FlextLdifPersonSpecification()
person_entries = [e for e in entries if person_spec.is_satisfied_by(e)]
```

### 3. Handle Large Files Efficiently

```python
# ✅ Configure for large files
config = FlextLdifConfig(
    max_entries=100000,
    enable_streaming=True,
    buffer_size=16384
)

api = FlextLdifAPI(config)

# ✅ Process in batches
def process_large_ldif(file_path: str) -> None:
    result = api.parse_file(file_path)
    if result.is_success:
        entries = result.value

        # Process in chunks
        batch_size = 1000
        for i in range(0, len(entries), batch_size):
            batch = entries[i:i + batch_size]
            process_batch(batch)
```

### 4. Use Proper Configuration

```python
# ✅ Environment-specific configuration
def create_api_for_environment() -> FlextLdifAPI:
    env = os.getenv("ENVIRONMENT", "development")

    if env == "production":
        config = FlextLdifConfig(
            max_entries=50000,
            strict_validation=True,
            enable_observability=True,
            log_level="INFO"
        )
    else:
        config = FlextLdifConfig(
            max_entries=10000,
            strict_validation=False,
            log_level="DEBUG"
        )

    return FlextLdifAPI(config)
```

### 5. Implement Proper Error Handling

```python
# ✅ Comprehensive error handling
def robust_ldif_processing(content: str) -> Optional[str]:
    try:
        api = FlextLdifAPI()

        # Parse with error handling
        parse_result = api.parse(content)
        if parse_result.is_failure:
            logger.error(f"Parse failed: {parse_result.error}")
            return None

        entries = parse_result.value

        # Validate entries
        validation_result = api.validate(entries)
        if validation_result.is_failure:
            logger.warning(f"Validation issues: {validation_result.error}")
            # Continue with warning, don't fail

        # Generate output
        output_result = api.write(entries)
        if output_result.is_success:
            return output_result.value
        else:
            logger.error(f"Write failed: {output_result.error}")
            return None

    except Exception as e:
        logger.exception(f"Unexpected error in LDIF processing: {e}")
        return None
```

---

## 📚 Migration Guide

### From Standard LDIF Libraries

```python
# Before: python-ldap/ldif
import ldif
from io import StringIO

parser = ldif.LDIFRecordList(StringIO(content))
parser.parse()
records = parser.all_records

# After: FLEXT-LDIF
from flext_ldif import FlextLdifAPI

api = FlextLdifAPI()
result = api.parse(content)
if result.is_success:
    entries = result.value
```

### From Legacy FLEXT-LDIF Versions

```python
# Before: Complex imports (deprecated)
from flext_ldif.domain.entities import FlextLdifEntry
from flext_ldif.infrastructure.parsers import LDIFParser

# After: Simple imports
from flext_ldif import FlextLdifEntry, FlextLdifAPI

# Before: Direct parser usage
parser = LDIFParser()
entries = parser.parse(content)

# After: Unified API with error handling
api = FlextLdifAPI()
result = api.parse(content)
# Use FlextResult's unwrap_or method for cleaner code
entries = result.unwrap_or([])
```

---

**API Version**: 0.9.0 | **Last Updated**: 2025-08-03
**Status**: Active Development | **FLEXT Ecosystem**: Compatible

This comprehensive API reference covers all public interfaces, integration patterns, and best practices for the FLEXT-LDIF library within the FLEXT ecosystem.
