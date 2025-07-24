# 📚 FLEXT LDIF API Reference

Complete API documentation for FLEXT LDIF library.

## 🚀 Quick Import Guide

### ✅ Recommended Imports (Simple & Clean)

```python
# Simple functions - most common use cases
from flext_ldif import parse_ldif, write_ldif, validate_ldif

# Core classes with FlextLdif prefix
from flext_ldif import FlextLdifEntry, FlextLdifParser, FlextLdifValidator

# Value objects
from flext_ldif import FlextLdifDistinguishedName, FlextLdifAttributes

# Processing classes
from flext_ldif import FlextLdifProcessor, FlextLdifWriter
```

### ⚠️ Legacy Imports (Deprecated but Still Work)

```python
# These still work but show deprecation warnings
from flext_ldif import LDIFEntry, LDIFParser  # Use FlextLdifEntry, FlextLdifParser
from flext_ldif.domain.entities import FlextLdifEntry  # Use root import
```

## 🔧 Simple Functions API

### `parse_ldif(content: str | LDIFContent) -> list[FlextLdifEntry]`

Parse LDIF content into entry objects.

**Parameters:**
- `content`: LDIF content as string or LDIFContent type

**Returns:**
- `list[FlextLdifEntry]`: List of parsed LDIF entries

**Example:**
```python
from flext_ldif import parse_ldif

ldif_content = """
dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
mail: john@example.com

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
objectClass: person
mail: jane@example.com
"""

entries = parse_ldif(ldif_content)
print(f"Parsed {len(entries)} entries")

for entry in entries:
    print(f"DN: {entry.dn}")
    print(f"Mail: {entry.get_attribute_values('mail')}")
```

### `write_ldif(entries: list[FlextLdifEntry], output_path: str | None = None) -> str`

Write LDIF entries to string or file.

**Parameters:**
- `entries`: List of FlextLdifEntry objects to write
- `output_path`: Optional file path to write to

**Returns:**
- `str`: LDIF content as string, or success message if writing to file

**Example:**
```python
from flext_ldif import parse_ldif, write_ldif

# Parse some entries
entries = parse_ldif(ldif_content)

# Write to string
ldif_output = write_ldif(entries)
print(ldif_output)

# Write to file
result = write_ldif(entries, "/tmp/output.ldif")
print(result)  # "Written to /tmp/output.ldif"
```

### `validate_ldif(content: str | LDIFContent) -> bool`

Validate LDIF content format and structure.

**Parameters:**
- `content`: LDIF content to validate

**Returns:**
- `bool`: True if valid, False otherwise

**Example:**
```python
from flext_ldif import validate_ldif

valid_ldif = """
dn: cn=Test User,dc=example,dc=com
cn: Test User
objectClass: person
"""

invalid_ldif = """
invalid-dn-format
cn: Test User
"""

print(validate_ldif(valid_ldif))    # True
print(validate_ldif(invalid_ldif))  # False
```

## 📊 Core Classes API

### `FlextLdifEntry`

Main class representing an LDIF entry.

#### Constructor

```python
FlextLdifEntry.model_validate(data: dict) -> FlextLdifEntry
```

**Parameters:**
- `data`: Dictionary with `dn` and `attributes` keys

**Example:**
```python
from flext_ldif import FlextLdifEntry

entry = FlextLdifEntry.model_validate({
    "dn": "cn=John Doe,ou=people,dc=example,dc=com",
    "attributes": {
        "cn": ["John Doe"],
        "objectClass": ["person", "inetOrgPerson"],
        "mail": ["john@example.com"],
        "sn": ["Doe"],
        "givenName": ["John"]
    }
})
```

#### Properties

- `dn: FlextLdifDistinguishedName` - Distinguished name
- `attributes: FlextLdifAttributes` - Entry attributes

#### Methods

##### `get_object_classes() -> list[str]`

Get all objectClass values for this entry.

```python
entry = FlextLdifEntry.model_validate({...})
classes = entry.get_object_classes()
print(classes)  # ['person', 'inetOrgPerson']
```

##### `has_object_class(object_class: str) -> bool`

Check if entry has specific object class.

```python
if entry.has_object_class("person"):
    print("This is a person entry")
```

##### `get_attribute_values(name: str) -> list[str]`

Get all values for specified attribute.

```python
emails = entry.get_attribute_values("mail")
phone_numbers = entry.get_attribute_values("telephoneNumber")
```

##### `has_attribute(name: str) -> bool`

Check if entry has specific attribute.

```python
if entry.has_attribute("mail"):
    print("Entry has email address")
```

##### `get_attribute(name: str) -> list[str] | None`

Get attribute values or None if not present.

```python
mail = entry.get_attribute("mail")
if mail:
    print(f"Primary email: {mail[0]}")
```

##### `get_single_attribute(name: str) -> str | None`

Get first value of attribute or None.

```python
cn = entry.get_single_attribute("cn")
if cn:
    print(f"Common name: {cn}")
```

##### `to_ldif() -> str`

Convert entry to LDIF string format.

```python
ldif_string = entry.to_ldif()
print(ldif_string)
# dn: cn=John Doe,ou=people,dc=example,dc=com
# cn: John Doe
# objectClass: person
# objectClass: inetOrgPerson
# mail: john@example.com
```

##### `validate_domain_rules() -> None`

Validate entry against domain business rules.

```python
try:
    entry.validate_domain_rules()
    print("Entry is valid")
except ValueError as e:
    print(f"Validation error: {e}")
```

##### `is_modify_operation() -> bool`

Check if entry represents a modify operation.

```python
if entry.is_modify_operation():
    print("This is a modify operation")
```

##### `is_add_operation() -> bool`

Check if entry represents an add operation.

##### `is_delete_operation() -> bool`

Check if entry represents a delete operation.

#### Class Methods

##### `from_ldif_block(ldif_block: str) -> FlextLdifEntry`

Create entry from LDIF text block.

```python
ldif_block = """
dn: cn=Test User,dc=example,dc=com
cn: Test User
objectClass: person
mail: test@example.com
"""

entry = FlextLdifEntry.from_ldif_block(ldif_block)
```

### `FlextLdifDistinguishedName`

Immutable value object representing a distinguished name.

#### Constructor

```python
FlextLdifDistinguishedName.model_validate({"value": "cn=user,dc=example,dc=com"})
```

#### Properties

- `value: str` - The DN string value

#### Methods

##### `get_rdn() -> str`

Get the relative distinguished name (first component).

```python
dn = FlextLdifDistinguishedName.model_validate({
    "value": "cn=John Doe,ou=people,dc=example,dc=com"
})
rdn = dn.get_rdn()  # "cn=John Doe"
```

##### `get_parent_dn() -> FlextLdifDistinguishedName | None`

Get parent DN or None for root.

```python
parent = dn.get_parent_dn()
if parent:
    print(f"Parent: {parent.value}")  # "ou=people,dc=example,dc=com"
```

##### `is_child_of(parent: FlextLdifDistinguishedName) -> bool`

Check if this DN is a child of another DN.

```python
child_dn = FlextLdifDistinguishedName.model_validate({
    "value": "cn=John,ou=people,dc=example,dc=com"
})
parent_dn = FlextLdifDistinguishedName.model_validate({
    "value": "ou=people,dc=example,dc=com"
})

if child_dn.is_child_of(parent_dn):
    print("Child relationship confirmed")
```

##### `get_depth() -> int`

Get the depth of the DN (number of components).

```python
depth = dn.get_depth()  # 4 for "cn=John,ou=people,dc=example,dc=com"
```

##### `validate_domain_rules() -> None`

Validate DN format and business rules.

### `FlextLdifAttributes`

Immutable value object representing LDIF attributes.

#### Constructor

```python
FlextLdifAttributes.model_validate({
    "attributes": {
        "cn": ["John Doe"],
        "mail": ["john@example.com", "j.doe@example.com"]
    }
})
```

#### Properties

- `attributes: dict[str, list[str]]` - Attribute dictionary

#### Methods

##### `get_values(name: str) -> list[str]`

Get all values for an attribute.

```python
attrs = FlextLdifAttributes.model_validate({
    "attributes": {"mail": ["john@example.com", "j.doe@example.com"]}
})
emails = attrs.get_values("mail")  # ["john@example.com", "j.doe@example.com"]
missing = attrs.get_values("phone")  # []
```

##### `get_single_value(name: str) -> str | None`

Get first value of attribute or None.

```python
primary_email = attrs.get_single_value("mail")  # "john@example.com"
phone = attrs.get_single_value("phone")  # None
```

##### `has_attribute(name: str) -> bool`

Check if attribute exists.

```python
if attrs.has_attribute("mail"):
    print("Has email address")
```

##### `add_value(name: str, value: str) -> FlextLdifAttributes`

Return new instance with added value (immutable).

```python
new_attrs = attrs.add_value("phone", "+1-555-123-4567")
# Original attrs unchanged, new_attrs has the phone number
```

##### `remove_value(name: str, value: str) -> FlextLdifAttributes`

Return new instance with removed value.

```python
new_attrs = attrs.remove_value("mail", "j.doe@example.com")
# new_attrs only has "john@example.com"
```

##### `get_attribute_names() -> list[str]`

Get list of all attribute names.

```python
names = attrs.get_attribute_names()  # ["cn", "mail", "objectClass"]
```

##### `get_total_values() -> int`

Get total number of values across all attributes.

```python
total = attrs.get_total_values()  # Sum of all value counts
```

##### `is_empty() -> bool`

Check if attributes collection is empty.

```python
if attrs.is_empty():
    print("No attributes defined")
```

## 🏗️ Processing Classes API

### `FlextLdifParser`

LDIF parsing with error handling and validation.

#### Methods

##### `parse_ldif_content(content: str) -> FlextResult[list[FlextLdifEntry]]`

Parse LDIF content with comprehensive error handling.

```python
from flext_ldif import FlextLdifParser

parser = FlextLdifParser()
result = parser.parse_ldif_content(ldif_content)

if result.success:
    entries = result.data
    print(f"Parsed {len(entries)} entries")
else:
    print(f"Parse error: {result.error}")
```

##### `parse_ldif_file(file_path: Path) -> FlextResult[list[FlextLdifEntry]]`

Parse LDIF file with error handling.

```python
from pathlib import Path

result = parser.parse_ldif_file(Path("/path/to/file.ldif"))
if result.success:
    entries = result.data
```

### `FlextLdifValidator`

LDIF validation with detailed error reporting.

#### Methods

##### `validate_entry(entry: FlextLdifEntry) -> FlextResult[bool]`

Validate single LDIF entry.

```python
from flext_ldif import FlextLdifValidator

validator = FlextLdifValidator()
result = validator.validate_entry(entry)

if result.success:
    print("Entry is valid")
else:
    print(f"Validation error: {result.error}")
```

##### `validate_entries(entries: list[FlextLdifEntry]) -> FlextResult[bool]`

Validate multiple LDIF entries.

```python
result = validator.validate_entries(entries)
if not result.success:
    print(f"Validation failed: {result.error}")
```

### `FlextLdifWriter`

LDIF writing with formatting and error handling.

#### Methods

##### `write_entries_to_file(file_path: Path, entries: list[dict]) -> FlextResult[str]`

Write dictionary entries to file.

```python
from flext_ldif import FlextLdifWriter
from pathlib import Path

writer = FlextLdifWriter()
dict_entries = [
    {
        "dn": "cn=John,dc=example,dc=com",
        "cn": ["John"],
        "objectClass": ["person"]
    }
]

result = writer.write_entries_to_file(Path("/tmp/output.ldif"), dict_entries)
if result.success:
    print("File written successfully")
```

##### `write_flext_entries_to_file(file_path: Path, entries: list[FlextLdifEntry]) -> FlextResult[str]`

Write FlextLdifEntry objects to file.

```python
result = writer.write_flext_entries_to_file(Path("/tmp/output.ldif"), entries)
```

### `FlextLdifProcessor`

High-level processing orchestrator.

#### Methods

##### `parse_ldif_content(content: str) -> FlextResult[list[FlextLdifEntry]]`

Parse LDIF content using domain objects.

##### `validate_entries(entries: list[FlextLdifEntry]) -> FlextResult[bool]`

Validate entries using domain specifications.

##### `filter_entries(entries: list[FlextLdifEntry], spec: FlextSpecification) -> list[FlextLdifEntry]`

Filter entries using specification pattern.

```python
from flext_ldif import FlextLdifProcessor

processor = FlextLdifProcessor()

# Parse content
result = processor.parse_ldif_content(ldif_content)
if result.success:
    entries = result.data
    
    # Filter for person entries only
    person_entries = processor.filter_person_entries(entries)
    
    # Validate all entries
    validation_result = processor.validate_entries(entries)
```

##### `filter_person_entries(entries: list[FlextLdifEntry]) -> list[FlextLdifEntry]`

Filter entries that are person objects.

##### `filter_valid_entries(entries: list[FlextLdifEntry]) -> list[FlextLdifEntry]`

Filter entries that pass validation.

## 🔧 Utility Functions API

### `FlextLdifUtils`

Utility functions for LDIF operations.

```python
from flext_ldif import FlextLdifUtils

# Hierarchical sorting
sorted_entries = FlextLdifUtils.sort_entries_hierarchically(entries)

# Find entry by DN
entry = FlextLdifUtils.find_entry_by_dn(entries, "cn=John,dc=example,dc=com")

# Filter by object class
person_entries = FlextLdifUtils.filter_by_objectclass(entries, "person")
```

## 🎯 Domain Specifications API

### `FlextLdifPersonSpecification`

Specification for person entries.

```python
from flext_ldif.domain.specifications import FlextLdifPersonSpecification

spec = FlextLdifPersonSpecification()
if spec.is_satisfied_by(entry):
    print("Entry represents a person")
```

### `FlextLdifValidSpecification`

Specification for valid entries.

```python
from flext_ldif.domain.specifications import FlextLdifValidSpecification

spec = FlextLdifValidSpecification()
if spec.is_satisfied_by(entry):
    print("Entry is valid")
```

## 🚨 Exception Handling

### Exception Types

```python
from flext_ldif import (
    FlextLdifError,          # Base exception
    FlextLdifParseError,     # Parsing errors
    FlextLdifValidationError, # Validation errors
    FlextLdifEntryError      # Entry-specific errors
)

try:
    entries = parse_ldif(invalid_content)
except FlextLdifParseError as e:
    print(f"Parse error: {e}")
except FlextLdifError as e:
    print(f"General LDIF error: {e}")
```

## 🔄 Migration Examples

### From Standard LDIF Libraries

```python
# Old way (standard ldif library)
import ldif
from io import StringIO

parser = ldif.LDIFRecordList(StringIO(ldif_content))
parser.parse()
records = parser.all_records

# New way (FLEXT LDIF)
from flext_ldif import parse_ldif

entries = parse_ldif(ldif_content)
```

### From Complex to Simple Imports

```python
# Old complex imports (still work but deprecated)
from flext_ldif.domain.entities import FlextLdifEntry
from flext_ldif.infrastructure.parsers import LDIFParser

# New simple imports
from flext_ldif import FlextLdifEntry, FlextLdifParser
```

## 🔍 Type Information

### Type Aliases

```python
from flext_ldif import LDIFContent, LDIFLines

# LDIFContent: Union of string types for LDIF content
# LDIFLines: List of LDIF lines
```

### Generic Types

```python
from flext_core import FlextResult

# All methods returning results use FlextResult[T]
result: FlextResult[list[FlextLdifEntry]] = parser.parse_ldif_content(content)
```

## 📝 Best Practices

### 1. **Use Simple Imports**

```python
# ✅ Recommended
from flext_ldif import parse_ldif, FlextLdifEntry

# ❌ Avoid (deprecated)
from flext_ldif.domain.entities import FlextLdifEntry
```

### 2. **Handle Results Properly**

```python
# ✅ Check result status
result = parser.parse_ldif_content(content)
if result.success:
    entries = result.data
else:
    logger.error(f"Parse failed: {result.error}")

# ❌ Don't assume success
entries = parser.parse_ldif_content(content).data  # May be None!
```

### 3. **Use Domain Validation**

```python
# ✅ Validate using domain rules
try:
    entry.validate_domain_rules()
except ValueError as e:
    logger.error(f"Domain validation failed: {e}")

# ✅ Use specifications for business logic
if person_spec.is_satisfied_by(entry):
    process_person_entry(entry)
```

### 4. **Leverage Immutability**

```python
# ✅ Value objects are immutable
new_attrs = attrs.add_value("phone", "+1-555-123")
# Original attrs unchanged

# ✅ Create new instances for modifications
new_entry = FlextLdifEntry.model_validate({
    "dn": entry.dn,
    "attributes": new_attrs
})
```

---

This comprehensive API reference covers all public interfaces and common usage patterns for FLEXT LDIF library.