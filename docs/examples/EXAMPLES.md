# 🚀 FLEXT-LDIF Examples

**Version**: 0.9.0 | **Status**: Production Ready  
**Integration**: FLEXT Ecosystem Compatible

Comprehensive examples demonstrating FLEXT-LDIF enterprise LDIF processing library usage patterns.

---

## 📚 Table of Contents

- [🔧 Basic Usage](#-basic-usage)
- [🏗️ Advanced API Usage](#️-advanced-api-usage)
- [✅ Validation Examples](#-validation-examples)
- [📝 Writing and Export](#-writing-and-export)
- [🎯 Domain Operations](#-domain-operations)
- [🔍 Filtering and Search](#-filtering-and-search)
- [🏢 Enterprise Patterns](#-enterprise-patterns)
- [🚨 Error Handling](#-error-handling)
- [⚡ Performance Examples](#-performance-examples)
- [🔌 FLEXT Ecosystem Integration](#-flext-ecosystem-integration)
- [🔄 Migration Examples](#-migration-examples)

---

## 🔧 Basic Usage

### Simple LDIF Processing

```python
from flext_ldif import FlextLdifAPI

# Initialize API with default configuration
api = FlextLdifAPI()

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

# Parse LDIF content with comprehensive error handling
result = api.parse(ldif_content)

if result.is_success:
    entries = result.data
    print(f"✅ Successfully parsed {len(entries)} entries")

    # Validate entries
    validation_result = api.validate(entries)
    if validation_result.is_success:
        print("✅ All entries are valid")
    else:
        print(f"❌ Validation failed: {validation_result.error}")

    # Generate LDIF output
    output_result = api.write(entries)
    if output_result.is_success:
        print("✅ Generated LDIF output:")
        print(output_result.data)
else:
    print(f"❌ Parse failed: {result.error}")
```

### Working with Individual Entries

```python
from flext_ldif import FlextLdifEntry, FlextLdifDistinguishedName, FlextLdifAttributes

# Create entry programmatically using domain objects
dn = FlextLdifDistinguishedName(value="cn=Alice Johnson,ou=people,dc=example,dc=com")

attributes = FlextLdifAttributes(attributes={
    "cn": ["Alice Johnson"],
    "sn": ["Johnson"],
    "givenName": ["Alice"],
    "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
    "mail": ["alice.johnson@example.com", "alice@example.com"],
    "title": ["Senior Developer"],
    "department": ["Engineering"],
    "telephoneNumber": ["+1-555-456-7890"]
})

entry = FlextLdifEntry.model_validate({
    "dn": dn,
    "attributes": attributes
})

# Access entry properties
print(f"DN: {entry.dn.value}")
print(f"RDN: {entry.dn.get_rdn()}")
print(f"DN Depth: {entry.dn.get_depth()}")
print(f"Name: {entry.get_single_attribute_value('cn')}")
print(f"Object Classes: {entry.get_object_classes()}")
print(f"Email Addresses: {entry.get_attribute_values('mail')}")

# Check entry characteristics
if entry.has_object_class("person"):
    print("This is a person entry")

if entry.has_attribute("telephoneNumber"):
    print(f"Phone: {entry.get_single_attribute_value('telephoneNumber')}")

# Domain validation
try:
    entry.validate_domain_rules()
    print("✅ Entry passes domain validation")
except ValueError as e:
    print(f"❌ Domain validation failed: {e}")
```

---

## 🏗️ Advanced API Usage

### Configuration and Customization

```python
from flext_ldif import FlextLdifAPI, FlextLdifConfig

# Advanced configuration
config = FlextLdifConfig(
    max_entries=50000,              # Handle large LDIF files
    strict_validation=True,         # Enable strict business rules
    input_encoding="utf-8",         # Input file encoding
    output_encoding="utf-8",        # Output encoding
    allow_empty_attributes=False,   # Reject empty attributes
    enable_observability=True       # Enable monitoring
)

api = FlextLdifAPI(config)

# Parse large LDIF file
large_file_result = api.parse_file("data/large_export.ldif")

if large_file_result.is_success:
    entries = large_file_result.data
    print(f"Processed {len(entries)} entries from large file")

    # Write to output file
    write_result = api.write_file(entries, "output/processed.ldif")
    if write_result.is_success:
        print("Successfully wrote processed entries to file")
```

### Service Layer Usage

```python
from flext_ldif.services import (
    FlextLdifParserService,
    FlextLdifValidatorService,
    FlextLdifWriterService
)

# Use individual services for fine-grained control
config = FlextLdifConfig(strict_validation=True)

parser = FlextLdifParserService(config)
validator = FlextLdifValidatorService(config)
writer = FlextLdifWriterService(config)

# Parse with service
parse_result = parser.parse(ldif_content)
if parse_result.is_success:
    entries = parse_result.data

    # Validate each entry individually
    for i, entry in enumerate(entries):
        validation_result = validator.validate_entry(entry)
        if validation_result.is_failure:
            print(f"Entry {i} validation failed: {validation_result.error}")

    # Write with custom formatting
    write_result = writer.write(entries)
    if write_result.is_success:
        formatted_ldif = write_result.data
        print("Custom formatted LDIF:")
        print(formatted_ldif)
```

---

## ✅ Validation Examples

### Basic Validation

```python
from flext_ldif import FlextLdifAPI

api = FlextLdifAPI()

# Valid LDIF content
valid_ldif = """
dn: cn=Test User,ou=people,dc=example,dc=com
cn: Test User
sn: User
objectClass: person
objectClass: organizationalPerson
"""

# Invalid LDIF content (missing required attribute)
invalid_ldif = """
dn: cn=Invalid User,ou=people,dc=example,dc=com
cn: Invalid User
objectClass: person
# Missing required 'sn' attribute for person
"""

# Parse and validate
valid_result = api.parse(valid_ldif)
if valid_result.is_success:
    validation = api.validate(valid_result.data)
    print(f"Valid LDIF validation: {'PASSED' if validation.is_success else 'FAILED'}")

invalid_result = api.parse(invalid_ldif)
if invalid_result.is_success:
    validation = api.validate(invalid_result.data)
    print(f"Invalid LDIF validation: {'PASSED' if validation.is_success else 'FAILED'}")
    if validation.is_failure:
        print(f"Validation error: {validation.error}")
```

### Domain Rule Validation

```python
from flext_ldif import FlextLdifEntry, FlextLdifDistinguishedName, FlextLdifAttributes

# Create entry with business rule violations
try:
    # Invalid DN (empty)
    invalid_dn = FlextLdifDistinguishedName(value="")
except ValueError as e:
    print(f"DN validation error: {e}")

try:
    # Invalid attributes (no objectClass)
    dn = FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com")
    attrs = FlextLdifAttributes(attributes={"cn": ["test"]})  # Missing objectClass

    entry = FlextLdifEntry.model_validate({"dn": dn, "attributes": attrs})
    entry.validate_domain_rules()  # Will raise ValueError

except ValueError as e:
    print(f"Domain validation error: {e}")

# Valid entry with all required attributes
valid_dn = FlextLdifDistinguishedName(value="cn=Valid User,ou=people,dc=example,dc=com")
valid_attrs = FlextLdifAttributes(attributes={
    "cn": ["Valid User"],
    "sn": ["User"],  # Required for person
    "objectClass": ["person", "organizationalPerson"]
})

valid_entry = FlextLdifEntry.model_validate({"dn": valid_dn, "attributes": valid_attrs})

try:
    valid_entry.validate_domain_rules()
    print("✅ Entry passes all domain validation rules")
except ValueError as e:
    print(f"❌ Domain validation failed: {e}")
```

### Specification Pattern Validation

```python
# Future implementation with specifications
from flext_ldif.domain.specifications import (
    FlextLdifPersonSpecification,
    FlextLdifValidSpecification
)

# Business rule specifications
person_spec = FlextLdifPersonSpecification()
valid_spec = FlextLdifValidSpecification()

# Check if entry satisfies business rules
if person_spec.is_satisfied_by(entry):
    print("Entry represents a person")

    # Get specific validation errors for person entries
    person_violations = person_spec.validate_person_entry(entry)
    if person_violations:
        print("Person validation violations:")
        for violation in person_violations:
            print(f"  - {violation}")
    else:
        print("✅ Person entry is fully compliant")

# General validity check
if valid_spec.is_satisfied_by(entry):
    print("✅ Entry is valid according to all specifications")
else:
    validation_errors = valid_spec.get_validation_errors(entry)
    print("❌ Entry validation errors:")
    for error in validation_errors:
        print(f"  - {error}")
```

---

## 📝 Writing and Export

### Basic Writing Operations

```python
from flext_ldif import FlextLdifAPI
from pathlib import Path

api = FlextLdifAPI()

# Parse entries from file
result = api.parse_file("input/users.ldif")

if result.is_success:
    entries = result.data

    # Write to string
    ldif_output = api.write(entries)
    if ldif_output.is_success:
        print("LDIF String Output:")
        print(ldif_output.data[:500] + "..." if len(ldif_output.data) > 500 else ldif_output.data)

    # Write to file
    file_result = api.write_file(entries, "output/exported_users.ldif")
    if file_result.is_success:
        print("✅ Successfully exported entries to file")

        # Verify file was created
        output_path = Path("output/exported_users.ldif")
        if output_path.exists():
            print(f"File size: {output_path.stat().st_size} bytes")
```

### Filtered Export

```python
from flext_ldif import FlextLdifAPI

api = FlextLdifAPI()

# Parse all entries
result = api.parse_file("data/organization.ldif")

if result.is_success:
    all_entries = result.data

    # Filter for person entries only
    person_entries = [
        entry for entry in all_entries
        if entry.has_object_class("person")
    ]

    print(f"Found {len(person_entries)} person entries out of {len(all_entries)} total")

    # Export only person entries
    person_export = api.write(person_entries)
    if person_export.is_success:
        # Save to file
        with open("output/people_only.ldif", "w", encoding="utf-8") as f:
            f.write(person_export.data)
        print("✅ Exported person entries to people_only.ldif")

    # Filter by department
    engineering_entries = [
        entry for entry in person_entries
        if entry.has_attribute("department") and
           "Engineering" in entry.get_attribute_values("department")
    ]

    if engineering_entries:
        eng_export = api.write(engineering_entries)
        if eng_export.is_success:
            with open("output/engineering_team.ldif", "w", encoding="utf-8") as f:
                f.write(eng_export.data)
            print(f"✅ Exported {len(engineering_entries)} engineering team members")
```

---

## 🎯 Domain Operations

### DN Hierarchy Operations

```python
from flext_ldif import FlextLdifDistinguishedName

# Create DN hierarchy
base_dn = FlextLdifDistinguishedName(value="dc=example,dc=com")
org_dn = FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com")
user_dn = FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com")

# Check hierarchy relationships
print(f"Base DN: {base_dn.value}")
print(f"Org DN: {org_dn.value}")
print(f"User DN: {user_dn.value}")

print(f"User is child of org: {user_dn.is_child_of(org_dn)}")
print(f"Org is child of base: {org_dn.is_child_of(base_dn)}")
print(f"User is child of base: {user_dn.is_child_of(base_dn)}")

# Get DN components
print(f"User DN components: {user_dn.get_components()}")
print(f"User RDN: {user_dn.get_rdn()}")
print(f"User DN depth: {user_dn.get_depth()}")

# Get parent DN
parent = user_dn.get_parent_dn()
if parent:
    print(f"User parent DN: {parent.value}")

    # Navigate up the hierarchy
    grandparent = parent.get_parent_dn()
    if grandparent:
        print(f"User grandparent DN: {grandparent.value}")
```

### Attribute Manipulation

```python
from flext_ldif import FlextLdifAttributes

# Create attributes
original_attrs = FlextLdifAttributes(attributes={
    "cn": ["John Doe"],
    "sn": ["Doe"],
    "givenName": ["John"],
    "objectClass": ["person", "organizationalPerson"],
    "mail": ["john.doe@example.com"]
})

print("Original attributes:")
for name in original_attrs.get_attribute_names():
    values = original_attrs.get_values(name)
    print(f"  {name}: {values}")

# Add additional email (immutable operation)
updated_attrs = original_attrs.add_value("mail", "j.doe@example.com")

print("\nAfter adding secondary email:")
print(f"  mail: {updated_attrs.get_values('mail')}")

# Add phone number
with_phone = updated_attrs.add_value("telephoneNumber", "+1-555-123-4567")

print("\nAfter adding phone number:")
for name in with_phone.get_attribute_names():
    values = with_phone.get_values(name)
    print(f"  {name}: {values}")

# Remove an email
final_attrs = with_phone.remove_value("mail", "j.doe@example.com")

print("\nAfter removing secondary email:")
print(f"  mail: {final_attrs.get_values('mail')}")

# Replace all values for an attribute
title_attrs = final_attrs.replace_values("title", ["Senior Software Engineer", "Team Lead"])

print("\nAfter setting title:")
print(f"  title: {title_attrs.get_values('title')}")
```

### Entry Transformation

```python
from flext_ldif import FlextLdifEntry, FlextLdifDistinguishedName, FlextLdifAttributes

# Original entry
original_entry = FlextLdifEntry.model_validate({
    "dn": FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com"),
    "attributes": FlextLdifAttributes(attributes={
        "cn": ["John Doe"],
        "sn": ["Doe"],
        "givenName": ["John"],
        "objectClass": ["person", "organizationalPerson"],
        "mail": ["john.doe@company.com"],
        "title": ["Software Engineer"]
    })
})

# Transform entry (promote to senior position)
promoted_attrs = original_entry.attributes.replace_values("title", ["Senior Software Engineer"])
promoted_attrs = promoted_attrs.add_value("mail", "john.doe@senior.company.com")

# Create new entry with transformations
promoted_entry = FlextLdifEntry.model_validate({
    "dn": original_entry.dn,
    "attributes": promoted_attrs
})

print("Original entry:")
print(f"  Title: {original_entry.get_attribute_values('title')}")
print(f"  Emails: {original_entry.get_attribute_values('mail')}")

print("\nPromoted entry:")
print(f"  Title: {promoted_entry.get_attribute_values('title')}")
print(f"  Emails: {promoted_entry.get_attribute_values('mail')}")

# Validate the transformation
try:
    promoted_entry.validate_domain_rules()
    print("✅ Promoted entry passes validation")
except ValueError as e:
    print(f"❌ Transformation validation failed: {e}")
```

---

## 🔍 Filtering and Search

### Entry Filtering

```python
from flext_ldif import FlextLdifAPI

api = FlextLdifAPI()

# Load sample organization data
result = api.parse_file("data/organization.ldif")

if result.is_success:
    all_entries = result.data
    print(f"Total entries: {len(all_entries)}")

    # Filter by object class
    people = [entry for entry in all_entries if entry.has_object_class("person")]
    groups = [entry for entry in all_entries if entry.has_object_class("groupOfNames")]

    print(f"People: {len(people)}")
    print(f"Groups: {len(groups)}")

    # Filter by attribute presence
    with_email = [entry for entry in people if entry.has_attribute("mail")]
    with_phone = [entry for entry in people if entry.has_attribute("telephoneNumber")]

    print(f"People with email: {len(with_email)}")
    print(f"People with phone: {len(with_phone)}")

    # Filter by attribute value
    engineers = [
        entry for entry in people
        if entry.has_attribute("department") and
           "Engineering" in entry.get_attribute_values("department")
    ]

    managers = [
        entry for entry in people
        if entry.has_attribute("title") and
           any("Manager" in title for title in entry.get_attribute_values("title"))
    ]

    print(f"Engineers: {len(engineers)}")
    print(f"Managers: {len(managers)}")

    # Complex filtering with multiple conditions
    senior_engineers = [
        entry for entry in engineers
        if entry.has_attribute("title") and
           any("Senior" in title for title in entry.get_attribute_values("title"))
    ]

    print(f"Senior Engineers: {len(senior_engineers)}")

    # Display results
    print("\nSenior Engineers:")
    for entry in senior_engineers:
        name = entry.get_single_attribute_value("cn")
        title = entry.get_single_attribute_value("title")
        email = entry.get_single_attribute_value("mail")
        print(f"  - {name} ({title}) - {email}")
```

### DN-based Filtering

```python
from flext_ldif import FlextLdifAPI

api = FlextLdifAPI()

# Parse organizational data
result = api.parse_file("data/company.ldif")

if result.is_success:
    all_entries = result.data

    # Filter by OU (organizational unit)
    people_entries = [
        entry for entry in all_entries
        if "ou=people" in entry.dn.value.lower()
    ]

    groups_entries = [
        entry for entry in all_entries
        if "ou=groups" in entry.dn.value.lower()
    ]

    service_entries = [
        entry for entry in all_entries
        if "ou=services" in entry.dn.value.lower()
    ]

    print(f"People OU: {len(people_entries)} entries")
    print(f"Groups OU: {len(groups_entries)} entries")
    print(f"Services OU: {len(service_entries)} entries")

    # Filter by DN depth (hierarchy level)
    root_entries = [entry for entry in all_entries if entry.dn.get_depth() <= 3]
    deep_entries = [entry for entry in all_entries if entry.dn.get_depth() > 5]

    print(f"Root level entries (depth ≤ 3): {len(root_entries)}")
    print(f"Deep entries (depth > 5): {len(deep_entries)}")

    # Find entries under specific parent DN
    from flext_ldif import FlextLdifDistinguishedName

    people_base = FlextLdifDistinguishedName(value="ou=people,dc=company,dc=com")

    people_under_base = [
        entry for entry in all_entries
        if entry.dn.is_child_of(people_base)
    ]

    print(f"Entries under {people_base.value}: {len(people_under_base)}")
```

---

## 🏢 Enterprise Patterns

### Batch Processing

```python
from flext_ldif import FlextLdifAPI, FlextLdifConfig
from pathlib import Path
import time

# Configure for enterprise workloads
config = FlextLdifConfig(
    max_entries=100000,           # Handle large files
    strict_validation=True,       # Enforce business rules
    enable_observability=True     # Monitor performance
)

api = FlextLdifAPI(config)

def process_ldif_files_batch(input_dir: str, output_dir: str):
    """Process multiple LDIF files in batch."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    ldif_files = list(input_path.glob("*.ldif"))
    print(f"Found {len(ldif_files)} LDIF files to process")

    results = {
        "processed": 0,
        "failed": 0,
        "total_entries": 0,
        "processing_time": 0
    }

    start_time = time.time()

    for ldif_file in ldif_files:
        print(f"\nProcessing: {ldif_file.name}")

        try:
            # Parse file
            parse_result = api.parse_file(str(ldif_file))

            if parse_result.is_success:
                entries = parse_result.data
                print(f"  Parsed: {len(entries)} entries")

                # Validate entries
                validation_result = api.validate(entries)

                if validation_result.is_success:
                    print("  Validation: PASSED")

                    # Process only valid entries
                    valid_entries = [
                        entry for entry in entries
                        if entry.has_object_class("person") and entry.has_attribute("mail")
                    ]

                    if valid_entries:
                        # Write processed entries
                        output_file = output_path / f"processed_{ldif_file.name}"
                        write_result = api.write_file(valid_entries, str(output_file))

                        if write_result.is_success:
                            print(f"  Output: {len(valid_entries)} entries -> {output_file.name}")
                            results["processed"] += 1
                            results["total_entries"] += len(valid_entries)
                        else:
                            print(f"  ❌ Write failed: {write_result.error}")
                            results["failed"] += 1
                    else:
                        print("  No valid entries to process")
                else:
                    print(f"  ❌ Validation failed: {validation_result.error}")
                    results["failed"] += 1
            else:
                print(f"  ❌ Parse failed: {parse_result.error}")
                results["failed"] += 1

        except Exception as e:
            print(f"  ❌ Processing error: {e}")
            results["failed"] += 1

    results["processing_time"] = time.time() - start_time

    print(f"\n📊 Batch Processing Results:")
    print(f"  Successfully processed: {results['processed']} files")
    print(f"  Failed: {results['failed']} files")
    print(f"  Total entries processed: {results['total_entries']}")
    print(f"  Processing time: {results['processing_time']:.2f} seconds")
    print(f"  Average entries/second: {results['total_entries'] / results['processing_time']:.1f}")

# Run batch processing
process_ldif_files_batch("input/ldif_files", "output/processed")
```

### Data Transformation Pipeline

```python
from flext_ldif import FlextLdifAPI, FlextLdifEntry, FlextLdifDistinguishedName, FlextLdifAttributes
from typing import List, Callable

api = FlextLdifAPI()

def create_transformation_pipeline(*transformations: Callable[[FlextLdifEntry], FlextLdifEntry]) -> Callable:
    """Create a pipeline of entry transformations."""
    def pipeline(entries: List[FlextLdifEntry]) -> List[FlextLdifEntry]:
        result = entries.copy()
        for transformation in transformations:
            result = [transformation(entry) for entry in result]
        return result
    return pipeline

def normalize_email_domains(entry: FlextLdifEntry) -> FlextLdifEntry:
    """Transform to standardize email domains."""
    if not entry.has_attribute("mail"):
        return entry

    emails = entry.get_attribute_values("mail")
    normalized_emails = []

    for email in emails:
        # Replace old domain with new domain
        if "@oldcompany.com" in email:
            normalized_emails.append(email.replace("@oldcompany.com", "@newcompany.com"))
        else:
            normalized_emails.append(email)

    new_attrs = entry.attributes.replace_values("mail", normalized_emails)

    return FlextLdifEntry.model_validate({
        "dn": entry.dn,
        "attributes": new_attrs
    })

def add_employee_id(entry: FlextLdifEntry) -> FlextLdifEntry:
    """Add employee ID based on CN."""
    if not entry.has_object_class("person") or entry.has_attribute("employeeId"):
        return entry

    cn = entry.get_single_attribute_value("cn")
    if cn:
        # Generate employee ID from name
        employee_id = cn.lower().replace(" ", ".") + ".001"
        new_attrs = entry.attributes.add_value("employeeId", employee_id)

        return FlextLdifEntry.model_validate({
            "dn": entry.dn,
            "attributes": new_attrs
        })

    return entry

def standardize_phone_numbers(entry: FlextLdifEntry) -> FlextLdifEntry:
    """Standardize phone number format."""
    if not entry.has_attribute("telephoneNumber"):
        return entry

    phones = entry.get_attribute_values("telephoneNumber")
    standardized_phones = []

    for phone in phones:
        # Remove all non-numeric characters and reformat
        digits = ''.join(filter(str.isdigit, phone))
        if len(digits) == 10:
            formatted = f"+1-{digits[:3]}-{digits[3:6]}-{digits[6:]}"
            standardized_phones.append(formatted)
        else:
            standardized_phones.append(phone)  # Keep original if can't format

    new_attrs = entry.attributes.replace_values("telephoneNumber", standardized_phones)

    return FlextLdifEntry.model_validate({
        "dn": entry.dn,
        "attributes": new_attrs
    })

# Create transformation pipeline
transformation_pipeline = create_transformation_pipeline(
    normalize_email_domains,
    add_employee_id,
    standardize_phone_numbers
)

# Load and transform data
result = api.parse_file("data/employee_export.ldif")

if result.is_success:
    original_entries = result.data
    print(f"Original entries: {len(original_entries)}")

    # Apply transformations
    transformed_entries = transformation_pipeline(original_entries)

    # Validate transformed entries
    validation_result = api.validate(transformed_entries)

    if validation_result.is_success:
        print("✅ All transformed entries are valid")

        # Export transformed data
        export_result = api.write_file(transformed_entries, "output/transformed_employees.ldif")

        if export_result.is_success:
            print("✅ Exported transformed data")

            # Show transformation results
            print("\nTransformation Summary:")
            for i, (original, transformed) in enumerate(zip(original_entries[:3], transformed_entries[:3])):
                print(f"\nEntry {i+1}: {original.get_single_attribute_value('cn')}")

                # Compare emails
                orig_emails = original.get_attribute_values("mail")
                trans_emails = transformed.get_attribute_values("mail")
                if orig_emails != trans_emails:
                    print(f"  Email: {orig_emails} → {trans_emails}")

                # Check for employee ID
                emp_id = transformed.get_single_attribute_value("employeeId")
                if emp_id:
                    print(f"  Employee ID: {emp_id}")

                # Compare phone numbers
                orig_phones = original.get_attribute_values("telephoneNumber")
                trans_phones = transformed.get_attribute_values("telephoneNumber")
                if orig_phones != trans_phones:
                    print(f"  Phone: {orig_phones} → {trans_phones}")
    else:
        print(f"❌ Transformation validation failed: {validation_result.error}")
```

---

## 🚨 Error Handling

### Comprehensive Error Handling

```python
from flext_ldif import FlextLdifAPI, FlextLdifConfig
from flext_ldif.exceptions import (
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
    FlextLdifEntryError
)

def robust_ldif_processing(file_path: str) -> bool:
    """Process LDIF with comprehensive error handling."""
    try:
        # Configure with error tolerance
        config = FlextLdifConfig(
            strict_validation=False,  # Continue on validation errors
            max_entries=10000
        )

        api = FlextLdifAPI(config)

        print(f"Processing LDIF file: {file_path}")

        # Parse file with error handling
        parse_result = api.parse_file(file_path)

        if parse_result.is_failure:
            print(f"❌ Parse failed: {parse_result.error}")

            # Check for specific error types
            if "file not found" in parse_result.error.lower():
                print("  → File does not exist")
                return False
            elif "encoding" in parse_result.error.lower():
                print("  → Try different encoding")
                return False
            else:
                print("  → Check LDIF format")
                return False

        entries = parse_result.data
        print(f"✅ Successfully parsed {len(entries)} entries")

        # Validate entries with detailed error reporting
        validation_result = api.validate(entries)

        if validation_result.is_failure:
            print(f"⚠️  Validation issues found: {validation_result.error}")

            # Validate entries individually to identify specific problems
            valid_entries = []
            invalid_count = 0

            for i, entry in enumerate(entries):
                try:
                    entry.validate_domain_rules()
                    valid_entries.append(entry)
                except ValueError as e:
                    invalid_count += 1
                    print(f"  Entry {i+1} ({entry.dn.value}): {e}")

            print(f"  Valid entries: {len(valid_entries)}")
            print(f"  Invalid entries: {invalid_count}")

            # Continue with valid entries only
            entries = valid_entries
        else:
            print("✅ All entries passed validation")

        if entries:
            # Write results
            output_result = api.write_file(entries, "output/processed.ldif")

            if output_result.is_success:
                print("✅ Successfully exported processed entries")
                return True
            else:
                print(f"❌ Export failed: {output_result.error}")
                return False
        else:
            print("❌ No valid entries to process")
            return False

    except FlextLdifParseError as e:
        print(f"❌ LDIF Parse Error: {e}")
        if hasattr(e, 'line_number'):
            print(f"  At line: {e.line_number}")
        if hasattr(e, 'content_snippet'):
            print(f"  Content: {e.content_snippet}")
        return False

    except FlextLdifValidationError as e:
        print(f"❌ LDIF Validation Error: {e}")
        if hasattr(e, 'field_name'):
            print(f"  Field: {e.field_name}")
        if hasattr(e, 'field_value'):
            print(f"  Value: {e.field_value}")
        return False

    except FlextLdifEntryError as e:
        print(f"❌ LDIF Entry Error: {e}")
        return False

    except FlextLdifError as e:
        print(f"❌ FLEXT LDIF Error: {e}")
        return False

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("  Please check the LDIF file format and try again")
        return False

# Test error handling with various scenarios
test_files = [
    "data/valid.ldif",        # Should succeed
    "data/invalid.ldif",      # Should fail gracefully
    "data/nonexistent.ldif",  # Should handle file not found
    "data/malformed.ldif"     # Should handle parse errors
]

for test_file in test_files:
    print(f"\n{'='*50}")
    success = robust_ldif_processing(test_file)
    print(f"Processing result: {'SUCCESS' if success else 'FAILED'}")
```

### Recovery Strategies

```python
from flext_ldif import FlextLdifAPI, FlextLdifConfig
import logging

# Setup logging for error tracking
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ldif_processing.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('flext_ldif_processor')

def process_with_recovery(file_path: str, max_retries: int = 3) -> bool:
    """Process LDIF with recovery strategies."""

    for attempt in range(max_retries + 1):
        try:
            logger.info(f"Processing attempt {attempt + 1}/{max_retries + 1} for {file_path}")

            # Adjust configuration based on attempt
            if attempt == 0:
                # First attempt: strict mode
                config = FlextLdifConfig(strict_validation=True, max_entries=50000)
            elif attempt == 1:
                # Second attempt: relaxed validation
                config = FlextLdifConfig(strict_validation=False, max_entries=50000)
            else:
                # Final attempts: minimal requirements
                config = FlextLdifConfig(
                    strict_validation=False,
                    max_entries=10000,
                    allow_empty_attributes=True
                )

            api = FlextLdifAPI(config)

            # Parse with current configuration
            result = api.parse_file(file_path)

            if result.is_success:
                entries = result.data
                logger.info(f"Successfully parsed {len(entries)} entries on attempt {attempt + 1}")

                # Try to save successful result
                output_result = api.write_file(entries, f"output/recovered_{attempt+1}.ldif")

                if output_result.is_success:
                    logger.info(f"Successfully saved recovered data on attempt {attempt + 1}")
                    return True
                else:
                    logger.warning(f"Save failed on attempt {attempt + 1}: {output_result.error}")
            else:
                logger.warning(f"Parse failed on attempt {attempt + 1}: {result.error}")

                if attempt < max_retries:
                    logger.info("Retrying with relaxed configuration...")
                    continue
                else:
                    logger.error("All recovery attempts failed")
                    return False

        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed with exception: {e}")

            if attempt < max_retries:
                logger.info("Retrying after exception...")
                continue
            else:
                logger.error("Recovery failed after all attempts")
                return False

    return False

# Test recovery strategies
problem_files = [
    "data/large_file.ldif",     # May need memory adjustment
    "data/strict_schema.ldif",   # May need validation relaxation
    "data/mixed_format.ldif"     # May need format tolerance
]

for problem_file in problem_files:
    print(f"\n🔄 Processing {problem_file} with recovery...")
    success = process_with_recovery(problem_file)
    print(f"Recovery result: {'SUCCESS' if success else 'FAILED'}")
```

---

## ⚡ Performance Examples

### Large File Processing

```python
from flext_ldif import FlextLdifAPI, FlextLdifConfig
import time
import psutil
import os

def monitor_performance(func):
    """Decorator to monitor performance metrics."""
    def wrapper(*args, **kwargs):
        # Get initial system state
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        start_time = time.time()

        print(f"📈 Starting performance monitoring...")
        print(f"   Initial memory usage: {initial_memory:.2f} MB")

        try:
            result = func(*args, **kwargs)

            # Get final system state
            end_time = time.time()
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            duration = end_time - start_time
            memory_increase = final_memory - initial_memory

            print(f"📊 Performance Results:")
            print(f"   Execution time: {duration:.2f} seconds")
            print(f"   Memory usage: {final_memory:.2f} MB (Δ {memory_increase:+.2f} MB)")
            print(f"   Peak memory: {max(initial_memory, final_memory):.2f} MB")

            return result

        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            print(f"❌ Performance monitoring failed after {duration:.2f}s: {e}")
            raise

    return wrapper

@monitor_performance
def process_large_file(file_path: str, chunk_size: int = 10000):
    """Process large LDIF files efficiently."""

    # Configure for large file processing
    config = FlextLdifConfig(
        max_entries=chunk_size,
        strict_validation=False,
        enable_observability=True
    )

    api = FlextLdifAPI(config)

    print(f"🔄 Processing large file: {file_path}")
    print(f"   Chunk size: {chunk_size} entries")

    # Parse large file
    start_parse = time.time()
    result = api.parse_file(file_path)
    parse_time = time.time() - start_parse

    if result.is_success:
        entries = result.data
        print(f"✅ Parsed {len(entries)} entries in {parse_time:.2f}s")
        print(f"   Parse rate: {len(entries) / parse_time:.1f} entries/second")

        # Process in chunks for memory efficiency
        chunk_results = []
        total_processed = 0

        for i in range(0, len(entries), chunk_size):
            chunk = entries[i:i + chunk_size]
            chunk_start = time.time()

            # Validate chunk
            validation_result = api.validate(chunk)

            if validation_result.is_success:
                # Write chunk
                chunk_output = f"output/chunk_{i//chunk_size + 1}.ldif"
                write_result = api.write_file(chunk, chunk_output)

                if write_result.is_success:
                    chunk_time = time.time() - chunk_start
                    total_processed += len(chunk)
                    chunk_results.append({
                        'chunk': i//chunk_size + 1,
                        'entries': len(chunk),
                        'time': chunk_time,
                        'file': chunk_output
                    })

                    print(f"   Chunk {i//chunk_size + 1}: {len(chunk)} entries in {chunk_time:.2f}s")

        print(f"\n📊 Chunk Processing Summary:")
        print(f"   Total processed: {total_processed} entries")
        print(f"   Chunks created: {len(chunk_results)}")
        print(f"   Average chunk time: {sum(r['time'] for r in chunk_results) / len(chunk_results):.2f}s")

        return chunk_results
    else:
        print(f"❌ Large file processing failed: {result.error}")
        return None

# Test with different file sizes and chunk sizes
performance_tests = [
    ("data/medium.ldif", 5000),    # Medium file, small chunks
    ("data/large.ldif", 10000),    # Large file, medium chunks
    ("data/huge.ldif", 20000),     # Huge file, large chunks
]

for file_path, chunk_size in performance_tests:
    print(f"\n{'='*60}")
    results = process_large_file(file_path, chunk_size)

    if results:
        print(f"✅ Successfully processed file with {len(results)} chunks")
    else:
        print("❌ Processing failed")
```

### Memory-Efficient Streaming

```python
from flext_ldif import FlextLdifAPI, FlextLdifConfig
from typing import Generator, List
import gc

def stream_process_ldif(file_path: str, batch_size: int = 1000) -> Generator[List, None, None]:
    """Stream process LDIF file in batches to minimize memory usage."""

    config = FlextLdifConfig(
        max_entries=batch_size * 2,  # Allow some buffer
        strict_validation=False       # Focus on throughput
    )

    api = FlextLdifAPI(config)

    print(f"🌊 Streaming LDIF file: {file_path}")
    print(f"   Batch size: {batch_size} entries")

    try:
        # Read file in text mode first to estimate size
        with open(file_path, 'r', encoding='utf-8') as f:
            # Count entries by counting 'dn:' lines
            entry_count = sum(1 for line in f if line.strip().startswith('dn:'))

        print(f"   Estimated entries: {entry_count}")
        print(f"   Estimated batches: {(entry_count + batch_size - 1) // batch_size}")

        # Read and process file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse all entries first
        result = api.parse(content)

        if result.is_success:
            all_entries = result.data
            print(f"   Actual entries: {len(all_entries)}")

            # Yield batches
            for i in range(0, len(all_entries), batch_size):
                batch = all_entries[i:i + batch_size]

                # Process batch
                validation_result = api.validate(batch)

                batch_info = {
                    'batch_number': i // batch_size + 1,
                    'entries': batch,
                    'entry_count': len(batch),
                    'validation_passed': validation_result.is_success,
                    'validation_error': validation_result.error if validation_result.is_failure else None
                }

                yield batch_info

                # Force garbage collection to free memory
                gc.collect()
        else:
            print(f"❌ Failed to parse file: {result.error}")

    except Exception as e:
        print(f"❌ Streaming error: {e}")

def process_stream_batches(file_path: str):
    """Process LDIF file using streaming approach."""

    batch_count = 0
    total_entries = 0
    successful_batches = 0
    failed_batches = 0

    start_time = time.time()

    try:
        for batch_info in stream_process_ldif(file_path, batch_size=2000):
            batch_count += 1
            batch_entries = batch_info['entry_count']
            total_entries += batch_entries

            print(f"📦 Batch {batch_info['batch_number']}: {batch_entries} entries")

            if batch_info['validation_passed']:
                # Process valid entries
                person_entries = [
                    entry for entry in batch_info['entries']
                    if entry.has_object_class("person")
                ]

                if person_entries:
                    # Export person entries from this batch
                    api = FlextLdifAPI()
                    output_file = f"output/stream_batch_{batch_info['batch_number']}_people.ldif"

                    write_result = api.write_file(person_entries, output_file)

                    if write_result.is_success:
                        print(f"   ✅ Exported {len(person_entries)} people to {output_file}")
                        successful_batches += 1
                    else:
                        print(f"   ❌ Export failed: {write_result.error}")
                        failed_batches += 1
                else:
                    print("   ℹ️  No person entries in this batch")
                    successful_batches += 1
            else:
                print(f"   ❌ Validation failed: {batch_info['validation_error']}")
                failed_batches += 1

    except Exception as e:
        print(f"❌ Stream processing error: {e}")

    processing_time = time.time() - start_time

    print(f"\n📊 Stream Processing Results:")
    print(f"   Total batches: {batch_count}")
    print(f"   Total entries: {total_entries}")
    print(f"   Successful batches: {successful_batches}")
    print(f"   Failed batches: {failed_batches}")
    print(f"   Processing time: {processing_time:.2f} seconds")
    print(f"   Throughput: {total_entries / processing_time:.1f} entries/second")

# Test streaming with large files
stream_test_files = [
    "data/employees_10k.ldif",
    "data/organization_50k.ldif",
    "data/directory_export_100k.ldif"
]

for test_file in stream_test_files:
    print(f"\n{'='*70}")
    print(f"Stream processing: {test_file}")
    process_stream_batches(test_file)
```

---

## 🔌 FLEXT Ecosystem Integration

### Dependency Injection Usage

```python
from flext_core import get_flext_container
from flext_ldif import FlextLdifAPI
from flext_ldif.services import register_ldif_services

# Register FLEXT-LDIF services in the DI container
container = get_flext_container()
register_ldif_services(container)

# Get API instance from container
api = container.get(FlextLdifAPI)

# Use API with dependency injection
result = api.parse_file("data/sample.ldif")

if result.is_success:
    entries = result.data
    print(f"DI-managed API processed {len(entries)} entries")
```

### Observability Integration

```python
from flext_observability import flext_monitor_function, flext_create_trace
from flext_ldif import FlextLdifAPI

@flext_monitor_function("ldif_bulk_processing")
def process_multiple_files(file_paths: list[str]) -> dict:
    """Process multiple LDIF files with observability."""

    api = FlextLdifAPI()
    results = {
        "processed_files": 0,
        "total_entries": 0,
        "failed_files": 0,
        "processing_errors": []
    }

    for file_path in file_paths:
        with flext_create_trace(f"process_file_{file_path}") as trace:
            try:
                trace.set_attribute("file_path", file_path)

                # Parse file with tracing
                parse_result = api.parse_file(file_path)

                if parse_result.is_success:
                    entries = parse_result.data
                    trace.set_attribute("entries_count", len(entries))

                    # Validate with tracing
                    validation_result = api.validate(entries)
                    trace.set_attribute("validation_passed", validation_result.is_success)

                    if validation_result.is_success:
                        results["processed_files"] += 1
                        results["total_entries"] += len(entries)
                        trace.set_status("success")
                    else:
                        results["failed_files"] += 1
                        results["processing_errors"].append(f"{file_path}: {validation_result.error}")
                        trace.set_status("error", validation_result.error)
                else:
                    results["failed_files"] += 1
                    results["processing_errors"].append(f"{file_path}: {parse_result.error}")
                    trace.set_status("error", parse_result.error)

            except Exception as e:
                results["failed_files"] += 1
                results["processing_errors"].append(f"{file_path}: {str(e)}")
                trace.set_status("error", str(e))

    return results

# Test observability integration
test_files = [
    "data/users.ldif",
    "data/groups.ldif",
    "data/services.ldif"
]

processing_results = process_multiple_files(test_files)

print("📊 Processing Results with Observability:")
print(f"   Processed: {processing_results['processed_files']} files")
print(f"   Total entries: {processing_results['total_entries']}")
print(f"   Failed: {processing_results['failed_files']} files")

if processing_results['processing_errors']:
    print("   Errors:")
    for error in processing_results['processing_errors']:
        print(f"     - {error}")
```

### FlextResult Pattern Usage

```python
from flext_core import FlextResult
from flext_ldif import FlextLdifAPI

def chain_ldif_operations(file_path: str) -> FlextResult[str]:
    """Chain LDIF operations using FlextResult pattern."""

    api = FlextLdifAPI()

    # Chain operations using bind method
    return (api.parse_file(file_path)
              .bind(lambda entries: api.validate(entries).map(lambda _: entries))
              .bind(lambda entries: filter_person_entries(entries))
              .bind(lambda filtered: api.write(filtered)))

def filter_person_entries(entries) -> FlextResult[list]:
    """Filter for person entries only."""
    try:
        person_entries = [
            entry for entry in entries
            if entry.has_object_class("person")
        ]
        return FlextResult.success(person_entries)
    except Exception as e:
        return FlextResult.failure(f"Filtering failed: {e}")

# Use chained operations
result = chain_ldif_operations("data/mixed_entries.ldif")

if result.is_success:
    ldif_output = result.data
    print("✅ Chained operations successful")
    print(f"Generated LDIF length: {len(ldif_output)} characters")
else:
    print(f"❌ Chained operations failed: {result.error}")

# Railway-oriented programming with multiple files
def process_files_railway(*file_paths: str) -> FlextResult[dict]:
    """Process multiple files using railway-oriented programming."""

    api = FlextLdifAPI()
    results = {"files": {}, "summary": {"success": 0, "failed": 0}}

    for file_path in file_paths:
        file_result = (api.parse_file(file_path)
                         .bind(lambda entries: api.validate(entries).map(lambda _: entries))
                         .bind(lambda entries: FlextResult.success({
                             "file": file_path,
                             "entries": len(entries),
                             "people": len([e for e in entries if e.has_object_class("person")])
                         })))

        if file_result.is_success:
            file_data = file_result.data
            results["files"][file_path] = file_data
            results["summary"]["success"] += 1
        else:
            results["files"][file_path] = {"error": file_result.error}
            results["summary"]["failed"] += 1

    return FlextResult.success(results)

# Test railway pattern
railway_result = process_files_railway(
    "data/users.ldif",
    "data/groups.ldif",
    "data/invalid.ldif"
)

if railway_result.is_success:
    data = railway_result.data
    print("\n🚂 Railway Processing Results:")
    print(f"   Success: {data['summary']['success']} files")
    print(f"   Failed: {data['summary']['failed']} files")

    for file_path, file_data in data["files"].items():
        if "error" in file_data:
            print(f"   ❌ {file_path}: {file_data['error']}")
        else:
            print(f"   ✅ {file_path}: {file_data['entries']} entries, {file_data['people']} people")
```

---

## 🔄 Migration Examples

### From Standard LDIF Libraries

```python
# Before: Using python-ldap and ldif
"""
import ldif
from io import StringIO

# Old approach
class LDIFProcessor(ldif.LDIFRecordList):
    def __init__(self, input_file):
        self.records = []
        ldif.LDIFRecordList.__init__(self, input_file)

    def handle(self, dn, entry):
        self.records.append((dn, entry))

# Parse LDIF
with open('data.ldif', 'r') as f:
    parser = LDIFProcessor(f)
    parser.parse()

for dn, entry in parser.records:
    print(f"DN: {dn}")
    for attr, values in entry.items():
        print(f"  {attr}: {values}")
"""

# After: Using FLEXT-LDIF
from flext_ldif import FlextLdifAPI

def migrate_from_standard_ldif():
    """Migrate from standard LDIF processing."""

    api = FlextLdifAPI()

    # Parse LDIF (much simpler)
    result = api.parse_file('data.ldif')

    if result.is_success:
        entries = result.data

        for entry in entries:
            print(f"DN: {entry.dn.value}")

            # Access attributes (type-safe)
            for attr_name in entry.attributes.get_attribute_names():
                values = entry.attributes.get_values(attr_name)
                print(f"  {attr_name}: {values}")

            # Business logic operations (new capabilities)
            if entry.has_object_class("person"):
                print(f"  → Person: {entry.get_single_attribute_value('cn')}")

                # Domain validation
                try:
                    entry.validate_domain_rules()
                    print("  ✅ Valid person entry")
                except ValueError as e:
                    print(f"  ❌ Validation error: {e}")
    else:
        print(f"Parse error: {result.error}")

migrate_from_standard_ldif()
```

### From Legacy FLEXT-LDIF Versions

```python
# Before: Complex imports and manual instantiation
"""
from flext_ldif.domain.entities import FlextLdifEntry
from flext_ldif.infrastructure.parsers import LDIFParser
from flext_ldif.infrastructure.validators import LDIFValidator

# Old approach
parser = LDIFParser()
validator = LDIFValidator()

entries = parser.parse(content)
is_valid = validator.validate(entries)
"""

# After: Unified API
from flext_ldif import FlextLdifAPI

def migrate_from_legacy_flext():
    """Migrate from legacy FLEXT-LDIF versions."""

    # New unified approach
    api = FlextLdifAPI()

    # All operations through single API
    content = """
    dn: cn=Test User,ou=people,dc=example,dc=com
    cn: Test User
    sn: User
    objectClass: person
    objectClass: organizationalPerson
    """

    # Parse (with comprehensive error handling)
    parse_result = api.parse(content)

    if parse_result.is_success:
        entries = parse_result.data
        print(f"Parsed {len(entries)} entries")

        # Validate (integrated validation)
        validation_result = api.validate(entries)

        if validation_result.is_success:
            print("✅ Validation passed")

            # Generate output (consistent formatting)
            output_result = api.write(entries)

            if output_result.is_success:
                print("✅ Output generated")
                print(output_result.data)
            else:
                print(f"❌ Output generation failed: {output_result.error}")
        else:
            print(f"❌ Validation failed: {validation_result.error}")
    else:
        print(f"❌ Parse failed: {parse_result.error}")

migrate_from_legacy_flext()
```

### Configuration Migration

```python
# Before: Manual configuration management
"""
class OldConfig:
    def __init__(self):
        self.max_entries = 10000
        self.strict_mode = True
        self.encoding = "utf-8"
"""

# After: Structured configuration with validation
from flext_ldif import FlextLdifConfig, FlextLdifAPI

def migrate_configuration():
    """Migrate configuration to new structured approach."""

    # Environment-specific configurations
    development_config = FlextLdifConfig(
        max_entries=5000,
        strict_validation=False,
        input_encoding="utf-8",
        output_encoding="utf-8",
        allow_empty_attributes=True,
        enable_observability=False
    )

    production_config = FlextLdifConfig(
        max_entries=100000,
        strict_validation=True,
        input_encoding="utf-8",
        output_encoding="utf-8",
        allow_empty_attributes=False,
        enable_observability=True
    )

    # Use environment-specific API
    import os
    env = os.getenv("ENVIRONMENT", "development")

    if env == "production":
        api = FlextLdifAPI(production_config)
        print("🏭 Using production configuration")
    else:
        api = FlextLdifAPI(development_config)
        print("🔧 Using development configuration")

    # Configuration is now type-safe and validated
    config = api._config
    print(f"   Max entries: {config.max_entries}")
    print(f"   Strict validation: {config.strict_validation}")
    print(f"   Observability: {config.enable_observability}")

    return api

# Test configuration migration
api = migrate_configuration()

# Test with configuration
test_content = """
dn: cn=Config Test,ou=people,dc=example,dc=com
cn: Config Test
objectClass: person
objectClass: organizationalPerson
"""

result = api.parse(test_content)
print(f"Configuration test result: {'SUCCESS' if result.is_success else 'FAILED'}")
```

---

## 📚 Complete Example: Enterprise LDIF Processing

```python
"""
Complete enterprise LDIF processing example demonstrating
all major features and best practices.
"""

from flext_ldif import FlextLdifAPI, FlextLdifConfig
from flext_core import get_logger
from pathlib import Path
import time
import json

# Setup enterprise logging
logger = get_logger("enterprise_ldif_processor")

class EnterpriseLdifProcessor:
    """
    Enterprise-grade LDIF processor with comprehensive features.
    """

    def __init__(self, config_file: str | None = None):
        """Initialize with configuration."""
        self.config = self._load_config(config_file)
        self.api = FlextLdifAPI(self.config)
        self.statistics = {
            "files_processed": 0,
            "total_entries": 0,
            "valid_entries": 0,
            "invalid_entries": 0,
            "processing_time": 0,
            "errors": []
        }

    def _load_config(self, config_file: str | None) -> FlextLdifConfig:
        """Load configuration from file or use defaults."""
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            return FlextLdifConfig(**config_data)
        else:
            return FlextLdifConfig(
                max_entries=50000,
                strict_validation=True,
                enable_observability=True
            )

    def process_directory(self, input_dir: str, output_dir: str) -> dict:
        """Process all LDIF files in a directory."""
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        ldif_files = list(input_path.glob("*.ldif"))
        logger.info(f"Found {len(ldif_files)} LDIF files to process")

        start_time = time.time()

        for ldif_file in ldif_files:
            logger.info(f"Processing {ldif_file.name}")

            try:
                self._process_single_file(ldif_file, output_path)
                self.statistics["files_processed"] += 1

            except Exception as e:
                error_msg = f"Failed to process {ldif_file.name}: {e}"
                logger.error(error_msg)
                self.statistics["errors"].append(error_msg)

        self.statistics["processing_time"] = time.time() - start_time

        return self.statistics

    def _process_single_file(self, input_file: Path, output_dir: Path):
        """Process a single LDIF file with comprehensive handling."""

        # Parse file
        parse_result = self.api.parse_file(str(input_file))

        if parse_result.is_failure:
            raise ValueError(f"Parse failed: {parse_result.error}")

        entries = parse_result.data
        self.statistics["total_entries"] += len(entries)
        logger.info(f"  Parsed {len(entries)} entries")

        # Separate valid and invalid entries
        valid_entries = []
        invalid_entries = []

        for entry in entries:
            try:
                entry.validate_domain_rules()
                valid_entries.append(entry)
            except ValueError as e:
                invalid_entries.append((entry, str(e)))

        self.statistics["valid_entries"] += len(valid_entries)
        self.statistics["invalid_entries"] += len(invalid_entries)

        logger.info(f"  Valid: {len(valid_entries)}, Invalid: {len(invalid_entries)}")

        # Process valid entries by category
        self._export_by_category(valid_entries, output_dir, input_file.stem)

        # Log invalid entries
        if invalid_entries:
            self._log_invalid_entries(invalid_entries, output_dir, input_file.stem)

    def _export_by_category(self, entries: list, output_dir: Path, base_name: str):
        """Export entries categorized by type."""

        categories = {
            "people": [e for e in entries if e.has_object_class("person")],
            "groups": [e for e in entries if e.has_object_class("groupOfNames")],
            "services": [e for e in entries if e.has_object_class("applicationProcess")],
            "other": [e for e in entries if not any([
                e.has_object_class("person"),
                e.has_object_class("groupOfNames"),
                e.has_object_class("applicationProcess")
            ])]
        }

        for category, category_entries in categories.items():
            if category_entries:
                output_file = output_dir / f"{base_name}_{category}.ldif"

                write_result = self.api.write_file(category_entries, str(output_file))

                if write_result.is_success:
                    logger.info(f"  Exported {len(category_entries)} {category} to {output_file.name}")
                else:
                    logger.error(f"  Failed to export {category}: {write_result.error}")

    def _log_invalid_entries(self, invalid_entries: list, output_dir: Path, base_name: str):
        """Log invalid entries with details."""
        log_file = output_dir / f"{base_name}_invalid.log"

        with open(log_file, 'w') as f:
            f.write(f"Invalid Entries Log for {base_name}\n")
            f.write("=" * 50 + "\n\n")

            for i, (entry, error) in enumerate(invalid_entries, 1):
                f.write(f"Entry {i}: {entry.dn.value}\n")
                f.write(f"Error: {error}\n")
                f.write(f"Object Classes: {entry.get_object_classes()}\n")
                f.write("-" * 30 + "\n")

        logger.info(f"  Logged {len(invalid_entries)} invalid entries to {log_file.name}")

    def generate_report(self) -> str:
        """Generate processing report."""
        stats = self.statistics

        report = f"""
Enterprise LDIF Processing Report
================================

Processing Summary:
  Files processed: {stats['files_processed']}
  Total entries: {stats['total_entries']}
  Valid entries: {stats['valid_entries']} ({stats['valid_entries']/stats['total_entries']*100:.1f}%)
  Invalid entries: {stats['invalid_entries']} ({stats['invalid_entries']/stats['total_entries']*100:.1f}%)
  Processing time: {stats['processing_time']:.2f} seconds
  Processing rate: {stats['total_entries']/stats['processing_time']:.1f} entries/second

Quality Metrics:
  Success rate: {(stats['files_processed']/(stats['files_processed']+len(stats['errors'])))*100:.1f}%
  Validation rate: {stats['valid_entries']/stats['total_entries']*100:.1f}%

"""

        if stats['errors']:
            report += "\nErrors Encountered:\n"
            for error in stats['errors']:
                report += f"  - {error}\n"

        return report

# Usage example
def main():
    """Main enterprise processing example."""

    print("🏢 Enterprise LDIF Processor")
    print("=" * 50)

    # Initialize processor
    processor = EnterpriseLdifProcessor("config/production.json")

    # Process directory
    try:
        stats = processor.process_directory("input/ldif_files", "output/processed")

        # Generate and display report
        report = processor.generate_report()
        print(report)

        # Save report
        with open("output/processing_report.txt", "w") as f:
            f.write(report)

        print("✅ Processing complete. Report saved to output/processing_report.txt")

    except Exception as e:
        logger.error(f"Enterprise processing failed: {e}")
        print(f"❌ Processing failed: {e}")

if __name__ == "__main__":
    main()
```

---

**Examples Version**: 0.9.0 | **Last Updated**: 2025-08-03  
**Status**: Production Ready | **FLEXT Ecosystem**: Compatible

These comprehensive examples demonstrate the full capabilities of FLEXT-LDIF within the FLEXT ecosystem, from basic usage to enterprise-grade processing patterns.
