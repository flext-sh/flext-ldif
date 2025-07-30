#!/usr/bin/env python3
"""Advanced LDIF validation example.

Demonstrates domain validation with business rules using
Clean Architecture patterns and FlextResult error handling.
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdifAPI, FlextLdifConfig, FlextLdifEntry


def validate_business_rules(entry: FlextLdifEntry) -> tuple[bool, list[str]]:
    """Apply custom business validation rules.
    
    Args:
        entry: LDIF entry to validate
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Rule 1: Person entries must have email
    if entry.is_person_entry():
        mail = entry.attributes.get("mail")
        if not mail or not mail[0]:
            errors.append("Person entries must have email address")
    
    # Rule 2: Employee numbers must be numeric
    employee_num = entry.attributes.get("employeeNumber")
    if employee_num:
        try:
            int(employee_num[0])
        except (ValueError, IndexError):
            errors.append("Employee number must be numeric")
    
    # Rule 3: Phone numbers must follow format
    phone = entry.attributes.get("telephoneNumber")
    if phone and phone[0]:
        phone_num = phone[0]
        if not phone_num.startswith("+1-555-"):
            errors.append("Phone number must follow +1-555-XXXX format")
    
    # Rule 4: Manager must be a valid DN
    manager = entry.attributes.get("manager")
    if manager and manager[0]:
        manager_dn = manager[0]
        if "ou=People" not in manager_dn:
            errors.append("Manager must be in People OU")
    
    return len(errors) == 0, errors


def main() -> None:
    """Demonstrate advanced LDIF validation."""
    print("🔍 FLEXT LDIF Advanced Validation Example")
    print("=" * 55)

    # Create API with strict validation
    config = FlextLdifConfig(
        strict_validation=True,
        allow_empty_attributes=False,
        max_entries=50,
    )
    api = FlextLdifAPI(config)

    # Parse complex LDIF file
    sample_file = Path(__file__).parent / "sample_complex.ldif"
    print(f"📖 Parsing complex LDIF file: {sample_file}")
    
    result = api.parse_file(sample_file)
    
    if not result.is_success:
        print(f"❌ Parsing failed: {result.error}")
        return
    
    entries = result.data
    if not entries:
        print("❌ No entries found")
        return
        
    print(f"✅ Successfully parsed {len(entries)} entries")
    
    # Perform domain validation
    print("\n🔬 Performing domain validation...")
    domain_valid = 0
    domain_errors = []
    
    for i, entry in enumerate(entries):
        validation_result = entry.validate_domain_rules()
        if validation_result.is_success:
            domain_valid += 1
        else:
            domain_errors.append(f"Entry {i+1} ({entry.dn}): {validation_result.error}")
    
    print(f"✅ Domain validation: {domain_valid}/{len(entries)} entries valid")
    
    if domain_errors:
        print("❌ Domain validation errors:")
        for error in domain_errors[:5]:  # Show first 5 errors
            print(f"  - {error}")
        if len(domain_errors) > 5:
            print(f"  ... and {len(domain_errors) - 5} more errors")
    
    # Perform business rule validation
    print("\n📋 Applying business rules validation...")
    business_valid = 0
    business_errors = []
    
    for i, entry in enumerate(entries):
        is_valid, errors = validate_business_rules(entry)
        if is_valid:
            business_valid += 1
        else:
            for error in errors:
                business_errors.append(f"Entry {i+1} ({entry.dn}): {error}")
    
    print(f"✅ Business rules: {business_valid}/{len(entries)} entries valid")
    
    if business_errors:
        print("❌ Business rule violations:")
        for error in business_errors[:5]:  # Show first 5 errors
            print(f"  - {error}")
        if len(business_errors) > 5:
            print(f"  ... and {len(business_errors) - 5} more violations")
    
    # Analyze entry types
    print("\n📊 Entry type analysis:")
    person_result = api.filter_persons(entries)
    group_result = api.filter_groups(entries)
    ou_result = api.filter_organizational_units(entries)
    
    if person_result.is_success and person_result.data is not None:
        print(f"  👤 Person entries: {len(person_result.data)}")
    
    if group_result.is_success and group_result.data is not None:
        print(f"  👥 Group entries: {len(group_result.data)}")
    
    if ou_result.is_success and ou_result.data is not None:
        print(f"  🏢 Organizational units: {len(ou_result.data)}")
    
    # Test with invalid LDIF
    print("\n🚨 Testing with invalid LDIF...")
    invalid_file = Path(__file__).parent / "sample_invalid.ldif"
    
    if invalid_file.exists():
        invalid_result = api.parse_file(invalid_file)
        
        if invalid_result.is_success and invalid_result.data:
            print(f"⚠️  Parsed {len(invalid_result.data)} entries from invalid file")
            
            # Validate each invalid entry
            for i, entry in enumerate(invalid_result.data):
                validation_result = entry.validate_domain_rules()
                if not validation_result.is_success:
                    print(f"  ❌ Invalid entry {i+1}: {validation_result.error}")
        else:
            print(f"❌ Invalid file parsing failed: {invalid_result.error}")
    
    # Generate validation report
    print("\n📋 Validation Summary Report:")
    print(f"  Total entries processed: {len(entries)}")
    print(f"  Domain validation passed: {domain_valid}")
    print(f"  Business rules passed: {business_valid}")
    print(f"  Domain validation rate: {domain_valid/len(entries)*100:.1f}%")
    print(f"  Business rules compliance: {business_valid/len(entries)*100:.1f}%")
    
    print("\n🎉 Advanced validation example completed!")


if __name__ == "__main__":
    main()