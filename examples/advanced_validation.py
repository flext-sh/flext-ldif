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
    # Create API with strict validation
    config = FlextLdifConfig(
        strict_validation=True,
        allow_empty_attributes=False,
        max_entries=50,
    )
    api = FlextLdifAPI(config)

    # Parse complex LDIF file
    sample_file = Path(__file__).parent / "sample_complex.ldif"

    result = api.parse_file(sample_file)

    if not result.is_success:
        return

    entries = result.data
    if not entries:
        return

    # Perform domain validation
    domain_valid = 0
    domain_errors = []

    for i, entry in enumerate(entries):
        validation_result = entry.validate_domain_rules()
        if validation_result.is_success:
            domain_valid += 1
        else:
            domain_errors.append(f"Entry {i + 1} ({entry.dn}): {validation_result.error}")

    if domain_errors:
        for _error in domain_errors[:5]:  # Show first 5 errors
            pass
        if len(domain_errors) > 5:
            pass

    # Perform business rule validation
    business_valid = 0
    business_errors = []

    for i, entry in enumerate(entries):
        is_valid, errors = validate_business_rules(entry)
        if is_valid:
            business_valid += 1
        else:
            business_errors.extend(f"Entry {i + 1} ({entry.dn}): {error}" for error in errors)

    if business_errors:
        for _error in business_errors[:5]:  # Show first 5 errors
            pass
        if len(business_errors) > 5:
            pass

    # Analyze entry types
    person_result = api.filter_persons(entries)
    group_result = api.filter_groups(entries)
    ou_result = api.filter_organizational_units(entries)

    if person_result.is_success and person_result.data is not None:
        pass

    if group_result.is_success and group_result.data is not None:
        pass

    if ou_result.is_success and ou_result.data is not None:
        pass

    # Test with invalid LDIF
    invalid_file = Path(__file__).parent / "sample_invalid.ldif"

    if invalid_file.exists():
        invalid_result = api.parse_file(invalid_file)

        if invalid_result.is_success and invalid_result.data:

            # Validate each invalid entry
            for i, entry in enumerate(invalid_result.data):
                validation_result = entry.validate_domain_rules()
                if not validation_result.is_success:
                    pass

    # Generate validation report


if __name__ == "__main__":
    main()
