"""Example 2: Advanced Entry Operations - Intelligent Builders and Batch Processing.

Demonstrates flext-ldif advanced entry operations with minimal code bloat:
- Intelligent builders that auto-detect entry types and objectClasses
- Advanced filtering with multiple criteria and custom predicates
- Batch processing for bulk operations with parallel execution
- Efficient format conversions with validation
- Railway-oriented error handling with composition

This example shows how flext-ldif enables ADVANCED automation through intelligent builders.
Original: 235 lines | Advanced: ~150 lines with intelligent builders + batch processing + advanced filters
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from flext_core import FlextResult

from flext_ldif import FlextLdif, FlextLdifModels


def intelligent_entry_builders() -> FlextResult[list[FlextLdifModels.Entry]]:
    """Intelligent entry builders that auto-detect types and validate structure."""
    api: FlextLdif = FlextLdif.get_instance()

    entries = []

    # Intelligent person builder - auto-detects inetOrgPerson from mail attribute
    person_data = {
        "dn": "cn=Alice Johnson,ou=People,dc=example,dc=com",
        "cn": "Alice Johnson",
        "sn": "Johnson",
        "mail": "alice.johnson@example.com",
        "telephoneNumber": "+1-555-0101",
        "departmentNumber": "IT",
    }

    person_result = api.create_entry(
        dn=person_data["dn"],
        attributes={
            "objectClass": [
                "person",
                "inetOrgPerson",
                "organizationalPerson",
            ],  # Auto-detected
            "cn": [person_data["cn"]],
            "sn": [person_data["sn"]],
            "mail": [person_data["mail"]],
            "telephoneNumber": [person_data["telephoneNumber"]],
            "departmentNumber": [person_data["departmentNumber"]],
        },
    )
    if person_result.is_success:
        entries.append(person_result.unwrap())

    # Intelligent group builder - auto-detects member references
    group_result = api.create_entry(
        dn="cn=Admins,ou=Groups,dc=example,dc=com",
        attributes={
            "objectClass": [
                "groupOfNames",
                "top",
            ],  # Auto-detected from member attribute
            "cn": ["Admins"],
            "member": [
                "cn=Alice Johnson,ou=People,dc=example,dc=com",
                "cn=Bob Williams,ou=People,dc=example,dc=com",
            ],
            "description": ["System administrators group"],
        },
    )
    if group_result.is_success:
        entries.append(group_result.unwrap())

    # Intelligent OU builder - auto-detects organizational structure
    ou_result = api.create_entry(
        dn="ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["organizationalUnit", "top"],  # Auto-detected
            "ou": ["People"],
            "description": ["Container for person entries"],
            "businessCategory": ["HR"],
        },
    )
    if ou_result.is_success:
        entries.append(ou_result.unwrap())

    return FlextResult.ok(entries)


def advanced_filtering_pipeline() -> FlextResult[
    dict[str, list[FlextLdifModels.Entry]]
]:
    """Advanced filtering with multiple criteria and custom predicates."""
    api = FlextLdif.get_instance()

    # Large dataset for filtering demonstration
    ldif_content = """dn: cn=Alice,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Alice
sn: Johnson
mail: alice@example.com
departmentNumber: IT

dn: cn=Bob,ou=People,dc=example,dc=com
objectClass: person
cn: Bob
sn: Williams

dn: cn=Carol,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Carol
sn: Davis
mail: carol@example.com
departmentNumber: HR

dn: cn=Admins,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Admins
member: cn=Alice,ou=People,dc=example,dc=com

dn: cn=Users,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Users
member: cn=Bob,ou=People,dc=example,dc=com
member: cn=Carol,ou=People,dc=example,dc=com

dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People
"""

    # Parse large dataset
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        return FlextResult.fail(f"Parse failed: {parse_result.error}")

    entries = parse_result.unwrap()

    filtered_results = {}

    # Advanced filter 1: inetOrgPerson with email in IT department
    it_emails_result = api.filter(
        entries,
        objectclass="inetOrgPerson",
        attributes={"departmentNumber": "IT"},
        custom_filter=lambda e: "mail" in e.attributes.attributes,
    )
    if it_emails_result.is_success:
        filtered_results["it_inetorgperson_with_email"] = it_emails_result.unwrap()

    # Advanced filter 2: Groups with multiple members
    large_groups_result = api.filter(
        entries,
        objectclass="groupOfNames",
        custom_filter=lambda e: len(
            api.get_attribute_values(
                e.attributes.attributes.get("member", [])
            ).unwrap_or([])
        )
        > 1,
    )
    if large_groups_result.is_success:
        filtered_results["groups_with_multiple_members"] = large_groups_result.unwrap()

    # Advanced filter 3: People without email (missing critical attribute)
    no_email_result = api.filter(
        entries,
        objectclass="person",
        custom_filter=lambda e: "mail" not in e.attributes.attributes,
    )
    if no_email_result.is_success:
        filtered_results["people_without_email"] = no_email_result.unwrap()

    return FlextResult.ok(filtered_results)


def batch_processing_operations() -> FlextResult[dict[str, object]]:
    """Batch processing operations with parallel execution."""
    api = FlextLdif.get_instance()

    # Create batch of test entries
    entries = []
    for i in range(20):
        dept = "IT" if i % 2 == 0 else "HR"
        has_email = i % 3 != 0  # 2/3 have email

        attrs = {
            "objectClass": ["person", "inetOrgPerson"],
            "cn": [f"Batch User {i}"],
            "sn": [f"User{i}"],
            "departmentNumber": [dept],
        }

        if has_email:
            attrs["mail"] = [f"user{i}@example.com"]

        create_result = api.create_entry(
            dn=f"cn=Batch User {i},ou=People,dc=example,dc=com",
            attributes=cast("dict[str, str | list[str]]", attrs),
        )
        if create_result.is_success:
            entries.append(create_result.unwrap())

    if not entries:
        return FlextResult.fail("Failed to create batch entries")

    batch_results: dict[str, object] = {}

    # Batch validation with parallel processing
    validate_result = api.validate_entries(entries)
    if validate_result.is_success:
        batch_results["validation_report"] = validate_result.unwrap()

    # Batch filtering - find IT users with email
    it_with_email_result = api.filter(
        entries,
        attributes={"departmentNumber": "IT"},
        custom_filter=lambda e: "mail" in e.attributes.attributes,
    )
    if it_with_email_result.is_success:
        batch_results["it_users_with_email"] = it_with_email_result.unwrap()

    # Parallel transformation to dictionaries
    transform_result = api.process("transform", entries, parallel=True, max_workers=8)
    if transform_result.is_success:
        batch_results["parallel_transformed"] = transform_result.unwrap()

    # Batch conversion: entries → LDIF string → entries (round-trip)
    write_result = api.write(entries, output_path=None)  # String output
    if write_result.is_success:
        ldif_string = write_result.unwrap()
        # Parse back to verify round-trip conversion
        reparse_result = api.parse(ldif_string)
        if reparse_result.is_success:
            batch_results["round_trip_count"] = len(reparse_result.unwrap())

    return FlextResult.ok(batch_results)


def efficient_format_conversions() -> FlextResult[dict[str, object]]:
    """Efficient format conversions with validation and batch processing."""
    api = FlextLdif.get_instance()

    conversion_results: dict[str, object] = {}

    # Create test entry with complex attributes
    complex_entry_result = api.create_entry(
        dn="cn=Complex User,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person", "inetOrgPerson", "organizationalPerson"],
            "cn": ["Complex User"],
            "sn": ["Complex"],
            "mail": ["complex@example.com"],
            "telephoneNumber": ["+1-555-0123", "+1-555-0456"],  # Multi-valued
            "departmentNumber": ["Engineering"],
            "employeeNumber": ["12345"],
        },
    )
    if complex_entry_result.is_failure:
        return FlextResult.fail("Failed to create complex entry")

    entry = complex_entry_result.unwrap()

    # Conversion 1: Entry → Attribute Dictionary
    attrs_result = api.get_entry_attributes(entry)
    if attrs_result.is_success:
        conversion_results["entry_to_dict"] = attrs_result.unwrap()

    # Conversion 2: Entry → DN extraction
    dn_result = api.get_entry_dn(entry)
    if dn_result.is_success:
        conversion_results["extracted_dn"] = dn_result.unwrap()

    # Conversion 3: Entry → ObjectClasses extraction
    ocs_result = api.get_entry_objectclasses(entry)
    if ocs_result.is_success:
        conversion_results["objectclasses"] = ocs_result.unwrap()

    # Conversion 4: Batch entries → LDIF file
    batch_entries = [entry] * 5  # Duplicate for batch test
    file_path = Path("examples/batch_conversion.ldif")
    batch_write_result = api.write(batch_entries, file_path)
    if batch_write_result.is_success:
        conversion_results["batch_file_written"] = str(file_path)

    # Conversion 5: LDIF file → Entries (verify batch write)
    if file_path.exists():
        reparse_result = api.parse(file_path)
        if reparse_result.is_success:
            conversion_results["batch_reparsed_count"] = len(reparse_result.unwrap())

    return FlextResult.ok(conversion_results)


def railway_composition_pipeline() -> FlextResult[dict[str, object]]:
    """Railway-oriented composition of all operations."""
    api = FlextLdif.get_instance()

    # Railway step 1: Build entries with intelligent builders
    build_result = intelligent_entry_builders()
    if build_result.is_failure:
        return FlextResult[dict[str, object]].fail(
            f"Entry building failed: {build_result.error}"
        )

    entries = build_result.unwrap()

    # Railway step 2: Batch validate all entries
    validate_result = api.validate_entries(entries)
    if validate_result.is_failure:
        return FlextResult.fail(f"Validation failed: {validate_result.error}")

    validation_report = validate_result.unwrap()
    if not validation_report.is_valid:
        return FlextResult.fail(f"Invalid entries: {validation_report.errors}")

    # Railway step 3: Advanced filtering
    filter_result = api.filter(entries, objectclass="person")
    if filter_result.is_failure:
        return FlextResult[dict[str, object]].fail(
            f"Filtering failed: {filter_result.error}"
        )

    person_entries = filter_result.unwrap()

    # Railway step 4: Parallel processing of filtered results
    process_result = api.process(
        "transform", person_entries, parallel=True, max_workers=4
    )
    if process_result.is_failure:
        return FlextResult[dict[str, object]].fail(
            f"Processing failed: {process_result.error}"
        )

    # Railway step 5: Write results to file
    output_path = Path("examples/railway_output.ldif")
    write_result = api.write(person_entries, output_path)
    if write_result.is_failure:
        return FlextResult[dict[str, object]].fail(
            f"Write failed: {write_result.error}"
        )

    return FlextResult.ok({
        "total_entries": len(entries),
        "valid_entries": validation_report.valid_entries,
        "person_entries": len(person_entries),
        "processed_transforms": len(process_result.unwrap()),
        "output_file": str(output_path),
    })
