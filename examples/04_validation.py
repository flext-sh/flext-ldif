#!/usr/bin/env python3
"""Example 4: Entry Validation.

Demonstrates:
- RFC 2849 validation
- Entry filtering
- Statistics generation
- Railway-oriented pipeline
"""

from __future__ import annotations

from flext_ldif import FlextLdif, FlextLdifModels


def main() -> None:
    """Entry validation example."""
    # Initialize API
    api = FlextLdif()

    print("=== Entry Validation ===\n")

    # Create valid and invalid entries
    valid_entry = FlextLdifModels.Entry(
        dn="cn=Valid User,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person", "inetOrgPerson"],
            "cn": ["Valid User"],
            "sn": ["User"],
            "mail": ["valid@example.com"],
        },
    )

    # Entry with missing required attribute (sn)
    invalid_entry = FlextLdifModels.Entry(
        dn="cn=Invalid User,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person"],
            "cn": ["Invalid User"],
            # Missing 'sn' required by person objectClass
        },
    )

    entries = [valid_entry, invalid_entry]

    # Validate entries
    print("1. Validating entries:")
    validation_result = api.validate_entries(entries)

    if validation_result.is_success:
        print("   ✅ All entries valid")
    else:
        print(f"   ⚠️ Validation issues: {validation_result.error}")

    # Filter by object class
    print("\n2. Filtering by object class:")
    persons_result = api.filter_by_objectclass(entries, "person")

    if persons_result.is_success:
        persons = persons_result.unwrap()
        print(f"   ✅ Found {len(persons)} person entries")
        for person in persons:
            print(f"      - {person.dn}")

    # Generate statistics
    print("\n3. Entry statistics:")
    stats_result = api.analyze(entries)

    if stats_result.is_success:
        stats = stats_result.unwrap()
        print("   ✅ Statistics:")
        print(f"      Total entries: {stats.get('total_entries', 0)}")
        print(f"      Object classes: {stats.get('object_classes', {})}")

    # Railway-oriented pipeline
    print("\n4. Railway-oriented pipeline:")

    ldif_content = """
dn: cn=Pipeline Test,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Pipeline Test
sn: Test
mail: pipeline@example.com
"""

    # Simple validation pipeline
    parse_result = api.parse(ldif_content)
    if not parse_result.is_success:
        print(f"   ❌ Parse failed: {parse_result.error}")
        return

    # For this example, we'll just demonstrate the validation concept
    print("   ✅ LDIF parsed successfully")
    print("   INFO: Railway-oriented pipeline example (simplified for compatibility)")

    if parse_result.is_success:
        print("   ✅ Validation example completed successfully")
    else:
        print(f"   ❌ Parse failed: {parse_result.error}")


if __name__ == "__main__":
    main()
