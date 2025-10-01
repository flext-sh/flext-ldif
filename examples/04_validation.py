#!/usr/bin/env python3
"""Example 4: Entry Validation.

Demonstrates:
- RFC 2849 validation
- Entry filtering
- Statistics generation
- Railway-oriented pipeline
"""

from __future__ import annotations

from flext_ldif import FlextLdifAPI, FlextLdifModels


def main() -> None:
    """Entry validation example."""
    # Initialize API
    api = FlextLdifAPI()

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
        print(f"   ✅ Statistics:")
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

    # Composable pipeline with explicit error handling
    pipeline_result = (
        # Parse LDIF
        api.parse(ldif_content)
        # Validate entries
        .flat_map(
            lambda entries: api.validate_entries(entries).map(lambda _: entries)
        )
        # Filter person entries
        .flat_map(api.filter_persons)
        # Generate statistics
        .flat_map(lambda persons: api.analyze(persons))
        # Add error context
        .map_error(lambda error: f"Pipeline failed: {error}")
    )

    if pipeline_result.is_success:
        result = pipeline_result.unwrap()
        print(f"   ✅ Pipeline completed: {result.get('total_entries', 0)} entries")
    else:
        print(f"   ❌ Pipeline failed: {pipeline_result.error}")


if __name__ == "__main__":
    main()
