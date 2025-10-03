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
    validation_result = api.validate_entries(entries)

    if validation_result.is_success:
        pass

    # Filter by object class
    persons_result = api.filter_by_objectclass(entries, "person")

    if persons_result.is_success:
        persons = persons_result.unwrap()
        for _person in persons:
            pass

    # Generate statistics
    stats_result = api.analyze(entries)

    if stats_result.is_success:
        stats_result.unwrap()

    # Railway-oriented pipeline

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
        return

    # For this example, we'll just demonstrate the validation concept

    if parse_result.is_success:
        pass


if __name__ == "__main__":
    main()
