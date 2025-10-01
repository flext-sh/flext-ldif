#!/usr/bin/env python3
"""Example 1: Basic LDIF Parsing.

Demonstrates:
- Library-only usage (NO CLI)
- Basic parsing with FlextLdifAPI facade
- FlextResult error handling
- Entry inspection
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdifAPI


def main() -> None:
    """Basic LDIF parsing example."""
    # Initialize API (library-only, no CLI)
    api = FlextLdifAPI()

    # Sample LDIF content
    ldif_content = """
dn: cn=John Doe,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
mail: john.doe@example.com

dn: cn=Jane Smith,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Jane Smith
sn: Smith
mail: jane.smith@example.com
"""

    # Parse LDIF string using FlextResult pattern
    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        print(f"❌ Parse failed: {parse_result.error}")
        return

    entries = parse_result.unwrap()
    print(f"✅ Parsed {len(entries)} entries\n")

    # Inspect each entry
    for idx, entry in enumerate(entries, 1):
        print(f"Entry {idx}:")
        print(f"  DN: {entry.dn}")
        print(f"  CN: {entry.attributes.get('cn', ['N/A'])[0]}")
        print(f"  Email: {entry.attributes.get('mail', ['N/A'])[0]}")
        print(f"  Object Classes: {entry.attributes.get('objectClass', [])}")
        print()

    # Parse from file (if exists)
    sample_file = Path("examples/sample_basic.ldif")
    if sample_file.exists():
        file_result = api.parse(sample_file)
        if file_result.is_success:
            file_entries = file_result.unwrap()
            print(f"✅ Parsed {len(file_entries)} entries from file")


if __name__ == "__main__":
    main()
