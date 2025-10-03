#!/usr/bin/env python3
"""Example 1: Basic LDIF Parsing.

Demonstrates:
- Library-only usage (NO CLI)
- Basic parsing with FlextLdif facade
- FlextResult error handling
- Entry inspection
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif


def main() -> None:
    """Basic LDIF parsing example."""
    # Initialize API (library-only, no CLI)
    api = FlextLdif()

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
        return

    entries = parse_result.unwrap()

    # Inspect each entry
    for _entry in entries:
        pass

    # Parse from file (if exists)
    sample_file = Path("examples/sample_basic.ldif")
    if sample_file.exists():
        file_result = api.parse(sample_file)
        if file_result.is_success:
            file_result.unwrap()


if __name__ == "__main__":
    main()
