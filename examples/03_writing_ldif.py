#!/usr/bin/env python3
"""Example 3: Writing LDIF.

Demonstrates:
- Creating entries programmatically
- Writing LDIF to string
- Writing LDIF to file
- FlextResult error handling
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif, FlextLdifModels


def main() -> None:
    """LDIF writing example."""
    # Initialize API
    api = FlextLdif()

    # Create entries using domain models
    entries = [
        FlextLdifModels.Entry(
            dn="cn=Alice Johnson,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["Alice Johnson"],
                "sn": ["Johnson"],
                "mail": ["alice.johnson@example.com"],
                "telephoneNumber": ["+1-555-0101"],
            },
        ),
        FlextLdifModels.Entry(
            dn="cn=Bob Williams,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["Bob Williams"],
                "sn": ["Williams"],
                "mail": ["bob.williams@example.com"],
                "telephoneNumber": ["+1-555-0102"],
            },
        ),
        FlextLdifModels.Entry(
            dn="cn=Admins,ou=Groups,dc=example,dc=com",
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": ["Admins"],
                "member": [
                    "cn=Alice Johnson,ou=People,dc=example,dc=com",
                    "cn=Bob Williams,ou=People,dc=example,dc=com",
                ],
            },
        ),
    ]

    # Write to LDIF string
    write_result = api.write(entries)

    if write_result.is_failure:
        return

    write_result.unwrap()

    # Write to file
    output_file = Path("examples/output_basic.ldif")

    file_result = api.write(entries, output_path=output_file)

    if file_result.is_success:
        pass

    # Verify by reading back
    verify_result = api.parse(output_file)

    if verify_result.is_success:
        verified_entries = verify_result.unwrap()

        for _entry in verified_entries:
            pass


if __name__ == "__main__":
    main()
