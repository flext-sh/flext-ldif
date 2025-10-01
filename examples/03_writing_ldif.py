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

from flext_ldif import FlextLdifAPI, FlextLdifModels


def main() -> None:
    """LDIF writing example."""
    # Initialize API
    api = FlextLdifAPI()

    print("=== Creating LDIF Entries ===\n")

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

    print(f"Created {len(entries)} entries\n")

    # Write to LDIF string
    print("=== Writing to String ===")
    write_result = api.write(entries)

    if write_result.is_failure:
        print(f"❌ Write failed: {write_result.error}")
        return

    ldif_string = write_result.unwrap()
    print(ldif_string)

    # Write to file
    print("\n=== Writing to File ===")
    output_file = Path("examples/output_basic.ldif")

    file_result = api.write(entries, output_path=output_file)

    if file_result.is_success:
        print(f"✅ Written {len(entries)} entries to {output_file}")
        print(f"   File size: {output_file.stat().st_size} bytes")
    else:
        print(f"❌ File write failed: {file_result.error}")

    # Verify by reading back
    print("\n=== Verifying Written File ===")
    verify_result = api.parse(output_file)

    if verify_result.is_success:
        verified_entries = verify_result.unwrap()
        print(f"✅ Verified: read {len(verified_entries)} entries from file")

        for entry in verified_entries:
            print(f"   - {entry.dn}")
    else:
        print(f"❌ Verification failed: {verify_result.error}")


if __name__ == "__main__":
    main()
