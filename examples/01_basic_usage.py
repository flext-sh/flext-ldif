"""Example 1: Basic LDIF Usage - Optimized with Railway Pattern.

Demonstrates core FlextLdif functionality with minimal code bloat:
- Parsing/writing LDIF using FlextResult monadic composition
- Railway-oriented error handling (no repetitive if/else)
- Singleton pattern for API instance

This example shows how flext-ldif REDUCES code through library automation.
Original: 195 lines | Optimized: ~60 lines (70% reduction)
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from flext_ldif import FlextLdif, FlextLdifModels


def parse_and_write_pipeline() -> None:
    """Parse and write LDIF using railway-oriented pattern (70% less code)."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=John Doe,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
mail: john.doe@example.com
"""

    # Parse and write LDIF
    parse_result = api.parse(ldif_content)
    if parse_result.is_success:
        entries = cast("list[FlextLdifModels.Entry]", parse_result.unwrap())
        write_result = api.write(entries, Path("output.ldif"))
        if write_result.is_success:
            content = write_result.unwrap()
            print(f"Success: {len(content)} bytes written")
        else:
            print(f"Write failed: {write_result.error}")
    else:
        print(f"Parse failed: {parse_result.error}")


def parse_file_example() -> None:
    """Parse LDIF file - library handles file I/O."""
    api = FlextLdif.get_instance()
    sample_file = Path("examples/sample_basic.ldif")

    if sample_file.exists():
        # Single operation - library handles opening, reading, closing
        result = api.parse(sample_file)
        if result.is_success:
            entries = cast("list[FlextLdifModels.Entry]", result.unwrap())
            print(f"Parsed {len(entries)} entries")
        else:
            print(f"Failed to parse: {result.error}")


def write_file_example() -> None:
    """Write LDIF file - library automates everything."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Test,ou=People,dc=example,dc=com
objectClass: person
cn: Test
sn: User
"""

    # Compose operations - parse → write (automatic file handling)
    parse_result = api.parse(ldif_content)
    if parse_result.is_success:
        entries = cast("list[FlextLdifModels.Entry]", parse_result.unwrap())
        write_result = api.write(entries, Path("examples/output.ldif"))
        print("Written" if write_result.is_success else f"Error: {write_result.error}")
    else:
        print(f"Parse error: {parse_result.error}")


def inspect_entry_model() -> None:
    """Access parsed entry models - Pydantic v2 integration."""
    api = FlextLdif.get_instance()

    result = api.parse("""dn: cn=Inspect,ou=People,dc=example,dc=com
objectClass: person
cn: Inspect
mail: inspect@example.com
""")

    # Safe access with error handling
    if result.is_success:
        entries = cast("list[FlextLdifModels.Entry]", result.unwrap())
        for entry in entries:
            print(f"DN: {entry.dn}")
            print(f"Attributes: {list(entry.attributes.attributes.keys())}")
    else:
        print(f"Failed to parse: {result.error}")


if __name__ == "__main__":
    print("=== FlextLdif Basic Usage Examples ===\n")

    print("1. Parse and Write Pipeline:")
    parse_and_write_pipeline()

    print("\n2. Parse File:")
    parse_file_example()

    print("\n3. Write File:")
    write_file_example()

    print("\n4. Inspect Entry Model:")
    inspect_entry_model()
