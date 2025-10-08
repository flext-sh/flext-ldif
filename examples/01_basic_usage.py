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

from flext_ldif import FlextLdif


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

    # Railway pattern - chain operations, automatic error propagation
    result = api.parse(ldif_content).flat_map(api.write)  # Auto-handles errors

    # Single error check at end (vs repetitive if/else)
    if result.is_success:
        print(f"Success: {len(result.unwrap())} bytes written")
    else:
        print(f"Failed: {result.error}")


def parse_file_example() -> None:
    """Parse LDIF file - library handles file I/O."""
    api = FlextLdif.get_instance()
    sample_file = Path("examples/sample_basic.ldif")

    if sample_file.exists():
        # Single operation - library handles opening, reading, closing
        result = api.parse(sample_file)
        print(f"Parsed {len(result.unwrap_or([]))} entries")


def write_file_example() -> None:
    """Write LDIF file - library automates everything."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Test,ou=People,dc=example,dc=com
objectClass: person
cn: Test
sn: User
"""

    # Compose operations - parse → write (automatic file handling)
    result = api.parse(ldif_content).flat_map(
        lambda entries: api.write(entries, Path("examples/output.ldif"))
    )

    print("Written" if result.is_success else f"Error: {result.error}")


def inspect_entry_model() -> None:
    """Access parsed entry models - Pydantic v2 integration."""
    api = FlextLdif.get_instance()

    result = api.parse("""dn: cn=Inspect,ou=People,dc=example,dc=com
objectClass: person
cn: Inspect
mail: inspect@example.com
""")

    # Use unwrap_or for safe access with default
    for entry in result.unwrap_or([]):
        print(f"DN: {entry.dn}")
        print(f"Attributes: {list(entry.attributes.data.keys())}")


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
