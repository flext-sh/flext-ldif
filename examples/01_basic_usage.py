"""Example 1: Basic LDIF Usage.

Demonstrates core FlextLdif functionality:
- Parsing LDIF from strings and files
- Writing LDIF to strings and files
- FlextResult railway-oriented error handling
- Entry model inspection
- Singleton pattern for API instance

This is a library-only example. All functionality is accessed through
the FlextLdif facade using the recommended singleton pattern.
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif


def parse_ldif_string() -> None:
    """Parse LDIF content from a string."""
    # Use singleton instance (recommended pattern)
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=John Doe,ou=People,dc=example,dc=com
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

    # Parse using FlextResult pattern
    result = api.parse(ldif_content)

    if result.is_success:
        entries = result.unwrap()
        # Successfully parsed entries
        # entries is list[FlextLdifModels.Entry]
        for entry in entries:
            _ = entry.dn
            _ = entry.attributes
    else:
        # Handle error
        _ = result.error


def parse_ldif_file() -> None:
    """Parse LDIF content from a file."""
    api = FlextLdif.get_instance()

    sample_file = Path("examples/sample_basic.ldif")

    if not sample_file.exists():
        return

    # Parse from file path
    result = api.parse(sample_file)

    if result.is_success:
        entries = result.unwrap()
        # Successfully parsed file entries
        _ = len(entries)
    else:
        # Handle parse error
        _ = result.error


def write_ldif_string() -> None:
    """Write entries to LDIF string."""
    api = FlextLdif.get_instance()

    # First parse to get entries
    ldif_content = """dn: cn=Test User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Test User
sn: User
mail: test@example.com
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Write entries to string
    write_result = api.write(entries)

    if write_result.is_success:
        ldif_string = write_result.unwrap()
        # ldif_string contains RFC 2849 compliant LDIF
        _ = len(ldif_string)
    else:
        _ = write_result.error


def write_ldif_file() -> None:
    """Write entries to LDIF file."""
    api = FlextLdif.get_instance()

    # Create sample entry
    ldif_content = """dn: cn=File Test,ou=People,dc=example,dc=com
objectClass: person
cn: File Test
sn: Test
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Write to file
    output_path = Path("examples/output_basic.ldif")
    write_result = api.write(entries, output_path)

    # File written successfully or handle error
    # Result contains success message or error details
    _ = write_result.unwrap() if write_result.is_success else write_result.error


def railway_oriented_pipeline() -> None:
    """Demonstrate FlextResult railway-oriented programming."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Pipeline,ou=People,dc=example,dc=com
objectClass: person
cn: Pipeline
sn: Test
"""

    # Chain operations with early return on failure
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        _ = parse_result.error
        return

    entries = parse_result.unwrap()

    # Continue pipeline
    write_result = api.write(entries)
    if write_result.is_failure:
        _ = write_result.error
        return

    ldif_output = write_result.unwrap()

    # Pipeline succeeded
    _ = len(ldif_output)


def inspect_entry_model() -> None:
    """Inspect parsed entry models."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Inspect,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Inspect
sn: Model
mail: inspect@example.com
telephoneNumber: +1234567890
"""

    result = api.parse(ldif_content)

    if result.is_success:
        entries = result.unwrap()

        for entry in entries:
            # Access entry properties
            dn = entry.dn
            attributes = entry.attributes

            # Attributes is a custom type - iterate to inspect
            for attr_name in attributes:
                attr_values = attributes[attr_name]
                _ = (attr_name, attr_values)

            # Entry models are Pydantic v2 - access via api.models
            _ = (dn, dict(attributes))
