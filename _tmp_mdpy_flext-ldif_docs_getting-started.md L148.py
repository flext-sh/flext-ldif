# from flext-ldif/docs/getting-started.md:148
from __future__ import annotations

from flext_ldif import ldif
from pathlib import Path

api = ldif()

# Prepare a sample LDIF file
ldif_path = Path("directory.ldif")
ldif_path.write_text(
    "dn: cn=John Doe,ou=People,dc=example,dc=com\ncn: John Doe\nobjectClass: person\n"
)

# Parse LDIF file
result = api.parse_string(ldif_path.read_text())

if result.success:
    entries = result.unwrap().entries

    # Validate entries
    validation_result = api.validate_entries(entries)
    if validation_result.success:
        print("All entries are valid")

        # Write to new file
        output_path = Path("processed_directory.ldif")
        write_result = api.write_ldif_file(entries, output_path)
        if write_result.success:
            print(f"Successfully wrote {len(entries)} entries to {output_path}")
    else:
        print(f"Validation failed: {validation_result.error}")
else:
    print(f"Failed to parse {ldif_path}: {result.error}")```
## Configuration

### Basic Configuration

Configure LDIF processing behavior:

