# from flext-ldif/docs/api-reference.md:1162
from flext_ldif import ldif
from pathlib import Path

# Initialize API (library-only, no CLI)
api = ldif()

# Write a sample LDIF file and load it as text
ldif_path = Path("directory.ldif")
ldif_path.write_text(
    "dn: cn=user,ou=people,dc=example,dc=com\nobjectClass: person\ncn: user\n"
)

ldif_content = ldif_path.read_text()
parse_result = api.parse_string(ldif_content)
if parse_result.failure:
    u.Cli.print(f"Parse failed: {parse_result.error}")
    exit(1)

entries = parse_result.unwrap()
u.Cli.print(f"✅ Parsed {len(entries)} entries")

# Validate entries
validation_result = api.validate_entries(entries)
if validation_result.failure:
    u.Cli.print(f"Validation failed: {validation_result.error}")
    exit(1)

u.Cli.print("✅ All entries valid")```
### LDIF Parsing Example

