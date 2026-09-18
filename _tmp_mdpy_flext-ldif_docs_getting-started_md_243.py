# from flext-ldif_docs/getting-started.md:243
from __future__ import annotations

from flext_ldif import FlextLdif
from pathlib import Path

# Write a sample LDIF schema file
schema_path = Path("oid_schema.ldif")
schema_path.write_text("dn: cn=example,dc=example,dc=com\nobjectClass: top\n")

# Initialize parser and parse the sample schema
parser = FlextLdif()
result = parser.parse_ldif_file(schema_path)

if result.success:
    schema_data = result.unwrap().entries
    print(f"Parsed schema entries: {len(schema_data)}")

# Works with any LDAP server - OpenLDAP, OUD, AD, etc.```
### Generic Entry Migration Between Servers

Migrate entries between different LDAP servers using generic transformation:

