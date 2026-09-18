# from flext-ldif/docs/development.md:111
from flext_ldif import ldif, FlextLdifModels

# LDIF entry creation using Factory pattern
entry_data = {
    "dn": "cn=user,ou=people,dc=example,dc=com",
    "attributes": {
        "cn": ["user"],
        "objectClass": ["person", "organizationalPerson"],
        "mail": ["user@example.com"],
    },
}
entry = FlextLdifModels.Factory.create(entry_data)

# LDIF processing with memory awareness
api = ldif()

# For small files (< 100MB)
result = api.parse_file("small_directory.ldif")

# For larger files, consider external tools
# grep "objectClass: person" large_directory.ldif | processing...```
#### LDIF Validation Patterns

