# from flext-ldif/docs/api-reference.md:1073
from flext_ldif import FlextLdif

# Initialize the public facade and query server servers
client = FlextLdif()

schema_server = client.schema_server("oid")
entry_server = client.entry("oud")
acl_server = client.acl("openldap")

# Servers are automatically resolved by the registered server registry
# and exposed through the facade API.```
## Integration with FLEXT Ecosystem

### FlextContainer Usage

