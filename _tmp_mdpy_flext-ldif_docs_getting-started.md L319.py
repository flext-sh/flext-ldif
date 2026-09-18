# from flext-ldif/docs/getting-started.md:319
from flext_ldif import ServerRegistryService

# Initialize registry once
server_registry = ServerRegistryService()

# Get servers for different servers
openldap = server_registry.get_entrys("openldap")
oid = server_registry.get_entrys("oid")
ouds = server_registry.get_entrys("oud")

# Each server knows how to handle server-specific extensions
# All servers follow the same Protocol interface
# Servers are tried in priority order (lower number = higher priority)```
### Data Validation and Cleaning

Validate and clean LDIF data:

