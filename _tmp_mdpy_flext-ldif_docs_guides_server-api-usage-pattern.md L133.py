# from flext-ldif/docs/guides/server-api-usage-pattern.md:133
# ANTES
oid = FlextLdifServersOid()
oud = FlextLdifServersOud()

# DEPOIS
from flext_ldif import FlextLdifServer

server = FlextLdifServer()
oid = server.server("oid")
oud = server.server("oud")```
### Passo 3: Atualizar Type Hints

