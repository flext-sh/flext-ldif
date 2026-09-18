# from flext-ldif/docs/guides/server-api-usage-pattern.md:47
# CORRETO - Via FlextLdifServer API
from flext_ldif import FlextLdifServer
from flext_ldif import FlextLdifServersBase

server = FlextLdifServer()

# Obter servers via API
oid_server: FlextLdifServersBase = server.server("oid")
oud_server: FlextLdifServersBase = server.server("oud")
rfc_server: FlextLdifServersBase = server.server("rfc")```
**Benefícios**:

- ✅ Usa o gerenciamento centralizado de servers
- ✅ Respeita singleton/registry pattern
- ✅ Facilita mocks em testes
- ✅ API única e consistente
- ✅ Evita duplicação de funcionalidade

______________________________________________________________________

## 📝 Uso em Testes (Fixtures)

### Fixtures Centralizadas (`conftest.py`)

