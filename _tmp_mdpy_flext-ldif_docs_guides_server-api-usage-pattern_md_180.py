# from flext-ldif_docs/guides/server-api-usage-pattern.md:180
from flext_ldif import FlextLdifServer

server = FlextLdifServer()

# Servers totalmente implementados
server.server("rfc")  # RFC 2849/4512 baseline
server.server("oid")  # Oracle Internet Directory
server.server("oud")  # Oracle Unified Directory
server.server("openldap")  # OpenLDAP 2.x
server.server("openldap1")  # OpenLDAP 1.x
server.server("relaxed")  # Lenient parsing mode

# Servers com stubs
server.server("ad")  # Active Directory
server.server("apache")  # Apache Directory Server
server.server("ds389")  # Red Hat DS
server.server("novell")  # Novell eDirectory
server.server("tivoli")  # IBM Tivoli DS```
______________________________________________________________________

## 🔍 Verificação

Para verificar se código está usando padrão correto:

