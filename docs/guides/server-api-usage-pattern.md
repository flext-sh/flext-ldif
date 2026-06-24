# Server API Usage Pattern - Padrão Correto

**Data**: 2025-11-18
**Status**: PADRÃO OBRIGATÓRIO

______________________________________________________________________

## ❌ PADRÃO INCORRETO (Deprecado)

```python
# ERRADO - Instanciação direta de servers
from flext_ldif import FlextLdifServersOid
from flext_ldif import FlextLdifServersOud
from flext_ldif import FlextLdifServersRfc

oid = FlextLdifServersOid()  # ❌ NÃO FAÇA ISSO
oud = FlextLdifServersOud()  # ❌ NÃO FAÇA ISSO
rfc = FlextLdifServersRfc()  # ❌ NÃO FAÇA ISSO
```

**Problemas**:

- Bypassa o gerenciamento de registro do `FlextLdifServer`
- Duplica funcionalidade que pertence ao `services/server.py`
- Quebra o padrão singleton/registry
- Dificulta manutenção e testes

______________________________________________________________________

## ✅ PADRÃO CORRETO (Obrigatório)

```python
# CORRETO - Via FlextLdifServer API
from flext_ldif import FlextLdifServer
from flext_ldif import FlextLdifServersBase

server = FlextLdifServer()

# Obter servers via API
oid_server: FlextLdifServersBase = server.server("oid")
oud_server: FlextLdifServersBase = server.server("oud")
rfc_server: FlextLdifServersBase = server.server("rfc")
```

**Benefícios**:

- ✅ Usa o gerenciamento centralizado de servers
- ✅ Respeita singleton/registry pattern
- ✅ Facilita mocks em testes
- ✅ API única e consistente
- ✅ Evita duplicação de funcionalidade

______________________________________________________________________

## 📝 Uso em Testes (Fixtures)

### Fixtures Centralizadas (`conftest.py`)

```python
import pytest
from flext_ldif import FlextLdifServer
from flext_ldif import FlextLdifServersBase


@pytest.fixture
def server() -> FlextLdifServer:
    """Get FlextLdifServer instance for server management."""
    return FlextLdifServer()


@pytest.fixture
def oid_server(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OID server server via FlextLdifServer API."""
    server = server.server("oid")
    assert server is not None, "OID server must be registered"
    return server


@pytest.fixture
def oud_server(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OUD server server via FlextLdifServer API."""
    server = server.server("oud")
    assert server is not None, "OUD server must be registered"
    return server


@pytest.fixture
def rfc_server(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get RFC server server via FlextLdifServer API."""
    server = server.server("rfc")
    assert server is not None, "RFC server must be registered"
    return server
```

### Uso nas Funções de Teste

```python
def test_conversion_oid_to_oud(
    oid_server: FlextLdifServersBase,
    oud_server: FlextLdifServersBase,
) -> None:
    """Test conversion from OID to OUD."""
    # Use os servers diretamente
    result = conversion_service.convert(oid_server, oud_server, entry)
    assert result.success
```

______________________________________________________________________

## 🔄 Migração de Código Existente

### Passo 1: Atualizar Imports

```python
# ANTES
from flext_ldif import FlextLdifServersOid
from flext_ldif import FlextLdifServersOud

# DEPOIS
from flext_ldif import FlextLdifServer
from flext_ldif import FlextLdifServersBase
```

### Passo 2: Atualizar Instanciação

```python
# ANTES
oid = FlextLdifServersOid()
oud = FlextLdifServersOud()

# DEPOIS
from flext_ldif import FlextLdifServer

server = FlextLdifServer()
oid = server.server("oid")
oud = server.server("oud")
```

### Passo 3: Atualizar Type Hints

```python
# ANTES
def my_function(oid: FlextLdifServersOid) -> None:
    pass


# DEPOIS
def my_function(oid: FlextLdifServersBase) -> None:
    pass
```

______________________________________________________________________

## 📊 Status de Migração

**Arquivos Já Migrados**:

- ✅ `tests/conftest.py` - Fixtures centralizadas criadas
- ✅ `tests/unit/services/test_conversion_service.py` - Migrado e testado (38/38 tests passing)
- ✅ `src/flext_ldif/services/conversion.py` - Já usa padrão correto via `_resolve_server()`

**Arquivos Pendentes** (~50 arquivos, 231 instanciações diretas):

- ⏳ `tests/unit/servers/servers/*.py` - Tests de servers específicos
- ⏳ `tests/unit/servers/test_*.py` - Tests de conversão
- ⏳ `tests/unit/rfc/*.py` - Tests RFC
- ⏳ `tests/integration/*.py` - Tests de integração
- ⏳ `tests/helpers/*.py` - Helpers

______________________________________________________________________

## 🎯 Servers Disponíveis via API

```python
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
server.server("tivoli")  # IBM Tivoli DS
```

______________________________________________________________________

## 🔍 Verificação

Para verificar se código está usando padrão correto:

```bash
# Buscar instanciações diretas (INCORRETO)
grep -r "FlextLdifServersOid()\|FlextLdifServersOud()\|FlextLdifServersRfc()" src/

# Buscar imports diretos (INCORRETO)
grep -r "from flext_ldif.servers.\(oid\|oud\|rfc\) import" src/

# Buscar uso correto (CORRETO)
grep -r "server.server(" src/
```

______________________________________________________________________

## 📚 Referências

- **API Central**: `src/flext_ldif/services/server.py` - FlextLdifServer class
- **Base Class**: `src/flext_ldif/servers/base.py` - FlextLdifServersBase
- **Exemplo Correto**: `src/flext_ldif/services/conversion.py` - método `_resolve_server()`
- **Fixtures Corretas**: `tests/conftest.py` - server, oid_server, oud_server, rfc_server

______________________________________________________________________

**IMPORTANTE**: Este padrão é OBRIGATÓRIO para todo código novo. Código existente deve ser migrado progressivamente.
