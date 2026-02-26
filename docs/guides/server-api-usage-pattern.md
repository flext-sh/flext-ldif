# Server API Usage Pattern - Padrão Correto

<!-- TOC START -->

- [❌ PADRÃO INCORRETO (Deprecado)](#padro-incorreto-deprecado)
- [✅ PADRÃO CORRETO (Obrigatório)](#padro-correto-obrigatrio)
- [📝 Uso em Testes (Fixtures)](#uso-em-testes-fixtures)
  - [Fixtures Centralizadas (`conftest.py`)](#fixtures-centralizadas-conftestpy)
  - [Uso nas Funções de Teste](#uso-nas-funes-de-teste)
- [🔄 Migração de Código Existente](#migrao-de-cdigo-existente)
  - [Passo 1: Atualizar Imports](#passo-1-atualizar-imports)
  - [Passo 2: Atualizar Instanciação](#passo-2-atualizar-instanciao)
  - [Passo 3: Atualizar Type Hints](#passo-3-atualizar-type-hints)
- [📊 Status de Migração](#status-de-migrao)
- [🎯 Servers Disponíveis via API](#servers-disponveis-via-api)
- [🔍 Verificação](#verificao)
- [📚 Referências](#referncias)

<!-- TOC END -->

**Data**: 2025-11-18
**Status**: PADRÃO OBRIGATÓRIO

______________________________________________________________________

## ❌ PADRÃO INCORRETO (Deprecado)

```python
# ERRADO - Instanciação direta de servers
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.rfc import FlextLdifServersRfc

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
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.servers.base import FlextLdifServersBase

server = FlextLdifServer()

# Obter quirks via API
oid_quirk: FlextLdifServersBase = server.quirk("oid")
oud_quirk: FlextLdifServersBase = server.quirk("oud")
rfc_quirk: FlextLdifServersBase = server.quirk("rfc")
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
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.servers.base import FlextLdifServersBase


@pytest.fixture
def server() -> FlextLdifServer:
    """Get FlextLdifServer instance for quirk management."""
    return FlextLdifServer()


@pytest.fixture
def oid_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OID server quirk via FlextLdifServer API."""
    quirk = server.quirk("oid")
    assert quirk is not None, "OID quirk must be registered"
    return quirk


@pytest.fixture
def oud_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OUD server quirk via FlextLdifServer API."""
    quirk = server.quirk("oud")
    assert quirk is not None, "OUD quirk must be registered"
    return quirk


@pytest.fixture
def rfc_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get RFC server quirk via FlextLdifServer API."""
    quirk = server.quirk("rfc")
    assert quirk is not None, "RFC quirk must be registered"
    return quirk
```

### Uso nas Funções de Teste

```python
def test_conversion_oid_to_oud(
    oid_quirk: FlextLdifServersBase,
    oud_quirk: FlextLdifServersBase,
) -> None:
    """Test conversion from OID to OUD."""
    # Use os quirks diretamente
    result = conversion_service.convert(oid_quirk, oud_quirk, entry)
    assert result.is_success
```

______________________________________________________________________

## 🔄 Migração de Código Existente

### Passo 1: Atualizar Imports

```python
# ANTES
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud

# DEPOIS
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.servers.base import FlextLdifServersBase
```

### Passo 2: Atualizar Instanciação

```python
# ANTES
oid = FlextLdifServersOid()
oud = FlextLdifServersOud()

# DEPOIS
server = FlextLdifServer()
oid = server.quirk("oid")
oud = server.quirk("oud")
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
- ✅ `src/flext_ldif/services/conversion.py` - Já usa padrão correto via `_resolve_quirk()`

**Arquivos Pendentes** (~50 arquivos, 231 instanciações diretas):

- ⏳ `tests/unit/quirks/servers/*.py` - Tests de quirks específicos
- ⏳ `tests/unit/quirks/test_*.py` - Tests de conversão
- ⏳ `tests/unit/rfc/*.py` - Tests RFC
- ⏳ `tests/integration/*.py` - Tests de integração
- ⏳ `tests/helpers/*.py` - Helpers

______________________________________________________________________

## 🎯 Servers Disponíveis via API

```python
server = FlextLdifServer()

# Servers totalmente implementados
server.quirk("rfc")      # RFC 2849/4512 baseline
server.quirk("oid")      # Oracle Internet Directory
server.quirk("oud")      # Oracle Unified Directory
server.quirk("openldap") # OpenLDAP 2.x
server.quirk("openldap1")# OpenLDAP 1.x
server.quirk("relaxed")  # Lenient parsing mode

# Servers com stubs
server.quirk("ad")       # Active Directory
server.quirk("apache")   # Apache Directory Server
server.quirk("ds389")    # Red Hat DS
server.quirk("novell")   # Novell eDirectory
server.quirk("tivoli")   # IBM Tivoli DS
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
grep -r "server.quirk(" src/
```

______________________________________________________________________

## 📚 Referências

- **API Central**: `src/flext_ldif/services/server.py` - FlextLdifServer class
- **Base Class**: `src/flext_ldif/servers/base.py` - FlextLdifServersBase
- **Exemplo Correto**: `src/flext_ldif/services/conversion.py` - método `_resolve_quirk()`
- **Fixtures Corretas**: `tests/conftest.py` - server, oid_quirk, oud_quirk, rfc_quirk

______________________________________________________________________

**IMPORTANTE**: Este padrão é OBRIGATÓRIO para todo código novo. Código existente deve ser migrado progressivamente.
