# from flext-ldif/docs/guides/server-api-usage-pattern.md:146
from __future__ import annotations


# ANTES
def my_function(oid: FlextLdifServersOid) -> None:
    pass


# DEPOIS
def my_function(oid: FlextLdifServersBase) -> None:
    pass```
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

