# from flext-ldif/docs/guides/server-api-usage-pattern.md:110
from __future__ import annotations


def test_conversion_oid_to_oud(
    oid_server: FlextLdifServersBase, oud_server: FlextLdifServersBase
) -> None:
    """Test conversion from OID to OUD."""
    # Use os servers diretamente
    result = conversion_service.convert(oid_server, oud_server, entry)
    assert result.success```
______________________________________________________________________

## 🔄 Migração de Código Existente

### Passo 1: Atualizar Imports

