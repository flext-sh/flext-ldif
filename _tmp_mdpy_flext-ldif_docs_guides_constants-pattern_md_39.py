# from flext-ldif_docs/guides/constants-pattern.md:39
from __future__ import annotations


class Constants(FlextLdifServersRfc.Constants):
    # ✅ Sobrescrevendo RFC - usar ClassVar
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([...])

    # ✅ Nova constante server-specific - pode usar Final
    OUD_SPECIFIC_FEATURE: Final[str] = "oud_value"

    # ✅ Padrões server-specific - Final OK
    ACL_TYPE_PATTERN: Final[str] = r"^orclaci:"```
## Quando usar o quê

| Cenário                        | RFC.Constants | Server.Constants      |
| ------------------------------ | ------------- | --------------------- |
| Valor baseline para todos      | `ClassVar`    | -                     |
| Override de valor RFC          | -             | `ClassVar`            |
| Nova constante server-specific | -             | `Final` ou `ClassVar` |
| Constante que NUNCA muda       | -             | `Final`               |

## Benefícios

- ✅ Sem conflitos de lint
- ✅ Herança funciona corretamente
- ✅ Type safety mantida
- ✅ Flexibilidade para override
