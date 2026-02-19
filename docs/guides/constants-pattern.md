# Constants Pattern Guide


<!-- TOC START -->
- [RFC.Constants (Base)](#rfcconstants-base)
- [Server.Constants (Específicos)](#serverconstants-especficos)
- [Quando usar o quê](#quando-usar-o-qu)
- [Benefícios](#benefcios)
<!-- TOC END -->

## RFC.Constants (Base)

**Rule:** Use ONLY `ClassVar` - never `Final`

- Allows all servers to override if needed
- Provides baseline values

```python
class Constants:
    # ✅ Correto - pode ser sobrescrito
    PERMISSION_READ: ClassVar[str] = "read"
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([...])

    # ❌ Errado - não usar Final em RFC
    # PERMISSION_READ: Final[str] = "read"
```

## Server.Constants (Específicos)

**Rule:**

- `ClassVar` quando sobrescrever RFC
- `Final` apenas para novas constantes server-specific

```python
class Constants(FlextLdifServersRfc.Constants):
    # ✅ Sobrescrevendo RFC - usar ClassVar
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([...])

    # ✅ Nova constante server-specific - pode usar Final
    OUD_SPECIFIC_FEATURE: Final[str] = "oud_value"

    # ✅ Padrões server-specific - Final OK
    ACL_TYPE_PATTERN: Final[str] = r"^orclaci:"
```

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
