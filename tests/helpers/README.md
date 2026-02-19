# Test Helpers Module


<!-- TOC START -->
- [Módulos](#mdulos)
  - [`test_assertions.py`](#testassertionspy)
  - [`test_operations.py`](#testoperationspy)
- [Exemplo de Refatoração](#exemplo-de-refatorao)
  - [Antes (Duplicação Massiva)](#antes-duplicao-massiva)
  - [Depois (Usando Helpers)](#depois-usando-helpers)
- [Benefícios](#benefcios)
- [Uso em Testes Parametrizados](#uso-em-testes-parametrizados)
- [Integração com Fixtures](#integrao-com-fixtures)
<!-- TOC END -->

Este módulo fornece helpers reutilizáveis para reduzir duplicação massiva de testes pytest, método a método.

## Módulos

### `test_assertions.py`

Fornece asserções reutilizáveis para padrões comuns:

```python
from tests.helpers import TestAssertions

# Assert success e retorna valor unwrapped
value = TestAssertions.assert_success(result)

# Assert failure e retorna mensagem de erro
error = TestAssertions.assert_failure(result, expected_error="expected")

# Validar entry
TestAssertions.assert_entry_valid(entry)

# Validar múltiplas entries
TestAssertions.assert_entries_valid(entries)

# Validar schema attribute
TestAssertions.assert_schema_attribute_valid(attr, expected_oid="1.2.3.4")

# Validar schema objectClass
TestAssertions.assert_schema_objectclass_valid(oc, expected_name="person")

# Assert parse success
entries = TestAssertions.assert_parse_success(result, expected_count=5)

# Assert write success
ldif = TestAssertions.assert_write_success(result, expected_content="dn:")

# Validar roundtrip
TestAssertions.assert_roundtrip_preserves(original_entries, roundtripped_entries)
```

### `test_operations.py`

Fornece operações reutilizáveis para padrões comuns:

```python
from tests.helpers import TestOperations

# Parse e validar
entries = TestOperations.parse_and_validate(parser, ldif_content, expected_count=5)

# Write e validar
ldif = TestOperations.write_and_validate(writer, entries, expected_content="dn:")

# Roundtrip completo (parse -> write -> parse)
original, roundtripped = TestOperations.roundtrip_and_validate(
    api, ldif_content, tmp_path, expected_count=5
)

# Parse attribute e validar
attr = TestOperations.parse_attribute_and_validate(
    schema_quirk, attr_def, expected_oid="1.2.3.4", expected_name="testAttr"
)

# Parse objectClass e validar
oc = TestOperations.parse_objectclass_and_validate(
    schema_quirk, oc_def, expected_oid="1.2.3.5", expected_name="testOC"
)

# Write entry e validar
ldif = TestOperations.write_entry_and_validate(
    entry_quirk, entry, expected_content="dn:"
)
```

## Exemplo de Refatoração

### Antes (Duplicação Massiva)

```python
def test_parse_attribute(self, schema_quirk):
    """Test parse attribute."""
    result = schema_quirk.parse_attribute("( 1.2.3.4 NAME 'testAttr' )")
    assert result.is_success
    attr = result.unwrap()
    assert attr.oid == "1.2.3.4"
    assert attr.name == "testAttr"

def test_parse_another_attribute(self, schema_quirk):
    """Test parse another attribute."""
    result = schema_quirk.parse_attribute("( 1.2.3.5 NAME 'anotherAttr' )")
    assert result.is_success
    attr = result.unwrap()
    assert attr.oid == "1.2.3.5"
    assert attr.name == "anotherAttr"
```

### Depois (Usando Helpers)

```python
from tests.helpers import TestOperations

def test_parse_attribute(self, schema_quirk):
    """Test parse attribute."""
    attr = TestOperations.parse_attribute_and_validate(
        schema_quirk,
        "( 1.2.3.4 NAME 'testAttr' )",
        expected_oid="1.2.3.4",
        expected_name="testAttr"
    )

def test_parse_another_attribute(self, schema_quirk):
    """Test parse another attribute."""
    attr = TestOperations.parse_attribute_and_validate(
        schema_quirk,
        "( 1.2.3.5 NAME 'anotherAttr' )",
        expected_oid="1.2.3.5",
        expected_name="anotherAttr"
    )
```

## Benefícios

1. **Redução de Duplicação**: Padrões comuns são centralizados
2. **Consistência**: Todos os testes usam as mesmas validações
3. **Manutenibilidade**: Mudanças em validações são feitas em um único lugar
4. **Legibilidade**: Testes ficam mais concisos e focados no que está sendo testado
5. **Reutilização**: Helpers podem ser usados em qualquer teste

## Uso em Testes Parametrizados

```python
import pytest
from tests.helpers import TestOperations

@pytest.mark.parametrize("attr_def,expected_oid,expected_name", [
    ("( 1.2.3.4 NAME 'testAttr' )", "1.2.3.4", "testAttr"),
    ("( 1.2.3.5 NAME 'anotherAttr' )", "1.2.3.5", "anotherAttr"),
])
def test_parse_multiple_attributes(schema_quirk, attr_def, expected_oid, expected_name):
    """Test parse multiple attributes."""
    TestOperations.parse_attribute_and_validate(
        schema_quirk, attr_def, expected_oid, expected_name
    )
```

## Integração com Fixtures

```python
from tests.helpers import TestOperations, TestAssertions

def test_roundtrip_with_fixture(ldif_api, tmp_path):
    """Test roundtrip using fixture."""
    # Load fixture
    entries = FlextLdifTestUtils.load_fixture(ldif_api, "rfc", "rfc_entries.ldif")

    # Roundtrip
    original, roundtripped = TestOperations.roundtrip_and_validate(
        ldif_api, entries, tmp_path
    )

    # Validações adicionais
    TestAssertions.assert_roundtrip_preserves(original, roundtripped)
```
