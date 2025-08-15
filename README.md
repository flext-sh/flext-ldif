# FLEXT-LDIF — Biblioteca de Processamento LDIF

Biblioteca Python para processar arquivos LDIF (LDAP Data Interchange Format), alinhada à arquitetura FLEXT. Oferece parsing, validação e geração de LDIF com padrões de Clean Architecture e FlextResult.

## ⚡ Início rápido

Instalação
```bash
git clone https://github.com/flext-sh/flext-ldif.git
cd flext-ldif
poetry install
```

Uso básico
```python
from flext_ldif import FlextLdifAPI

api = FlextLdifAPI()
ldif = """
dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
objectClass: inetOrgPerson
mail: john.doe@example.com
"""
parsed = api.parse(ldif)
if parsed.is_success:
    entries = parsed.data
    print(f"{len(entries)} entradas")
```

CLI
```bash
flext-ldif parse sample.ldif
flext-ldif validate --strict sample.ldif
flext-ldif transform --filter "objectClass=person" input.ldif output.ldif
```

## 🏛️ Estrutura real

```
src/flext_ldif/
├── api.py              # API unificada
├── cli.py              # CLI (entrypoint: flext-ldif)
├── core.py             # Núcleo de processamento
├── ldif_parser.py      # Parser LDIF
├── ldif_writer.py      # Escrita LDIF
├── models.py           # Entidades e VOs
├── entry_*             # Serviços de domínio (validação, transformação, repositório)
├── config.py | exceptions.py | constants.py | protocols.py | types.py
└── format_*            # Manipuladores/validadores de formato
```

## 🔧 Recursos

- Parsing RFC-compatível, validação e escrita
- Transformações (filtros e modificações)
- Padrões enterprise: FlextResult, DI (flext-core), tipagem estrita

## 🧪 Desenvolvimento

```bash
make lint
make type-check
make test
make validate
```

## 📦 Dependências (pyproject.toml)

- `ldif3`, `click`, `pydantic`, `pydantic-settings`
- Integrações locais opcionais: `flext-core`, `flext-cli`, `flext-ldap`, `flext-observability`

## 📄 Licença

MIT — veja `LICENSE`.
