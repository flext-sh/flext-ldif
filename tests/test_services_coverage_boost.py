"""Testes específicos para aumentar cobertura crítica da API LDIF.

Este módulo contém testes focados na FlextLdifAPI (que consolidou services)
para cobrir os statements não testados, especialmente os métodos complexos
e edge cases de parsing, validação e escrita.
"""

from __future__ import annotations

import uuid

from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import (
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
)


class TestFlextLdifAPICoverage:
    """Testes para aumentar cobertura de FlextLdifAPI (consolidado services)."""

    def test_api_initialization(self) -> None:
        """Testa inicialização da API LDIF."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        assert api.config == config
        assert hasattr(api, "parse")
        assert hasattr(api, "parse_file")
        assert hasattr(api, "validate")
        assert hasattr(api, "write_file")

    def test_parse_valid_ldif_content(self) -> None:
        """Testa parsing de conteúdo LDIF válido."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: person
cn: Jane Smith
sn: Smith
"""

        result = api.parse(ldif_content)
        assert result.success
        assert result.data is not None
        assert len(result.data) == 2

        # Testa primeiro entry
        first_entry = result.data[0]
        assert isinstance(first_entry, FlextLdifEntry)
        assert first_entry.dn.value == "cn=John Doe,ou=people,dc=example,dc=com"
        assert first_entry.has_attribute("objectClass")
        assert first_entry.has_object_class("person")

    def test_parse_invalid_ldif_content(self) -> None:
        """Testa parsing de conteúdo LDIF inválido."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        invalid_ldif = "invalid ldif content without proper format"

        result = api.parse(invalid_ldif)
        assert not result.success
        assert result.error is not None

    def test_parse_empty_content(self) -> None:
        """Testa parsing de conteúdo vazio."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        result = api.parse("")
        assert result.success
        assert result.data == []

    def test_validate_entries(self) -> None:
        """Testa validação de entries."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        # Criar entrada válida
        entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Test,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Test"],
                    "sn": ["User"],
                }
            ),
        )

        result = api.validate([entry])
        assert result.success

    def test_write_entries_to_ldif(self) -> None:
        """Testa escrita de entries para formato LDIF."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        # Criar entrada para escrita
        entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Test,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Test"],
                    "sn": ["User"],
                }
            ),
        )

        result = api.write([entry])
        assert result.success
        assert result.data is not None
        assert "dn: cn=Test,dc=example,dc=com" in result.data
        assert "objectClass: person" in result.data

    def test_filter_persons(self) -> None:
        """Testa filtro de pessoas."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        # Criar entries de teste
        person_entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Person,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Person"],
                }
            ),
        )

        group_entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Group,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["groupOfNames"],
                    "cn": ["Group"],
                }
            ),
        )

        entries = [person_entry, group_entry]
        result = api.filter_persons(entries)
        assert result.success
        assert result.data is not None
        assert len(result.data) == 1
        assert result.data[0].dn.value == "cn=Person,dc=example,dc=com"

    def test_get_entry_statistics(self) -> None:
        """Testa obtenção de estatísticas de entries."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        entries = [
            FlextLdifEntry(
                id=str(uuid.uuid4()),
                dn=FlextLdifDistinguishedName(value="cn=Test1,dc=example,dc=com"),
                attributes=FlextLdifAttributes(
                    attributes={
                        "objectClass": ["person"],
                        "cn": ["Test1"],
                    }
                ),
            ),
            FlextLdifEntry(
                id=str(uuid.uuid4()),
                dn=FlextLdifDistinguishedName(value="cn=Test2,dc=example,dc=com"),
                attributes=FlextLdifAttributes(
                    attributes={
                        "objectClass": ["inetOrgPerson", "person"],
                        "cn": ["Test2"],
                    }
                ),
            ),
        ]

        result = api.get_entry_statistics(entries)
        assert result.success
        assert result.data is not None
        assert isinstance(result.data, dict)
        assert "total" in result.data
        assert result.data["total"] == 2
        assert "persons" in result.data
        assert result.data["persons"] == 2

    def test_sort_hierarchically(self) -> None:
        """Testa ordenação hierárquica de entries."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        # Criar entries em ordem não hierárquica
        child_entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Child,ou=people,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Child"],
                }
            ),
        )

        parent_entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["organizationalUnit"],
                    "ou": ["people"],
                }
            ),
        )

        entries = [child_entry, parent_entry]  # Ordem incorreta
        result = api.sort_hierarchically(entries)
        assert result.success
        assert result.data is not None
        assert len(result.data) == 2
        # Parent deve vir primeiro (menor profundidade)
        assert result.data[0].dn.value == "ou=people,dc=example,dc=com"
        assert result.data[1].dn.value == "cn=Child,ou=people,dc=example,dc=com"

    def test_find_entry_by_dn(self) -> None:
        """Testa busca de entry por DN."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        target_dn = "cn=Target,dc=example,dc=com"
        target_entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value=target_dn),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Target"],
                }
            ),
        )

        other_entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Other,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Other"],
                }
            ),
        )

        entries = [target_entry, other_entry]
        result = api.find_entry_by_dn(entries, target_dn)
        assert result.success
        assert result.data is not None
        assert result.data.dn.value == target_dn

    def test_find_entry_by_dn_not_found(self) -> None:
        """Testa busca de entry por DN quando não encontrado."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Exists,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Exists"],
                }
            ),
        )

        entries = [entry]
        result = api.find_entry_by_dn(entries, "cn=NotFound,dc=example,dc=com")
        assert result.success
        assert result.data is None

    def test_filter_by_objectclass(self) -> None:
        """Testa filtro por objectClass."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        person_entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Person,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": ["Person"],
                }
            ),
        )

        group_entry = FlextLdifEntry(
            id=str(uuid.uuid4()),
            dn=FlextLdifDistinguishedName(value="cn=Group,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "objectClass": ["groupOfNames"],
                    "cn": ["Group"],
                }
            ),
        )

        entries = [person_entry, group_entry]
        result = api.filter_by_objectclass(entries, "person")
        assert result.success
        assert result.data is not None
        assert len(result.data) == 1
        assert result.data[0].dn.value == "cn=Person,dc=example,dc=com"

    def test_config_integration(self) -> None:
        """Testa integração com configuração."""
        config = FlextLdifConfig(max_entries=5)
        api = FlextLdifAPI(config=config)

        assert api.config.max_entries == 5

    def test_error_handling_edge_cases(self) -> None:
        """Testa casos extremos de tratamento de erro."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        # Test empty entries
        result = api.get_entry_statistics([])
        assert result.success
        assert result.data is not None
        assert result.data["total"] == 0

        # Test invalid LDIF parsing
        result = api.parse("invalid format")
        assert not result.success
        assert result.error is not None
