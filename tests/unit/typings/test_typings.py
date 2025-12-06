from __future__ import annotations
from tests import c, p, s, t

import ast
import inspect
from pathlib import Path
from typing import ClassVar, cast

import pytest
# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)
# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py
    def test_namespace_exists(self) -> None:
        """FlextLdifTypes class must be accessible."""
        assert FlextLdifTypes is not None
        assert hasattr(FlextLdifTypes, "__name__")

    @pytest.mark.parametrize("namespace", ["Entry", "CommonDict", "Models"])
    def test_has_required_namespaces(self, namespace: str) -> None:
        """FlextLdifTypes must have required namespaces."""
        assert hasattr(FlextLdifTypes, namespace)

    def test_srp_compliance_no_functions(self) -> None:
        """typings.py must not contain functions (SRP violation)."""
        members = inspect.getmembers(flext_ldif.typings)
        # Filter out built-in functions like TypedDict from typing module
        user_functions = [
            m
            for m in members
            if inspect.isfunction(m[1])
            and not m[0].startswith("__")
            and m[1].__module__ not in {"typing", "builtins"}
        ]
        assert len(user_functions) == 0, "typings.py must not contain functions"

    def test_only_required_imports(self) -> None:
        """typings.py must only import from flext_core and public flext_ldif modules."""
        project_root = Path(__file__).parent.parent.parent.parent
        types_path = project_root / "src" / "flext_ldif" / "typings.py"
        tree = ast.parse(types_path.read_text())

        flext_ldif_imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module
            and "flext_ldif" in node.module
        ]

        # Only public modules should be imported (no _models/ internal imports)
        # typings.py imports from flext_ldif.protocols (and possibly others)
        assert "flext_ldif.protocols" in flext_ldif_imports, (
            "typings.py must import from flext_ldif.protocols"
        )
        # Verify no internal imports
        internal_imports = [
            imp for imp in flext_ldif_imports if "_" in imp.split(".")[-1]
        ]
        assert len(internal_imports) == 0, (
            f"typings.py must not import from internal modules: {internal_imports}"
        )

class TestsFlextLdifCommonDictionaryTypes(s):
    """Test common dictionary type definitions with REAL data."""

    SAMPLE_ATTR_DICT: ClassVar[dict[str, list[str]]] = {
        c.Names.CN: ["John Doe"],
        c.Names.SN: ["Doe"],
        c.Names.MAIL: ["john@example.com", "john.doe@example.com"],
        c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INET_ORG_PERSON],
    }

    SAMPLE_DISTRIBUTION: ClassVar[dict[str, int]] = {
        c.Names.INET_ORG_PERSON: 1245,
        "groupOfNames": 89,
        "organizationalUnit": 34,
        "domain": 1,
        "country": 1,
        "dcObject": 1,
    }

    def test_attribute_dict_with_ldif_entry(self) -> None:
        """AttributeDict must work with real LDIF entry attributes."""
        attr_dict: FlextLdifTypes.CommonDict.AttributeDict = self.SAMPLE_ATTR_DICT
        assert isinstance(attr_dict, dict)
        assert attr_dict[c.Names.CN] == ["John Doe"]
        assert len(attr_dict[c.Names.MAIL]) == 2

    def test_attribute_dict_empty(self) -> None:
        """AttributeDict must handle empty attributes."""
        attr_dict: FlextLdifTypes.CommonDict.AttributeDict = {}
        assert len(attr_dict) == 0

    def test_distribution_dict_with_entry_counts(self) -> None:
        """DistributionDict must work with entry type statistics."""
        dist: FlextLdifTypes.CommonDict.DistributionDict = self.SAMPLE_DISTRIBUTION
        assert dist[c.Names.INET_ORG_PERSON] == 1245
        assert sum(dist.values()) == 1371

    def test_distribution_dict_from_schema_stats(self) -> None:
        """DistributionDict works for schema statistics."""
        dist: FlextLdifTypes.CommonDict.DistributionDict = {
            "attributeTypes": 156,
            "objectClasses": 78,
            "dITContentRules": 23,
        }
        assert all(isinstance(v, int) for v in dist.values())

class TestEntryTypes:
    """Test Entry namespace type definitions with REAL data."""

    def test_entry_create_data_with_real_ldif_entry(self) -> None:
        """EntryCreateData must accept real LDIF entry data."""
        data: FlextLdifTypes.Entry.EntryCreateData = {
            c.Names.DN: f"cn=John Doe,ou=users,{c.DNs.EXAMPLE}",
            c.Names.OBJECTCLASS: [
                c.Names.INET_ORG_PERSON,
                "organizationalPerson",
                c.Names.PERSON,
                c.Names.TOP,
            ],
            c.Names.CN: "John Doe",
            c.Names.SN: "Doe",
            "givenName": "John",
            c.Names.MAIL: "john@example.com",
            c.Names.UID: "jdoe",
            "userPassword": "{SSHA}encrypted_password_here",
        }
        assert data[c.Names.DN] == f"cn=John Doe,ou=users,{c.DNs.EXAMPLE}"
        # Type narrowing: EntryCreateData values can be ScalarValue | list[str] | dict[str, list[str]]
        objectclass_value = data[c.Names.OBJECTCLASS]
        assert isinstance(objectclass_value, list), "objectClass must be a list"
        assert len(objectclass_value) == 4

    def test_entry_create_data_with_nested_structures(self) -> None:
        """EntryCreateData must support nested structures from LDIF."""
        # EntryCreateData nested dicts must be dict[str, list[str]], not dict[str, str]
        data: FlextLdifTypes.Entry.EntryCreateData = {
            c.Names.DN: f"cn=REDACTED_LDAP_BIND_PASSWORD,{c.DNs.EXAMPLE}",
            "permissions": ["read", "write"],
            "metadata": {
                "source": ["oid"],
                "imported": ["true"],
            },  # dict[str, list[str]]
            "attributes_count": "12",
        }
        assert isinstance(data["permissions"], list)
        # Type narrowing: metadata is dict[str, list[str]]
        metadata_value = data["metadata"]
        assert isinstance(metadata_value, dict)

class TestModelsNamespace:
    """Test Models namespace type definitions with REAL data patterns."""

    def test_entry_attributes_dict_with_real_ldif_data(self) -> None:
        """EntryAttributesDict must work with real LDIF attribute data."""
        # GenericFieldsDict doesn't have these keys defined, use cast for type flexibility
        attrs: GenericFieldsDict = cast(
            "GenericFieldsDict",
            {
                c.Names.CN: ["John Doe"],
                c.Names.OBJECTCLASS: [c.Names.INET_ORG_PERSON, c.Names.PERSON, c.Names.TOP],
                c.Names.SN: "Doe",
                c.Names.MAIL: ["john@example.com"],
                c.Names.UID: "jdoe",
            },
        )
        # Type narrowing: access with cast since keys aren't in GenericFieldsDict
        cn_value = cast("list[str]", attrs.get(c.Names.CN))
        assert cn_value == ["John Doe"]
        objectclass_value = cast("list[str]", attrs.get(c.Names.OBJECTCLASS))
        assert isinstance(objectclass_value, list)

    def test_attributes_data_with_real_schema(self) -> None:
        """AttributesData must support real schema attribute patterns."""
        # GenericFieldsDict doesn't have schema keys, use cast for type flexibility
        data: dict[str, GenericFieldsDict] = {
            c.Names.CN: cast(
                "GenericFieldsDict",
                {
                    "oid": OIDs.CN,
                    "syntax": "Directory String",
                    "equality": "caseIgnoreMatch",
                    "single_valued": False,
                },
            ),
            c.Names.UID: cast(
                "GenericFieldsDict",
                {
                    "oid": "0.9.2342.19200300.100.1.1",
                    "syntax": "Directory String",
                    "single_valued": True,
                },
            ),
        }
        # Type narrowing: access with cast since keys aren't in GenericFieldsDict
        cn_oid = cast("str", data[c.Names.CN].get("oid"))
        assert cn_oid == OIDs.CN
        uid_single_valued = cast("bool", data[c.Names.UID].get("single_valued"))
        assert uid_single_valued is True

    def test_objectclasses_data_with_real_schema(self) -> None:
        """ObjectClassesData must support real objectClass patterns."""
        # GenericFieldsDict doesn't have schema keys, use cast for type flexibility
        data: dict[str, GenericFieldsDict] = {
            c.Names.INET_ORG_PERSON: cast(
                "GenericFieldsDict",
                {
                    "oid": "2.16.840.1.113730.3.2.2",
                    "kind": "STRUCTURAL",
                    "sup": "organizationalPerson",
                    "must": [c.Names.UID],
                    "may": [c.Names.MAIL, "mobile"],
                },
            ),
        }
        # Type narrowing: access with cast since keys aren't in GenericFieldsDict
        oid_value = cast("str", data[c.Names.INET_ORG_PERSON].get("oid"))
        assert oid_value == "2.16.840.1.113730.3.2.2"
        may_values = cast("list[str]", data[c.Names.INET_ORG_PERSON].get("may"))
        assert c.Names.MAIL in may_values

    def test_extensions_with_reals(self) -> None:
        """QuirkExtensions must support real quirk metadata."""
        # GenericFieldsDict doesn't have these keys, use dict[str, object] for flexibility
        extensions_dict: dict[str, object] = {
            "supports_dn_case_registry": True,
            "priority": 10,
            "server_type": "oud",
        }
        # Cast to GenericFieldsDict for type compatibility
        extensions: GenericFieldsDict = cast("GenericFieldsDict", extensions_dict)
        # Type narrowing: access with cast since keys aren't in GenericFieldsDict
        supports_dn_case = cast("bool", extensions.get("supports_dn_case_registry"))
        assert supports_dn_case is True

class TestRemovalOfOverEngineering:
    """Test that over-engineered types were properly removed."""

    REMOVED_NAMESPACES: ClassVar[list[str]] = [
        "Parser",
        "Writer",
        "LdifValidation",
        "LdifProcessing",
        "Analytics",
        "ServerTypes",
        "Functional",
        "Streaming",
        "AnnotatedLdif",
        "ModelAliases",
        "LdifProject",
        "Project",
    ]

    REMOVED_COMMON_DICT: ClassVar[list[str]] = [
        "ChangeDict",
        "CategorizedDict",
        "TreeDict",
        "HierarchyDict",
    ]

    REMOVED_ENTRY: ClassVar[list[str]] = [
        "EntryConfiguration",
        "EntryAttributes",
        "EntryValidation",
        "EntryTransformation",
        "EntryMetadata",
        "EntryProcessing",
    ]

    @pytest.mark.parametrize("namespace", REMOVED_NAMESPACES)
    def test_removed_namespaces(self, namespace: str) -> None:
        """Over-engineered namespaces must be removed."""
        assert not hasattr(FlextLdifTypes, namespace)

    @pytest.mark.parametrize("type_name", REMOVED_COMMON_DICT)
    def test_removed_common_dict_types(self, type_name: str) -> None:
        """Unused CommonDict types must be removed."""
        assert not hasattr(FlextLdifTypes.CommonDict, type_name)

    @pytest.mark.parametrize("type_name", REMOVED_ENTRY)
    def test_removed_entry_types(self, type_name: str) -> None:
        """Unused Entry types must be removed."""
        assert not hasattr(FlextLdifTypes.Entry, type_name)

class TestPhase1StandardizationResults:
    """Test that Phase 1 standardization goals were achieved."""

    def test_minimal_type_system(self) -> None:
        """Type system should be minimal and focused on actual usage."""
        classes = [
            m
            for m in inspect.getmembers(FlextLdifTypes)
            if inspect.isclass(m[1]) and not m[0].startswith("_")
        ]
        assert len(classes) >= 3

    @pytest.mark.parametrize("attr", ["AttributeDict", "DistributionDict"])
    def test_common_dict_simple_patterns(self, attr: str) -> None:
        """Simple patterns should be kept in CommonDict."""
        assert hasattr(FlextLdifTypes.CommonDict, attr)

    def test_entry_create_data_exists(self) -> None:
        """EntryCreateData should exist in Entry namespace."""
        assert hasattr(FlextLdifTypes.Entry, "EntryCreateData")

    def test_types_work_with_real_data(self) -> None:
        """Verify types work with real data."""
        attr_dict: FlextLdifTypes.CommonDict.AttributeDict = {c.Names.CN: ["test"]}
        dist: FlextLdifTypes.CommonDict.DistributionDict = {"type": 100}
        entry_data: FlextLdifTypes.Entry.EntryCreateData = {c.Names.DN: c.DNs.TEST_USER}

        assert isinstance(attr_dict, dict)
        assert isinstance(dist, dict)
        assert isinstance(entry_data, dict)

class TestIntegrationWithLdifFixtures:
    """Integration tests using real LDIF fixture data."""

    @pytest.fixture
    def oid_ldif_path(self) -> Path:
        """Path to OID LDIF fixtures."""
        return Path("tests/fixtures/oid/oid_entries_fixtures.ldif")

    def test_types_work_with_ldif_fixtures(self, oid_ldif_path: Path) -> None:
        """Verify types work with real LDIF fixture files."""
        assert oid_ldif_path.exists()
        entry_attrs: FlextLdifTypes.CommonDict.AttributeDict = {
            c.Names.CN: ["Test Entry"],
            c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INET_ORG_PERSON],
        }
        assert c.Names.CN in entry_attrs

    def test_models_namespace_with_schema_data(self) -> None:
        """Verify Models namespace types work with schema data."""
        # GenericFieldsDict doesn't have schema keys, use dict[str, object] for flexibility
        schema_dict: dict[str, dict[str, object]] = {
            c.Names.CN: {"oid": OIDs.CN, "syntax": "Directory String"}
        }
        # Cast to dict[str, GenericFieldsDict] for type compatibility
        schema_attrs: dict[str, GenericFieldsDict] = cast(
            "dict[str, GenericFieldsDict]", schema_dict
        )
        # Type narrowing: access with cast since keys aren't in GenericFieldsDict
        cn_oid = cast("str", schema_attrs[c.Names.CN].get("oid"))
        assert cn_oid == OIDs.CN
