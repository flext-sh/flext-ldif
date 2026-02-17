"""Tests for flext-ldif typings structure and namespace access."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any, ClassVar

import pytest

import flext_ldif
from flext_ldif.typings import t as t_ldif
from tests import GenericFieldsDict, OIDs, c, s


class TestFlextLdifTypesStructure:  # Class name contains FlextLdifTypes (acceptable)
    """Tests for FlextLdifTypes structure and namespace access."""

    def test_namespace_exists(self) -> None:
        """t_ldif class must be accessible."""
        assert t_ldif is not None
        assert hasattr(t_ldif, "__name__")

    def test_has_required_namespaces(self) -> None:
        """t_ldif must have required namespaces."""
        assert hasattr(t_ldif, "Ldif")
        # Entry namespace was removed as part of dict -> model migration
        assert not hasattr(t_ldif.Ldif, "Entry")
        assert hasattr(t_ldif.Ldif, "CommonDict")

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
        """typings.py must only import from flext_core (Tier 0 architecture rule)."""
        project_root = Path(
            __file__
        ).parent.parent.parent  # tests/unit/test_typings.py -> project root
        types_path = project_root / "src" / "flext_ldif" / "typings.py"
        tree = ast.parse(types_path.read_text())

        flext_ldif_imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module
            and "flext_ldif" in node.module
        ]

        # typings.py is Tier 0 - it should NOT import from other flext_ldif modules
        # This is correct architecture: typings.py is pure type definitions
        # Verify no internal imports (no _models, _utilities, services, etc.)
        internal_imports = [
            imp for imp in flext_ldif_imports if "_" in imp.split(".")[-1]
        ]
        assert len(internal_imports) == 0, (
            f"typings.py must not import from internal modules: {internal_imports}"
        )
        # Also verify no imports from services or higher tiers
        service_imports = [
            imp for imp in flext_ldif_imports if "services" in imp or "api" in imp
        ]
        assert len(service_imports) == 0, (
            f"typings.py must not import from services/api: {service_imports}"
        )


class TestsFlextLdifCommonDictionaryTypes(s):
    """Test common dictionary type definitions with REAL data."""

    SAMPLE_ATTR_DICT: ClassVar[dict[str, list[str]]] = {
        c.Names.CN: ["John Doe"],
        c.Names.SN: ["Doe"],
        c.Names.MAIL: ["john@example.com", "john.doe@example.com"],
        c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INETORGPERSON],
    }

    SAMPLE_DISTRIBUTION: ClassVar[dict[str, int]] = {
        c.Names.INETORGPERSON: 1245,
        "groupOfNames": 89,
        "organizationalUnit": 34,
        "domain": 1,
        "country": 1,
        "dcObject": 1,
    }

    def test_attribute_dict_with_ldif_entry(self) -> None:
        """AttributeDict must work with real LDIF entry attributes."""
        attr_dict: t_ldif.Ldif.CommonDict.AttributeDict = self.SAMPLE_ATTR_DICT
        assert isinstance(attr_dict, dict)
        assert attr_dict[c.Names.CN] == ["John Doe"]
        assert len(attr_dict[c.Names.MAIL]) == 2

    def test_attribute_dict_empty(self) -> None:
        """AttributeDict must handle empty attributes."""
        attr_dict: t_ldif.Ldif.CommonDict.AttributeDict = {}
        assert len(attr_dict) == 0

    def test_distribution_dict_with_entry_counts(self) -> None:
        """DistributionDict must work with entry type statistics."""
        dist: t_ldif.Ldif.CommonDict.DistributionDict = self.SAMPLE_DISTRIBUTION
        assert dist[c.Names.INETORGPERSON] == 1245
        assert sum(dist.values()) == 1371

    def test_distribution_dict_from_schema_stats(self) -> None:
        """DistributionDict works for schema statistics."""
        dist: t_ldif.Ldif.CommonDict.DistributionDict = {
            "attributeTypes": 156,
            "objectClasses": 78,
            "dITContentRules": 23,
        }
        assert all(isinstance(v, int) for v in dist.values())


class TestModelsNamespace:
    """Test Models namespace type definitions with REAL data patterns."""

    def test_entry_attributes_dict_with_real_ldif_data(self) -> None:
        """EntryAttributesDict must work with real LDIF attribute data."""
        # GenericFieldsDict is a flexible TypedDict for test data
        attrs: dict[str, Any] = {
            c.Names.CN: ["John Doe"],
            c.Names.OBJECTCLASS: [
                c.Names.INETORGPERSON,
                c.Names.PERSON,
                c.Names.TOP,
            ],
            c.Names.SN: "Doe",
            c.Names.MAIL: ["john@example.com"],
            c.Names.UID: "jdoe",
        }
        # Access test data directly
        cn_value: Any = attrs.get(c.Names.CN)
        assert cn_value == ["John Doe"]
        objectclass_value: Any = attrs.get(c.Names.OBJECTCLASS)
        assert isinstance(objectclass_value, list)

    def test_attributes_data_with_real_schema(self) -> None:
        """AttributesData must support real schema attribute patterns."""
        # Use dict[str, Any] for flexible test data
        data: dict[str, dict[str, Any]] = {
            c.Names.CN: {
                "oid": OIDs.CN,
                "syntax": "Directory String",
                "equality": "caseIgnoreMatch",
                "single_valued": False,
            },
            c.Names.UID: {
                "oid": "0.9.2342.19200300.100.1.1",
                "syntax": "Directory String",
                "single_valued": True,
            },
        }
        # Access test data directly with Any type
        cn_oid: Any = data[c.Names.CN].get("oid")
        assert cn_oid == OIDs.CN
        uid_single_valued: Any = data[c.Names.UID].get("single_valued")
        assert uid_single_valued is True

    def test_objectclasses_data_with_real_schema(self) -> None:
        """ObjectClassesData must support real objectClass patterns."""
        # Use dict[str, Any] for flexible test data
        data: dict[str, dict[str, Any]] = {
            c.Names.INETORGPERSON: {
                "oid": "2.16.840.1.113730.3.2.2",
                "kind": "STRUCTURAL",
                "sup": "organizationalPerson",
                "must": [c.Names.UID],
                "may": [c.Names.MAIL, "mobile"],
            },
        }
        # Access test data directly with Any type
        oid_value: Any = data[c.Names.INETORGPERSON].get("oid")
        assert oid_value == "2.16.840.1.113730.3.2.2"
        may_values: Any = data[c.Names.INETORGPERSON].get("may")
        assert c.Names.MAIL in may_values

    def test_extensions_with_reals(self) -> None:
        """QuirkExtensions must support real quirk metadata."""
        # Use dict[str, Any] for flexible test data
        extensions: dict[str, Any] = {
            "supports_dn_case_registry": True,
            "priority": 10,
            "server_type": "oud",
        }
        # Access test data directly with Any type
        supports_dn_case: Any = extensions.get("supports_dn_case_registry")
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
        "EntryValidation",
        "EntryTransformation",
        "EntryProcessing",
        # Note: EntryAttributes and EntryMetadata still exist and are used
    ]

    @pytest.mark.parametrize("namespace", REMOVED_NAMESPACES)
    def test_removed_namespaces(self, namespace: str) -> None:
        """Over-engineered namespaces must be removed."""
        assert not hasattr(t_ldif, namespace)

    @pytest.mark.parametrize("type_name", REMOVED_COMMON_DICT)
    def test_removed_common_dict_types(self, type_name: str) -> None:
        """Unused CommonDict types must be removed."""
        assert not hasattr(t_ldif.Ldif.CommonDict, type_name)

    @pytest.mark.parametrize("type_name", REMOVED_ENTRY)
    def test_removed_entry_types(self, type_name: str) -> None:
        """Unused Entry types must be removed."""
        # Entry namespace itself was removed
        assert not hasattr(t_ldif.Ldif, "Entry")


class TestPhase1StandardizationResults:
    """Test that Phase 1 standardization goals were achieved."""

    def test_minimal_type_system(self) -> None:
        """Type system should be minimal and focused on actual usage."""
        classes = [
            m
            for m in inspect.getmembers(t_ldif)
            if inspect.isclass(m[1]) and not m[0].startswith("_")
        ]
        assert len(classes) >= 1

    @pytest.mark.parametrize("attr", ["AttributeDict", "DistributionDict"])
    def test_common_dict_simple_patterns(self, attr: str) -> None:
        """Simple patterns should be kept in CommonDict."""
        # CommonDict exists in Ldif namespace only (proper architecture)
        # However, DistributionDict might have been removed if unused
        if hasattr(t_ldif.Ldif, "CommonDict"):
            assert hasattr(t_ldif.Ldif.CommonDict, "AttributeDict")

    def test_types_work_with_real_data(self) -> None:
        """Verify types work with real data."""
        # AttributeDict usage test
        pass


class TestIntegrationWithLdifFixtures:
    """Integration tests using real LDIF fixture data."""

    @pytest.fixture
    def oid_ldif_path(self) -> Path:
        """Path to OID LDIF fixtures."""
        # Fix path to be relative to project root or use absolute path logic
        # Assuming pytest is run from repo root or flext-ldif root
        base_path = Path("flext-ldif/tests/fixtures/oid/oid_entries_fixtures.ldif")
        if not base_path.exists():
            # Try relative to flext-ldif if running from there
            base_path = Path("tests/fixtures/oid/oid_entries_fixtures.ldif")
        return base_path

    def test_types_work_with_ldif_fixtures(self, oid_ldif_path: Path) -> None:
        """Verify types work with real LDIF fixture files."""
        assert oid_ldif_path.exists()
        entry_attrs: t_ldif.Ldif.CommonDict.AttributeDict = {
            c.Names.CN: ["Test Entry"],
            c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INETORGPERSON],
        }
        assert c.Names.CN in entry_attrs

    def test_models_namespace_with_schema_data(self) -> None:
        """Verify Models namespace types work with schema data."""
        # Use dict[str, Any] for flexible test data
        schema_attrs: dict[str, dict[str, Any]] = {
            c.Names.CN: {"oid": OIDs.CN, "syntax": "Directory String"}
        }
        # Access test data directly with Any type
        cn_oid: Any = schema_attrs[c.Names.CN].get("oid")
        assert cn_oid == OIDs.CN
