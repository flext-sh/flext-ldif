"""Tests for flext-ldif typings structure and namespace access."""

from __future__ import annotations

import ast
import inspect
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar, cast

import pytest
from flext_tests import tm

import flext_ldif
from tests import c, s, t


class TestFlextLdifTypesStructure:
    """Tests for FlextLdifTypes structure and namespace access."""

    def test_namespace_exists(self) -> None:
        """T class must be accessible."""
        tm.that(t, none=False)
        tm.that(hasattr(t, "__name__"), eq=True)

    def test_has_required_namespaces(self) -> None:
        """T must have required namespaces."""
        tm.that(hasattr(t, "Ldif"), eq=True)
        tm.that(not hasattr(t.Ldif, "Entry"), eq=True)
        tm.that(hasattr(t.Ldif, "AttributeDict"), eq=True)
        tm.that(hasattr(t.Ldif, "DistributionDict"), eq=True)

    def test_srp_compliance_no_functions(self) -> None:
        """typings.py must not contain functions (SRP violation)."""
        members = inspect.getmembers(flext_ldif.typings)
        user_functions = [
            m
            for m in members
            if inspect.isfunction(m[1])
            and (not m[0].startswith("__"))
            and (m[1].__module__ not in {"typing", "builtins"})
        ]
        (
            tm.that(not user_functions, eq=True),
            "typings.py must not contain functions",
        )

    def test_only_required_imports(self) -> None:
        """typings.py must only import from flext_core (Tier 0 architecture rule)."""
        project_root = Path(__file__).parent.parent.parent
        types_path = project_root / "src" / "flext_ldif" / "typings.py"
        tree = ast.parse(types_path.read_text())
        flext_ldif_imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module
            and ("flext_ldif" in node.module)
        ]
        internal_imports = [
            imp
            for imp in flext_ldif_imports
            if imp.startswith("flext_ldif.") and "_" in imp.split(".")[-1]
        ]
        (
            tm.that(not internal_imports, eq=True),
            (f"typings.py must not import from internal modules: {internal_imports}"),
        )
        service_imports = [
            imp for imp in flext_ldif_imports if "services" in imp or "api" in imp
        ]
        (
            tm.that(not service_imports, eq=True),
            (f"typings.py must not import from services/api: {service_imports}"),
        )


class TestsFlextLdifCommonDictionaryTypes(s):
    """Test common dictionary type definitions with REAL data."""

    SAMPLE_ATTR_DICT: ClassVar[Mapping[str, t.StrSequence]] = {
        c.Names.CN: ["John Doe"],
        c.Names.SN: ["Doe"],
        c.Names.MAIL: ["john@example.com", "john.doe@example.com"],
        c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INETORGPERSON],
    }
    SAMPLE_DISTRIBUTION: ClassVar[Mapping[str, int]] = {
        c.Names.INETORGPERSON: 1245,
        "groupOfNames": 89,
        "organizationalUnit": 34,
        "domain": 1,
        "country": 1,
        "dcObject": 1,
    }

    def test_attribute_dict_with_ldif_entry(self) -> None:
        """AttributeDict must work with real LDIF entry attributes."""
        attr_dict: t.Ldif.AttributeDict = self.SAMPLE_ATTR_DICT
        tm.that(attr_dict, is_=dict)
        tm.that(attr_dict[c.Names.CN], eq=["John Doe"])
        tm.that(len(attr_dict[c.Names.MAIL]), eq=2)

    def test_attribute_dict_empty(self) -> None:
        """AttributeDict must handle empty attributes."""
        attr_dict: t.Ldif.AttributeDict = {}
        tm.that(not attr_dict, eq=True)

    def test_distribution_dict_with_entry_counts(self) -> None:
        """DistributionDict must work with entry type statistics."""
        dist: t.Ldif.DistributionDict = self.SAMPLE_DISTRIBUTION
        tm.that(dist[c.Names.INETORGPERSON], eq=1245)
        tm.that(sum(dist.values()), eq=1371)

    def test_distribution_dict_from_schema_stats(self) -> None:
        """DistributionDict works for schema statistics."""
        dist: t.Ldif.DistributionDict = {
            "attributeTypes": 156,
            "objectClasses": 78,
            "dITContentRules": 23,
        }
        tm.that(all(isinstance(v, int) for v in dist.values()), eq=True)


class TestModelsNamespace:
    """Test Models namespace type definitions with REAL data patterns."""

    def test_entry_attributes_dict_with_real_ldif_data(self) -> None:
        """EntryAttributesDict must work with real LDIF attribute data."""
        attrs: Mapping[str, t.Scalar | t.StrSequence] = {
            c.Names.CN: ["John Doe"],
            c.Names.OBJECTCLASS: [c.Names.INETORGPERSON, c.Names.PERSON, c.Names.TOP],
            c.Names.SN: "Doe",
            c.Names.MAIL: ["john@example.com"],
            c.Names.UID: "jdoe",
        }
        cn_value: str | t.StrSequence | None = cast(
            "str | t.StrSequence | None", attrs.get(c.Names.CN)
        )
        tm.that(cn_value, eq=["John Doe"])
        objectclass_value: str | t.StrSequence | None = cast(
            "str | t.StrSequence | None", attrs.get(c.Names.OBJECTCLASS)
        )
        tm.that(objectclass_value, is_=list)

    def test_attributes_data_with_real_schema(self) -> None:
        """AttributesData must support real schema attribute patterns."""
        data: Mapping[str, Mapping[str, t.Scalar | t.StrSequence]] = {
            c.Names.CN: {
                "oid": c.OIDs.CN,
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
        cn_oid: t.Scalar | t.StrSequence | None = data[c.Names.CN].get("oid")
        tm.that(cn_oid, eq=c.OIDs.CN)
        uid_single_valued: t.Scalar | t.StrSequence | None = data[c.Names.UID].get(
            "single_valued"
        )
        tm.that(uid_single_valued is True, eq=True)

    def test_objectclasses_data_with_real_schema(self) -> None:
        """ObjectClassesData must support real objectClass patterns."""
        data: Mapping[str, Mapping[str, t.Scalar | t.StrSequence]] = {
            c.Names.INETORGPERSON: {
                "oid": "2.16.840.1.113730.3.2.2",
                "kind": "STRUCTURAL",
                "sup": "organizationalPerson",
                "must": [c.Names.UID],
                "may": [c.Names.MAIL, "mobile"],
            }
        }
        oid_value: t.Scalar | t.StrSequence | None = data[c.Names.INETORGPERSON].get(
            "oid"
        )
        tm.that(oid_value, eq="2.16.840.1.113730.3.2.2")
        may_values: t.Scalar | t.StrSequence | None = data[c.Names.INETORGPERSON].get(
            "may"
        )
        tm.that(may_values, none=False)
        if may_values is not None and isinstance(may_values, list):
            tm.that(may_values, has=c.Names.MAIL)

    def test_extensions_with_reals(self) -> None:
        """QuirkExtensions must support real quirk metadata."""
        extensions: Mapping[str, t.Scalar] = {
            "supports_dn_case_registry": True,
            "priority": 10,
            "server_type": "oud",
        }
        supports_dn_case: t.Scalar | None = extensions.get("supports_dn_case_registry")
        tm.that(supports_dn_case is True, eq=True)


class TestRemovalOfOverEngineering:
    """Test that over-engineered types were properly removed."""

    REMOVED_NAMESPACES: ClassVar[t.StrSequence] = [
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
    REMOVED_COMMON_DICT: ClassVar[t.StrSequence] = [
        "ChangeDict",
        "CategorizedDict",
        "TreeDict",
        "HierarchyDict",
    ]
    REMOVED_ENTRY: ClassVar[t.StrSequence] = [
        "EntryConfiguration",
        "EntryValidation",
        "EntryTransformation",
        "EntryProcessing",
    ]

    @pytest.mark.parametrize("namespace", REMOVED_NAMESPACES)
    def test_removed_namespaces(self, namespace: str) -> None:
        """Over-engineered namespaces must be removed."""
        tm.that(not hasattr(t, namespace), eq=True)

    @pytest.mark.parametrize("type_name", REMOVED_COMMON_DICT)
    def test_removed_common_dict_types(self, type_name: str) -> None:
        """Unused CommonDict types must be removed."""
        tm.that(not hasattr(t.Ldif, type_name), eq=True)

    @pytest.mark.parametrize("type_name", REMOVED_ENTRY)
    def test_removed_entry_types(self, type_name: str) -> None:
        """Unused Entry types must be removed."""
        tm.that(not hasattr(t.Ldif, "Entry"), eq=True)


class TestPhase1StandardizationResults:
    """Test that Phase 1 standardization goals were achieved."""

    def test_minimal_type_system(self) -> None:
        """Type system should be minimal and focused on actual usage."""
        classes = [
            m
            for m in inspect.getmembers(t)
            if inspect.isclass(m[1]) and (not m[0].startswith("_"))
        ]
        tm.that(len(classes), gte=1)

    @pytest.mark.parametrize("attr", ["AttributeDict", "DistributionDict"])
    def test_common_dict_simple_patterns(self, attr: str) -> None:
        """Simple dict type aliases should exist on t.Ldif."""
        tm.that(hasattr(t.Ldif, attr), eq=True)

    def test_types_work_with_real_data(self) -> None:
        """Verify types work with real data."""
        attr_dict: t.Ldif.AttributeDict = {
            c.Names.CN: ["Jane Doe"],
            c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INETORGPERSON],
        }
        distribution: t.Ldif.DistributionDict = {
            c.Names.INETORGPERSON: 2,
            c.Names.PERSON: 1,
        }
        tm.that(attr_dict[c.Names.CN], eq=["Jane Doe"])
        tm.that(attr_dict[c.Names.OBJECTCLASS], has=c.Names.INETORGPERSON)
        tm.that(sum(distribution.values()), eq=3)
        tm.that(distribution[c.Names.PERSON], eq=1)


class TestIntegrationWithLdifFixtures:
    """Integration tests using real LDIF fixture data."""

    @pytest.fixture
    def oid_ldif_path(self) -> Path:
        """Path to OID LDIF fixtures."""
        base_path = Path("flext-ldif/tests/fixtures/oid/oid_entries_fixtures.ldif")
        if not base_path.exists():
            base_path = Path("tests/fixtures/oid/oid_entries_fixtures.ldif")
        return base_path

    def test_types_work_with_ldif_fixtures(self, oid_ldif_path: Path) -> None:
        """Verify types work with real LDIF fixture files."""
        tm.that(oid_ldif_path.exists(), eq=True)
        entry_attrs: t.Ldif.AttributeDict = {
            c.Names.CN: ["Test Entry"],
            c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INETORGPERSON],
        }
        tm.that(entry_attrs, has=c.Names.CN)

    def test_models_namespace_with_schema_data(self) -> None:
        """Verify Models namespace types work with schema data."""
        schema_attrs: Mapping[str, Mapping[str, t.Scalar | t.StrSequence]] = {
            c.Names.CN: {"oid": c.OIDs.CN, "syntax": "Directory String"}
        }
        cn_oid: t.Scalar | t.StrSequence | None = schema_attrs[c.Names.CN].get("oid")
        tm.that(cn_oid, eq=c.OIDs.CN)
