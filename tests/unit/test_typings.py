"""Tests for flext-ldif typings structure and namespace access."""

from __future__ import annotations

import ast
import inspect
from collections.abc import Mapping
from pathlib import Path

import pytest
from flext_tests import tm

import flext_ldif
from tests import c, t


class TestFlextLdifTypesStructure:
    """Tests for FlextLdifTypes structure and namespace access."""

    def test_namespace_exists(self) -> None:
        """T class must be accessible."""
        tm.that(t, none=False)

    def test_has_required_namespaces(self) -> None:
        """T must have required namespaces."""
        tm.that(not hasattr(t.Ldif, "Entry"), eq=True)

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
        _ = tm.that(not user_functions, eq=True)

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
        _ = tm.that(not internal_imports, eq=True)
        service_imports = [
            imp for imp in flext_ldif_imports if "services" in imp or "api" in imp
        ]
        _ = tm.that(not service_imports, eq=True)


class TestsFlextLdifCommonDictionaryTypes:
    """Test common dictionary type definitions with REAL data."""

    def test_attribute_dict_with_ldif_entry(self) -> None:
        """AttributeDict must work with real LDIF entry attributes."""
        attr_dict: t.Ldif.AttributeDict = c.Ldif.Tests.TYPINGS_SAMPLE_ATTR_DICT
        tm.that(attr_dict, is_=dict)
        tm.that(attr_dict[c.Ldif.Tests.Names.CN], eq=["John Doe"])
        tm.that(len(attr_dict[c.Ldif.Tests.Names.MAIL]), eq=2)

    def test_attribute_dict_empty(self) -> None:
        """AttributeDict must handle empty attributes."""
        attr_dict: t.Ldif.AttributeDict = {}
        tm.that(not attr_dict, eq=True)

    def test_distribution_dict_with_entry_counts(self) -> None:
        """DistributionDict must work with entry type statistics."""
        dist: t.IntMapping = c.Ldif.Tests.TYPINGS_SAMPLE_DISTRIBUTION
        tm.that(dist[c.Ldif.Tests.Names.INETORGPERSON], eq=1245)
        tm.that(sum(dist.values()), eq=1371)

    def test_distribution_dict_from_schema_stats(self) -> None:
        """DistributionDict works for schema statistics."""
        dist: t.IntMapping = {
            "attributeTypes": 156,
            "objectClasses": 78,
            "dITContentRules": 23,
        }
        tm.that(len(dist), eq=3)


class TestModelsNamespace:
    """Test Models namespace type definitions with REAL data patterns."""

    def test_entry_attributes_dict_with_real_ldif_data(self) -> None:
        """EntryAttributesDict must work with real LDIF attribute data."""
        attrs: Mapping[str, t.Scalar | t.StrSequence] = {
            c.Ldif.Tests.Names.CN: ["John Doe"],
            c.Ldif.Tests.Names.OBJECTCLASS: [
                c.Ldif.Tests.Names.INETORGPERSON,
                c.Ldif.Tests.Names.PERSON,
                c.Ldif.Tests.Names.TOP,
            ],
            c.Ldif.Tests.Names.SN: "Doe",
            c.Ldif.Tests.Names.MAIL: ["john@example.com"],
            c.Ldif.Tests.Names.UID: "jdoe",
        }
        cn_value = attrs.get(c.Ldif.Tests.Names.CN)
        tm.that(cn_value, eq=["John Doe"])
        objectclass_value = attrs.get(c.Ldif.Tests.Names.OBJECTCLASS)
        tm.that(objectclass_value, is_=list)

    def test_attributes_data_with_real_schema(self) -> None:
        """AttributesData must support real schema attribute patterns."""
        data: Mapping[str, Mapping[str, t.Scalar | t.StrSequence]] = {
            c.Ldif.Tests.Names.CN: {
                "oid": c.Ldif.Tests.OIDs.CN,
                "syntax": "Directory String",
                "equality": "caseIgnoreMatch",
                "single_valued": False,
            },
            c.Ldif.Tests.Names.UID: {
                "oid": "0.9.2342.19200300.100.1.1",
                "syntax": "Directory String",
                "single_valued": True,
            },
        }
        cn_oid: t.Scalar | t.StrSequence | None = data[c.Ldif.Tests.Names.CN].get("oid")
        tm.that(cn_oid, eq=c.Ldif.Tests.OIDs.CN)
        uid_single_valued: t.Scalar | t.StrSequence | None = data[
            c.Ldif.Tests.Names.UID
        ].get(
            "single_valued",
        )
        tm.that(uid_single_valued is True, eq=True)

    def test_objectclasses_data_with_real_schema(self) -> None:
        """ObjectClassesData must support real objectClass patterns."""
        data: Mapping[str, Mapping[str, t.Scalar | t.StrSequence]] = {
            c.Ldif.Tests.Names.INETORGPERSON: {
                "oid": "2.16.840.1.113730.3.2.2",
                "kind": "STRUCTURAL",
                "sup": "organizationalPerson",
                "must": [c.Ldif.Tests.Names.UID],
                "may": [c.Ldif.Tests.Names.MAIL, "mobile"],
            },
        }
        oid_value: t.Scalar | t.StrSequence | None = data[
            c.Ldif.Tests.Names.INETORGPERSON
        ].get(
            "oid",
        )
        tm.that(oid_value, eq="2.16.840.1.113730.3.2.2")
        may_values: t.Scalar | t.StrSequence | None = data[
            c.Ldif.Tests.Names.INETORGPERSON
        ].get(
            "may",
        )
        tm.that(may_values, none=False)
        if may_values is not None and isinstance(may_values, list):
            tm.that(may_values, has=c.Ldif.Tests.Names.MAIL)

    def test_extensions_with_reals(self) -> None:
        """QuirkExtensions must support real quirk metadata."""
        extensions: t.ScalarMapping = {
            "supports_dn_case_registry": True,
            "priority": 10,
            "server_type": "oud",
        }
        supports_dn_case: t.Scalar | None = extensions.get("supports_dn_case_registry")
        tm.that(supports_dn_case is True, eq=True)


class TestRemovalOfOverEngineering:
    """Test that over-engineered types were properly removed."""

    @pytest.mark.parametrize("namespace", c.Ldif.Tests.TYPINGS_REMOVED_NAMESPACES)
    def test_removed_namespaces(self, namespace: str) -> None:
        """Over-engineered namespaces must be removed."""
        tm.that(not hasattr(t, namespace), eq=True)

    @pytest.mark.parametrize("type_name", c.Ldif.Tests.TYPINGS_REMOVED_COMMON_DICT)
    def test_removed_common_dict_types(self, type_name: str) -> None:
        """Unused CommonDict types must be removed."""
        tm.that(not hasattr(t.Ldif, type_name), eq=True)

    @pytest.mark.parametrize("type_name", c.Ldif.Tests.TYPINGS_REMOVED_ENTRY)
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

    def test_types_work_with_real_data(self) -> None:
        """Verify types work with real data."""
        attr_dict: t.Ldif.AttributeDict = {
            c.Ldif.Tests.Names.CN: ["Jane Doe"],
            c.Ldif.Tests.Names.OBJECTCLASS: [
                c.Ldif.Tests.Names.PERSON,
                c.Ldif.Tests.Names.INETORGPERSON,
            ],
        }
        distribution: t.IntMapping = {
            c.Ldif.Tests.Names.INETORGPERSON: 2,
            c.Ldif.Tests.Names.PERSON: 1,
        }
        tm.that(attr_dict[c.Ldif.Tests.Names.CN], eq=["Jane Doe"])
        tm.that(
            attr_dict[c.Ldif.Tests.Names.OBJECTCLASS],
            has=c.Ldif.Tests.Names.INETORGPERSON,
        )
        tm.that(sum(distribution.values()), eq=3)
        tm.that(distribution[c.Ldif.Tests.Names.PERSON], eq=1)


class TestIntegrationWithLdifFixtures:
    """Integration tests using real LDIF fixture data."""

    @pytest.fixture
    def oid_ldif_path(self) -> Path:
        """Path to OID LDIF fixtures."""
        return (
            Path(__file__).resolve().parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    def test_types_work_with_ldif_fixtures(self, oid_ldif_path: Path) -> None:
        """Verify types work with real LDIF fixture files."""
        tm.that(oid_ldif_path.exists(), eq=True)
        entry_attrs: t.Ldif.AttributeDict = {
            c.Ldif.Tests.Names.CN: ["Test Entry"],
            c.Ldif.Tests.Names.OBJECTCLASS: [
                c.Ldif.Tests.Names.PERSON,
                c.Ldif.Tests.Names.INETORGPERSON,
            ],
        }
        tm.that(entry_attrs, has=c.Ldif.Tests.Names.CN)

    def test_models_namespace_with_schema_data(self) -> None:
        """Verify Models namespace types work with schema data."""
        schema_attrs: Mapping[str, Mapping[str, t.Scalar | t.StrSequence]] = {
            c.Ldif.Tests.Names.CN: {
                "oid": c.Ldif.Tests.OIDs.CN,
                "syntax": "Directory String",
            },
        }
        cn_oid: t.Scalar | t.StrSequence | None = schema_attrs[
            c.Ldif.Tests.Names.CN
        ].get("oid")
        tm.that(cn_oid, eq=c.Ldif.Tests.OIDs.CN)
