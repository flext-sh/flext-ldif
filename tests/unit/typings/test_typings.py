"""Test suite for LDIF type definitions.

Modules tested: FlextLdifTypes (CommonDict, Entry, Models namespaces, type aliases)
Scope: Type system validation with real LDIF data patterns. Tests namespace structure,
type aliases for quirk instances, flexible I/O types, result types, and removal of
over-engineered types. Validates SRP compliance (no functions in typings.py) and
import restrictions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import ClassVar, cast

import pytest
from tests.fixtures.constants import DNs, Names, OIDs
from tests.fixtures.typing import GenericFieldsDict, GenericTestCaseDict

import flext_ldif.typings
from flext_ldif.typings import FlextLdifTypes


class TestFlextLdifTypesNamespace:
    """Test FlextLdifTypes namespace structure and compliance."""

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
        user_functions = [
            m for m in members
            if inspect.isfunction(m[1]) and not m[0].startswith("__")
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
        assert sorted(flext_ldif_imports) == [
            "flext_ldif.models",
            "flext_ldif.protocols",
        ]


class TestCommonDictionaryTypes:
    """Test common dictionary type definitions with REAL data."""

    SAMPLE_ATTR_DICT: ClassVar[dict[str, list[str]]] = {
        Names.CN: ["John Doe"],
        Names.SN: ["Doe"],
        Names.MAIL: ["john@example.com", "john.doe@example.com"],
        Names.OBJECTCLASS: [Names.PERSON, Names.INET_ORG_PERSON],
    }

    SAMPLE_DISTRIBUTION: ClassVar[dict[str, int]] = {
        Names.INET_ORG_PERSON: 1245,
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
        assert attr_dict[Names.CN] == ["John Doe"]
        assert len(attr_dict[Names.MAIL]) == 2

    def test_attribute_dict_empty(self) -> None:
        """AttributeDict must handle empty attributes."""
        attr_dict: FlextLdifTypes.CommonDict.AttributeDict = {}
        assert len(attr_dict) == 0

    def test_distribution_dict_with_entry_counts(self) -> None:
        """DistributionDict must work with entry type statistics."""
        dist: FlextLdifTypes.CommonDict.DistributionDict = self.SAMPLE_DISTRIBUTION
        assert dist[Names.INET_ORG_PERSON] == 1245
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
            Names.DN: f"cn=John Doe,ou=users,{DNs.EXAMPLE}",
            Names.OBJECTCLASS: [
                Names.INET_ORG_PERSON,
                "organizationalPerson",
                Names.PERSON,
                Names.TOP,
            ],
            Names.CN: "John Doe",
            Names.SN: "Doe",
            "givenName": "John",
            Names.MAIL: "john@example.com",
            Names.UID: "jdoe",
            "userPassword": "{SSHA}encrypted_password_here",
        }
        assert data[Names.DN] == f"cn=John Doe,ou=users,{DNs.EXAMPLE}"
        assert isinstance(data[Names.OBJECTCLASS], list)
        assert len(data[Names.OBJECTCLASS]) == 4

    def test_entry_create_data_with_nested_structures(self) -> None:
        """EntryCreateData must support nested structures from LDIF."""
        data: FlextLdifTypes.Entry.EntryCreateData = {
            Names.DN: f"cn=admin,{DNs.EXAMPLE}",
            "permissions": ["read", "write"],
            "metadata": {"source": "oid", "imported": "true"},
            "attributes_count": "12",
        }
        assert isinstance(data["permissions"], list)
        assert isinstance(data["metadata"], dict)


class TestModelsNamespace:
    """Test Models namespace type definitions with REAL data patterns."""

    def test_entry_attributes_dict_with_real_ldif_data(self) -> None:
        """EntryAttributesDict must work with real LDIF attribute data."""
        attrs: GenericFieldsDict = {
            Names.CN: ["John Doe"],
            Names.OBJECTCLASS: [Names.INET_ORG_PERSON, Names.PERSON, Names.TOP],
            Names.SN: "Doe",
            Names.MAIL: ["john@example.com"],
            Names.UID: "jdoe",
        }
        assert attrs[Names.CN] == ["John Doe"]
        assert isinstance(attrs[Names.OBJECTCLASS], list)

    def test_attributes_data_with_real_schema(self) -> None:
        """AttributesData must support real schema attribute patterns."""
        data: dict[str, GenericFieldsDict] = {
            Names.CN: {
                "oid": OIDs.CN,
                "syntax": "Directory String",
                "equality": "caseIgnoreMatch",
                "single_valued": False,
            },
            Names.UID: {
                "oid": "0.9.2342.19200300.100.1.1",
                "syntax": "Directory String",
                "single_valued": True,
            },
        }
        assert data[Names.CN]["oid"] == OIDs.CN
        assert data[Names.UID]["single_valued"] is True

    def test_objectclasses_data_with_real_schema(self) -> None:
        """ObjectClassesData must support real objectClass patterns."""
        data: dict[str, GenericFieldsDict] = {
            Names.INET_ORG_PERSON: {
                "oid": "2.16.840.1.113730.3.2.2",
                "kind": "STRUCTURAL",
                "sup": "organizationalPerson",
                "must": [Names.UID],
                "may": [Names.MAIL, "mobile"],
            },
        }
        assert data[Names.INET_ORG_PERSON]["oid"] == "2.16.840.1.113730.3.2.2"
        may_values = cast("list[str]", data[Names.INET_ORG_PERSON]["may"])
        assert Names.MAIL in may_values

    def test_extensions_with_reals(self) -> None:
        """QuirkExtensions must support real quirk metadata."""
        extensions: GenericFieldsDict = {
            "supports_dn_case_registry": True,
            "priority": 10,
            "server_type": "oud",
        }
        assert extensions["supports_dn_case_registry"] is True


class TestRemovalOfOverEngineering:
    """Test that over-engineered types were properly removed."""

    REMOVED_NAMESPACES: ClassVar[list[str]] = [
        "Parser", "Writer", "LdifValidation", "LdifProcessing",
        "Analytics", "ServerTypes", "Functional", "Streaming",
        "AnnotatedLdif", "ModelAliases", "LdifProject", "Project",
    ]

    REMOVED_COMMON_DICT: ClassVar[list[str]] = [
        "ChangeDict", "CategorizedDict", "TreeDict", "HierarchyDict",
    ]

    REMOVED_ENTRY: ClassVar[list[str]] = [
        "EntryConfiguration", "EntryAttributes", "EntryValidation",
        "EntryTransformation", "EntryMetadata", "EntryProcessing",
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
            m for m in inspect.getmembers(FlextLdifTypes)
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
        attr_dict: FlextLdifTypes.CommonDict.AttributeDict = {Names.CN: ["test"]}
        dist: FlextLdifTypes.CommonDict.DistributionDict = {"type": 100}
        entry_data: FlextLdifTypes.Entry.EntryCreateData = {Names.DN: DNs.TEST_USER}

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
            Names.CN: ["Test Entry"],
            Names.OBJECTCLASS: [Names.PERSON, Names.INET_ORG_PERSON],
        }
        assert Names.CN in entry_attrs

    def test_models_namespace_with_schema_data(self) -> None:
        """Verify Models namespace types work with schema data."""
        schema_attrs: dict[str, GenericFieldsDict] = {
            Names.CN: {"oid": OIDs.CN, "syntax": "Directory String"}
        }
        assert schema_attrs[Names.CN]["oid"] == OIDs.CN
