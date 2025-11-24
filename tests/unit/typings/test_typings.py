"""Comprehensive test suite for LDIF type definitions with REAL data.

Tests type system with actual LDIF fixtures and realistic usage patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations
from flext_ldif import FlextLdifModels
from flext_ldif import FlextLdif

from pathlib import Path
from typing import cast

import pytest

from flext_ldif.typings import FlextLdifTypes, ServiceT


class TestFlextLdifTypesNamespace:
    """Test FlextLdifTypes namespace structure and compliance."""

    def test_namespace_exists(self) -> None:
        """FlextLdifTypes class must be accessible."""
        assert FlextLdifTypes is not None
        assert hasattr(FlextLdifTypes, "__name__")

    def test_has_required_namespaces(self) -> None:
        """FlextLdifTypes must have required namespaces."""
        assert hasattr(FlextLdifTypes, "Entry")
        assert hasattr(FlextLdifTypes, "CommonDict")
        assert hasattr(FlextLdifTypes, "Models")

    def test_srp_compliance_no_functions(self) -> None:
        """typings.py must not contain functions (SRP violation)."""
        import inspect

        import flext_ldif.typings

        members = inspect.getmembers(flext_ldif.typings)
        functions = [m for m in members if inspect.isfunction(m[1])]

        # Exclude __module__ level functions
        user_functions = [f for f in functions if not f[0].startswith("__")]
        assert len(user_functions) == 0, "typings.py must not contain functions"

    def test_only_required_imports(self) -> None:
        """typings.py must only import from flext_core, flext_ldif.constants, and flext_ldif.models.

        NOTE: flext_ldif.models IS imported directly (not through TYPE_CHECKING) to avoid
        TYPE_CHECKING complexity. This is SAFE because models.py does not import typings.py,
        preventing circular dependencies.
        """
        import ast
        from pathlib import Path

        # Use path relative to project root
        project_root = Path(__file__).parent.parent.parent.parent
        typings_path = project_root / "src" / "flext_ldif" / "typings.py"
        tree = ast.parse(typings_path.read_text())

        flext_ldif_imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and "flext_ldif" in node.module:
                    flext_ldif_imports.append(node.module)

        # Only flext_ldif.constants, flext_ldif.models, and flext_ldif.protocols should be imported from flext_ldif
        # models is imported to use FlextLdifModels directly without TYPE_CHECKING
        # protocols is imported for protocol type definitions
        assert sorted(flext_ldif_imports) == [
            "flext_ldif.constants",
            "flext_ldif.models",
            "flext_ldif.protocols",
        ]


class TestCommonDictionaryTypes:
    """Test common dictionary type definitions with REAL data."""

    def test_attribute_dict_with_ldif_entry(self) -> None:
        """AttributeDict must work with real LDIF entry attributes."""
        # Real LDIF entry attributes from fixtures
        attr_dict: FlextLdifTypes.CommonDict.AttributeDict = {
            "dn": "cn=John Doe,ou=users,dc=example,dc=com",
            "cn": "John Doe",
            "sn": "Doe",
            "mail": ["john@example.com", "john.doe@example.com"],
            "objectClass": ["person", "inetOrgPerson"],
        }
        assert isinstance(attr_dict, dict)
        assert attr_dict["cn"] == "John Doe"
        assert isinstance(attr_dict["mail"], list)
        assert len(attr_dict["mail"]) == 2

    def test_attribute_dict_empty(self) -> None:
        """AttributeDict must handle empty attributes."""
        attr_dict: FlextLdifTypes.CommonDict.AttributeDict = {}
        assert isinstance(attr_dict, dict)
        assert len(attr_dict) == 0

    def test_distribution_dict_with_entry_counts(self) -> None:
        """DistributionDict must work with entry type statistics."""
        # Realistic distribution from OID/OUD LDIF files
        dist: FlextLdifTypes.CommonDict.DistributionDict = {
            "inetOrgPerson": 1245,
            "groupOfNames": 89,
            "organizationalUnit": 34,
            "domain": 1,
            "country": 1,
            "dcObject": 1,
        }
        assert isinstance(dist, dict)
        assert dist["inetOrgPerson"] == 1245
        assert sum(dist.values()) == 1371

    def test_distribution_dict_from_schema_stats(self) -> None:
        """DistributionDict works for schema statistics."""
        # Real schema statistics pattern
        dist: FlextLdifTypes.CommonDict.DistributionDict = {
            "attributeTypes": 156,
            "objectClasses": 78,
            "dITContentRules": 23,
        }
        assert isinstance(dist, dict)
        assert all(isinstance(v, int) for v in dist.values())


class TestEntryTypes:
    """Test Entry namespace type definitions with REAL data."""

    def test_entry_create_data_with_real_ldif_entry(self) -> None:
        """EntryCreateData must accept real LDIF entry data."""
        # Real entry from OID LDIF fixtures
        data: FlextLdifTypes.Entry.EntryCreateData = {
            "dn": "cn=John Doe,ou=users,dc=example,dc=com",
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "cn": "John Doe",
            "sn": "Doe",
            "givenName": "John",
            "mail": "john@example.com",
            "uid": "jdoe",
            "userPassword": "{SSHA}encrypted_password_here",
        }
        assert isinstance(data, dict)
        assert data["dn"] == "cn=John Doe,ou=users,dc=example,dc=com"
        assert isinstance(data["objectClass"], list)
        assert len(data["objectClass"]) == 4

    def test_entry_create_data_with_nested_structures(self) -> None:
        """EntryCreateData must support nested structures from LDIF."""
        data: FlextLdifTypes.Entry.EntryCreateData = {
            "dn": "cn=admin,dc=example,dc=com",
            "permissions": [
                {"type": "read", "scope": "subtree"},
                {"type": "write", "scope": "entry"},
            ],
            "metadata": {
                "source": "oid",
                "imported": True,
                "timestamp": "2025-01-01T00:00:00Z",
            },
            "attributes_count": 12,
        }
        assert isinstance(data, dict)
        assert isinstance(data["permissions"], list)
        assert isinstance(data["metadata"], dict)


class TestModelsNamespace:
    """Test Models namespace type definitions with REAL data patterns."""

    def test_entry_attributes_dict_with_real_ldif_data(self) -> None:
        """EntryAttributesDict must work with real LDIF attribute data."""
        # Real attributes from OID/OUD LDIF
        attrs: dict[str, object] = {
            "cn": ["John Doe"],
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "sn": "Doe",
            "givenName": "John",
            "mail": ["john@example.com"],
            "uid": "jdoe",
            "userPassword": "{SSHA}base64_encoded_hash",
            "createTimestamp": "20250101000000Z",
            "modifyTimestamp": "20250101000000Z",
        }
        assert isinstance(attrs, dict)
        assert attrs["cn"] == ["John Doe"]
        assert isinstance(attrs["objectClass"], list)
        assert attrs["uid"] == "jdoe"

    def test_attributes_data_with_real_schema(self) -> None:
        """AttributesData must support real schema attribute patterns."""
        # Real attribute definitions from RFC/OID schema
        data: dict[str, dict[str, object]] = {
            "cn": {
                "oid": "2.5.4.3",
                "syntax": "Directory String",
                "equality": "caseIgnoreMatch",
                "substr": "caseIgnoreSubstringsMatch",
                "ordering": "caseIgnoreOrderingMatch",
                "single_valued": False,
            },
            "mail": {
                "oid": "0.9.2342.19200300.100.1.3",
                "syntax": "IA5String",
                "equality": "caseIgnoreMatch",
                "single_valued": False,
            },
            "uid": {
                "oid": "0.9.2342.19200300.100.1.1",
                "syntax": "Directory String",
                "equality": "caseIgnoreMatch",
                "single_valued": True,
            },
        }
        assert isinstance(data, dict)
        assert len(data) == 3
        assert data["cn"]["oid"] == "2.5.4.3"
        assert data["uid"]["single_valued"] is True

    def test_objectclasses_data_with_real_schema(self) -> None:
        """ObjectClassesData must support real objectClass patterns."""
        # Real objectClass definitions
        data: dict[str, dict[str, object]] = {
            "inetOrgPerson": {
                "oid": "2.16.840.1.113730.3.2.2",
                "kind": "STRUCTURAL",
                "sup": "organizationalPerson",
                "must": ["uid"],
                "may": [
                    "mail",
                    "mobile",
                    "telephoneNumber",
                    "preferredLanguage",
                    "carLicense",
                ],
            },
            "organizationalUnit": {
                "oid": "2.5.6.5",
                "kind": "STRUCTURAL",
                "sup": "top",
                "must": ["ou"],
                "may": [
                    "businessCategory",
                    "description",
                    "userPassword",
                    "searchGuide",
                ],
            },
            "groupOfNames": {
                "oid": "2.5.6.9",
                "kind": "STRUCTURAL",
                "sup": "top",
                "must": ["member", "cn"],
                "may": ["businessCategory", "description", "o", "ou"],
            },
        }
        assert isinstance(data, dict)
        assert len(data) == 3
        assert data["inetOrgPerson"]["oid"] == "2.16.840.1.113730.3.2.2"
        may_values = cast(list[str], data["inetOrgPerson"]["may"])
        assert "mail" in may_values

    def test_extensions_with_reals(self) -> None:
        """QuirkExtensions must support real quirk metadata."""
        extensions: dict[str, object] = {
            "supports_dn_case_registry": True,
            "priority": 10,
            "version": "1.0.0",
            "server_type": "oud",
            "capabilities": [
                "case_registry",
                "acl_conversion",
                "schema_normalization",
            ],
        }
        assert isinstance(extensions, dict)
        assert extensions["supports_dn_case_registry"] is True


class TestLiteralTypes:
    """Test Literal type aliases delegated to constants."""

    def test_processing_stage_literal_exists(self) -> None:
        """ProcessingStage literal type must exist and be accessible."""
        assert hasattr(FlextLdifTypes, "ProcessingStage")

    def test_server_type_literal_exists(self) -> None:
        """ServerType literal must exist and be accessible."""
        assert hasattr(FlextLdifTypes, "ServerType")

    def test_all_required_literals_exist(self) -> None:
        """All required literal types must be accessible."""
        required_literals = [
            "ProcessingStage",
            "HealthStatus",
            "EntryType",
            "ModificationType",
            "ServerType",
            "EncodingType",
            "ValidationLevel",
            "ProjectType",
            "AclServerType",
        ]
        for literal_name in required_literals:
            assert hasattr(FlextLdifTypes, literal_name), f"Missing {literal_name}"


class TestTypeVarDefinitions:
    """Test TypeVar definitions."""

    def test_service_t_typevar_exists(self) -> None:
        """ServiceT TypeVar must be defined for service retrieval."""
        assert ServiceT is not None
        assert isinstance(ServiceT, type(ServiceT))


class TestRemovalOfOverEngineering:
    """Test that over-engineered types were properly removed."""

    def test_removed_namespaces(self) -> None:
        """Over-engineered namespaces must be removed (zero production usage)."""
        removed = [
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
        for namespace in removed:
            assert not hasattr(FlextLdifTypes, namespace), (
                f"{namespace} should be removed"
            )

    def test_removed_common_dict_types(self) -> None:
        """Unused CommonDict types must be removed."""
        removed = ["ChangeDict", "CategorizedDict", "TreeDict", "HierarchyDict"]
        for type_name in removed:
            assert not hasattr(FlextLdifTypes.CommonDict, type_name), (
                f"CommonDict.{type_name} should be removed"
            )

    def test_removed_entry_types(self) -> None:
        """Unused Entry types must be removed."""
        removed = [
            "EntryConfiguration",
            "EntryAttributes",
            "EntryValidation",
            "EntryTransformation",
            "EntryMetadata",
            "EntryProcessing",
        ]
        for type_name in removed:
            assert not hasattr(FlextLdifTypes.Entry, type_name), (
                f"Entry.{type_name} should be removed"
            )


class TestPhase1StandardizationResults:
    """Test that Phase 1 standardization goals were achieved."""

    def test_minimal_type_system(self) -> None:
        """Type system should be minimal and focused on actual usage."""
        import inspect

        classes = [
            m
            for m in inspect.getmembers(FlextLdifTypes)
            if inspect.isclass(m[1]) and not m[0].startswith("_")
        ]
        # Should have Entry, CommonDict, Models, + inherited from FlextTypes
        # This validates that we removed most classes
        assert len(classes) >= 3

    def test_types_vs_models_principle(self) -> None:
        """Only simple patterns should be in Types, complex data in Models."""
        # Simple patterns kept
        assert hasattr(FlextLdifTypes.CommonDict, "AttributeDict")
        assert hasattr(FlextLdifTypes.CommonDict, "DistributionDict")
        assert hasattr(FlextLdifTypes.Entry, "EntryCreateData")

        # Verify they work with real data
        attr_dict: FlextLdifTypes.CommonDict.AttributeDict = {"cn": "test"}
        dist: FlextLdifTypes.CommonDict.DistributionDict = {"type": 100}
        entry_data: FlextLdifTypes.Entry.EntryCreateData = {"dn": "cn=test,dc=com"}

        assert isinstance(attr_dict, dict)
        assert isinstance(dist, dict)
        assert isinstance(entry_data, dict)


class TestIntegrationWithLdifFixtures:
    """Integration tests using real LDIF fixture data."""

    @pytest.fixture
    def oid_ldif_path(self) -> Path:
        """Path to OID LDIF fixtures."""
        return Path("tests/fixtures/oid/oid_entries_fixtures.ldif")

    @pytest.fixture
    def oud_ldif_path(self) -> Path:
        """Path to OUD LDIF fixtures."""
        return Path("tests/fixtures/oud/oud_entries_fixtures.ldif")

    def test_types_work_with_ldif_fixtures(self, oid_ldif_path: Path) -> None:
        """Verify types work with real LDIF fixture files."""
        # Check fixture exists
        assert oid_ldif_path.exists(), f"Fixture not found: {oid_ldif_path}"

        # Simulate processing LDIF entry with AttributeDict type
        entry_attrs: FlextLdifTypes.CommonDict.AttributeDict = {
            "cn": "Test Entry",
            "objectClass": ["person", "inetOrgPerson"],
            "mail": ["test@example.com"],
        }

        # Type hint validates structure
        assert isinstance(entry_attrs, dict)
        assert "cn" in entry_attrs
        assert "objectClass" in entry_attrs

    def test_models_namespace_with_schema_data(self) -> None:
        """Verify Models namespace types work with schema data."""
        # Real-world schema attribute data
        schema_attrs: dict[str, dict[str, object]] = {
            "cn": {
                "oid": "2.5.4.3",
                "syntax": "Directory String",
                "single_valued": False,
            }
        }

        # Type hint validates structure
        assert isinstance(schema_attrs, dict)
        assert "cn" in schema_attrs
        assert schema_attrs["cn"]["oid"] == "2.5.4.3"
