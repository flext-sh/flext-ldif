from __future__ import annotations

import base64
import dataclasses
from enum import StrEnum
from typing import Final, cast

import pytest
from flext_core import FlextModels
from tests import c, s

# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py

    # ============================================================================
    # Entry Tests
    # ============================================================================

    @pytest.mark.parametrize("test_case", )
                assert result.is_success
                entry = result.unwrap()
                # Type narrowing: entry.dn is not None after successful creation
                assert entry.dn is not None, ACL) with parametrized
    test cases to maximize coverage while minimizing code duplication.
    """

    # ============================================================================
    # Distinguished Name Tests
    # ============================================================================

    @pytest.mark.parametrize("test_case", AclTestCase(
        ModelTestType.ACL_PERMISSIONS, AclTestCase(
        ModelTestType.ACL_SUBJECT, AclTestCase(
        ModelTestType.ACL_UNIFIED, Attributes, AttributesTestCase(
        ModelTestType.ATTRS_EMPTY, AttributesTestCase(
        ModelTestType.ATTRS_EMPTY_VALUES, AttributesTestCase(
        ModelTestType.ATTRS_MISSING, AttributesTestCase(
        ModelTestType.ATTRS_OPERATIONS, DC=Com", DC=Example, DN, DnTestCase(
        ModelTestType.DN_CASE_PRESERVATION, DnTestCase(
        ModelTestType.DN_INVALID_PRESERVED, DnTestCase(
        ModelTestType.DN_LONG, DnTestCase(
        ModelTestType.DN_SPECIAL_CHARS, EntryTestCase(
        ModelTestType.ENTRY_BINARY, EntryTestCase(
        ModelTestType.ENTRY_SERIALIZATION, EntryTestCase(
        ModelTestType.ENTRY_VALIDATION_LENIENT, None, OIDs.CN, OIDs.PERSON, Schema, SchemaTestCase(
        ModelTestType.SCHEMA_ATTRIBUTE, SchemaTestCase(
        ModelTestType.SCHEMA_DISCOVERY, ]


def get_dn_tests() -> list[DnTestCase]:
    """Parametrization helper for DN tests."""
    return DN_TESTS


def get_attributes_tests() -> list[AttributesTestCase]:
    """Parametrization helper for attributes tests."""
    return ATTRIBUTES_TESTS


def get_entry_tests() -> list[EntryTestCase]:
    """Parametrization helper for entry tests."""
    return ENTRY_TESTS


def get_schema_tests() -> list[SchemaTestCase]:
    """Parametrization helper for schema tests."""
    return SCHEMA_TESTS


def get_acl_tests() -> list[AclTestCase]:
    """Parametrization helper for ACL tests."""
    return ACL_TESTS


class TestFlextLdifModels(s):
    """Comprehensive FlextLdifModels test suite.

    Tests all model types (Entry, ]

ACL_TESTS: Final[list[AclTestCase]] = [
    AclTestCase(
        ModelTestType.ACL_TARGET, ]

ATTRIBUTES_TESTS: Final[list[AttributesTestCase]] = [
    AttributesTestCase(
        ModelTestType.ATTRS_CREATION, ]

ENTRY_TESTS: Final[list[EntryTestCase]] = [
    EntryTestCase(
        ModelTestType.ENTRY_CREATION, ]

SCHEMA_TESTS: Final[list[SchemaTestCase]] = [
    SchemaTestCase(
        ModelTestType.SCHEMA_OBJECTCLASS, access directly
                # Access the computed field value
                components_list = dn.components
                assert isinstance(components_list, acl_name="test_acl", acl_server_type="oracle_oud", and serialization."""
        match test_case.test_type:
            case ModelTestType.ENTRY_CREATION:
                attrs_dict: dict[str, attr_name="missing", attr_name=c.Names.CN, attr_value)
                retrieved = attrs.get(test_case.attr_name or "")
                assert isinstance(retrieved, attr_value=c.Values.TEST, attributes=[c.Names.CN, attributes=attrs_dict, attributes={
            c.Names.OBJECTCLASS: [c.Names.INET_ORG_PERSON], attributes={
            c.Names.OBJECTCLASS: [c.Names.PERSON], attributes={c.Names.CN: [""], attributes={c.Names.CN: [c.Values.TEST], attributes={c.Names.OBJECTCLASS: [c.Names.PERSON]}, attributes={}, c, c.DNs.TEST_USER, c.Names.CN, c.Names.CN: [c.Values.TEST], c.Names.PERSON, c.Names.SN: []}, c.Names.SN: [c.Values.TEST], c.Names.SN: [c.Values.USER]}, c.Names.SN], dc=com", dc=example, description="Allow empty DN in lenient mode", description="Create ACL permissions", description="Create ACL subject", description="Create ACL target", description="Create attributes from dict", description="Create empty attributes", description="Create entry with attributes", description="Create entry with binary data", description="Create simple DN", description="Create unified ACL", description="Get non-existent attribute returns empty", description="Handle empty attribute values", description="Handle special characters in DN", description="Handle very long DN", description="Preserve DN case", description="Preserve invalid DN format", description="SchemaDiscoveryResult creation", description="Serialize entry to dict", description="Test add/get/remove operations", description="Validate entry lenient", dn="", dn=c.DNs.TEST_USER, expected_result=[], get_attributes_tests())
    def test_attributes_models(self, get_dn_tests())
    def test_dn_models(self, get_entry_tests())
    def test_entry_models(self, has_binary=True, list)
                assert len(components_list) == 3
            case ModelTestType.DN_CASE_PRESERVATION:
                assert dn.value == test_case.dn_value
            case ModelTestType.DN_INVALID_PRESERVED:
                assert dn.value == test_case.dn_value
            case ModelTestType.DN_SPECIAL_CHARS:
                assert "\+" in dn.value
            case ModelTestType.DN_LONG:
                assert len(dn.value) > 2048

    # ============================================================================
    # LdifAttributes Tests
    # ============================================================================

    @pytest.mark.parametrize("test_case", list)
                assert len(retrieved) > 0
                attrs.remove_attribute(test_case.attr_name or "")
                assert (test_case.attr_name or "") not in attrs.attributes

            case ModelTestType.ATTRS_MISSING:
                attrs = m.LdifAttributes(attributes={})
                values = attrs.get(test_case.attr_name or "missing")
                assert values == []

            case ModelTestType.ATTRS_EMPTY_VALUES:
                attrs = m.LdifAttributes(
                    attributes={c.Names.CN: [""], list[str]] | None = None
    attr_name: str | None = None
    attr_value: str | list[str] | None = None
    expected_result: list[str] | None = None
    description: str = ""


@dataclasses.dataclass(frozen=True)
class EntryTestCase:
    """Entry model test case."""

    test_type: ModelTestType
    dn: str
    attributes: dict[str, list[str]] | None = None
    should_succeed: bool = True
    has_binary: bool = False
    description: str = ""


@dataclasses.dataclass(frozen=True)
class SchemaTestCase:
    """Schema model test case."""

    test_type: ModelTestType
    name: str | None = None
    oid: str | None = None
    description: str = ""


@dataclasses.dataclass(frozen=True)
class AclTestCase:
    """ACL model test case."""

    test_type: ModelTestType
    target_dn: str | None = None
    attributes: list[str] | None = None
    subject_type: str | None = None
    subject_value: str | None = None
    permissions_read: bool = False
    permissions_write: bool = False
    permissions_search: bool = False
    acl_name: str | None = None
    acl_server_type: str | None = None
    description: str = ""


# Test case definitions
DN_TESTS: Final[list[DnTestCase]] = [
    DnTestCase(
        ModelTestType.DN_CREATION, m

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)
from flext_ldif import FlextLdifConstants
from flext_ldif.models import m


class ModelTestType(StrEnum):
    """Types of model tests."""

    DN_CREATION = "dn_creation"
    DN_CASE_PRESERVATION = "dn_case_preservation"
    DN_INVALID_PRESERVED = "dn_invalid_preserved"
    DN_SPECIAL_CHARS = "dn_special_chars"
    DN_LONG = "dn_long"
    ATTRS_CREATION = "attrs_creation"
    ATTRS_EMPTY = "attrs_empty"
    ATTRS_OPERATIONS = "attrs_operations"
    ATTRS_MISSING = "attrs_missing"
    ATTRS_EMPTY_VALUES = "attrs_empty_values"
    ENTRY_CREATION = "entry_creation"
    ENTRY_BINARY = "entry_binary"
    ENTRY_SERIALIZATION = "entry_serialization"
    ENTRY_VALIDATION_LENIENT = "entry_validation_lenient"
    SCHEMA_OBJECTCLASS = "schema_objectclass"
    SCHEMA_ATTRIBUTE = "schema_attribute"
    SCHEMA_DISCOVERY = "schema_discovery"
    ACL_TARGET = "acl_target"
    ACL_SUBJECT = "acl_subject"
    ACL_PERMISSIONS = "acl_permissions"
    ACL_UNIFIED = "acl_unified"
    NAMESPACE_INHERITANCE = "namespace_inheritance"
    NAMESPACE_ACCESS = "namespace_access"


@dataclasses.dataclass(frozen=True)
class DnTestCase:
    """DN model test case."""

    test_type: ModelTestType
    dn_value: str
    expected_value: str | None = None
    should_succeed: bool = True
    description: str = ""


@dataclasses.dataclass(frozen=True)
class AttributesTestCase:
    """LdifAttributes model test case."""

    test_type: ModelTestType
    attributes: dict[str, permissions_read=True, permissions_search=True, permissions_write=True, str | list[str]] = {}
                if test_case.attributes:
                    attrs.update(test_case.attributes)
                attrs["userCertificate, str | list[str]] = {}
                if test_case.attributes:
                    attrs_dict.update(test_case.attributes)
                result = m.Entry.create(
                    dn=test_case.dn, subject_type="user", subject_value=f"cn={c.Values.ADMIN}, target_dn=c.DNs.EXAMPLE, test_case: AttributesTestCase) -> None:
        """Test LdifAttributes model creation and operations."""
        match test_case.test_type:
            case ModelTestType.ATTRS_CREATION:
                attrs_data = test_case.attributes or {}
                result = m.LdifAttributes.create(attrs_data)
                assert result.is_success
                attrs = result.unwrap()
                assert c.Names.CN in attrs.attributes
                assert attrs.attributes[c.Names.CN] == [c.Values.TEST]

            case ModelTestType.ATTRS_EMPTY:
                result = m.LdifAttributes.create({})
                assert result.is_success
                attrs = result.unwrap()
                assert attrs.attributes == {}

            case ModelTestType.ATTRS_OPERATIONS:
                attrs = m.LdifAttributes(attributes={})
                attr_name = test_case.attr_name or ""
                attr_value = test_case.attr_value or ""
                attrs.add_attribute(attr_name, test_case: DnTestCase) -> None:
        """Test DN model creation and behavior."""
        dn = m.DistinguishedName(value=test_case.dn_value)

        # Basic creation check
        assert dn.value == test_case.dn_value

        # Type-specific validations
        match test_case.test_type:
            case ModelTestType.DN_CREATION:
                # components is a @computed_field property, test_case: EntryTestCase) -> None:
        """Test Entry model creation, validation, {c.DNs.EXAMPLE}", };binary"] = [encoded_data]
                result = m.Entry.create(
                    dn=test_case.dn,
                    attributes=attrs,
                )
                assert result.is_success
                entry = result.unwrap()
                # Type narrowing: entry.attributes is not None after successful creation
                assert entry.attributes is not None, "Entry must have attributes"
                assert "userCertificate;binary" in entry.attributes.attributes

            case ModelTestType.ENTRY_SERIALIZATION:
                entry = s.create_user_entry(c.Values.TEST)
                data = entry.model_dump()
                assert isinstance(data, dict)
                assert "dn" in data
                assert "attributes" in data

            case ModelTestType.ENTRY_VALIDATION_LENIENT:
                attrs_dict_lenient: dict[str, str | list[str]] = {}
                if test_case.attributes:
                    attrs_dict_lenient.update(test_case.attributes)
                result = m.Entry.create(
                    dn=test_case.dn,
                    attributes=attrs_dict_lenient,
                )
                assert result.is_success

    # ============================================================================
    # Schema Tests
    # ============================================================================

    def test_schema_objectclass(self) -> None:
        """Test SchemaObjectClass creation."""
        oc = m.SchemaObjectClass(
            name=c.Names.PERSON,
            oid=OIDs.PERSON,
            desc="Person object class",
            sup=None,
            must=["cn", "sn"],
            may=["telephoneNumber", "seeAlso"],
            kind="STRUCTURAL",
        )
        assert oc.name == c.Names.PERSON
        assert oc.oid == OIDs.PERSON
        assert oc.is_structural is True

    def test_schema_attribute(self) -> None:
        """Test SchemaAttribute creation."""
        attr = m.SchemaAttribute(
            name=c.Names.CN,
            oid=OIDs.CN,
            desc="Common name attribute",
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            syntax=OIDs.DIRECTORY_STRING,
            length=None,
            usage=None,
        )
        assert attr.name == c.Names.CN
        assert attr.oid == OIDs.CN
        assert attr.syntax == OIDs.DIRECTORY_STRING

    def test_schema_discovery_result(self) -> None:
        """Test SchemaDiscoveryResult creation."""
        # Create SchemaObjectClassMap and SchemaAttributeMap instances
        # These classes extend DynamicMetadata which accepts dict via extra="allow"
        objectclasses_map = m.SchemaObjectClassMap.model_validate({
            c.Names.PERSON: {
                "oid": OIDs.PERSON,
                "description": "Person class",
            },
        })
        attributes_map = m.SchemaAttributeMap.model_validate({
            c.Names.CN: {
                "oid": OIDs.CN,
                "description": "Common name",
                "syntax": OIDs.DIRECTORY_STRING,
            },
        })
        result = m.SchemaDiscoveryResult(
            objectclasses=objectclasses_map,
            attributes=attributes_map,
            total_attributes=1,
            total_objectclasses=1,
        )
        assert len(result.objectclasses) == 1
        assert len(result.attributes) == 1
        assert result.total_attributes == 1
        assert result.total_objectclasses == 1

    # ============================================================================
    # ACL Tests
    # ============================================================================

    @pytest.mark.parametrize("test_case", get_acl_tests())
    def test_acl_models(self, test_case: AclTestCase) -> None:
        """Test ACL model creation and composition."""
        match test_case.test_type:
            case ModelTestType.ACL_TARGET:
                target = m.AclTarget(
                    target_dn=test_case.target_dn or "",
                    attributes=test_case.attributes or [],
                )
                assert target.target_dn == test_case.target_dn
                assert target.attributes == test_case.attributes

            case ModelTestType.ACL_SUBJECT:
                # Type narrowing: cast str to AclSubjectTypeLiteral
                subject_type_str = test_case.subject_type or "user"
                subject_type_literal = cast(
                    "FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral",
                    subject_type_str,
                )
                subject = m.AclSubject(
                    subject_type=subject_type_literal,
                    subject_value=test_case.subject_value or "",
                )
                assert subject.subject_type == test_case.subject_type
                if test_case.subject_value:
                    assert test_case.subject_value in subject.subject_value

            case ModelTestType.ACL_PERMISSIONS:
                perms = m.AclPermissions(
                    read=test_case.permissions_read,
                    write=test_case.permissions_write,
                    search=test_case.permissions_search,
                )
                assert perms.read is test_case.permissions_read
                assert perms.write is test_case.permissions_write
                assert perms.search is test_case.permissions_search

            case ModelTestType.ACL_UNIFIED:
                target = m.AclTarget(
                    target_dn=test_case.target_dn or "",
                    attributes=test_case.attributes or [],
                )
                # Type narrowing: cast str to AclSubjectTypeLiteral
                subject_type_str = test_case.subject_type or "user"
                subject_type_literal = cast(
                    "FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral",
                    subject_type_str,
                )
                subject = m.AclSubject(
                    subject_type=subject_type_literal,
                    subject_value=test_case.subject_value or "",
                )
                permissions = m.AclPermissions(
                    read=test_case.permissions_read,
                    write=test_case.permissions_write,
                )
                # Normalize and cast server_type to ServerTypeLiteral
                server_type_str = test_case.acl_server_type or "oracle_oud"
                normalized_server_type = FlextLdifConstants.normalize_server_type(
                    server_type_str
                )
                server_type_literal = normalized_server_type
                acl = m.Acl(
                    name=test_case.acl_name or "",
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type=server_type_literal,
                )
                assert isinstance(acl, m.Acl)
                assert acl.name == test_case.acl_name
                # Compare with normalized server_type (normalize_server_type handles aliases)
                assert acl.server_type == normalized_server_type

    # ============================================================================
    # Namespace and Inheritance Tests
    # ============================================================================

    def test_model_inheritance(self) -> None:
        """Test that models properly inherit from FlextModels."""
        assert issubclass(m, FlextModels)

    def test_namespace_access(self) -> None:
        """Test namespace has all expected models."""
        expected_models = [
            "Entry",
            "DistinguishedName",
            "LdifAttributes",
            "SchemaObjectClass",
            "SchemaAttribute",
            "SchemaDiscoveryResult",
            "AclTarget",
            "AclSubject",
            "AclPermissions",
            "Acl",
        ]
        for model_name in expected_models:
            assert hasattr(m, model_name), f"FlextLdifModels missing {model_name}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
