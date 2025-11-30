"""Test suite for FlextLdifModels.

Modules tested: FlextLdifModels (Entry, DistinguishedName, LdifAttributes,
SchemaObjectClass, SchemaAttribute, SchemaDiscoveryResult, AclTarget, AclSubject,
AclPermissions, Acl)
Scope: Model validation, creation, serialization, inheritance, edge cases,
schema operations

Uses advanced Python 3.13 patterns: StrEnum, frozen dataclasses, parametrized tests,
and factory patterns to reduce code by 60%+ while maintaining comprehensive coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import dataclasses
from enum import StrEnum
from typing import Final

import pytest
from flext_core import FlextModels

# from flext_tests import FlextTestsFactories  # Mocked in conftest
from tests.fixtures.constants import DNs, Names, OIDs, Values
from tests.helpers.test_factories import FlextLdifTestFactories

from flext_ldif import FlextLdifModels


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
    attributes: dict[str, list[str]] | None = None
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
        ModelTestType.DN_CREATION,
        DNs.TEST_USER,
        DNs.TEST_USER,
        description="Create simple DN",
    ),
    DnTestCase(
        ModelTestType.DN_CASE_PRESERVATION,
        "CN=Test,DC=Example,DC=Com",
        "CN=Test,DC=Example,DC=Com",
        description="Preserve DN case",
    ),
    DnTestCase(
        ModelTestType.DN_INVALID_PRESERVED,
        "invalid-dn-format",
        "invalid-dn-format",
        description="Preserve invalid DN format",
    ),
    DnTestCase(
        ModelTestType.DN_SPECIAL_CHARS,
        "cn=test\\+user,dc=example,dc=com",
        "cn=test\\+user,dc=example,dc=com",
        description="Handle special characters in DN",
    ),
    DnTestCase(
        ModelTestType.DN_LONG,
        "cn=" + "x" * 2048 + ",dc=example,dc=com",
        None,
        description="Handle very long DN",
    ),
]

ATTRIBUTES_TESTS: Final[list[AttributesTestCase]] = [
    AttributesTestCase(
        ModelTestType.ATTRS_CREATION,
        attributes={Names.CN: [Values.TEST], Names.SN: [Values.USER]},
        description="Create attributes from dict",
    ),
    AttributesTestCase(
        ModelTestType.ATTRS_EMPTY,
        attributes={},
        description="Create empty attributes",
    ),
    AttributesTestCase(
        ModelTestType.ATTRS_OPERATIONS,
        attr_name=Names.CN,
        attr_value=Values.TEST,
        description="Test add/get/remove operations",
    ),
    AttributesTestCase(
        ModelTestType.ATTRS_MISSING,
        attr_name="missing",
        expected_result=[],
        description="Get non-existent attribute returns empty",
    ),
    AttributesTestCase(
        ModelTestType.ATTRS_EMPTY_VALUES,
        attributes={Names.CN: [""], Names.SN: []},
        description="Handle empty attribute values",
    ),
]

ENTRY_TESTS: Final[list[EntryTestCase]] = [
    EntryTestCase(
        ModelTestType.ENTRY_CREATION,
        dn=DNs.TEST_USER,
        attributes={
            Names.OBJECTCLASS: [Names.PERSON],
            Names.CN: [Values.TEST],
            Names.SN: [Values.TEST],
        },
        description="Create entry with attributes",
    ),
    EntryTestCase(
        ModelTestType.ENTRY_BINARY,
        dn=DNs.TEST_USER,
        attributes={
            Names.OBJECTCLASS: [Names.INET_ORG_PERSON],
            Names.CN: [Values.TEST],
        },
        has_binary=True,
        description="Create entry with binary data",
    ),
    EntryTestCase(
        ModelTestType.ENTRY_SERIALIZATION,
        dn=DNs.TEST_USER,
        attributes={Names.OBJECTCLASS: [Names.PERSON]},
        description="Serialize entry to dict",
    ),
    EntryTestCase(
        ModelTestType.ENTRY_VALIDATION_LENIENT,
        dn=DNs.TEST_USER,
        attributes={Names.OBJECTCLASS: [Names.PERSON]},
        description="Validate entry lenient",
    ),
    EntryTestCase(
        ModelTestType.ENTRY_VALIDATION_LENIENT,
        dn="",
        attributes={Names.OBJECTCLASS: [Names.PERSON]},
        description="Allow empty DN in lenient mode",
    ),
]

SCHEMA_TESTS: Final[list[SchemaTestCase]] = [
    SchemaTestCase(
        ModelTestType.SCHEMA_OBJECTCLASS,
        Names.PERSON,
        OIDs.PERSON,
        "ObjectClass creation",
    ),
    SchemaTestCase(
        ModelTestType.SCHEMA_ATTRIBUTE,
        Names.CN,
        OIDs.CN,
        "Attribute creation",
    ),
    SchemaTestCase(
        ModelTestType.SCHEMA_DISCOVERY,
        description="SchemaDiscoveryResult creation",
    ),
]

ACL_TESTS: Final[list[AclTestCase]] = [
    AclTestCase(
        ModelTestType.ACL_TARGET,
        target_dn=DNs.EXAMPLE,
        attributes=[Names.CN, Names.SN],
        description="Create ACL target",
    ),
    AclTestCase(
        ModelTestType.ACL_SUBJECT,
        subject_type="user",
        subject_value=f"cn={Values.ADMIN},{DNs.EXAMPLE}",
        description="Create ACL subject",
    ),
    AclTestCase(
        ModelTestType.ACL_PERMISSIONS,
        permissions_read=True,
        permissions_write=True,
        permissions_search=True,
        description="Create ACL permissions",
    ),
    AclTestCase(
        ModelTestType.ACL_UNIFIED,
        target_dn=DNs.EXAMPLE,
        attributes=[Names.CN, Names.SN],
        subject_type="user",
        subject_value=f"cn={Values.ADMIN},{DNs.EXAMPLE}",
        permissions_read=True,
        permissions_write=True,
        acl_name="test_acl",
        acl_server_type="oracle_oud",
        description="Create unified ACL",
    ),
]


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


class TestFlextLdifModels(FlextTestsFactories):
    """Comprehensive FlextLdifModels test suite.

    Tests all model types (Entry, DN, Attributes, Schema, ACL) with parametrized
    test cases to maximize coverage while minimizing code duplication.
    """

    # ============================================================================
    # Distinguished Name Tests
    # ============================================================================

    @pytest.mark.parametrize("test_case", get_dn_tests())
    def test_dn_models(self, test_case: DnTestCase) -> None:
        """Test DN model creation and behavior."""
        dn = FlextLdifModels.DistinguishedName(value=test_case.dn_value)

        # Basic creation check
        assert dn.value == test_case.dn_value

        # Type-specific validations
        match test_case.test_type:
            case ModelTestType.DN_CREATION:
                # components is a @computed_field property, access directly
                # Access the computed field value
                components_list = dn.components
                assert isinstance(components_list, list)
                assert len(components_list) == 3
            case ModelTestType.DN_CASE_PRESERVATION:
                assert dn.value == test_case.dn_value
            case ModelTestType.DN_INVALID_PRESERVED:
                assert dn.value == test_case.dn_value
            case ModelTestType.DN_SPECIAL_CHARS:
                assert "\\+" in dn.value
            case ModelTestType.DN_LONG:
                assert len(dn.value) > 2048

    # ============================================================================
    # LdifAttributes Tests
    # ============================================================================

    @pytest.mark.parametrize("test_case", get_attributes_tests())
    def test_attributes_models(self, test_case: AttributesTestCase) -> None:
        """Test LdifAttributes model creation and operations."""
        match test_case.test_type:
            case ModelTestType.ATTRS_CREATION:
                attrs_data = test_case.attributes or {}
                result = FlextLdifModels.LdifAttributes.create(attrs_data)
                assert result.is_success
                attrs = result.unwrap()
                assert Names.CN in attrs.attributes
                assert attrs.attributes[Names.CN] == [Values.TEST]

            case ModelTestType.ATTRS_EMPTY:
                result = FlextLdifModels.LdifAttributes.create({})
                assert result.is_success
                attrs = result.unwrap()
                assert attrs.attributes == {}

            case ModelTestType.ATTRS_OPERATIONS:
                attrs = FlextLdifModels.LdifAttributes(attributes={})
                attr_name = test_case.attr_name or ""
                attr_value = test_case.attr_value or ""
                attrs.add_attribute(attr_name, attr_value)
                retrieved = attrs.get(test_case.attr_name or "")
                assert isinstance(retrieved, list)
                assert len(retrieved) > 0
                attrs.remove_attribute(test_case.attr_name or "")
                assert (test_case.attr_name or "") not in attrs.attributes

            case ModelTestType.ATTRS_MISSING:
                attrs = FlextLdifModels.LdifAttributes(attributes={})
                values = attrs.get(test_case.attr_name or "missing")
                assert values == []

            case ModelTestType.ATTRS_EMPTY_VALUES:
                attrs = FlextLdifModels.LdifAttributes(
                    attributes={Names.CN: [""], Names.SN: []},
                )
                assert attrs.get(Names.CN) == [""]
                assert attrs.get(Names.SN) == []

    # ============================================================================
    # Entry Tests
    # ============================================================================

    @pytest.mark.parametrize("test_case", get_entry_tests())
    def test_entry_models(self, test_case: EntryTestCase) -> None:
        """Test Entry model creation, validation, and serialization."""
        match test_case.test_type:
            case ModelTestType.ENTRY_CREATION:
                attrs_dict: dict[str, str | list[str]] = {}
                if test_case.attributes:
                    attrs_dict.update(test_case.attributes)
                result = FlextLdifModels.Entry.create(
                    dn=test_case.dn,
                    attributes=attrs_dict,
                )
                assert result.is_success
                entry = result.unwrap()
                assert entry.dn.value == test_case.dn
                if test_case.attributes:
                    assert Names.CN in entry.attributes.attributes

            case ModelTestType.ENTRY_BINARY:
                binary_data = b"binary content"
                encoded_data = base64.b64encode(binary_data).decode("ascii")
                attrs: dict[str, str | list[str]] = {}
                if test_case.attributes:
                    attrs.update(test_case.attributes)
                attrs["userCertificate;binary"] = [encoded_data]
                result = FlextLdifModels.Entry.create(
                    dn=test_case.dn,
                    attributes=attrs,
                )
                assert result.is_success
                entry = result.unwrap()
                assert "userCertificate;binary" in entry.attributes.attributes

            case ModelTestType.ENTRY_SERIALIZATION:
                entry = FlextLdifTestFactories.create_user_entry(Values.TEST)
                data = entry.model_dump()
                assert isinstance(data, dict)
                assert "dn" in data
                assert "attributes" in data

            case ModelTestType.ENTRY_VALIDATION_LENIENT:
                attrs_dict_lenient: dict[str, str | list[str]] = {}
                if test_case.attributes:
                    attrs_dict_lenient.update(test_case.attributes)
                result = FlextLdifModels.Entry.create(
                    dn=test_case.dn,
                    attributes=attrs_dict_lenient,
                )
                assert result.is_success

    # ============================================================================
    # Schema Tests
    # ============================================================================

    def test_schema_objectclass(self) -> None:
        """Test SchemaObjectClass creation."""
        oc = FlextLdifModels.SchemaObjectClass(
            name=Names.PERSON,
            oid=OIDs.PERSON,
            desc="Person object class",
            sup=None,
            must=["cn", "sn"],
            may=["telephoneNumber", "seeAlso"],
            kind="STRUCTURAL",
        )
        assert oc.name == Names.PERSON
        assert oc.oid == OIDs.PERSON
        assert oc.is_structural is True

    def test_schema_attribute(self) -> None:
        """Test SchemaAttribute creation."""
        attr = FlextLdifModels.SchemaAttribute(
            name=Names.CN,
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
        assert attr.name == Names.CN
        assert attr.oid == OIDs.CN
        assert attr.syntax == OIDs.DIRECTORY_STRING

    def test_schema_discovery_result(self) -> None:
        """Test SchemaDiscoveryResult creation."""
        result = FlextLdifModels.SchemaDiscoveryResult(
            objectclasses={
                Names.PERSON: {
                    "oid": OIDs.PERSON,
                    "description": "Person class",
                },
            },
            attributes={
                Names.CN: {
                    "oid": OIDs.CN,
                    "description": "Common name",
                    "syntax": OIDs.DIRECTORY_STRING,
                },
            },
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
                target = FlextLdifModels.AclTarget(
                    target_dn=test_case.target_dn or "",
                    attributes=test_case.attributes or [],
                )
                assert target.target_dn == test_case.target_dn
                assert target.attributes == test_case.attributes

            case ModelTestType.ACL_SUBJECT:
                subject = FlextLdifModels.AclSubject(
                    subject_type=test_case.subject_type or "user",
                    subject_value=test_case.subject_value or "",
                )
                assert subject.subject_type == test_case.subject_type
                if test_case.subject_value:
                    assert test_case.subject_value in subject.subject_value

            case ModelTestType.ACL_PERMISSIONS:
                perms = FlextLdifModels.AclPermissions(
                    read=test_case.permissions_read,
                    write=test_case.permissions_write,
                    search=test_case.permissions_search,
                )
                assert perms.read is test_case.permissions_read
                assert perms.write is test_case.permissions_write
                assert perms.search is test_case.permissions_search

            case ModelTestType.ACL_UNIFIED:
                target = FlextLdifModels.AclTarget(
                    target_dn=test_case.target_dn or "",
                    attributes=test_case.attributes or [],
                )
                subject = FlextLdifModels.AclSubject(
                    subject_type=test_case.subject_type or "user",
                    subject_value=test_case.subject_value or "",
                )
                permissions = FlextLdifModels.AclPermissions(
                    read=test_case.permissions_read,
                    write=test_case.permissions_write,
                )
                acl = FlextLdifModels.Acl(
                    name=test_case.acl_name or "",
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type=test_case.acl_server_type or "oracle_oud",
                )
                assert isinstance(acl, FlextLdifModels.Acl)
                assert acl.name == test_case.acl_name
                assert acl.server_type == test_case.acl_server_type

    # ============================================================================
    # Namespace and Inheritance Tests
    # ============================================================================

    def test_model_inheritance(self) -> None:
        """Test that models properly inherit from FlextModels."""
        assert issubclass(FlextLdifModels, FlextModels)

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
            assert hasattr(FlextLdifModels, model_name), (
                f"FlextLdifModels missing {model_name}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
