"""Test suite for FlextLdifObjectClassManager."""

from typing import cast

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.schema.objectclass_manager import FlextLdifObjectClassManager


class TestFlextLdifObjectClassManager:
    """Test suite for FlextLdifObjectClassManager."""

    def test_initialization(self) -> None:
        """Test objectClass manager initialization."""
        manager = FlextLdifObjectClassManager()
        assert manager is not None
        assert manager is not None

    def test_execute(self) -> None:
        """Test execute method."""
        manager = FlextLdifObjectClassManager()
        result = manager.execute()

        assert result.is_success
        data = result.value
        assert isinstance(data, dict)
        assert "service" in data
        assert "status" in data
        assert data["status"] == "ready"

    @pytest.mark.asyncio
    async def test_execute_async(self) -> None:
        """Test async execute method."""
        manager = FlextLdifObjectClassManager()
        result = await manager.execute_async()

        assert result.is_success
        data = result.value
        assert isinstance(data, dict)
        assert "service" in data
        assert "status" in data
        assert data["status"] == "ready"

    def test_resolve_objectclass_hierarchy_single(self) -> None:
        """Test resolving objectClass hierarchy for single class."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with objectClass definition
        oc_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", superior=["top"]
        )
        cn_attr = FlextLdifModels.SchemaAttribute(name="cn", oid="2.5.4.3")
        sn_attr = FlextLdifModels.SchemaAttribute(name="sn", oid="2.5.4.4")
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": oc_def},
            attributes={"cn": cn_attr, "sn": sn_attr},
        )

        result = manager.resolve_objectclass_hierarchy("person", schema)

        assert result.is_success
        hierarchy = result.value
        assert isinstance(hierarchy, list)
        assert "person" in hierarchy
        assert "top" in hierarchy

    def test_resolve_objectclass_hierarchy_unknown(self) -> None:
        """Test resolving objectClass hierarchy for unknown class."""
        manager = FlextLdifObjectClassManager()

        # Create an empty schema
        schema = FlextLdifModels.SchemaDiscoveryResult(object_classes={}, attributes={})

        result = manager.resolve_objectclass_hierarchy("unknown", schema)

        assert result.is_success
        hierarchy = result.value
        assert isinstance(hierarchy, list)
        assert hierarchy == ["unknown"]

    def test_resolve_objectclass_hierarchy_multiple_superiors(self) -> None:
        """Test resolving objectClass hierarchy with multiple superiors."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with complex hierarchy
        person_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", superior=["top"]
        )
        inetorgperson_def = FlextLdifModels.SchemaObjectClass(
            name="inetOrgPerson",
            oid="2.16.840.1.113730.3.2.2",
            superior=["person", "top"],
        )

        cn_attr = FlextLdifModels.SchemaAttribute(name="cn", oid="2.5.4.3")
        sn_attr = FlextLdifModels.SchemaAttribute(name="sn", oid="2.5.4.4")
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_def, "inetOrgPerson": inetorgperson_def},
            attributes={"cn": cn_attr, "sn": sn_attr},
        )

        result = manager.resolve_objectclass_hierarchy("inetOrgPerson", schema)

        assert result.is_success
        hierarchy = result.value
        assert isinstance(hierarchy, list)
        assert "inetOrgPerson" in hierarchy
        assert "person" in hierarchy
        assert "top" in hierarchy

    def test_get_all_required_attributes_single(self) -> None:
        """Test getting required attributes for single objectClass."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with objectClass definition
        oc_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", required_attributes=["cn", "sn"]
        )
        cn_attr = FlextLdifModels.SchemaAttribute(name="cn", oid="2.5.4.3")
        sn_attr = FlextLdifModels.SchemaAttribute(name="sn", oid="2.5.4.4")
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": oc_def},
            attributes={"cn": cn_attr, "sn": sn_attr},
        )

        result = manager.get_all_required_attributes(["person"], schema)

        assert result.is_success
        required_attrs = result.value
        assert isinstance(required_attrs, list)
        assert "cn" in required_attrs
        assert "sn" in required_attrs

    def test_get_all_required_attributes_multiple(self) -> None:
        """Test getting required attributes for multiple objectClasses."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with multiple objectClass definitions
        person_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", required_attributes=["cn", "sn"]
        )
        group_def = FlextLdifModels.SchemaObjectClass(
            name="group", oid="2.5.6.9", required_attributes=["cn", "member"]
        )

        cn_attr = FlextLdifModels.SchemaAttribute(name="cn", oid="2.5.4.3")
        sn_attr = FlextLdifModels.SchemaAttribute(name="sn", oid="2.5.4.4")
        member_attr = FlextLdifModels.SchemaAttribute(name="member", oid="2.5.4.31")
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_def, "group": group_def},
            attributes={
                "cn": cn_attr,
                "sn": sn_attr,
                "member": member_attr,
            },
        )

        result = manager.get_all_required_attributes(["person", "group"], schema)

        assert result.is_success
        required_attrs = result.value
        assert isinstance(required_attrs, list)
        assert "cn" in required_attrs
        assert "sn" in required_attrs
        assert "member" in required_attrs

    def test_get_all_required_attributes_unknown(self) -> None:
        """Test getting required attributes for unknown objectClasses."""
        manager = FlextLdifObjectClassManager()

        # Create an empty schema
        schema = FlextLdifModels.SchemaDiscoveryResult(object_classes={}, attributes={})

        result = manager.get_all_required_attributes(["unknown"], schema)

        assert result.is_success
        required_attrs = result.value
        assert isinstance(required_attrs, list)
        assert len(required_attrs) == 0

    def test_get_all_optional_attributes_single(self) -> None:
        """Test getting optional attributes for single objectClass."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with objectClass definition
        oc_def = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            optional_attributes=["mail", "telephoneNumber"],
        )
        mail_attr = FlextLdifModels.SchemaAttribute(
            name="mail", oid="0.9.2342.19200300.100.1.3"
        )
        tel_attr = FlextLdifModels.SchemaAttribute(
            name="telephoneNumber", oid="2.5.4.20"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": oc_def},
            attributes={
                "mail": mail_attr,
                "telephoneNumber": tel_attr,
            },
        )

        result = manager.get_all_optional_attributes(["person"], schema)

        assert result.is_success
        optional_attrs = result.value
        assert isinstance(optional_attrs, list)
        assert "mail" in optional_attrs
        assert "telephoneNumber" in optional_attrs

    def test_get_all_optional_attributes_multiple(self) -> None:
        """Test getting optional attributes for multiple objectClasses."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with multiple objectClass definitions
        person_def = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            optional_attributes=["mail", "telephoneNumber"],
        )
        group_def = FlextLdifModels.SchemaObjectClass(
            name="group", oid="2.5.6.9", optional_attributes=["description"]
        )

        mail_attr = FlextLdifModels.SchemaAttribute(
            name="mail", oid="0.9.2342.19200300.100.1.3"
        )
        tel_attr = FlextLdifModels.SchemaAttribute(
            name="telephoneNumber", oid="2.5.4.20"
        )
        desc_attr = FlextLdifModels.SchemaAttribute(name="description", oid="2.5.4.13")
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_def, "group": group_def},
            attributes={
                "mail": mail_attr,
                "telephoneNumber": tel_attr,
                "description": desc_attr,
            },
        )

        result = manager.get_all_optional_attributes(["person", "group"], schema)

        assert result.is_success
        optional_attrs = result.value
        assert isinstance(optional_attrs, list)
        assert "mail" in optional_attrs
        assert "telephoneNumber" in optional_attrs
        assert "description" in optional_attrs

    def test_get_all_optional_attributes_unknown(self) -> None:
        """Test getting optional attributes for unknown objectClasses."""
        manager = FlextLdifObjectClassManager()

        # Create an empty schema
        schema = FlextLdifModels.SchemaDiscoveryResult(object_classes={}, attributes={})

        result = manager.get_all_optional_attributes(["unknown"], schema)

        assert result.is_success
        optional_attrs = result.value
        assert isinstance(optional_attrs, list)
        assert len(optional_attrs) == 0

    def test_validate_objectclass_combination_valid(self) -> None:
        """Test validating valid objectClass combination."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with one structural objectClass
        person_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", structural=True
        )
        top_def = FlextLdifModels.SchemaObjectClass(
            name="top", oid="2.5.6.0", structural=False
        )

        cn_attr = FlextLdifModels.SchemaAttribute(name="cn", oid="2.5.4.3")
        sn_attr = FlextLdifModels.SchemaAttribute(name="sn", oid="2.5.4.4")
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_def, "top": top_def},
            attributes={"cn": cn_attr, "sn": sn_attr},
        )

        result = manager.validate_objectclass_combination(["person", "top"], schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "issues" in validation_data
        assert "structural_count" in validation_data
        assert validation_data["valid"] is True
        assert validation_data["structural_count"] == 1

    def test_validate_objectclass_combination_multiple_structural(self) -> None:
        """Test validating invalid objectClass combination with multiple structural classes."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with multiple structural objectClasses
        person_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", structural=True
        )
        group_def = FlextLdifModels.SchemaObjectClass(
            name="group", oid="2.5.6.9", structural=True
        )

        cn_attr = FlextLdifModels.SchemaAttribute(name="cn", oid="2.5.4.3")
        sn_attr = FlextLdifModels.SchemaAttribute(name="sn", oid="2.5.4.4")
        member_attr = FlextLdifModels.SchemaAttribute(name="member", oid="2.5.4.31")
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_def, "group": group_def},
            attributes={
                "cn": cn_attr,
                "sn": sn_attr,
                "member": member_attr,
            },
        )

        result = manager.validate_objectclass_combination(["person", "group"], schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "issues" in validation_data
        assert "structural_count" in validation_data
        assert validation_data["valid"] is False
        assert validation_data["structural_count"] == 2
        issues: list[str] = cast("list[str]", validation_data["issues"])
        assert isinstance(issues, list)
        assert len(issues) > 0

    def test_validate_objectclass_combination_unknown_classes(self) -> None:
        """Test validating objectClass combination with unknown classes."""
        manager = FlextLdifObjectClassManager()

        # Create an empty schema
        schema = FlextLdifModels.SchemaDiscoveryResult(object_classes={}, attributes={})

        result = manager.validate_objectclass_combination(
            ["unknown1", "unknown2"], schema
        )

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "issues" in validation_data
        assert "structural_count" in validation_data
        assert validation_data["valid"] is True
        assert validation_data["structural_count"] == 0

    def test_validate_objectclass_combination_mixed(self) -> None:
        """Test validating objectClass combination with mixed structural/auxiliary."""
        manager = FlextLdifObjectClassManager()

        # Create a schema with mixed objectClass types
        person_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", structural=True
        )
        top_def = FlextLdifModels.SchemaObjectClass(
            name="top", oid="2.5.6.0", structural=False
        )
        extensibleobject_def = FlextLdifModels.SchemaObjectClass(
            name="extensibleObject",
            oid="1.3.6.1.4.1.1466.101.120.111",
            structural=False,
        )

        cn_attr = FlextLdifModels.SchemaAttribute(name="cn", oid="2.5.4.3")
        sn_attr = FlextLdifModels.SchemaAttribute(name="sn", oid="2.5.4.4")
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": person_def,
                "top": top_def,
                "extensibleObject": extensibleobject_def,
            },
            attributes={"cn": cn_attr, "sn": sn_attr},
        )

        result = manager.validate_objectclass_combination(
            ["person", "top", "extensibleObject"], schema
        )

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "issues" in validation_data
        assert "structural_count" in validation_data
        assert validation_data["valid"] is True
        assert validation_data["structural_count"] == 1

    def test_comprehensive_workflow(self) -> None:
        """Test comprehensive workflow using all methods."""
        manager = FlextLdifObjectClassManager()

        # Create a comprehensive schema
        person_def = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            superior=["top"],
            required_attributes=["cn", "sn"],
            optional_attributes=["mail", "telephoneNumber"],
            structural=True,
        )
        top_def = FlextLdifModels.SchemaObjectClass(
            name="top",
            oid="2.5.6.0",
            superior=[],
            required_attributes=[],
            optional_attributes=[],
            structural=False,
        )

        cn_attr = FlextLdifModels.SchemaAttribute(name="cn", oid="2.5.4.3")
        sn_attr = FlextLdifModels.SchemaAttribute(name="sn", oid="2.5.4.4")
        mail_attr = FlextLdifModels.SchemaAttribute(
            name="mail", oid="0.9.2342.19200300.100.1.3"
        )
        tel_attr = FlextLdifModels.SchemaAttribute(
            name="telephoneNumber", oid="2.5.4.20"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_def, "top": top_def},
            attributes={
                "cn": cn_attr,
                "sn": sn_attr,
                "mail": mail_attr,
                "telephoneNumber": tel_attr,
            },
        )

        # Test hierarchy resolution
        hierarchy_result = manager.resolve_objectclass_hierarchy("person", schema)
        assert hierarchy_result.is_success
        hierarchy = hierarchy_result.value
        assert "person" in hierarchy
        assert "top" in hierarchy

        # Test required attributes
        required_result = manager.get_all_required_attributes(["person"], schema)
        assert required_result.is_success
        required_attrs = required_result.value
        assert "cn" in required_attrs
        assert "sn" in required_attrs

        # Test optional attributes
        optional_result = manager.get_all_optional_attributes(["person"], schema)
        assert optional_result.is_success
        optional_attrs = optional_result.value
        assert "mail" in optional_attrs
        assert "telephoneNumber" in optional_attrs

        # Test validation
        validation_result = manager.validate_objectclass_combination(
            ["person", "top"], schema
        )
        assert validation_result.is_success
        validation_data = validation_result.value
        assert validation_data["valid"] is True
