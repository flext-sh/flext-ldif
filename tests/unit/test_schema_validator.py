"""Test suite for FlextLdifSchemaValidator."""

import pytest
from tests.test_support.ldif_data import LdifTestData

from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor
from flext_ldif.schema.validator import FlextLdifSchemaValidator


class TestFlextLdifSchemaValidator:
    """Test suite for FlextLdifSchemaValidator."""

    def test_initialization(self) -> None:
        """Test schema validator initialization."""
        validator = FlextLdifSchemaValidator()
        assert validator is not None

    def test_execute(self) -> None:
        """Test execute method."""
        validator = FlextLdifSchemaValidator()
        result = validator.execute()

        assert result.is_success
        data = result.value
        assert isinstance(data, dict)
        assert "service" in data
        assert "status" in data
        assert data["status"] == "ready"

    @pytest.mark.asyncio
    async def test_execute_async(self) -> None:
        """Test async execute method."""
        validator = FlextLdifSchemaValidator()
        result = await validator.execute_async()

        assert result.is_success
        data = result.value
        assert isinstance(data, dict)
        assert "service" in data
        assert "status" in data
        assert data["status"] == "ready"

    def test_validate_entry_against_schema_valid_entry(self) -> None:
        """Test validating a valid entry against schema."""
        validator = FlextLdifSchemaValidator()

        # Create a test entry
        sample = LdifTestData.basic_entries()
        processor = FlextLdifProcessor()
        parse_result = processor.parse_ldif_content(sample.content)
        assert parse_result.is_success
        entry = parse_result.value[0]

        # Create a mock schema that includes the entry's attributes
        person_oc = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", required_attributes=["cn", "sn"]
        )
        top_oc = FlextLdifModels.SchemaObjectClass(
            name="top", oid="2.5.6.0", required_attributes=[]
        )
        cn_attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", description="Common name"
        )
        sn_attr = FlextLdifModels.SchemaAttribute(
            name="sn", oid="2.5.4.4", description="Surname"
        )
        oc_attr = FlextLdifModels.SchemaAttribute(
            name="objectClass", oid="2.5.4.0", description="Object class"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_oc, "top": top_oc},
            attributes={"cn": cn_attr, "sn": sn_attr, "objectClass": oc_attr},
        )

        result = validator.validate_entry_against_schema(entry, schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "issues" in validation_data
        assert "warnings" in validation_data
        assert "dn" in validation_data

    def test_validate_entry_against_schema_invalid_attributes(self) -> None:
        """Test validating entry with attributes not in schema."""
        validator = FlextLdifSchemaValidator()

        # Create a test entry
        sample = LdifTestData.basic_entries()
        processor = FlextLdifProcessor()
        parse_result = processor.parse_ldif_content(sample.content)
        assert parse_result.is_success
        entry = parse_result.value[0]

        # Create a schema that doesn't include all attributes
        person_oc = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", required_attributes=["cn"]
        )
        top_oc = FlextLdifModels.SchemaObjectClass(
            name="top", oid="2.5.6.0", required_attributes=[]
        )
        cn_attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", description="Common name"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_oc, "top": top_oc},
            attributes={"cn": cn_attr},  # Missing sn and objectClass
        )

        result = validator.validate_entry_against_schema(entry, schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "warnings" in validation_data
        assert isinstance(validation_data["warnings"], list)

    def test_validate_entry_against_schema_invalid_object_classes(self) -> None:
        """Test validating entry with objectClass not in schema."""
        validator = FlextLdifSchemaValidator()

        # Create a test entry
        sample = LdifTestData.basic_entries()
        processor = FlextLdifProcessor()
        parse_result = processor.parse_ldif_content(sample.content)
        assert parse_result.is_success
        entry = parse_result.value[0]

        # Create a schema that doesn't include all objectClasses
        top_oc = FlextLdifModels.SchemaObjectClass(
            name="top", oid="2.5.6.0", required_attributes=[]
        )
        cn_attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", description="Common name"
        )
        sn_attr = FlextLdifModels.SchemaAttribute(
            name="sn", oid="2.5.4.4", description="Surname"
        )
        oc_attr = FlextLdifModels.SchemaAttribute(
            name="objectClass", oid="2.5.4.0", description="Object class"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"top": top_oc},  # Missing person
            attributes={"cn": cn_attr, "sn": sn_attr, "objectClass": oc_attr},
        )

        result = validator.validate_entry_against_schema(entry, schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "issues" in validation_data
        assert isinstance(validation_data["issues"], list)

    def test_validate_objectclass_requirements_valid(self) -> None:
        """Test validating objectClass requirements for valid entry."""
        validator = FlextLdifSchemaValidator()

        # Create a test entry
        sample = LdifTestData.basic_entries()
        processor = FlextLdifProcessor()
        parse_result = processor.parse_ldif_content(sample.content)
        assert parse_result.is_success
        entry = parse_result.value[0]

        # Create a schema with objectClass requirements
        oc_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", required_attributes=["cn", "sn"]
        )
        cn_attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", description="Common name"
        )
        sn_attr = FlextLdifModels.SchemaAttribute(
            name="sn", oid="2.5.4.4", description="Surname"
        )
        oc_attr = FlextLdifModels.SchemaAttribute(
            name="objectClass", oid="2.5.4.0", description="Object class"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": oc_def},
            attributes={"cn": cn_attr, "sn": sn_attr, "objectClass": oc_attr},
        )

        result = validator.validate_objectclass_requirements(entry, schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "issues" in validation_data
        assert "dn" in validation_data

    def test_validate_objectclass_requirements_missing_attributes(self) -> None:
        """Test validating objectClass requirements with missing attributes."""
        validator = FlextLdifSchemaValidator()

        # Create a test entry
        sample = LdifTestData.basic_entries()
        processor = FlextLdifProcessor()
        parse_result = processor.parse_ldif_content(sample.content)
        assert parse_result.is_success
        entry = parse_result.value[0]

        # Create a schema that requires attributes not present in entry
        oc_def = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            required_attributes=["cn", "sn", "missingAttr"],
        )
        cn_attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", description="Common name"
        )
        sn_attr = FlextLdifModels.SchemaAttribute(
            name="sn", oid="2.5.4.4", description="Surname"
        )
        oc_attr = FlextLdifModels.SchemaAttribute(
            name="objectClass", oid="2.5.4.0", description="Object class"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": oc_def},
            attributes={"cn": cn_attr, "sn": sn_attr, "objectClass": oc_attr},
        )

        result = validator.validate_objectclass_requirements(entry, schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "issues" in validation_data
        issues: list[str] = validation_data["issues"]  # type: ignore[assignment]
        assert isinstance(issues, list)
        # Should have issues due to missing required attribute
        assert len(issues) > 0

    def test_validate_objectclass_requirements_unknown_objectclass(self) -> None:
        """Test validating objectClass requirements for unknown objectClass."""
        validator = FlextLdifSchemaValidator()

        # Create a test entry
        sample = LdifTestData.basic_entries()
        processor = FlextLdifProcessor()
        parse_result = processor.parse_ldif_content(sample.content)
        assert parse_result.is_success
        entry = parse_result.value[0]

        # Create a schema that doesn't define the entry's objectClass
        cn_attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", description="Common name"
        )
        sn_attr = FlextLdifModels.SchemaAttribute(
            name="sn", oid="2.5.4.4", description="Surname"
        )
        oc_attr = FlextLdifModels.SchemaAttribute(
            name="objectClass", oid="2.5.4.0", description="Object class"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={},  # Empty objectClasses
            attributes={"cn": cn_attr, "sn": sn_attr, "objectClass": oc_attr},
        )

        result = validator.validate_objectclass_requirements(entry, schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "issues" in validation_data
        assert isinstance(validation_data["issues"], list)
        # Should be valid since unknown objectClass has no requirements
        assert validation_data["valid"] is True

    def test_validate_multiple_entries(self) -> None:
        """Test validating multiple entries against schema."""
        validator = FlextLdifSchemaValidator()

        # Create test entries
        sample = LdifTestData.basic_entries()
        processor = FlextLdifProcessor()
        parse_result = processor.parse_ldif_content(sample.content)
        assert parse_result.is_success
        entries = parse_result.value

        # Create a comprehensive schema
        person_oc = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", required_attributes=["cn", "sn"]
        )
        top_oc = FlextLdifModels.SchemaObjectClass(
            name="top", oid="2.5.6.0", required_attributes=[]
        )
        cn_attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", description="Common name"
        )
        sn_attr = FlextLdifModels.SchemaAttribute(
            name="sn", oid="2.5.4.4", description="Surname"
        )
        oc_attr = FlextLdifModels.SchemaAttribute(
            name="objectClass", oid="2.5.4.0", description="Object class"
        )
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_oc, "top": top_oc},
            attributes={"cn": cn_attr, "sn": sn_attr, "objectClass": oc_attr},
        )

        # Validate each entry
        for entry in entries:
            result = validator.validate_entry_against_schema(entry, schema)
            assert result.is_success
            validation_data = result.value
            assert isinstance(validation_data, dict)
            assert "dn" in validation_data

    def test_validate_with_complex_schema(self) -> None:
        """Test validation with complex schema definitions."""
        validator = FlextLdifSchemaValidator()

        # Create a test entry
        sample = LdifTestData.basic_entries()
        processor = FlextLdifProcessor()
        parse_result = processor.parse_ldif_content(sample.content)
        assert parse_result.is_success
        entry = parse_result.value[0]

        # Create a complex schema with multiple objectClasses
        person_def = FlextLdifModels.SchemaObjectClass(
            name="person", oid="2.5.6.6", required_attributes=["cn", "sn"]
        )
        top_def = FlextLdifModels.SchemaObjectClass(
            name="top", oid="2.5.6.0", required_attributes=[]
        )

        cn_attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", description="Common name"
        )
        sn_attr = FlextLdifModels.SchemaAttribute(
            name="sn", oid="2.5.4.4", description="Surname"
        )
        oc_attr = FlextLdifModels.SchemaAttribute(
            name="objectClass", oid="2.5.4.0", description="Object class"
        )
        uid_attr = FlextLdifModels.SchemaAttribute(
            name="uid", oid="0.9.2342.19200300.100.1.1", description="User identifier"
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": person_def, "top": top_def},
            attributes={
                "cn": cn_attr,
                "sn": sn_attr,
                "objectClass": oc_attr,
                "uid": uid_attr,
            },
        )

        # Test both validation methods
        result1 = validator.validate_entry_against_schema(entry, schema)
        result2 = validator.validate_objectclass_requirements(entry, schema)

        assert result1.is_success
        assert result2.is_success

        validation_data1 = result1.value
        validation_data2 = result2.value

        assert isinstance(validation_data1, dict)
        assert isinstance(validation_data2, dict)
        assert validation_data1["dn"] == validation_data2["dn"]

    def test_validate_empty_entry(self) -> None:
        """Test validation of empty entry."""
        validator = FlextLdifSchemaValidator()

        # Create an empty schema
        schema = FlextLdifModels.SchemaDiscoveryResult(object_classes={}, attributes={})

        # Create a minimal entry
        entry = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"objectClass": ["top"]},
            "domain_events": [],
        })
        assert entry.is_success
        test_entry = entry.value

        result = validator.validate_entry_against_schema(test_entry, schema)

        assert result.is_success
        validation_data = result.value
        assert isinstance(validation_data, dict)
        assert "valid" in validation_data
        assert "dn" in validation_data
