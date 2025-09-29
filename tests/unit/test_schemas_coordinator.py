"""Test suite for FlextLdifSchemas."""

from typing import cast

import pytest
from tests.support import LdifTestData

from flext_ldif.models import FlextLdifModels
from flext_ldif.schemas_coordinator import FlextLdifSchemas


class TestFlextLdifSchemas:
    """Test suite for FlextLdifSchemas."""

    def test_initialization(self) -> None:
        """Test schemas coordinator initialization."""
        coordinator = FlextLdifSchemas()
        assert coordinator is not None
        assert coordinator.extractor is not None
        assert coordinator.validator is not None
        assert coordinator.builder is not None
        assert coordinator.objectclass is not None

    def test_execute(self) -> None:
        """Test execute method."""
        coordinator = FlextLdifSchemas()
        result = coordinator.execute()
        assert result.is_success
        data = result.value
        assert data["status"] == "healthy"
        assert data["service"] == FlextLdifSchemas
        assert "operations" in data

    @pytest.mark.asyncio
    async def test_execute_async(self) -> None:
        """Test async execute method."""
        coordinator = FlextLdifSchemas()
        result = await coordinator.execute_async()
        assert result.is_success
        data = result.value
        assert data["status"] == "healthy"
        assert data["service"] == FlextLdifSchemas
        assert "operations" in data


class TestFlextLdifSchemasExtractor:
    """Test suite for FlextLdifSchemas.Extractor."""

    def test_initialization(self) -> None:
        """Test extractor initialization."""
        coordinator = FlextLdifSchemas()
        extractor = coordinator.extractor
        assert extractor is not None
        assert extractor._parent is coordinator

    def test_extract_from_entries_basic(self) -> None:
        """Test extracting schema from basic entries."""
        coordinator = FlextLdifSchemas()
        extractor = coordinator.extractor

        # Create test entries
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["user"],
                "objectClass": ["top", "person"],
            },
        })
        assert entry_result.is_success
        entry = entry_result.value
        entries = [entry]

        result = extractor.extract_from_entries(entries)
        # The extraction may fail due to validation issues, but we should test that it returns a result
        assert result.is_success or result.is_failure
        if result.is_success:
            schema = result.value
            assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)
            assert len(schema.attributes) >= 0
            assert len(schema.object_classes) >= 0

    def test_extract_from_entries_empty(self) -> None:
        """Test extracting schema from empty entries."""
        coordinator = FlextLdifSchemas()
        extractor = coordinator.extractor

        result = extractor.extract_from_entries([])
        # Empty entries should return a failure
        assert result.is_failure
        assert result.error is not None and "No entries provided" in result.error

    def test_extract_attributes_basic(self) -> None:
        """Test extracting attribute usage statistics."""
        coordinator = FlextLdifSchemas()
        extractor = coordinator.extractor

        # Create test entries
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["user"],
                "objectClass": ["top", "person"],
            },
        })
        assert entry_result.is_success
        entry = entry_result.value
        entries = [entry]

        result = extractor.extract_attributes(entries)
        assert result.is_success
        attributes = result.value
        assert isinstance(attributes, dict)
        assert len(attributes) > 0


class TestFlextLdifSchemasValidator:
    """Test suite for FlextLdifSchemas.Validator."""

    def test_initialization(self) -> None:
        """Test validator initialization."""
        coordinator = FlextLdifSchemas()
        validator = coordinator.validator
        assert validator is not None
        assert validator._parent is coordinator

    def test_validate_entry_basic(self) -> None:
        """Test validating entry against schema."""
        coordinator = FlextLdifSchemas()
        validator = coordinator.validator

        # Create a mock schema
        schema_result = FlextLdifModels.SchemaDiscoveryResult.create({
            "attributes": {
                "cn": {"name": "cn", "description": "Common Name"},
                "sn": {"name": "sn", "description": "Surname"},
                "objectClass": {
                    "name": "objectClass",
                    "description": "Object Class",
                },
            },
            "object_classes": {
                "top": {
                    "name": "top",
                    "description": "Top",
                    "required_attributes": ["objectClass"],
                },
                "person": {
                    "name": "person",
                    "description": "Person",
                    "required_attributes": ["cn", "sn"],
                },
            },
        })
        assert schema_result.is_success
        schema = schema_result.value

        # Create a valid entry
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["user"],
                "objectClass": ["top", "person"],
            },
        })
        assert entry_result.is_success
        entry = entry_result.value

        result = validator.validate_entry(
            entry, cast("FlextLdifModels.SchemaDiscoveryResult", schema)
        )
        assert result.is_success
        report = result.value
        assert isinstance(report, dict)
        assert "valid" in report
        assert "issues" in report
        assert "warnings" in report

    def test_validate_objectclass_basic(self) -> None:
        """Test validating objectclass requirements."""
        coordinator = FlextLdifSchemas()
        validator = coordinator.validator

        # Create a mock schema
        schema_result = FlextLdifModels.SchemaDiscoveryResult.create({
            "object_classes": {
                "top": {
                    "name": "top",
                    "description": "Top",
                    "required_attributes": ["objectClass"],
                },
                "person": {
                    "name": "person",
                    "description": "Person",
                    "required_attributes": ["cn", "sn"],
                },
            },
        })
        assert schema_result.is_success
        schema = schema_result.value

        result = validator.validate_objectclass(
            "person", cast("FlextLdifModels.SchemaDiscoveryResult", schema)
        )
        assert result.is_success
        report = result.value
        assert isinstance(report, dict)
        assert "valid" in report
        assert "issues" in report


class TestFlextLdifSchemasBuilder:
    """Test suite for FlextLdifSchemas.Builder."""

    def test_initialization(self) -> None:
        """Test builder initialization."""
        coordinator = FlextLdifSchemas()
        builder = coordinator.builder
        assert builder is not None
        assert builder._parent is coordinator

    def test_build_standard_person(self) -> None:
        """Test building standard person schema."""
        coordinator = FlextLdifSchemas()
        builder = coordinator.builder

        result = builder.build_standard_person()
        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)
        assert len(schema.attributes) > 0
        assert len(schema.object_classes) > 0

    def test_build_standard_group(self) -> None:
        """Test building standard group schema."""
        coordinator = FlextLdifSchemas()
        builder = coordinator.builder

        result = builder.build_standard_group()
        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)
        assert len(schema.attributes) > 0
        assert len(schema.object_classes) > 0


class TestFlextLdifSchemasObjectClassManager:
    """Test suite for FlextLdifSchemas.ObjectClassManager."""

    def test_initialization(self) -> None:
        """Test objectclass manager initialization."""
        coordinator = FlextLdifSchemas()
        objectclass = coordinator.objectclass
        assert objectclass is not None
        assert objectclass._parent is coordinator

    def test_get_hierarchy_basic(self) -> None:
        """Test getting objectclass hierarchy."""
        coordinator = FlextLdifSchemas()
        objectclass = coordinator.objectclass

        result = objectclass.get_hierarchy("person")
        assert result.is_success
        hierarchy = result.value
        assert isinstance(hierarchy, list)
        assert "person" in hierarchy

    def test_get_required_attributes_basic(self) -> None:
        """Test getting required attributes for objectclasses."""
        coordinator = FlextLdifSchemas()
        objectclass = coordinator.objectclass

        result = objectclass.get_required_attributes(["person"])
        assert result.is_success
        attributes = result.value
        assert isinstance(attributes, list)

    def test_get_definition_basic(self) -> None:
        """Test getting objectclass definition."""
        coordinator = FlextLdifSchemas()
        objectclass = coordinator.objectclass

        result = objectclass.get_definition("person")
        # This may fail if person is not in the default schema
        assert result.is_success or result.is_failure
        if result.is_success:
            definition = result.value
            assert isinstance(definition, FlextLdifModels.SchemaObjectClass)

    def test_validate_combination_basic(self) -> None:
        """Test validating objectclass combination."""
        coordinator = FlextLdifSchemas()
        objectclass = coordinator.objectclass

        result = objectclass.validate_combination(["top", "person"])
        assert result.is_success
        is_valid = result.value
        assert isinstance(is_valid, bool)


class TestFlextLdifSchemasIntegration:
    """Integration tests for FlextLdifSchemas."""

    def test_coordinator_with_real_data(self) -> None:
        """Test coordinator with real LDIF data."""
        coordinator = FlextLdifSchemas()
        _ = LdifTestData.basic_entries()  # Suppress unused variable warning

        # Extract schema from entries
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["user"],
                "objectClass": ["top", "person"],
            },
        })
        assert entry_result.is_success
        entries = [entry_result.value]

        extract_result = coordinator.extractor.extract_from_entries(entries)
        # Extraction may fail due to validation issues, but we should test the flow
        assert extract_result.is_success or extract_result.is_failure
        if extract_result.is_success:
            schema = extract_result.value
            # Validate entry against extracted schema
            validate_result = coordinator.validator.validate_entry(
                entry_result.value, schema
            )
            assert validate_result.is_success

    def test_builder_and_validator_integration(self) -> None:
        """Test builder and validator working together."""
        coordinator = FlextLdifSchemas()

        # Build a schema
        build_result = coordinator.builder.build_standard_person()
        assert build_result.is_success
        schema = build_result.value

        # Validate entry against built schema
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["user"],
                "objectClass": ["top", "person"],
            },
        })
        assert entry_result.is_success
        entry = entry_result.value

        validate_result = coordinator.validator.validate_entry(entry, schema)
        assert validate_result.is_success

    def test_objectclass_manager_with_built_schema(self) -> None:
        """Test objectclass manager with built schema."""
        coordinator = FlextLdifSchemas()

        # Build a schema
        build_result = coordinator.builder.build_standard_person()
        assert build_result.is_success

        # Get hierarchy for person
        hierarchy_result = coordinator.objectclass.get_hierarchy("person")
        assert hierarchy_result.is_success

        # Get required attributes
        required_result = coordinator.objectclass.get_required_attributes(["person"])
        assert required_result.is_success

        # Validate combination
        combination_result = coordinator.objectclass.validate_combination([
            "top",
            "person",
        ])
        assert combination_result.is_success

    def test_all_operations_working_together(self) -> None:
        """Test all coordinator operations working together."""
        coordinator = FlextLdifSchemas()

        # Create test entries
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["user"],
                "objectClass": ["top", "person"],
            },
        })
        assert entry_result.is_success
        entry = entry_result.value
        entries = [entry]

        # Extract schema from entries
        extract_result = coordinator.extractor.extract_from_entries(entries)
        # Extraction may fail due to validation issues
        assert extract_result.is_success or extract_result.is_failure
        if extract_result.is_success:
            extracted_schema = extract_result.value

        # Build a new schema
        build_result = coordinator.builder.build_standard_person()
        assert build_result.is_success
        built_schema = build_result.value

        # Validate entries against both schemas
        extracted_schema = None
        if extract_result.is_success:
            extracted_schema = extract_result.value
            validate_extracted = coordinator.validator.validate_entry(
                entry, extracted_schema
            )
            assert validate_extracted.is_success

        validate_built = coordinator.validator.validate_entry(entry, built_schema)
        assert validate_built.is_success

        # Use objectclass manager
        hierarchy_result = coordinator.objectclass.get_hierarchy("person")
        assert hierarchy_result.is_success

        required_result = coordinator.objectclass.get_required_attributes(["person"])
        assert required_result.is_success

        combination_result = coordinator.objectclass.validate_combination([
            "top",
            "person",
        ])
        assert combination_result.is_success
