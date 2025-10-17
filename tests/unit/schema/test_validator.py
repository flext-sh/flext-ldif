"""Comprehensive tests for FlextLdifSchemaValidator functionality.

Tests all validation methods with real functionality testing and edge cases.
Includes both basic and comprehensive test coverage for schema validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.schema.validator import FlextLdifSchemaValidator


class TestFlextLdifSchemaValidator:
    """Test FlextLdifSchemaValidator functionality."""

    def test_initialization(self) -> None:
        """Test schema validator initialization."""
        validator = FlextLdifSchemaValidator()
        assert validator is not None
        assert isinstance(validator, FlextLdifSchemaValidator)

    def test_execute_method(self) -> None:
        """Test execute method returns service status."""
        validator = FlextLdifSchemaValidator()
        result = validator.execute()

        assert result.is_success
        status = result.unwrap()
        assert isinstance(status, dict)
        assert status["service"] == FlextLdifSchemaValidator
        assert status["status"] == "ready"

    def test_validate_entries_empty_list(self) -> None:
        """Test validating empty entries list."""
        validator = FlextLdifSchemaValidator()
        result = validator.validate_entries([])

        assert result.is_success
        validation = result.unwrap()
        assert validation.is_valid is True
        assert len(validation.errors) == 0
        assert len(validation.warnings) == 0

    def test_validate_entries_missing_dn(self) -> None:
        """Test validating entries with missing DN."""
        validator = FlextLdifSchemaValidator()

        # Create entry with empty DN
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value=""),
            attributes=FlextLdifModels.Attributes(attributes={})
        )

        result = validator.validate_entries([entry])
        assert result.is_success
        validation = result.unwrap()
        assert validation.is_valid is False
        assert len(validation.errors) == 1
        assert "Missing or empty DN" in validation.errors[0]

    def test_validate_entries_none_dn(self) -> None:
        """Test validating entries with None DN."""
        validator = FlextLdifSchemaValidator()

        # Create entry with None DN
        entry = FlextLdifModels.Entry(
            dn=None,  # type: ignore
            attributes=FlextLdifModels.Attributes(attributes={})
        )

        result = validator.validate_entries([entry])
        assert result.is_success
        validation = result.unwrap()
        assert validation.is_valid is False
        assert len(validation.errors) == 1
        assert "Missing or empty DN" in validation.errors[0]

    def test_validate_entries_missing_objectclass(self) -> None:
        """Test validating entries with missing objectClass."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={})
        )

        result = validator.validate_entries([entry])
        assert result.is_success
        validation = result.unwrap()
        assert validation.is_valid is False
        assert len(validation.errors) == 1
        assert "Missing objectClass attribute" in validation.errors[0]

    def test_validate_entries_valid_basic(self) -> None:
        """Test validating valid basic entries."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "cn": ["test"]
            })
        )

        result = validator.validate_entries([entry])
        assert result.is_success
        validation = result.unwrap()
        assert validation.is_valid is True
        assert len(validation.errors) == 0
        assert len(validation.warnings) == 0

    def test_validate_entries_strict_mode_missing_cn(self) -> None:
        """Test strict mode validation with missing required cn attribute."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "sn": ["Test"]
            })
        )

        result = validator.validate_entries([entry], strict=True)
        assert result.is_success
        validation = result.unwrap()
        assert validation.is_valid is False
        assert len(validation.errors) == 1
        assert "Missing required attribute" in validation.errors[0]
        assert "cn" in validation.errors[0]

    def test_validate_entries_strict_mode_missing_sn(self) -> None:
        """Test strict mode validation with missing required sn attribute."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "cn": ["Test"]
            })
        )

        result = validator.validate_entries([entry], strict=True)
        assert result.is_success
        validation = result.unwrap()
        assert validation.is_valid is False
        assert len(validation.errors) == 1
        assert "Missing required attribute" in validation.errors[0]
        assert "'sn'" in validation.errors[0]

    def test_validate_entries_strict_mode_valid_person(self) -> None:
        """Test strict mode validation with valid person entry."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "cn": ["Test"],
                "sn": ["User"]
            })
        )

        result = validator.validate_entries([entry], strict=True)
        assert result.is_success
        validation = result.unwrap()
        assert validation.is_valid is True
        assert len(validation.errors) == 0

    def test_validate_entry_against_schema_unknown_attributes(self) -> None:
        """Test validating entry against schema with unknown attributes."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "cn": ["Test"],
                "unknownAttr": ["value"]
            })
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            attributes={"cn": {}, "sn": {}},
            objectclasses={"person": {}}
        )

        result = validator.validate_entry_against_schema(entry, schema)
        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True
        assert len(validation["warnings"]) == 1
        assert "unknownAttr" in validation["warnings"][0]

    def test_validate_entry_against_schema_unknown_objectclass(self) -> None:
        """Test validating entry against schema with unknown objectClass."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["unknownOC"],
                "cn": ["Test"]
            })
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            attributes={"cn": {}, "sn": {}},
            objectclasses={"person": {}}
        )

        result = validator.validate_entry_against_schema(entry, schema)
        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is False
        assert len(validation["issues"]) == 1
        assert "unknownOC" in validation["issues"][0]

    def test_validate_entry_against_schema_valid(self) -> None:
        """Test validating entry against schema with all known attributes/objectClasses."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "cn": ["Test"],
                "sn": ["User"]
            })
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            attributes={"cn": {}, "sn": {}},
            objectclasses={"person": {}}
        )

        result = validator.validate_entry_against_schema(entry, schema)
        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True
        assert len(validation["issues"]) == 0
        assert len(validation["warnings"]) == 0

    def test_validate_objectclass_requirements_missing_required_attr(self) -> None:
        """Test validating objectClass requirements with missing required attribute."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "sn": ["User"]
                # Missing required 'cn' attribute
            })
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            attributes={"cn": {}, "sn": {}},
            objectclasses={"person": {"required_attributes": ["cn", "sn"]}}
        )

        result = validator.validate_objectclass_requirements(entry, schema)
        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is False
        assert len(validation["issues"]) == 1
        assert "Missing required attribute 'cn'" in validation["issues"][0]

    def test_validate_objectclass_requirements_valid(self) -> None:
        """Test validating objectClass requirements with all required attributes present."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "cn": ["Test"],
                "sn": ["User"]
            })
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            attributes={"cn": {}, "sn": {}},
            objectclasses={"person": {"required_attributes": ["cn", "sn"]}}
        )

        result = validator.validate_objectclass_requirements(entry, schema)
        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True
        assert len(validation["issues"]) == 0

    def test_validate_objectclass_requirements_unknown_objectclass(self) -> None:
        """Test validating objectClass requirements with unknown objectClass."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["unknownOC"],
                "cn": ["Test"]
            })
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            attributes={"cn": {}},
            objectclasses={"person": {}}
        )

        result = validator.validate_objectclass_requirements(entry, schema)
        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True  # Unknown objectClass is not validated
        assert len(validation["issues"]) == 0

    def test_validate_objectclass_requirements_no_required_attrs(self) -> None:
        """Test validating objectClass requirements with no required attributes defined."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "cn": ["Test"]
            })
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            attributes={"cn": {}},
            objectclasses={"person": {}}  # No required_attributes defined
        )

        result = validator.validate_objectclass_requirements(entry, schema)
        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True
        assert len(validation["issues"]) == 0

    def test_validate_objectclass_requirements_non_list_required_attrs(self) -> None:
        """Test validating objectClass requirements with non-list required_attributes."""
        validator = FlextLdifSchemaValidator()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.Dn(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={
                "objectClass": ["person"],
                "cn": ["Test"]
            })
        )

        schema = FlextLdifModels.SchemaDiscoveryResult(
            attributes={"cn": {}},
            objectclasses={"person": {"required_attributes": "invalid"}}  # Non-list
        )

        result = validator.validate_objectclass_requirements(entry, schema)
        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True  # Non-list is ignored
        assert len(validation["issues"]) == 0