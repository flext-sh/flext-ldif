"""Comprehensive test suite for ObjectClass manager.

This module provides testing for FlextLdifObjectClassManager covering:
- ObjectClass hierarchy resolution
- Required/optional attribute collection
- ObjectClass combination validation
- Structural objectClass validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from flext_ldif.schema.objectclass_manager import FlextLdifObjectClassManager


class TestObjectClassManagerInitialization:
    """Test suite for ObjectClass manager initialization."""

    def test_manager_initialization(self) -> None:
        """Test ObjectClass manager initializes correctly."""
        manager = FlextLdifObjectClassManager()

        assert manager is not None

    def test_manager_execute_returns_success(self) -> None:
        """Test execute method returns success status."""
        manager = FlextLdifObjectClassManager()

        result = manager.execute()

        assert result.is_success
        data = result.unwrap()
        assert data["status"] == "ready"

    def test_manager_execute_returns_success_duplicate(self) -> None:
        """Test execute method returns success status (duplicate test removed in async cleanup)."""
        # NOTE: This was test_manager_execute_async_returns_success
        # Converted to sync-only architecture - async method removed
        # Keeping this as a duplicate of test_manager_execute_returns_success
        manager = FlextLdifObjectClassManager()

        result = manager.execute()

        assert result.is_success
        data = result.unwrap()
        assert data["status"] == "ready"


class TestObjectClassHierarchyResolution:
    """Test suite for objectClass hierarchy resolution."""

    def test_resolve_basic_hierarchy(self) -> None:
        """Test resolving basic objectClass hierarchy."""
        manager = FlextLdifObjectClassManager()

        # Create schema with simple hierarchy
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    superior=["top"],
                    structural=True,
                    required_attributes=["cn", "sn"],
                    optional_attributes=[],
                ),
            },
            attributes={},
        )

        result = manager.resolve_objectclass_hierarchy("person", schema)

        assert result.is_success
        hierarchy = result.unwrap()
        assert "person" in hierarchy
        assert "top" in hierarchy

    def test_resolve_unknown_objectclass(self) -> None:
        """Test resolving unknown objectClass returns base only."""
        manager = FlextLdifObjectClassManager()

        # Empty schema
        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={},
            attributes={},
        )

        result = manager.resolve_objectclass_hierarchy("unknown", schema)

        assert result.is_success
        hierarchy = result.unwrap()
        assert hierarchy == ["unknown"]


class TestRequiredAttributesCollection:
    """Test suite for required attributes collection."""

    def test_get_required_attributes_single_objectclass(self) -> None:
        """Test getting required attributes for single objectClass."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    superior=["top"],
                    structural=True,
                    required_attributes=["cn", "sn"],
                    optional_attributes=["description"],
                ),
            },
            attributes={},
        )

        result = manager.get_all_required_attributes(["person"], schema)

        assert result.is_success
        required = result.unwrap()
        assert "cn" in required
        assert "sn" in required
        assert len(required) == 2

    def test_get_required_attributes_multiple_objectclasses(self) -> None:
        """Test getting required attributes from multiple objectClasses."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    superior=["top"],
                    structural=True,
                    required_attributes=["cn", "sn"],
                    optional_attributes=[],
                ),
                "organizationalPerson": FlextLdifModels.SchemaObjectClass(
                    name="organizationalPerson",
                    oid="2.5.6.7",
                    superior=["person"],
                    structural=True,
                    required_attributes=["cn", "sn", "ou"],
                    optional_attributes=[],
                ),
            },
            attributes={},
        )

        result = manager.get_all_required_attributes(
            ["person", "organizationalPerson"], schema
        )

        assert result.is_success
        required = result.unwrap()
        assert "cn" in required
        assert "sn" in required
        assert "ou" in required

    def test_get_required_attributes_unknown_objectclass(self) -> None:
        """Test getting required attributes for unknown objectClass."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={},
            attributes={},
        )

        result = manager.get_all_required_attributes(["unknown"], schema)

        assert result.is_success
        required = result.unwrap()
        assert len(required) == 0


class TestOptionalAttributesCollection:
    """Test suite for optional attributes collection."""

    def test_get_optional_attributes_single_objectclass(self) -> None:
        """Test getting optional attributes for single objectClass."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    superior=["top"],
                    structural=True,
                    required_attributes=["cn", "sn"],
                    optional_attributes=["description", "telephoneNumber"],
                ),
            },
            attributes={},
        )

        result = manager.get_all_optional_attributes(["person"], schema)

        assert result.is_success
        optional = result.unwrap()
        assert "description" in optional
        assert "telephoneNumber" in optional
        assert len(optional) == 2

    def test_get_optional_attributes_multiple_objectclasses(self) -> None:
        """Test getting optional attributes from multiple objectClasses."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    superior=["top"],
                    structural=True,
                    required_attributes=["cn", "sn"],
                    optional_attributes=["description"],
                ),
                "inetOrgPerson": FlextLdifModels.SchemaObjectClass(
                    name="inetOrgPerson",
                    oid="2.16.840.1.113730.3.2.2",
                    superior=["person"],
                    structural=False,
                    required_attributes=[],
                    optional_attributes=["mail", "displayName"],
                ),
            },
            attributes={},
        )

        result = manager.get_all_optional_attributes(
            ["person", "inetOrgPerson"], schema
        )

        assert result.is_success
        optional = result.unwrap()
        assert "description" in optional
        assert "mail" in optional
        assert "displayName" in optional


class TestObjectClassCombinationValidation:
    """Test suite for objectClass combination validation."""

    def test_validate_single_structural_objectclass(self) -> None:
        """Test validation with single structural objectClass."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    superior=["top"],
                    structural=True,
                    required_attributes=["cn", "sn"],
                    optional_attributes=[],
                ),
            },
            attributes={},
        )

        result = manager.validate_objectclass_combination(["person"], schema)

        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True
        assert validation["structural_count"] == 1
        issues = validation["issues"]
        assert isinstance(issues, list)
        assert len(issues) == 0

    def test_validate_multiple_structural_objectclasses(self) -> None:
        """Test validation fails with multiple structural objectClasses."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    superior=["top"],
                    structural=True,
                    required_attributes=["cn", "sn"],
                    optional_attributes=[],
                ),
                "organizationalUnit": FlextLdifModels.SchemaObjectClass(
                    name="organizationalUnit",
                    oid="2.5.6.5",
                    superior=["top"],
                    structural=True,
                    required_attributes=["ou"],
                    optional_attributes=[],
                ),
            },
            attributes={},
        )

        result = manager.validate_objectclass_combination(
            ["person", "organizationalUnit"], schema
        )

        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is False
        assert validation["structural_count"] == 2
        issues = validation["issues"]
        assert isinstance(issues, list)
        assert len(issues) > 0

    def test_validate_auxiliary_objectclasses(self) -> None:
        """Test validation with auxiliary objectClasses."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    superior=["top"],
                    structural=True,
                    required_attributes=["cn", "sn"],
                    optional_attributes=[],
                ),
                "inetOrgPerson": FlextLdifModels.SchemaObjectClass(
                    name="inetOrgPerson",
                    oid="2.16.840.1.113730.3.2.2",
                    superior=["person"],
                    structural=False,  # Auxiliary
                    required_attributes=[],
                    optional_attributes=["mail"],
                ),
            },
            attributes={},
        )

        result = manager.validate_objectclass_combination(
            ["person", "inetOrgPerson"], schema
        )

        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True
        assert validation["structural_count"] == 1

    def test_validate_unknown_objectclasses(self) -> None:
        """Test validation with unknown objectClasses."""
        manager = FlextLdifObjectClassManager()

        schema = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={},
            attributes={},
        )

        result = manager.validate_objectclass_combination(["unknown"], schema)

        assert result.is_success
        validation = result.unwrap()
        assert validation["valid"] is True
        assert validation["structural_count"] == 0
