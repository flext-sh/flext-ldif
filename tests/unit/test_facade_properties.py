"""Tests for FlextLdif facade property accessors.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif
from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.entry.builder import FlextLdifEntryBuilder
from flext_ldif.schema.builder import FlextLdifSchemaBuilder
from flext_ldif.schema.validator import FlextLdifSchemaValidator


class TestFacadeProperties:
    """Test suite for facade property accessors."""

    @pytest.fixture
    def ldif_facade(self) -> FlextLdif:
        """Create FlextLdif facade instance."""
        return FlextLdif()

    def test_entry_builder_property_returns_class(self, ldif_facade: FlextLdif) -> None:
        """Test that EntryBuilder property returns the builder class."""
        builder_class = ldif_facade.EntryBuilder
        assert builder_class is FlextLdifEntryBuilder
        assert builder_class.__name__ == "FlextLdifEntryBuilder"

    def test_entry_builder_can_be_instantiated(self, ldif_facade: FlextLdif) -> None:
        """Test that EntryBuilder class can be instantiated."""
        builder_class = ldif_facade.EntryBuilder
        builder = builder_class()
        assert isinstance(builder, FlextLdifEntryBuilder)

    def test_entry_builder_can_build_entries(self, ldif_facade: FlextLdif) -> None:
        """Test that EntryBuilder can create entries via facade."""
        builder_class = ldif_facade.EntryBuilder
        builder = builder_class()

        result = builder.build_person_entry(
            cn="John Doe", sn="Doe", base_dn="dc=example,dc=com"
        )

        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "cn=John Doe,dc=example,dc=com"

    def test_schema_builder_property_returns_class(
        self, ldif_facade: FlextLdif
    ) -> None:
        """Test that SchemaBuilder property returns the builder class."""
        builder_class = ldif_facade.SchemaBuilder
        assert builder_class is FlextLdifSchemaBuilder
        assert builder_class.__name__ == "FlextLdifSchemaBuilder"

    def test_schema_builder_can_be_instantiated(self, ldif_facade: FlextLdif) -> None:
        """Test that SchemaBuilder class can be instantiated."""
        builder_class = ldif_facade.SchemaBuilder
        builder = builder_class()
        assert isinstance(builder, FlextLdifSchemaBuilder)

    def test_acl_service_property_returns_class(self, ldif_facade: FlextLdif) -> None:
        """Test that AclService property returns the service class."""
        service_class = ldif_facade.AclService
        assert service_class is FlextLdifAclService
        assert service_class.__name__ == "FlextLdifAclService"

    def test_acl_service_can_be_instantiated(self, ldif_facade: FlextLdif) -> None:
        """Test that AclService class can be instantiated."""
        service_class = ldif_facade.AclService
        service = service_class()
        assert isinstance(service, FlextLdifAclService)

    def test_schema_validator_property_returns_class(
        self, ldif_facade: FlextLdif
    ) -> None:
        """Test that SchemaValidator property returns the validator class."""
        validator_class = ldif_facade.SchemaValidator
        assert validator_class is FlextLdifSchemaValidator
        assert validator_class.__name__ == "FlextLdifSchemaValidator"

    def test_schema_validator_can_be_instantiated(self, ldif_facade: FlextLdif) -> None:
        """Test that SchemaValidator class can be instantiated."""
        validator_class = ldif_facade.SchemaValidator
        validator = validator_class()
        assert isinstance(validator, FlextLdifSchemaValidator)

    def test_all_facade_properties_accessible(self, ldif_facade: FlextLdif) -> None:
        """Test that all facade properties are accessible without errors."""
        # Access all properties to ensure they don't raise exceptions
        _ = ldif_facade.EntryBuilder
        _ = ldif_facade.SchemaBuilder
        _ = ldif_facade.AclService
        _ = ldif_facade.SchemaValidator

        # If we got here, all properties are accessible
        assert True

    def test_facade_properties_are_classes_not_instances(
        self, ldif_facade: FlextLdif
    ) -> None:
        """Test that facade properties return classes, not instances."""
        import inspect

        assert inspect.isclass(ldif_facade.EntryBuilder)
        assert inspect.isclass(ldif_facade.SchemaBuilder)
        assert inspect.isclass(ldif_facade.AclService)
        assert inspect.isclass(ldif_facade.SchemaValidator)
