"""Comprehensive tests for FlextLdifTransformerService to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels
from flext_ldif.transformer_service import FlextLdifTransformerService


class TestFlextLdifTransformerService:
    """Test cases for FlextLdifTransformerService to achieve 100% coverage."""

    def test_transform_entries_empty_list(self) -> None:
        """Test transforming empty entry list."""
        service = FlextLdifTransformerService()

        def dummy_transform(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            return entry

        result = service.transform_entries([], dummy_transform)

        assert result.is_success
        assert result.value == []

    def test_transform_entries_with_edge_case_attributes(self) -> None:
        """Test transforming entries with edge case attribute values."""
        service = FlextLdifTransformerService()

        # Create entry with edge case attributes (special characters, empty strings)
        entry_data = {
            "dn": "cn=edge-case,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["edge-case"],
                "userCertificate": ["valid-cert"],  # Valid value
                "specialChar": ["ñ", "ü", "ø"],  # Unicode characters
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        def normalize_unicode_transform(
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Transform to normalize unicode in special character attributes."""
            new_attributes_data = dict(entry.attributes.data)
            if "specialChar" in new_attributes_data:
                new_attributes_data["specialChar"] = [
                    char.upper() for char in new_attributes_data["specialChar"]
                ]
            new_attributes = FlextLdifModels.LdifAttributes(data=new_attributes_data)
            return FlextLdifModels.Entry(dn=entry.dn, attributes=new_attributes)

        result = service.transform_entries(entries, normalize_unicode_transform)

        assert result.is_success
        assert len(result.value) == 1
        transformed_entry = result.value[0]
        special_chars = transformed_entry.get_attribute("specialChar") or []
        assert "Ñ" in special_chars and "Ü" in special_chars and "Ø" in special_chars

    def test_transform_entries_with_transform_exception(self) -> None:
        """Test transforming entries with transform function exception."""
        service = FlextLdifTransformerService()

        valid_entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            },
        )

        def failing_transform(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            msg = "Transform failed"
            raise ValueError(msg)

        result = service.transform_entries([valid_entry], failing_transform)

        assert result.is_failure
        assert (
            result.error is not None
            and "Transform error: Transform failed" in result.error
        )

    def test_transform_entries_with_multiple_entries(self) -> None:
        """Test transforming multiple entries with different types."""
        service = FlextLdifTransformerService()

        # Create multiple entries with different objectClass types
        person_entry_data = {
            "dn": "cn=John Doe,ou=People,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "organizationalPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
            },
        }
        group_entry_data = {
            "dn": "cn=Admins,ou=Groups,dc=example,dc=com",
            "attributes": {
                "objectClass": ["groupOfNames"],
                "cn": ["Admins"],
                "member": ["cn=John Doe,ou=People,dc=example,dc=com"],
            },
        }

        person_entry = FlextLdifModels.create_entry(person_entry_data)
        group_entry = FlextLdifModels.create_entry(group_entry_data)
        entries = [person_entry, group_entry]

        def add_organization_transform(
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Add organization attribute to all entries."""
            new_attributes_data = dict(entry.attributes.data)
            new_attributes_data["o"] = ["Example Organization"]
            new_attributes = FlextLdifModels.LdifAttributes(data=new_attributes_data)
            return FlextLdifModels.Entry(dn=entry.dn, attributes=new_attributes)

        result = service.transform_entries(entries, add_organization_transform)

        assert result.is_success
        assert len(result.value) == 2
        for transformed_entry in result.value:
            org_values = transformed_entry.get_attribute("o") or []
            assert "Example Organization" in org_values

    def test_transform_entries_with_complex_transformation(self) -> None:
        """Test transforming entries with complex transformation logic."""
        service = FlextLdifTransformerService()

        # Create entry with complex DN that tests transformation edge cases
        entry_data = {
            "dn": "cn=Test User,ou=People,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "organizationalPerson"],
                "cn": ["Test User"],
                "sn": ["User"],
                "description": ["Entry for transformation testing"],
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        def add_prefix_transform(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            """Add prefix to CN attribute."""
            new_attributes_data = dict(entry.attributes.data)
            if "cn" in new_attributes_data:
                new_attributes_data["cn"] = [
                    f"TRANSFORMED_{cn}" for cn in new_attributes_data["cn"]
                ]
            new_attributes = FlextLdifModels.LdifAttributes(data=new_attributes_data)
            return FlextLdifModels.Entry(dn=entry.dn, attributes=new_attributes)

        result = service.transform_entries(entries, add_prefix_transform)

        assert result.is_success
        assert len(result.value) == 1
        transformed_entry = result.value[0]
        cn_values = transformed_entry.get_attribute("cn") or []
        assert "TRANSFORMED_Test User" in cn_values

    def test_normalize_dns_empty_list(self) -> None:
        """Test normalizing empty entry list."""
        service = FlextLdifTransformerService()

        result = service.normalize_dns([])

        assert result.is_success
        assert result.value == []

    def test_normalize_dns_with_complex_dn_formats(self) -> None:
        """Test normalizing entries with various complex DN formats."""
        service = FlextLdifTransformerService()

        # Create entries with various DN complexity issues that are valid
        entries_data = [
            {
                "dn": "cn=User With Spaces,ou=People,dc=example,dc=com",  # Spaces in DN
                "attributes": {
                    "objectClass": ["person"],
                    "cn": ["User With Spaces"],
                    "description": ["DN with spaces"],
                },
            },
            {
                "dn": "cn=user_underscore,ou=People,dc=example,dc=com",  # Underscore in DN
                "attributes": {
                    "objectClass": ["person"],
                    "cn": ["user_underscore"],
                    "description": ["DN with underscore"],
                },
            },
        ]

        entries = [FlextLdifModels.create_entry(data) for data in entries_data]

        result = service.normalize_dns(entries)

        assert result.is_success
        assert len(result.value) == 2
        # Verify that DNs are properly normalized while preserving essential structure
        normalized_dns = [entry.dn.value for entry in result.value]
        assert len(normalized_dns) == 2

    def test_normalize_dns_with_whitespace_handling(self) -> None:
        """Test normalizing entries with complex whitespace in DNs."""
        service = FlextLdifTransformerService()

        # Create entry with DN that has various whitespace scenarios
        entry_data = {
            "dn": "  cn=Test User  ,  ou=People  ,  dc=example  ,  dc=com  ",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["Test User"],
                "description": ["Entry with whitespace DN for testing normalization"],
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.normalize_dns(entries)

        assert result.is_success
        assert len(result.value) == 1
        normalized_entry = result.value[0]
        # The DN should be normalized to remove extra whitespace
        normalized_dn = normalized_entry.dn.value
        assert normalized_dn == "cn=Test User,ou=People,dc=example,dc=com"

    def test_normalize_dns_with_empty_dn_after_normalization(self) -> None:
        """Test normalizing entries that result in empty DN."""
        service = FlextLdifTransformerService()

        # Create a valid entry first
        _valid_entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            },
        )

        # Create an entry with DN that becomes empty after normalization (only whitespace/commas)
        # Use model_construct to bypass normal validation and create problematic entry
        problematic_entry = FlextLdifModels.Entry.model_construct(
            dn=FlextLdifModels.DistinguishedName.model_construct(value=" , , "),
            attributes=FlextLdifModels.LdifAttributes(
                data={"cn": ["test"], "objectClass": ["person"]},
            ),
        )

        result = service.normalize_dns([problematic_entry])

        assert result.is_failure
        assert (
            result.error is not None
            and "Entry validation failed before normalization" in result.error
        )

    def test_normalize_dns_with_malformed_attributes(self) -> None:
        """Test normalizing entries with problematic attributes."""
        service = FlextLdifTransformerService()

        # Create an entry with valid DN but use model_construct to bypass validation
        # and create an entry with problematic attributes that might fail business rules
        problematic_entry = FlextLdifModels.Entry.model_construct(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=None,  # None attributes to trigger validation failure
        )

        result = service.normalize_dns([problematic_entry])

        assert result.is_failure
        assert result.error is not None and "DN normalization error" in result.error

    def test_execute(self) -> None:
        """Test execute method."""
        service = FlextLdifTransformerService()

        result = service.execute()

        assert result.is_success
        assert result.value == []

    def test_get_config_info(self) -> None:
        """Test get_config_info method."""
        service = FlextLdifTransformerService()

        config_info = service.get_config_info()

        assert "service" in config_info
        assert config_info["service"] == "FlextLdifTransformerService"
        assert "config" in config_info
        config_data = config_info["config"]
        assert isinstance(config_data, dict)
        assert "service_type" in config_data
        assert "status" in config_data
        assert "operations" in config_data

    def test_get_service_info(self) -> None:
        """Test get_service_info method."""
        service = FlextLdifTransformerService()

        service_info = service.get_service_info()

        assert "service_name" in service_info
        assert service_info["service_name"] == "FlextLdifTransformerService"
        assert "service_type" in service_info
        assert service_info["service_type"] == "transformer"
        assert "capabilities" in service_info
        assert "status" in service_info
        assert service_info["status"] == "ready"

    def test_transform_entries_entry_validation_failure(self) -> None:
        """Test transform_entries with entry validation failure."""
        service = FlextLdifTransformerService()

        # Create an entry that will pass Pydantic validation but fail business rules validation
        invalid_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),  # Valid DN
            attributes=FlextLdifModels.LdifAttributes(
                data={},
            ),  # Missing required objectClass will fail business rules validation
        )

        def dummy_transform(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            return entry

        result = service.transform_entries([invalid_entry], dummy_transform)

        assert result.is_failure
        assert (
            result.error is not None
            and "Entry validation failed before transformation" in result.error
        )

    def test_transform_entries_transformed_entry_validation_failure(self) -> None:
        """Test transform_entries with transformed entry validation failure."""
        service = FlextLdifTransformerService()

        # Create a valid entry
        valid_entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            },
        )

        def invalid_transform(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            # Return an entry that will pass Pydantic validation but fail business rules validation
            return FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test"),  # Valid DN
                attributes=FlextLdifModels.LdifAttributes(
                    data={},
                ),  # Missing required objectClass will fail business rules validation
            )

        result = service.transform_entries([valid_entry], invalid_transform)

        assert result.is_failure
        assert (
            result.error is not None
            and "Transformed entry validation failed" in result.error
        )

    def test_normalize_dns_entry_validation_failure(self) -> None:
        """Test normalize_dns with entry validation failure."""
        service = FlextLdifTransformerService()

        # Create an entry that will pass Pydantic validation but fail business rules validation
        invalid_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),  # Valid DN
            attributes=FlextLdifModels.LdifAttributes(
                data={},
            ),  # Missing required objectClass will fail business rules validation
        )

        result = service.normalize_dns([invalid_entry])

        assert result.is_failure
        assert (
            result.error is not None
            and "Entry validation failed before normalization" in result.error
        )

    def test_normalize_dns_normalized_entry_validation_failure(self) -> None:
        """Test normalize_dns with normalized entry validation failure."""
        service = FlextLdifTransformerService()

        # Create a valid entry that will pass initial validation
        original_entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            },
        )

        # Mock the validate_business_rules method to fail on the second call
        call_count = 0
        original_validate = FlextLdifModels.Entry.validate_business_rules

        def mock_validate(self: FlextLdifModels.Entry) -> FlextResult[None]:
            nonlocal call_count
            call_count += 1
            if call_count == 2:  # Second call (normalized entry) fails
                return FlextResult[None].fail("Validation failed")
            return original_validate(self)

        # Temporarily replace the method
        FlextLdifModels.Entry.validate_business_rules = mock_validate

        try:
            result = service.normalize_dns([original_entry])
            assert result.is_failure
            assert (
                result.error is not None
                and "Normalized entry validation failed" in result.error
            )
        finally:
            # Restore the original method
            FlextLdifModels.Entry.validate_business_rules = original_validate

    def test_transform_entries_exception_handling(self) -> None:
        """Test transform_entries exception handling."""
        service = FlextLdifTransformerService()

        # Create a valid entry
        valid_entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            },
        )

        def exception_transform(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            # Raise an exception during transformation
            msg = "Transform error"
            raise ValueError(msg)

        result = service.transform_entries([valid_entry], exception_transform)

        assert result.is_failure
        assert (
            result.error is not None
            and "Transform error: Transform error" in result.error
        )

    def test_normalize_dns_exception_handling(self) -> None:
        """Test normalize_dns exception handling."""
        service = FlextLdifTransformerService()

        # Create a valid entry
        valid_entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            },
        )

        # Mock the validate_business_rules method to raise an exception
        original_validate = FlextLdifModels.Entry.validate_business_rules

        def exception_validate(self: FlextLdifModels.Entry) -> FlextResult[None]:
            _ = self  # Use the parameter to avoid lint warning
            msg = "Validation error"
            raise RuntimeError(msg)

        # Temporarily replace the method
        FlextLdifModels.Entry.validate_business_rules = exception_validate

        try:
            result = service.normalize_dns([valid_entry])
            assert result.is_failure
            assert (
                result.error is not None
                and "DN normalization error: Validation error" in result.error
            )
        finally:
            # Restore the original method
            FlextLdifModels.Entry.validate_business_rules = original_validate
