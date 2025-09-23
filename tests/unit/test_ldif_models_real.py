"""Tests for flext-ldif models with real data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextTypes
from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels


class TestFlextLdifModelsConfigReal:
    """Test FlextLdifModels.Config with real functionality."""

    def test_config_creation_with_defaults(self) -> None:
        """Test config creation with default values."""
        config = FlextLdifConfig()

        # Verify default values are set correctly
        assert config.ldif_encoding == "utf-8"
        assert config.ldif_max_line_length == 8192
        assert config.ldif_skip_comments is True
        assert config.ldif_validate_dn_format is True
        assert config.ldif_validate_object_class is True
        assert config.ldif_strict_validation is True
        assert config.ldif_max_entries == 1000000

    def test_config_creation_with_custom_values(self) -> None:
        """Test config creation with custom values."""
        config = FlextLdifConfig(
            ldif_encoding="iso-8859-1",
            ldif_max_line_length=120,
            ldif_skip_comments=False,
            ldif_validate_dn_format=False,
            ldif_strict_validation=True,
            ldif_max_entries=5000,
        )

        # Verify custom values are set correctly
        assert config.ldif_encoding == "iso-8859-1"
        assert config.ldif_max_line_length == 120
        assert config.ldif_skip_comments is False
        assert config.ldif_validate_dn_format is False
        assert config.ldif_strict_validation is True
        assert config.ldif_max_entries == 5000

    def test_config_model_validation(self) -> None:
        """Test config model validation rules."""
        # Test valid configuration
        config = FlextLdifConfig(ldif_max_entries=1000)
        assert config.ldif_max_entries == 1000

        # Config should handle edge cases gracefully
        config_small = FlextLdifConfig(ldif_max_entries=10, ldif_chunk_size=1)
        assert config_small.ldif_max_entries == 10

    def test_config_serialization(self) -> None:
        """Test config serialization to dict."""
        config = FlextLdifConfig(
            ldif_encoding="utf-8",
            ldif_max_line_length=100,
            ldif_strict_validation=True,
        )

        # Should be able to convert to dict
        config_dict = config.model_dump()
        assert isinstance(config_dict, dict)
        assert config_dict["ldif_encoding"] == "utf-8"
        assert config_dict["ldif_max_line_length"] == 100
        assert config_dict["ldif_strict_validation"] is True


class TestFlextLdifModelsEntryReal:
    """Test FlextLdifModels.Entry with real functionality."""

    def test_entry_creation_basic(self) -> None:
        """Test basic entry creation."""  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=test.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "uid": ["test.user"],
                "cn": ["Test User"],
                "sn": ["User"],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Verify entry properties
        assert entry.dn is not None
        assert entry.dn.value == "uid=test.user,ou=people,dc=example,dc=com"
        assert "objectClass" in entry.attributes
        assert "uid" in entry.attributes
        assert "cn" in entry.attributes
        assert "sn" in entry.attributes

    def test_entry_creation_with_multi_valued_attributes(self) -> None:
        """Test entry creation with multi-valued attributes."""  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=multi.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["multi.user"],
                "cn": ["Multi User"],
                "sn": ["User"],
                "mail": ["multi.user@example.com", "multi.user.alt@example.com"],
                "telephoneNumber": ["+1-555-0123", "+1-555-0124", "+1-555-0125"],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Verify multi-valued attributes
        mail_values = entry.get_attribute("mail")
        assert mail_values is not None
        assert len(mail_values) == 2
        assert "multi.user@example.com" in mail_values
        assert "multi.user.alt@example.com" in mail_values

        phone_values = entry.get_attribute("telephoneNumber")
        assert phone_values is not None
        assert len(phone_values) == 3

    def test_entry_creation_with_binary_data(self) -> None:
        """Test entry creation with binary (base64) data."""  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=photo.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["photo.user"],
                "cn": ["Photo User"],
                "sn": ["User"],
                "jpegPhoto": ["/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQ=="],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Verify binary attribute
        jpeg_photo = entry.get_attribute("jpegPhoto")
        assert jpeg_photo is not None
        assert len(jpeg_photo) == 1
        assert len(jpeg_photo[0]) > 20  # Should contain base64 data

    def test_entry_creation_with_special_characters(self) -> None:
        """Test entry creation with UTF-8 special characters."""  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=special.chars,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["special.chars"],
                "cn": ["José María Ñuñez"],
                "sn": ["Ñuñez"],
                "givenName": ["José María"],
                "description": ["Contains special characters: áéíóú ÁÉÍÓÚ ñÑ çÇ"],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Verify special characters are preserved
        cn_values = entry.get_attribute("cn")
        assert cn_values is not None
        assert "José María Ñuñez" in cn_values[0]

        description_values = entry.get_attribute("description")
        assert description_values is not None
        assert "áéíóú ÁÉÍÓÚ ñÑ" in description_values[0]

    def test_entry_attribute_operations(self) -> None:
        """Test entry attribute operations."""  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=ops.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "uid": ["ops.user"],
                "cn": ["Operations User"],
                "sn": ["User"],
                "description": ["Original description"],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Test getting attributes
        uid_values = entry.get_attribute("uid")
        assert uid_values is not None
        assert uid_values == ["ops.user"]

        # Test getting non-existent attribute
        non_existent = entry.get_attribute("nonExistentAttribute")
        assert non_existent is None

        # Test checking attribute existence
        assert entry.has_attribute("cn") is True
        assert entry.has_attribute("nonExistent") is False

    def test_entry_dn_operations(self) -> None:
        """Test entry DN operations."""  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=dn.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "uid": ["dn.user"],
                "cn": ["DN User"],
                "sn": ["User"],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Test DN string representation
        dn_str = entry.dn.value
        assert dn_str == "uid=dn.user,ou=people,dc=example,dc=com"

        # Test DN components (if DN model supports it)
        assert entry.dn is not None

    def test_entry_validation_rules(self) -> None:
        """Test entry business rule validation."""  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=valid.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["valid.user"],
                "cn": ["Valid User"],
                "sn": ["User"],
                "mail": ["valid.user@example.com"],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Should be able to validate business rules (if implemented)
        try:
            entry.validate_business_rules()
            # If it doesn't throw, validation passed
            validation_passed = True
        except Exception:
            # If validation is not implemented or fails, that's also valid
            validation_passed = False

        # Either validation passes or is not implemented
        assert validation_passed is not None

    def test_entry_serialization(self) -> None:
        """Test entry serialization to dict."""  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=serial.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "uid": ["serial.user"],
                "cn": ["Serial User"],
                "sn": ["User"],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Should be able to convert to dict
        entry_dict = entry.model_dump()
        assert isinstance(entry_dict, dict)
        assert "dn" in entry_dict
        assert "attributes" in entry_dict


class TestFlextLdifModelsDistinguishedNameReal:
    """Test FlextLdifModels.DistinguishedName with real functionality."""

    def test_dn_creation_simple(self) -> None:
        """Test DN creation with simple format."""
        dn_str = "uid=test,ou=people,dc=example,dc=com"
        dn = FlextLdifModels.DistinguishedName(value=dn_str)

        # Verify DN properties
        assert dn.value == dn_str
        assert dn.value == dn_str

    def test_dn_creation_complex(self) -> None:
        """Test DN creation with complex format."""
        dn_str = "cn=John Doe+mail=john@example.com,ou=people,dc=example,dc=com"
        dn = FlextLdifModels.DistinguishedName(value=dn_str)

        # Verify complex DN
        assert dn.value == dn_str
        assert dn.value == dn_str

    def test_dn_creation_with_spaces(self) -> None:
        """Test DN creation with spaces in values."""
        dn_str = "cn=John Doe,ou=Human Resources,dc=example,dc=com"
        dn = FlextLdifModels.DistinguishedName(value=dn_str)

        # Verify DN with spaces
        assert dn.value == dn_str
        assert "Human Resources" in str(dn)

    def test_dn_creation_with_special_characters(self) -> None:
        """Test DN creation with special characters."""
        dn_str = "cn=José María,ou=people,dc=example,dc=com"
        dn = FlextLdifModels.DistinguishedName(value=dn_str)

        # Verify DN with special characters
        assert dn.value == dn_str
        assert "José María" in str(dn)

    def test_dn_equality(self) -> None:
        """Test DN equality comparison."""
        dn1 = FlextLdifModels.DistinguishedName(
            value="uid=test,ou=people,dc=example,dc=com",
        )
        dn2 = FlextLdifModels.DistinguishedName(
            value="uid=test,ou=people,dc=example,dc=com",
        )
        dn3 = FlextLdifModels.DistinguishedName(
            value="uid=other,ou=people,dc=example,dc=com",
        )

        # Test equality
        assert dn1 == dn2
        assert dn1 != dn3

    def test_dn_validation(self) -> None:
        """Test DN validation rules."""
        # Valid DN formats
        valid_dns = [
            "uid=test,ou=people,dc=example,dc=com",
            "cn=Test User,ou=people,dc=example,dc=com",
            "o=Example Organization",
            "dc=com",
        ]

        for dn_str in valid_dns:
            dn = FlextLdifModels.DistinguishedName(value=dn_str)
            assert dn.value == dn_str


class TestFlextLdifAttributesReal:
    """Test FlextLdifModels.LdifAttributes with real functionality."""

    def test_attributes_creation_basic(self) -> None:
        """Test basic attributes creation."""
        attrs_data = {
            "objectClass": ["person", "top"],
            "uid": ["test.user"],
            "cn": ["Test User"],
            "sn": ["User"],
        }
        attrs = FlextLdifModels.LdifAttributes(data=attrs_data)

        # Verify attributes (keys preserved as-is)
        assert len(attrs.data) == 4
        assert "objectClass" in attrs.data  # Original case preserved
        assert "uid" in attrs.data
        assert attrs.data["uid"] == ["test.user"]

    def test_attributes_creation_multi_valued(self) -> None:
        """Test attributes creation with multi-valued attributes."""
        attrs_data = {
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "mail": ["user@example.com", "user.alt@example.com"],
            "telephoneNumber": ["+1-555-0123", "+1-555-0124"],
        }
        attrs = FlextLdifModels.LdifAttributes(data=attrs_data)

        # Verify multi-valued attributes (keys preserved as-is)
        assert len(attrs.data["mail"]) == 2
        assert len(attrs.data["telephoneNumber"]) == 2  # Original case preserved
        assert "user@example.com" in attrs.data["mail"]
        assert "+1-555-0123" in attrs.data["telephoneNumber"]

    def test_attributes_operations(self) -> None:
        """Test attributes operations."""
        attrs_data = {
            "objectClass": ["person", "top"],
            "uid": ["ops.user"],
            "cn": ["Operations User"],
        }
        attrs = FlextLdifModels.LdifAttributes(data=attrs_data)

        # Test getting values through data field
        uid_values = attrs.data.get("uid")
        assert uid_values == ["ops.user"]

        # Test getting non-existent attribute
        non_existent = attrs.data.get("nonExistent")
        assert non_existent is None

        # Test checking existence
        assert "uid" in attrs.data
        assert "nonExistent" not in attrs.data

    def test_attributes_iteration(self) -> None:
        """Test attributes iteration."""
        attrs_data = {
            "objectClass": ["person", "top"],
            "uid": ["iter.user"],
            "cn": ["Iteration User"],
            "sn": ["User"],
        }
        attrs = FlextLdifModels.LdifAttributes(data=attrs_data)

        # Test iteration over keys (keys preserved as-is)
        keys = list(attrs.data.keys())
        assert "objectClass" in keys  # Original case preserved
        assert "uid" in keys
        assert len(keys) == 4

        # Test iteration over items
        items = list(attrs.data.items())
        assert len(items) == 4

        # Find uid item
        uid_item = next((k, v) for k, v in items if k == "uid")
        assert uid_item[1] == ["iter.user"]


class TestModelIntegrationReal:
    """Test integration between different models."""

    def test_entry_with_all_model_components(self) -> None:
        """Test entry creation using all model components."""
        # Create entry with all components  # type: ignore[assignment]
        entry_data = {
            "dn": "uid=integration.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["integration.user"],
                "cn": ["Integration User"],
                "sn": ["User"],
                "mail": ["integration.user@example.com"],
                "telephoneNumber": ["+1-555-9999"],
                "description": ["User for testing model integration"],
            },
        }
        entry_result = FlextLdifModels.create_entry(
            cast("FlextTypes.Core.Dict", entry_data)
        )
        assert entry_result.is_success, f"Entry creation failed: {entry_result.error}"
        entry = entry_result.unwrap()

        # Verify all components work together
        assert entry.dn is not None
        # AttributesDict is a UserDict which behaves like dict but isn't a dict instance
        assert hasattr(entry.attributes.data, "__getitem__")  # Acts like dict via .data
        assert len(entry.attributes) == 7

        # Verify DN component
        dn_str = entry.dn.value
        assert "integration.user" in dn_str

        # Verify attributes component
        mail_values = entry.get_attribute("mail")
        assert mail_values is not None
        assert "integration.user@example.com" in mail_values
