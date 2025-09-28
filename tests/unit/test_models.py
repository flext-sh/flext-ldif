"""Test suite for FlextLdifModels.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels


class TestFlextLdifModels:
    """Test suite for FlextLdifModels."""

    def test_dn_creation(self) -> None:
        """Test DN model creation."""
        dn = FlextLdifModels.DN(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

    def test_dn_validation(self) -> None:
        """Test DN validation."""
        # Valid DN
        dn = FlextLdifModels.DN(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

        # Empty DN should fail
        with pytest.raises(ValidationError):
            FlextLdifModels.DN(value="")

        # DN too long should fail
        long_dn = "cn=" + "x" * 2048 + ",dc=example,dc=com"
        with pytest.raises(ValidationError):
            FlextLdifModels.DN(value=long_dn)

    def test_dn_normalization(self) -> None:
        """Test DN normalization."""
        # Test case normalization
        dn = FlextLdifModels.DN(value="CN=Test,DC=Example,DC=Com")
        assert dn.value == "CN=Test,DC=Example,DC=Com"  # Should preserve case

    def test_attribute_values_creation(self) -> None:
        """Test AttributeValues model creation."""
        values = FlextLdifModels.AttributeValues(values=["value1", "value2"])
        assert values.values == ["value1", "value2"]

    def test_attribute_values_validation(self) -> None:
        """Test AttributeValues validation."""
        # Valid values
        values = FlextLdifModels.AttributeValues(values=["value1", "value2"])
        assert len(values.values) == 2

        # Empty values should be allowed
        empty_values = FlextLdifModels.AttributeValues(values=[])
        assert empty_values.values == []

    def test_attribute_values_single_value(self) -> None:
        """Test AttributeValues single value property."""
        values = FlextLdifModels.AttributeValues(values=["single_value"])
        assert values.single_value == "single_value"

        empty_values = FlextLdifModels.AttributeValues(values=[])
        assert empty_values.single_value is None

    def test_attributes_creation(self) -> None:
        """Test Attributes model creation."""
        attrs = FlextLdifModels.Attributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
                "sn": FlextLdifModels.AttributeValues(values=["user"]),
            }
        )
        assert len(attrs.attributes) == 2
        assert "cn" in attrs.attributes
        assert "sn" in attrs.attributes

    def test_attributes_get_attribute(self) -> None:
        """Test getting attributes by name."""
        attrs = FlextLdifModels.Attributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )

        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test"]

        # Non-existent attribute
        missing_attr = attrs.get_attribute("missing")
        assert missing_attr is None

    def test_attributes_add_attribute(self) -> None:
        """Test adding attributes."""
        attrs = FlextLdifModels.Attributes(attributes={})

        attrs.add_attribute("cn", "test")
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test"]

    def test_attributes_add_attribute_multiple_values(self) -> None:
        """Test adding attributes with multiple values."""
        attrs = FlextLdifModels.Attributes(attributes={})

        attrs.add_attribute("cn", ["test1", "test2"])
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test1", "test2"]

    def test_attributes_remove_attribute(self) -> None:
        """Test removing attributes."""
        attrs = FlextLdifModels.Attributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )

        attrs.remove_attribute("cn")
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is None

    def test_attributes_remove_nonexistent_attribute(self) -> None:
        """Test removing non-existent attribute."""
        attrs = FlextLdifModels.Attributes(attributes={})

        # Should not raise error
        attrs.remove_attribute("nonexistent")

    def test_entry_creation(self) -> None:
        """Test Entry model creation."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert "cn" in entry.attributes.attributes

    def test_entry_validation(self) -> None:
        """Test Entry validation."""
        # Valid entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(attributes={}),
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_entry_from_ldif_string(self) -> None:
        """Test creating entry from LDIF string."""
        ldif_string = """dn: cn=test,dc=example,dc=com
cn: test
sn: user
"""

        result = FlextLdifModels.Entry.from_ldif_string(ldif_string)
        assert isinstance(result, FlextResult)
        assert result.is_success

        entry = result.value
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert entry.attributes.get_attribute("cn") is not None
        assert entry.attributes.get_attribute("sn") is not None

    def test_entry_from_ldif_string_invalid(self) -> None:
        """Test creating entry from invalid LDIF string."""
        invalid_ldif = "invalid ldif content"

        result = FlextLdifModels.Entry.from_ldif_string(invalid_ldif)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_entry_from_ldif_string_empty(self) -> None:
        """Test creating entry from empty LDIF string."""
        result = FlextLdifModels.Entry.from_ldif_string("")
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_entry_to_ldif_string(self) -> None:
        """Test converting entry to LDIF string."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "sn": FlextLdifModels.AttributeValues(values=["user"]),
                }
            ),
        )

        ldif_string = entry.to_ldif_string()
        assert isinstance(ldif_string, str)
        assert "dn: cn=test,dc=example,dc=com" in ldif_string
        assert "cn: test" in ldif_string
        assert "sn: user" in ldif_string

    def test_entry_to_ldif_string_with_indent(self) -> None:
        """Test converting entry to LDIF string with indentation."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )

        ldif_string = entry.to_ldif_string(indent=4)
        assert isinstance(ldif_string, str)
        assert "dn: cn=test,dc=example,dc=com" in ldif_string

    def test_search_config_creation(self) -> None:
        """Test SearchConfig model creation."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn"],
        )
        assert config.base_dn == "dc=example,dc=com"
        assert config.search_filter == "(objectClass=person)"
        assert config.attributes == ["cn", "sn"]

    def test_search_config_validation(self) -> None:
        """Test SearchConfig validation."""
        # Valid config
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn"],
        )
        assert config.base_dn == "dc=example,dc=com"

        # Empty base_dn should fail
        with pytest.raises(ValidationError):
            FlextLdifModels.SearchConfig(
                base_dn="",
                search_filter="(objectClass=person)",
                attributes=["cn"],
            )

    def test_search_config_default_filter(self) -> None:
        """Test SearchConfig with default filter."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            attributes=["cn", "sn"],
        )
        assert config.search_filter == "(objectClass=*)"

    def test_search_config_empty_attributes(self) -> None:
        """Test SearchConfig with empty attributes."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=[],
        )
        assert config.attributes == []

    def test_ldif_document_creation(self) -> None:
        """Test LdifDocument model creation."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DN(value="cn=test1,dc=example,dc=com"),
                attributes=FlextLdifModels.Attributes(attributes={}),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DN(value="cn=test2,dc=example,dc=com"),
                attributes=FlextLdifModels.Attributes(attributes={}),
            ),
        ]

        document = FlextLdifModels.LdifDocument(entries=entries, domain_events=[])
        assert len(document.entries) == 2

    def test_ldif_document_validation(self) -> None:
        """Test LdifDocument validation."""
        # Valid document
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.Attributes(attributes={}),
            ),
        ]

        document = FlextLdifModels.LdifDocument(entries=entries, domain_events=[])
        assert len(document.entries) == 1

    def test_ldif_document_empty(self) -> None:
        """Test LdifDocument with empty entries."""
        document = FlextLdifModels.LdifDocument(entries=[], domain_events=[])
        assert len(document.entries) == 0

    def test_ldif_document_to_string(self) -> None:
        """Test converting LdifDocument to string."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.Attributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    }
                ),
            ),
        ]

        document = FlextLdifModels.LdifDocument(entries=entries, domain_events=[])
        ldif_string = document.to_ldif_string()

        assert isinstance(ldif_string, str)
        assert "dn: cn=test,dc=example,dc=com" in ldif_string
        assert "cn: test" in ldif_string

    def test_ldif_document_from_string(self) -> None:
        """Test creating LdifDocument from string."""
        ldif_string = """dn: cn=test1,dc=example,dc=com
cn: test1

dn: cn=test2,dc=example,dc=com
cn: test2
"""

        result = FlextLdifModels.LdifDocument.from_ldif_string(ldif_string)
        assert isinstance(result, FlextResult)
        assert result.is_success

        document = result.value
        assert len(document.entries) == 2
        assert document.entries[0].dn.value == "cn=test1,dc=example,dc=com"
        assert document.entries[1].dn.value == "cn=test2,dc=example,dc=com"

    def test_ldif_document_from_string_invalid(self) -> None:
        """Test creating LdifDocument from invalid string."""
        invalid_ldif = "invalid ldif content"

        result = FlextLdifModels.LdifDocument.from_ldif_string(invalid_ldif)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_ldif_document_from_string_empty(self) -> None:
        """Test creating LdifDocument from empty string."""
        result = FlextLdifModels.LdifDocument.from_ldif_string("")
        assert isinstance(result, FlextResult)
        assert result.is_success

        document = result.value
        assert len(document.entries) == 0

    def test_model_serialization(self) -> None:
        """Test model serialization."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )

        # Test model_dump
        data = entry.model_dump()
        assert isinstance(data, dict)
        assert data["dn"]["value"] == "cn=test,dc=example,dc=com"

    def test_model_deserialization(self) -> None:
        """Test model deserialization."""
        data = {
            "dn": {"value": "cn=test,dc=example,dc=com"},
            "attributes": {
                "attributes": {
                    "cn": {"values": ["test"]},
                }
            },
        }

        entry = FlextLdifModels.Entry.model_validate(data)
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert entry.attributes.get_attribute("cn") is not None

    def test_model_validation_errors(self) -> None:
        """Test model validation errors."""
        # Invalid DN
        with pytest.raises(ValidationError):
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DN(value=""),  # Empty DN
                attributes=FlextLdifModels.Attributes(attributes={}),
            )

    def test_model_inheritance(self) -> None:
        """Test that models properly inherit from FlextModels."""
        # Test that all models are properly structured
        assert hasattr(FlextLdifModels, "DN")
        assert hasattr(FlextLdifModels, "AttributeValues")
        assert hasattr(FlextLdifModels, "Attributes")
        assert hasattr(FlextLdifModels, "Entry")
        assert hasattr(FlextLdifModels, "SearchConfig")
        assert hasattr(FlextLdifModels, "LdifDocument")

    def test_model_methods(self) -> None:
        """Test that model methods work correctly."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.Attributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )

        # Test that methods exist and are callable
        assert hasattr(entry, "to_ldif_string")
        assert callable(entry.to_ldif_string)

        assert hasattr(FlextLdifModels.Entry, "from_ldif_string")
        assert callable(FlextLdifModels.Entry.from_ldif_string)

        assert hasattr(FlextLdifModels.LdifDocument, "from_ldif_string")
        assert callable(FlextLdifModels.LdifDocument.from_ldif_string)

    def test_edge_cases(self) -> None:
        """Test edge cases in models."""
        # Test DN with special characters
        dn = FlextLdifModels.DN(value="cn=test+user,dc=example,dc=com")
        assert dn.value == "cn=test+user,dc=example,dc=com"

        # Test attributes with special characters
        attrs = FlextLdifModels.Attributes(
            attributes={
                "cn;lang-en": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )
        assert "cn;lang-en" in attrs.attributes

        # Test empty attribute values
        attrs = FlextLdifModels.Attributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=[""]),
            }
        )
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == [""]
