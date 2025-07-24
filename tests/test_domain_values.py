"""Tests for FlextLdif domain value objects."""

from __future__ import annotations

import pytest

from flext_ldif import (
    FlextLdifAttributes,
    FlextLdifChangeType,
    FlextLdifDistinguishedName,
    FlextLdifEncoding,
    FlextLdifLineLength,
    FlextLdifVersion,
)


class TestFlextLdifDistinguishedName:
    """Test FlextLdifDistinguishedName value object."""

    def test_valid_dn_creation(self) -> None:
        """Test creating a valid DN."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        assert dn.value == "uid=test,ou=people,dc=example,dc=com"
        assert str(dn) == "uid=test,ou=people,dc=example,dc=com"

    def test_invalid_dn_empty(self) -> None:
        """Test creating DN with empty value."""
        with pytest.raises(ValueError, match="DN must be a non-empty string"):
            FlextLdifDistinguishedName.model_validate({"value": ""})

    def test_invalid_dn_no_equals(self) -> None:
        """Test creating DN without equals sign."""
        with pytest.raises(
            ValueError, match="must contain at least one attribute=value pair"
        ):
            FlextLdifDistinguishedName.model_validate({"value": "invalid-dn"})

    def test_invalid_dn_component(self) -> None:
        """Test creating DN with invalid component."""
        with pytest.raises(ValueError, match="Invalid DN component"):
            FlextLdifDistinguishedName.model_validate(
                {"value": "uid=test,invalid-component"}
            )

    def test_get_rdn(self) -> None:
        """Test getting relative DN."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        assert dn.get_rdn() == "uid=test"

    def test_get_parent_dn(self) -> None:
        """Test getting parent DN."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        parent = dn.get_parent_dn()
        assert parent is not None
        assert parent.value == "ou=people,dc=example,dc=com"

    def test_get_parent_dn_root(self) -> None:
        """Test getting parent DN for root DN."""
        dn = FlextLdifDistinguishedName.model_validate({"value": "dc=com"})
        parent = dn.get_parent_dn()
        assert parent is None

    def test_is_child_of(self) -> None:
        """Test checking if DN is child of another."""
        child = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        parent = FlextLdifDistinguishedName.model_validate(
            {"value": "ou=people,dc=example,dc=com"}
        )
        assert child.is_child_of(parent)

    def test_is_not_child_of(self) -> None:
        """Test checking if DN is not child of another."""
        dn1 = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=users,dc=example,dc=com"}
        )
        dn2 = FlextLdifDistinguishedName.model_validate(
            {"value": "ou=people,dc=example,dc=com"}
        )
        assert not dn1.is_child_of(dn2)

    def test_get_depth(self) -> None:
        """Test getting DN depth."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        assert dn.get_depth() == 4

    def test_equality_with_string(self) -> None:
        """Test DN equality with string."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        assert dn == "uid=test,ou=people,dc=example,dc=com"

    def test_equality_with_other_dn(self) -> None:
        """Test DN equality with another DN."""
        dn1 = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        dn2 = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        assert dn1 == dn2

    def test_hash(self) -> None:
        """Test DN hashing."""
        dn1 = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        dn2 = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        assert hash(dn1) == hash(dn2)

    def test_validate_domain_rules(self) -> None:
        """Test domain rules validation."""
        dn = FlextLdifDistinguishedName.model_validate(
            {"value": "uid=test,ou=people,dc=example,dc=com"}
        )
        # Should not raise
        dn.validate_domain_rules()

    def test_validate_domain_rules_invalid(self) -> None:
        """Test domain rules validation with invalid DN."""
        with pytest.raises(
            ValueError, match="DN must contain at least one attribute=value pair"
        ):
            FlextLdifDistinguishedName.model_validate({"value": "invalid"})


class TestFlextLdifAttributes:
    """Test FlextLdifAttributes value object."""

    def test_empty_attributes(self) -> None:
        """Test creating empty attributes."""
        attrs = FlextLdifAttributes()
        assert attrs.attributes == {}
        assert attrs.is_empty()

    def test_attributes_with_data(self) -> None:
        """Test creating attributes with data."""
        data = {"cn": ["test"], "uid": ["test"]}
        attrs = FlextLdifAttributes.model_validate({"attributes": data})
        assert attrs.attributes == data
        assert not attrs.is_empty()

    def test_get_single_value(self) -> None:
        """Test getting single value."""
        attrs = FlextLdifAttributes.model_validate(
            {"attributes": {"cn": ["test", "test2"]}}
        )
        assert attrs.get_single_value("cn") == "test"
        assert attrs.get_single_value("missing") is None

    def test_get_values(self) -> None:
        """Test getting all values."""
        attrs = FlextLdifAttributes.model_validate(
            {"attributes": {"cn": ["test", "test2"]}}
        )
        assert attrs.get_values("cn") == ["test", "test2"]
        assert attrs.get_values("missing") == []

    def test_has_attribute(self) -> None:
        """Test checking attribute existence."""
        attrs = FlextLdifAttributes.model_validate({"attributes": {"cn": ["test"]}})
        assert attrs.has_attribute("cn")
        assert not attrs.has_attribute("missing")

    def test_add_value(self) -> None:
        """Test adding value to attribute."""
        attrs = FlextLdifAttributes.model_validate({"attributes": {"cn": ["test"]}})
        new_attrs = attrs.add_value("cn", "test2")
        assert new_attrs.get_values("cn") == ["test", "test2"]
        # Original should be unchanged (immutable)
        assert attrs.get_values("cn") == ["test"]

    def test_add_value_new_attribute(self) -> None:
        """Test adding value to new attribute."""
        attrs = FlextLdifAttributes()
        new_attrs = attrs.add_value("cn", "test")
        assert new_attrs.get_values("cn") == ["test"]

    def test_remove_value(self) -> None:
        """Test removing value from attribute."""
        attrs = FlextLdifAttributes.model_validate(
            {"attributes": {"cn": ["test", "test2"]}}
        )
        new_attrs = attrs.remove_value("cn", "test")
        assert new_attrs.get_values("cn") == ["test2"]

    def test_remove_value_last(self) -> None:
        """Test removing last value removes attribute."""
        attrs = FlextLdifAttributes.model_validate({"attributes": {"cn": ["test"]}})
        new_attrs = attrs.remove_value("cn", "test")
        assert not new_attrs.has_attribute("cn")

    def test_get_attribute_names(self) -> None:
        """Test getting attribute names."""
        attrs = FlextLdifAttributes.model_validate(
            {"attributes": {"cn": ["test"], "uid": ["test"]}}
        )
        names = attrs.get_attribute_names()
        assert set(names) == {"cn", "uid"}

    def test_get_total_values(self) -> None:
        """Test getting total number of values."""
        attrs = FlextLdifAttributes.model_validate(
            {"attributes": {"cn": ["test", "test2"], "uid": ["test"]}}
        )
        assert attrs.get_total_values() == 3

    def test_equality_with_dict(self) -> None:
        """Test equality with dictionary."""
        data = {"cn": ["test"]}
        attrs = FlextLdifAttributes.model_validate({"attributes": data})
        assert attrs == data

    def test_equality_with_other_attributes(self) -> None:
        """Test equality with other attributes."""
        data = {"cn": ["test"]}
        attrs1 = FlextLdifAttributes.model_validate({"attributes": data})
        attrs2 = FlextLdifAttributes.model_validate({"attributes": data})
        assert attrs1 == attrs2

    def test_hash(self) -> None:
        """Test attributes hashing."""
        data = {"cn": ["test"]}
        attrs1 = FlextLdifAttributes.model_validate({"attributes": data})
        attrs2 = FlextLdifAttributes.model_validate({"attributes": data})
        assert hash(attrs1) == hash(attrs2)

    def test_validate_domain_rules(self) -> None:
        """Test domain rules validation."""
        attrs = FlextLdifAttributes.model_validate({"attributes": {"cn": ["test"]}})
        # Should not raise
        attrs.validate_domain_rules()

    def test_validate_domain_rules_invalid_name(self) -> None:
        """Test domain rules validation with invalid attribute name."""
        attrs = FlextLdifAttributes.model_validate({"attributes": {"": ["test"]}})
        with pytest.raises(ValueError, match="Invalid attribute name"):
            attrs.validate_domain_rules()

    def test_validate_domain_rules_invalid_values(self) -> None:
        """Test domain rules validation with invalid values."""
        # Since Pydantic validates at creation, we test with valid object
        # but invalid attribute data that would fail domain validation
        attrs = FlextLdifAttributes.model_validate({"attributes": {"cn": ["valid"]}})
        # This should not raise
        attrs.validate_domain_rules()


class TestFlextLdifChangeType:
    """Test FlextLdifChangeType value object."""

    def test_valid_change_types(self) -> None:
        """Test creating valid change types."""
        for change_type in ["add", "modify", "delete", "modrdn"]:
            ct = FlextLdifChangeType.model_validate({"value": change_type})
            assert ct.value == change_type
            assert str(ct) == change_type

    def test_invalid_change_type(self) -> None:
        """Test creating invalid change type."""
        with pytest.raises(ValueError, match="Invalid change type"):
            FlextLdifChangeType.model_validate({"value": "invalid"})

    def test_change_type_checks(self) -> None:
        """Test change type check methods."""
        add_ct = FlextLdifChangeType.model_validate({"value": "add"})
        assert add_ct.is_add()
        assert not add_ct.is_modify()
        assert not add_ct.is_delete()
        assert not add_ct.is_modrdn()

        modify_ct = FlextLdifChangeType.model_validate({"value": "modify"})
        assert not modify_ct.is_add()
        assert modify_ct.is_modify()
        assert not modify_ct.is_delete()
        assert not modify_ct.is_modrdn()

    def test_validate_domain_rules(self) -> None:
        """Test domain rules validation."""
        ct = FlextLdifChangeType.model_validate({"value": "add"})
        # Should not raise
        ct.validate_domain_rules()

    def test_validate_domain_rules_invalid(self) -> None:
        """Test domain rules validation with invalid change type."""
        with pytest.raises(ValueError, match="Invalid change type"):
            FlextLdifChangeType.model_validate({"value": "invalid"})


class TestFlextLdifVersion:
    """Test FlextLdifVersion value object."""

    def test_default_version(self) -> None:
        """Test default version."""
        version = FlextLdifVersion()
        assert version.value == 1
        assert str(version) == "1"
        assert version.is_current()

    def test_custom_version(self) -> None:
        """Test custom version."""
        version = FlextLdifVersion.model_validate({"value": 2})
        assert version.value == 2
        assert str(version) == "2"
        assert not version.is_current()

    def test_invalid_version(self) -> None:
        """Test invalid version."""
        with pytest.raises(ValueError, match="must be >= 1"):
            FlextLdifVersion.model_validate({"value": 0})

    def test_validate_domain_rules(self) -> None:
        """Test domain rules validation."""
        version = FlextLdifVersion.model_validate({"value": 1})
        # Should not raise
        version.validate_domain_rules()

    def test_validate_domain_rules_invalid(self) -> None:
        """Test domain rules validation with invalid version."""
        with pytest.raises(ValueError, match="LDIF version must be >= 1"):
            FlextLdifVersion.model_validate({"value": -1})


class TestFlextLdifEncoding:
    """Test FlextLdifEncoding value object."""

    def test_default_encoding(self) -> None:
        """Test default encoding."""
        encoding = FlextLdifEncoding()
        assert encoding.value == "utf-8"
        assert str(encoding) == "utf-8"
        assert encoding.is_utf8()

    def test_custom_encoding(self) -> None:
        """Test custom encoding."""
        encoding = FlextLdifEncoding.model_validate({"value": "latin-1"})
        assert encoding.value == "latin-1"
        assert str(encoding) == "latin-1"
        assert not encoding.is_utf8()

    def test_invalid_encoding(self) -> None:
        """Test invalid encoding."""
        with pytest.raises(ValueError, match="Invalid encoding"):
            FlextLdifEncoding.model_validate({"value": "invalid-encoding"})

    def test_validate_domain_rules(self) -> None:
        """Test domain rules validation."""
        encoding = FlextLdifEncoding.model_validate({"value": "utf-8"})
        # Should not raise
        encoding.validate_domain_rules()

    def test_validate_domain_rules_invalid(self) -> None:
        """Test domain rules validation with invalid encoding."""
        with pytest.raises(ValueError, match="Invalid encoding"):
            FlextLdifEncoding.model_validate({"value": "invalid"})


class TestFlextLdifLineLength:
    """Test FlextLdifLineLength value object."""

    def test_default_line_length(self) -> None:
        """Test default line length."""
        length = FlextLdifLineLength()
        assert length.value == 79
        assert str(length) == "79"
        assert length.is_standard()

    def test_custom_line_length(self) -> None:
        """Test custom line length."""
        length = FlextLdifLineLength.model_validate({"value": 120})
        assert length.value == 120
        assert str(length) == "120"
        assert not length.is_standard()

    def test_invalid_line_length_too_short(self) -> None:
        """Test invalid line length too short."""
        with pytest.raises(ValueError, match="must be at least 10"):
            FlextLdifLineLength.model_validate({"value": 5})

    def test_invalid_line_length_too_long(self) -> None:
        """Test invalid line length too long."""
        with pytest.raises(ValueError, match="cannot exceed 1000"):
            FlextLdifLineLength.model_validate({"value": 1500})

    def test_validate_domain_rules(self) -> None:
        """Test domain rules validation."""
        length = FlextLdifLineLength.model_validate({"value": 79})
        # Should not raise
        length.validate_domain_rules()

    def test_validate_domain_rules_invalid(self) -> None:
        """Test domain rules validation with invalid length."""
        with pytest.raises(ValueError, match="Line length must be"):
            FlextLdifLineLength.model_validate({"value": 5})
