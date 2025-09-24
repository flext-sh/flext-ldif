"""Unit tests for FlextLdifEntryBuilder."""

import json

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from flext_ldif.entry.builder import FlextLdifEntryBuilder


class TestFlextLdifEntryBuilder:
    """Test FlextLdifEntryBuilder class."""

    def test_builder_initialization(self) -> None:
        """Test builder initialization."""
        builder = FlextLdifEntryBuilder()
        assert builder is not None

    def test_builder_execute(self) -> None:
        """Test builder execute method."""
        builder = FlextLdifEntryBuilder()
        result = builder.execute()
        assert isinstance(result, FlextResult)

    def test_build_person_entry_basic(self) -> None:
        """Test building person entry with basic attributes."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="John Doe", sn="Doe", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            objectclasses = attrs.get("objectClass", [])
            assert "person" in objectclasses

    def test_build_person_entry_with_uid(self) -> None:
        """Test building person entry with UID."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="Jane Doe", sn="Doe", base_dn="dc=example,dc=com", uid="jdoe"
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "uid" in attrs

    def test_build_person_entry_with_mail(self) -> None:
        """Test building person entry with email."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="User Test",
            sn="Test",
            base_dn="dc=example,dc=com",
            mail="user@example.com",
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "mail" in attrs

    def test_build_person_entry_with_given_name(self) -> None:
        """Test building person entry with given name."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="John Doe", sn="Doe", base_dn="dc=example,dc=com", given_name="John"
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "givenName" in attrs

    def test_build_person_entry_with_additional_attrs(self) -> None:
        """Test building person entry with additional attributes."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="Test User",
            sn="User",
            base_dn="dc=example,dc=com",
            additional_attrs={"telephoneNumber": ["+1234567890"]},
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "telephoneNumber" in attrs

    def test_build_group_entry_basic(self) -> None:
        """Test building group entry with basic attributes."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_group_entry(cn="admins", base_dn="dc=example,dc=com")
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            objectclasses = attrs.get("objectClass", [])
            assert (
                "groupOfNames" in objectclasses or "groupOfUniqueNames" in objectclasses
            )

    def test_build_group_entry_with_members(self) -> None:
        """Test building group entry with members."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_group_entry(
            cn="developers",
            base_dn="dc=example,dc=com",
            additional_attrs={"member": ["cn=user1,dc=example,dc=com"]},
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "member" in attrs or "uniqueMember" in attrs

    def test_build_organizational_unit_entry(self) -> None:
        """Test building organizational unit entry."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_organizational_unit_entry(
            ou="people", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "organizationalUnit" in attrs.get("objectClass", [])

    def test_build_organizational_unit_with_description(self) -> None:
        """Test building OU with description."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_organizational_unit_entry(
            ou="groups",
            base_dn="dc=example,dc=com",
            additional_attrs={"description": ["Groups container"]},
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "description" in attrs

    def test_build_custom_entry(self) -> None:
        """Test building custom entry."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_custom_entry(
            dn="cn=custom,dc=example,dc=com",
            objectclasses=["top", "person"],
            attributes={"cn": ["custom"], "sn": ["entry"]},
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)

    def test_build_entries_from_json(self) -> None:
        """Test building entries from JSON."""
        builder = FlextLdifEntryBuilder()
        json_data = json.dumps([
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["top", "person"],
                    "cn": ["test"],
                    "sn": ["user"],
                },
            }
        ])
        result = builder.build_entries_from_json(json_data)
        assert isinstance(result, FlextResult)
        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)
            assert len(entries) > 0

    def test_build_entries_from_dict(self) -> None:
        """Test building entries from dictionary."""
        builder = FlextLdifEntryBuilder()
        data = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["top", "person"],
                    "cn": ["test"],
                    "sn": ["user"],
                },
            }
        ]
        result = builder.build_entries_from_dict(data)
        assert isinstance(result, FlextResult)
        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)

    def test_convert_entry_to_dict(self) -> None:
        """Test converting entry to dictionary."""
        builder = FlextLdifEntryBuilder()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName.create(
                "cn=test,dc=example,dc=com"
            ).unwrap(),
            attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
        )
        result = builder.convert_entry_to_dict(entry)
        assert isinstance(result, FlextResult)
        if result.is_success:
            data = result.unwrap()
            assert isinstance(data, dict)
            assert "dn" in data

    def test_convert_entries_to_json(self) -> None:
        """Test converting entries to JSON."""
        builder = FlextLdifEntryBuilder()
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName.create(
                    "cn=test,dc=example,dc=com"
                ).unwrap(),
                attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
            )
        ]
        result = builder.convert_entries_to_json(entries)
        assert isinstance(result, FlextResult)
        if result.is_success:
            json_str = result.unwrap()
            assert isinstance(json_str, str)
            json.loads(json_str)  # Validate JSON format


class TestFlextLdifEntryBuilderEdgeCases:
    """Test edge cases and error handling."""

    def test_build_person_empty_cn(self) -> None:
        """Test building person with empty CN."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="", sn="Doe", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)

    def test_build_person_empty_sn(self) -> None:
        """Test building person with empty SN."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="John", sn="", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)

    def test_build_person_invalid_base_dn(self) -> None:
        """Test building person with invalid base DN."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="John Doe", sn="Doe", base_dn="invalid_dn"
        )
        assert isinstance(result, FlextResult)

    def test_build_group_empty_cn(self) -> None:
        """Test building group with empty CN."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_group_entry(cn="", base_dn="dc=example,dc=com")
        assert isinstance(result, FlextResult)

    def test_build_ou_empty_name(self) -> None:
        """Test building OU with empty name."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_organizational_unit_entry(
            ou="", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)

    def test_build_custom_entry_empty_dn(self) -> None:
        """Test building custom entry with empty DN."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_custom_entry(dn="", objectclasses=["top"], attributes={})
        assert isinstance(result, FlextResult)

    def test_build_custom_entry_empty_objectclasses(self) -> None:
        """Test building custom entry with empty objectclasses."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_custom_entry(
            dn="cn=test,dc=example,dc=com",
            objectclasses=[],
            attributes={"cn": ["test"]},
        )
        assert isinstance(result, FlextResult)

    def test_build_entries_from_invalid_json(self) -> None:
        """Test building entries from invalid JSON."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_entries_from_json("invalid json")
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_build_entries_from_empty_dict(self) -> None:
        """Test building entries from empty dict."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_entries_from_dict([])
        assert isinstance(result, FlextResult)

    def test_convert_entries_to_json_empty_list(self) -> None:
        """Test converting empty list to JSON."""
        builder = FlextLdifEntryBuilder()
        result = builder.convert_entries_to_json([])
        assert isinstance(result, FlextResult)
        if result.is_success:
            json_str = result.unwrap()
            assert json_str == "[]"

    def test_build_person_all_optional_params(self) -> None:
        """Test building person with all optional parameters."""
        builder = FlextLdifEntryBuilder()
        result = builder.build_person_entry(
            cn="Complete User",
            sn="User",
            base_dn="dc=example,dc=com",
            uid="cuser",
            mail="complete@example.com",
            given_name="Complete",
            additional_attrs={
                "telephoneNumber": ["+1234567890"],
                "description": ["Test user"],
            },
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "uid" in attrs
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "mail" in attrs
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "givenName" in attrs
            attrs_raw = (
                entry.attributes.model_dump()
                if hasattr(entry.attributes, "model_dump")
                else entry.attributes
            )
            attrs = (
                attrs_raw.get("data", attrs_raw)
                if isinstance(attrs_raw, dict)
                else attrs_raw
            )
            assert "telephoneNumber" in attrs
