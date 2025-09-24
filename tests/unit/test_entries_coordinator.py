"""Unit tests for FlextLdifEntries coordinator."""

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from flext_ldif.entries_coordinator import FlextLdifEntries


class TestFlextLdifEntriesCoordinator:
    """Test FlextLdifEntries coordinator and nested classes."""

    def test_coordinator_initialization(self) -> None:
        """Test coordinator initialization."""
        coordinator = FlextLdifEntries()
        assert coordinator is not None
        assert hasattr(coordinator, "builder")
        assert hasattr(coordinator, "validator")
        assert hasattr(coordinator, "transformer")

    def test_coordinator_execute(self) -> None:
        """Test coordinator execute method."""
        coordinator = FlextLdifEntries()
        result = coordinator.execute()
        assert isinstance(result, FlextResult)

    def test_builder_build_person(self) -> None:
        """Test Builder.build_person method."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_person(
            cn="John Doe", sn="Doe", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)

    def test_builder_build_person_with_attributes(self) -> None:
        """Test Builder.build_person with additional attributes."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_person(
            cn="Jane Doe",
            sn="Doe",
            base_dn="dc=example,dc=com",
            attributes={"mail": ["jane@example.com"]},
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)

    def test_builder_build_group(self) -> None:
        """Test Builder.build_group method."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_group(
            cn="REDACTED_LDAP_BIND_PASSWORDs", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)

    def test_builder_build_group_with_members(self) -> None:
        """Test Builder.build_group with members."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_group(
            cn="developers",
            base_dn="dc=example,dc=com",
            attributes={"member": ["cn=user1,dc=example,dc=com"]},
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)

    def test_builder_build_organizational_unit(self) -> None:
        """Test Builder.build_organizational_unit method."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_organizational_unit(
            ou="people", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)

    def test_builder_build_from_json(self) -> None:
        """Test Builder.build_from_json method."""
        coordinator = FlextLdifEntries()
        json_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "objectClass": ["top", "person"],
                "cn": ["test"],
                "sn": ["user"],
            },
        }
        result = coordinator.builder.build_from_json(json_data)
        assert isinstance(result, FlextResult)

    def test_validator_validate_dn_valid(self) -> None:
        """Test Validator.validate_dn with valid DN."""
        coordinator = FlextLdifEntries()
        result = coordinator.validator.validate_dn("cn=test,dc=example,dc=com")
        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.unwrap() is True

    def test_validator_validate_dn_invalid(self) -> None:
        """Test Validator.validate_dn with invalid DN."""
        coordinator = FlextLdifEntries()
        result = coordinator.validator.validate_dn("invalid_dn_format")
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validator_validate_attributes(self) -> None:
        """Test Validator.validate_attributes method."""
        coordinator = FlextLdifEntries()
        attributes = {"cn": ["test"], "sn": ["user"], "objectClass": ["person"]}
        result = coordinator.validator.validate_attributes(attributes)
        assert isinstance(result, FlextResult)

    def test_validator_validate_objectclasses(self) -> None:
        """Test Validator.validate_objectclasses method."""
        coordinator = FlextLdifEntries()
        objectclasses = ["top", "person", "organizationalPerson"]
        result = coordinator.validator.validate_objectclasses(objectclasses)
        assert isinstance(result, FlextResult)

    def test_validator_validate_entry(self) -> None:
        """Test Validator.validate_entry method."""
        coordinator = FlextLdifEntries()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName.create(
                "cn=test,dc=example,dc=com"
            ).unwrap(),
            attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
        )
        result = coordinator.validator.validate_entry(entry)
        assert isinstance(result, FlextResult)

    def test_transformer_normalize_attributes(self) -> None:
        """Test Transformer.normalize_attributes method."""
        coordinator = FlextLdifEntries()
        attributes = {"CN": ["test"], "SN": ["user"], "ObjectClass": ["person"]}
        result = coordinator.transformer.normalize_attributes(attributes)
        assert isinstance(result, FlextResult)
        if result.is_success:
            normalized = result.unwrap()
            assert isinstance(normalized, dict)

    def test_transformer_adapt_for_server(self) -> None:
        """Test Transformer.adapt_for_server method."""
        coordinator = FlextLdifEntries()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName.create(
                "cn=test,dc=example,dc=com"
            ).unwrap(),
            attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
        )
        result = coordinator.transformer.adapt_for_server(entry, "openldap")
        assert isinstance(result, FlextResult)

    def test_transformer_convert_to_json(self) -> None:
        """Test Transformer.convert_to_json method."""
        coordinator = FlextLdifEntries()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName.create(
                "cn=test,dc=example,dc=com"
            ).unwrap(),
            attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
        )
        result = coordinator.transformer.convert_to_json(entry)
        assert isinstance(result, FlextResult)
        if result.is_success:
            json_data = result.unwrap()
            assert isinstance(json_data, dict)


class TestFlextLdifEntriesEdgeCases:
    """Test edge cases and error handling."""

    def test_builder_person_empty_cn(self) -> None:
        """Test Builder.build_person with empty CN."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_person(
            cn="", sn="Doe", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)

    def test_builder_person_empty_sn(self) -> None:
        """Test Builder.build_person with empty SN."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_person(
            cn="John", sn="", base_dn="dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)

    def test_validator_validate_dn_empty(self) -> None:
        """Test Validator.validate_dn with empty string."""
        coordinator = FlextLdifEntries()
        result = coordinator.validator.validate_dn("")
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_validator_validate_attributes_empty(self) -> None:
        """Test Validator.validate_attributes with empty dict."""
        coordinator = FlextLdifEntries()
        result = coordinator.validator.validate_attributes({})
        assert isinstance(result, FlextResult)

    def test_validator_validate_objectclasses_empty(self) -> None:
        """Test Validator.validate_objectclasses with empty list."""
        coordinator = FlextLdifEntries()
        result = coordinator.validator.validate_objectclasses([])
        assert isinstance(result, FlextResult)

    def test_transformer_normalize_empty_attributes(self) -> None:
        """Test Transformer.normalize_attributes with empty dict."""
        coordinator = FlextLdifEntries()
        result = coordinator.transformer.normalize_attributes({})
        assert isinstance(result, FlextResult)

    def test_transformer_adapt_for_unknown_server(self) -> None:
        """Test Transformer.adapt_for_server with unknown server type."""
        coordinator = FlextLdifEntries()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName.create(
                "cn=test,dc=example,dc=com"
            ).unwrap(),
            attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
        )
        result = coordinator.transformer.adapt_for_server(entry, "unknown_server")
        assert isinstance(result, FlextResult)

    def test_builder_from_json_invalid_structure(self) -> None:
        """Test Builder.build_from_json with invalid JSON structure."""
        coordinator = FlextLdifEntries()
        invalid_json = {"invalid": "structure"}
        result = coordinator.builder.build_from_json(invalid_json)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_builder_group_invalid_base_dn(self) -> None:
        """Test Builder.build_group with invalid base DN."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_group(cn="testgroup", base_dn="invalid_dn")
        assert isinstance(result, FlextResult)

    def test_builder_ou_invalid_base_dn(self) -> None:
        """Test Builder.build_organizational_unit with invalid base DN."""
        coordinator = FlextLdifEntries()
        result = coordinator.builder.build_organizational_unit(
            ou="testou", base_dn="invalid_dn"
        )
        assert isinstance(result, FlextResult)
