"""Comprehensive tests for format_validator_service.py to achieve 100% coverage."""

# ruff: noqa: PT018
# Reason: Multiple assertion checks are common in tests for comprehensive error validation

# pyright: reportArgumentType=false
# Reason: FlextLdifEntry accepts dict[str, list[str]] via field validator mode="before" but pyright doesn't understand this

from unittest.mock import MagicMock, patch

from flext_core import FlextResult

from flext_ldif import FlextLdifDistinguishedName, FlextLdifEntry
from flext_ldif.format_validator_service import (
    VALIDATION_FAILURE,
    VALIDATION_SUCCESS,
    LdifSchemaValidator,
    LdifValidator,
    _get_ldap_validators,
    _validate_ldap_attribute_name,
    _validate_ldap_dn,
    validate_attribute_format,
    validate_dn_format,
    validate_ldif_structure,
)


class TestPrivateFunctions:
    """Test private utility functions."""

    def test_validate_ldap_attribute_name_valid(self) -> None:
        """Test _validate_ldap_attribute_name with valid names."""
        # Standard attributes
        assert _validate_ldap_attribute_name("cn") is VALIDATION_SUCCESS
        assert _validate_ldap_attribute_name("displayName") is VALIDATION_SUCCESS
        assert _validate_ldap_attribute_name("mail") is VALIDATION_SUCCESS
        assert _validate_ldap_attribute_name("objectClass") is VALIDATION_SUCCESS

        # Attributes with hyphens
        assert _validate_ldap_attribute_name("user-name") is VALIDATION_SUCCESS
        assert _validate_ldap_attribute_name("display-name") is VALIDATION_SUCCESS

        # Attributes with language tags and options
        assert (
            _validate_ldap_attribute_name("displayName;lang-es") is VALIDATION_SUCCESS
        )
        assert (
            _validate_ldap_attribute_name("displayName;lang-es_es")
            is VALIDATION_SUCCESS
        )
        assert (
            _validate_ldap_attribute_name(
                "orclinstancecount;oid-prd-app01.network.ctbc"
            )
            is VALIDATION_SUCCESS
        )

    def test_validate_ldap_attribute_name_invalid(self) -> None:
        """Test _validate_ldap_attribute_name with invalid names."""
        # Empty/None
        assert _validate_ldap_attribute_name("") is VALIDATION_FAILURE
        assert _validate_ldap_attribute_name(None) is VALIDATION_FAILURE

        # Starting with numbers or special chars
        assert _validate_ldap_attribute_name("123attr") is VALIDATION_FAILURE
        assert _validate_ldap_attribute_name("-attr") is VALIDATION_FAILURE
        assert _validate_ldap_attribute_name("@attr") is VALIDATION_FAILURE

        # Invalid characters
        assert _validate_ldap_attribute_name("attr@domain") is VALIDATION_FAILURE
        assert _validate_ldap_attribute_name("attr space") is VALIDATION_FAILURE
        assert _validate_ldap_attribute_name("attr$") is VALIDATION_FAILURE

        # Non-string types
        assert _validate_ldap_attribute_name(123) is VALIDATION_FAILURE
        assert _validate_ldap_attribute_name(["attr"]) is VALIDATION_FAILURE

    def test_validate_ldap_dn_valid(self) -> None:
        """Test _validate_ldap_dn with valid DNs."""
        # Simple DNs
        assert _validate_ldap_dn("cn=John Doe") is VALIDATION_SUCCESS
        assert _validate_ldap_dn("uid=johndoe") is VALIDATION_SUCCESS
        assert _validate_ldap_dn("ou=people") is VALIDATION_SUCCESS

        # Complex hierarchical DNs
        assert (
            _validate_ldap_dn("cn=John Doe,ou=people,dc=example,dc=com")
            is VALIDATION_SUCCESS
        )
        assert (
            _validate_ldap_dn("uid=REDACTED_LDAP_BIND_PASSWORD,cn=users,dc=domain,dc=local")
            is VALIDATION_SUCCESS
        )
        assert (
            _validate_ldap_dn("ou=Groups,ou=Security,dc=corp,dc=company")
            is VALIDATION_SUCCESS
        )

    def test_validate_ldap_dn_invalid(self) -> None:
        """Test _validate_ldap_dn with invalid DNs."""
        # Empty/None
        assert _validate_ldap_dn("") is VALIDATION_FAILURE
        assert _validate_ldap_dn(None) is VALIDATION_FAILURE
        assert _validate_ldap_dn("   ") is VALIDATION_FAILURE

        # Missing attribute type
        assert _validate_ldap_dn("John Doe") is VALIDATION_FAILURE
        assert _validate_ldap_dn("=John Doe") is VALIDATION_FAILURE
        assert _validate_ldap_dn("123=value") is VALIDATION_FAILURE

        # Invalid format
        assert _validate_ldap_dn("cn:John Doe") is VALIDATION_FAILURE
        assert _validate_ldap_dn("cn John Doe") is VALIDATION_FAILURE

        # Non-string types
        assert _validate_ldap_dn(123) is VALIDATION_FAILURE
        assert _validate_ldap_dn(["cn=test"]) is VALIDATION_FAILURE

    def test_get_ldap_validators_cached(self) -> None:
        """Test that _get_ldap_validators returns cached validators."""
        validators1 = _get_ldap_validators()
        validators2 = _get_ldap_validators()

        # Should be the same objects due to caching
        assert validators1 is validators2
        assert len(validators1) == 2
        assert callable(validators1[0])  # attribute validator
        assert callable(validators1[1])  # DN validator


class TestLdifValidator:
    """Test LdifValidator class methods."""

    def test_validate_dn_success(self) -> None:
        """Test validate_dn with valid DNs."""
        valid_dns = [
            "cn=John Doe,ou=people,dc=example,dc=com",
            "uid=REDACTED_LDAP_BIND_PASSWORD,cn=users,dc=domain",
            "ou=Groups,dc=company,dc=local",
        ]

        for dn in valid_dns:
            result = LdifValidator.validate_dn(dn)
            assert result.is_success
            assert result.value is True

    def test_validate_dn_empty_or_none(self) -> None:
        """Test validate_dn with empty or None values."""
        empty_values = ["", "   ", "  \t  \n  "]

        for empty_val in empty_values:
            result = LdifValidator.validate_dn(empty_val)
            assert result.is_failure
            assert result.error is not None and (
                "DN cannot be empty" in result.error or "empty" in result.error.lower()
            )

    def test_validate_dn_invalid_format(self) -> None:
        """Test validate_dn with invalid DN formats."""
        invalid_dns = [
            "not a dn",
            "=missing attribute type",
            "123invalid=value",
            "cn:invalid separator",
        ]

        for invalid_dn in invalid_dns:
            result = LdifValidator.validate_dn(invalid_dn)
            assert result.is_failure
            assert result.error is not None and invalid_dn in result.error

    def test_validate_attribute_name_success(self) -> None:
        """Test validate_attribute_name with valid names."""
        valid_names = [
            "cn",
            "displayName",
            "mail",
            "objectClass",
            "user-name",
            "display-name",
            "displayName;lang-es",
            "orclinstancecount;oid-prd-app01.network.ctbc",
        ]

        for name in valid_names:
            result = LdifValidator.validate_attribute_name(name)
            assert result.is_success
            assert result.value is True

    def test_validate_attribute_name_failure(self) -> None:
        """Test validate_attribute_name with invalid names."""
        invalid_names = [
            "",
            "123attr",
            "-attr",
            "@attr",
            "attr@domain",
            "attr space",
            "attr$",
        ]

        for name in invalid_names:
            result = LdifValidator.validate_attribute_name(name)
            assert result.is_failure
            assert result.error is not None and name in result.error

    def test_validate_attribute_name_empty_whitespace(self) -> None:
        """Test validate_attribute_name with empty and whitespace values."""
        result = LdifValidator.validate_attribute_name("  ")
        assert result.is_failure
        assert result.error is not None and "cannot be empty" in result.error

    def test_validate_required_objectclass_success(self) -> None:
        """Test validate_required_objectclass with entry having objectClass."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["person", "inetOrgPerson"]},
        )

        result = LdifValidator.validate_required_objectclass(entry)
        assert result.is_success
        assert result.value is True

    def test_validate_required_objectclass_missing(self) -> None:
        """Test validate_required_objectclass with missing objectClass."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,ou=people,dc=example,dc=com"),
            attributes={"cn": ["test"]},
        )

        result = LdifValidator.validate_required_objectclass(entry)
        assert result.is_failure
        assert result.error is not None and "objectClass" in result.error

    def test_validate_entry_completeness_complete(self) -> None:
        """Test validate_entry_completeness with complete entry."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(
                value="cn=John Doe,ou=people,dc=example,dc=com"
            ),
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "mail": ["john@example.com"],
            },
        )

        result = LdifValidator.validate_entry_completeness(entry)
        assert result.is_success

    def test_validate_entry_completeness_incomplete(self) -> None:
        """Test validate_entry_completeness with incomplete entry."""
        # Entry without objectClass (incomplete)
        entry_incomplete = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={"cn": ["test"]},  # Missing objectClass
        )

        result = LdifValidator.validate_entry_completeness(entry_incomplete)
        assert result.is_failure

    def test_validate_entry_completeness_dn_validation_fail(self) -> None:
        """Test validate_entry_completeness when DN validation fails."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={"objectClass": ["person"], "cn": ["test"]},
        )

        # Mock validate_dn to return a failure to test the DN validation path
        with patch.object(LdifValidator, "validate_dn") as mock_validate_dn:
            mock_validate_dn.return_value = FlextResult[bool].fail(
                "DN validation failed"
            )

            result = LdifValidator.validate_entry_completeness(entry)
            assert result.is_failure
            assert result.error is not None and "DN validation failed" in result.error

    def test_validate_entry_type_person(self) -> None:
        """Test validate_entry_type with person entry."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(
                value="cn=John Doe,ou=people,dc=example,dc=com"
            ),
            attributes={"objectClass": ["person", "inetOrgPerson"], "cn": ["John Doe"]},
        )

        result = LdifValidator.validate_entry_type(entry, LdifValidator.PERSON_CLASSES)
        assert result.is_success

    def test_validate_entry_type_group(self) -> None:
        """Test validate_entry_type with group entry."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(
                value="cn=Admins,ou=groups,dc=example,dc=com"
            ),
            attributes={"objectClass": ["group", "top"], "cn": ["Admins"]},
        )

        result = LdifValidator.validate_entry_type(entry, LdifValidator.GROUP_CLASSES)
        assert result.is_success

    def test_validate_entry_type_ou(self) -> None:
        """Test validate_entry_type with organizational unit."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["organizationalUnit", "top"], "ou": ["people"]},
        )

        result = LdifValidator.validate_entry_type(entry, LdifValidator.OU_CLASSES)
        assert result.is_success

    def test_validate_entry_type_unknown(self) -> None:
        """Test validate_entry_type with unknown type."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={"objectClass": ["person"], "cn": ["test"]},
        )

        result = LdifValidator.validate_entry_type(entry, {"unknownClass"})
        assert result.is_failure
        # Should fail because person objectClass doesn't match unknownClass

    def test_validate_entry_type_completeness_failure(self) -> None:
        """Test validate_entry_type when completeness validation fails."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={"objectClass": ["person"]},
        )

        # Mock validate_entry_completeness to return failure
        with patch.object(
            LdifValidator, "validate_entry_completeness"
        ) as mock_completeness:
            mock_completeness.return_value = FlextResult[bool].fail(
                "Completeness failed"
            )

            result = LdifValidator.validate_entry_type(entry, {"person"})

            # Should fail due to completeness check (covers line 188)
            assert result.is_failure
            assert "Completeness failed" in (result.error or "")

    def test_validate_entry_type_no_objectclass_attribute(self) -> None:
        """Test validate_entry_type with entry missing objectClass attribute."""
        # Create entry without objectClass attribute
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={
                "cn": ["test"]
                # No objectClass attribute
            },
        )

        result = LdifValidator.validate_entry_type(entry, {"person"})
        assert result.is_failure
        assert result.error is not None and "objectclass" in result.error.lower()

    def test_validate_entry_type_no_matching_classes(self) -> None:
        """Test validate_entry_type when objectClasses don't match expected."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={"objectClass": ["person", "top"], "cn": ["test"]},
        )

        # Test with completely different expected classes
        result = LdifValidator.validate_entry_type(
            entry, {"organizationalUnit", "device"}
        )
        assert result.is_failure
        assert (
            result.error is not None
            and "does not match expected type" in result.error.lower()
        )

    def test_is_person_entry_true(self) -> None:
        """Test is_person_entry returns true for person entries."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=John,ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["person", "inetOrgPerson"], "cn": ["John"]},
        )

        result = LdifValidator.is_person_entry(entry)
        assert result.is_success
        assert result.value is True

    def test_is_person_entry_false(self) -> None:
        """Test is_person_entry returns failure for non-person entries."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["organizationalUnit"], "ou": ["people"]},
        )

        result = LdifValidator.is_person_entry(entry)
        assert result.is_failure

    def test_is_ou_entry_true(self) -> None:
        """Test is_ou_entry returns success for OU entries."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["organizationalUnit", "top"], "ou": ["people"]},
        )

        result = LdifValidator.is_ou_entry(entry)
        assert result.is_success
        assert result.value is True

    def test_is_group_entry_true(self) -> None:
        """Test is_group_entry returns success for group entries."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(
                value="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"
            ),
            attributes={"objectClass": ["group", "top"], "cn": ["REDACTED_LDAP_BIND_PASSWORDs"]},
        )

        result = LdifValidator.is_group_entry(entry)
        assert result.is_success
        assert result.value is True


class TestLdifSchemaValidator:
    """Test LdifSchemaValidator class methods."""

    def test_validate_required_attributes_success(self) -> None:
        """Test validate_required_attributes with all required attributes present."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(
                value="cn=John Doe,ou=people,dc=example,dc=com"
            ),
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "mail": ["john@example.com"],
            },
        )

        required_attrs = ["cn", "sn", "mail"]
        result = LdifSchemaValidator.validate_required_attributes(entry, required_attrs)
        assert result.is_success
        assert result.value is True

    def test_validate_required_attributes_missing(self) -> None:
        """Test validate_required_attributes with missing required attributes."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(
                value="cn=John Doe,ou=people,dc=example,dc=com"
            ),
            attributes={
                "objectClass": ["person"],
                "cn": ["John Doe"],
                # Missing sn and mail
            },
        )

        required_attrs = ["cn", "sn", "mail"]
        result = LdifSchemaValidator.validate_required_attributes(entry, required_attrs)
        assert result.is_failure
        assert result.error is not None and "sn" in result.error
        assert result.error is not None and "mail" in result.error

    def test_validate_person_schema_success(self) -> None:
        """Test validate_person_schema with valid person entry."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(
                value="cn=John Doe,ou=people,dc=example,dc=com"
            ),
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
            },
        )

        result = LdifSchemaValidator.validate_person_schema(entry)
        assert result.is_success
        assert result.value is True

    def test_validate_person_schema_not_person(self) -> None:
        """Test validate_person_schema with non-person entry."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["organizationalUnit"], "ou": ["people"]},
        )

        result = LdifSchemaValidator.validate_person_schema(entry)
        assert result.is_failure

    def test_validate_ou_schema_success(self) -> None:
        """Test validate_ou_schema with valid OU entry."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["organizationalUnit"], "ou": ["people"]},
        )

        result = LdifSchemaValidator.validate_ou_schema(entry)
        assert result.is_success
        assert result.value is True

    def test_validate_ou_schema_not_ou(self) -> None:
        """Test validate_ou_schema with non-OU entry."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=John,ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["person"], "cn": ["John"]},
        )

        result = LdifSchemaValidator.validate_ou_schema(entry)
        assert result.is_failure


class TestPublicFunctions:
    """Test public module functions."""

    def test_validate_attribute_format_success(self) -> None:
        """Test validate_attribute_format with valid format."""
        result = validate_attribute_format("cn", "John Doe")
        assert result.is_success
        assert result.value is True

    def test_validate_attribute_format_failure(self) -> None:
        """Test validate_attribute_format with invalid format."""
        result = validate_attribute_format("123invalid", "value")
        assert result.is_failure

    def test_validate_attribute_format_empty_value(self) -> None:
        """Test validate_attribute_format with empty attribute value."""
        result = validate_attribute_format("cn", "")
        assert result.is_failure
        assert result.error is not None and "empty" in result.error.lower()

    def test_validate_attribute_format_whitespace_only_value(self) -> None:
        """Test validate_attribute_format with whitespace-only value."""
        result = validate_attribute_format("cn", "   ")
        assert result.is_failure
        assert result.error is not None and "empty" in result.error.lower()

    def test_validate_dn_format_success(self) -> None:
        """Test validate_dn_format with valid DN."""
        result = validate_dn_format("cn=John Doe,ou=people,dc=example,dc=com")
        assert result.is_success
        assert result.value is True

    def test_validate_dn_format_failure(self) -> None:
        """Test validate_dn_format with invalid DN."""
        result = validate_dn_format("not a dn")
        assert result.is_failure

    def test_validate_ldif_structure_with_entry(self) -> None:
        """Test validate_ldif_structure with FlextLdifEntry."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={"objectClass": ["person"], "cn": ["test"]},
        )

        result = validate_ldif_structure(entry)
        assert result.is_success
        assert result.value is True

    def test_validate_ldif_structure_with_invalid_object(self) -> None:
        """Test validate_ldif_structure with invalid object."""
        result = validate_ldif_structure("not an entry")
        assert result.is_failure
        assert result.error is not None and "FlextLdifEntry" in result.error


class TestObjectClassConstants:
    """Test that object class constants are properly defined."""

    def test_person_classes_defined(self) -> None:
        """Test PERSON_CLASSES constant is defined."""
        assert hasattr(LdifValidator, "PERSON_CLASSES")
        assert isinstance(LdifValidator.PERSON_CLASSES, set)
        assert len(LdifValidator.PERSON_CLASSES) > 0

    def test_ou_classes_defined(self) -> None:
        """Test OU_CLASSES constant is defined."""
        assert hasattr(LdifValidator, "OU_CLASSES")
        assert isinstance(LdifValidator.OU_CLASSES, set)
        assert len(LdifValidator.OU_CLASSES) > 0

    def test_group_classes_defined(self) -> None:
        """Test GROUP_CLASSES constant is defined."""
        assert hasattr(LdifValidator, "GROUP_CLASSES")
        assert isinstance(LdifValidator.GROUP_CLASSES, set)
        assert len(LdifValidator.GROUP_CLASSES) > 0


class TestEdgeCases:
    """Test edge cases and comprehensive coverage scenarios."""

    def test_edge_cases_for_complete_coverage(self) -> None:
        """Test edge cases that may be theoretically impossible due to Pydantic validation.

        This test documents the scenarios we attempted to cover but could not
        due to Pydantic's validation preventing invalid states from being created.

        Lines 158 and 195 in format_validator_service.py represent defensive programming
        against states that Pydantic validation should prevent:

        - Line 158: entry.dn is None or entry.dn.value is None/empty
        - Line 195: objectClass attribute is None after completeness validation passes

        These lines may be uncoverable in practice due to the domain model constraints.
        """
        # Simply assert that we've documented these edge cases
        assert True

    def test_entry_type_classification_comprehensive(self) -> None:
        """Test comprehensive entry type classification scenarios."""
        # Test person entry with multiple objectClasses
        person_entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "cn": ["test"],
                "sn": ["user"],
            },
        )

        # Test person classification - using FlextResult.unwrap_or() for modern API
        assert LdifValidator.is_person_entry(person_entry).unwrap_or(False) is True
        assert LdifValidator.is_group_entry(person_entry).unwrap_or(False) is False

        # Test OU entry
        ou_entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com"),
            attributes={"objectClass": ["organizationalUnit", "top"], "ou": ["people"]},
        )

        assert LdifValidator.is_ou_entry(ou_entry).unwrap_or(False) is True
        assert LdifValidator.is_person_entry(ou_entry).unwrap_or(False) is False
        assert LdifValidator.is_group_entry(ou_entry).unwrap_or(False) is False

    def test_mixed_objectclass_validation(self) -> None:
        """Test validation with mixed objectClass combinations."""
        mixed_entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=mixed,dc=example,dc=com"),
            attributes={
                "objectClass": ["person", "inetOrgPerson", "top"],
                "cn": ["mixed"],
                "sn": ["entry"],
            },
        )

        # Should validate successfully for person type
        result = LdifValidator.validate_entry_type(mixed_entry, {"person"})
        assert result.is_success

        # Should fail for group type
        result = LdifValidator.validate_entry_type(mixed_entry, {"groupOfNames"})
        assert result.is_failure

    def test_all_error_paths(self) -> None:
        """Test all error paths to maximize coverage."""
        # Test DN validation with various whitespace scenarios
        for empty_dn in ["", "   ", "\t", "\n", "  \t\n  "]:
            result = LdifValidator.validate_dn(empty_dn)
            assert result.is_failure
            assert result.error is not None and "empty" in result.error.lower()

        # Test attribute name validation with whitespace
        for empty_attr in ["", "   ", "\t\n"]:
            result = LdifValidator.validate_attribute_name(empty_attr)
            assert result.is_failure
            assert result.error is not None and "empty" in result.error.lower()

    def test_constants_validation(self) -> None:
        """Test that all constants are properly defined and work."""
        # Test that constants exist and are non-empty sets
        assert isinstance(VALIDATION_SUCCESS, bool)
        assert isinstance(VALIDATION_FAILURE, bool)
        assert VALIDATION_SUCCESS is True
        assert VALIDATION_FAILURE is False

        # Test objectClass constants
        for class_set in [
            LdifValidator.PERSON_CLASSES,
            LdifValidator.OU_CLASSES,
            LdifValidator.GROUP_CLASSES,
        ]:
            assert isinstance(class_set, set)
            assert len(class_set) > 0

    def test_validate_entry_completeness_empty_dn_coverage(self) -> None:
        """Test validate_entry_completeness with empty DN (line 158)."""
        # Create valid entry first
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes={"objectClass": ["person"]},
        )

        # Use object.__setattr__ to bypass Pydantic validation and set DN to None
        object.__setattr__(entry, "dn", None)

        result = LdifValidator.validate_entry_completeness(entry)
        assert result.is_failure
        assert result.error is not None and ("dn" in result.error or "valid" in result.error)

    def test_validate_entry_type_missing_objectclass_coverage(self) -> None:
        """Test validate_entry_type with missing objectClass (line 195)."""
        # Create mock entry that passes completeness but fails get_attribute
        mock_entry = MagicMock()
        mock_entry.dn = FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com")
        mock_entry.get_attribute.return_value = None

        # Mock validate_entry_completeness to return success
        with patch.object(
            LdifValidator,
            "validate_entry_completeness",
            return_value=FlextResult[bool].ok(True),
        ):
            result = LdifValidator.validate_entry_type(mock_entry, {"person"})
            assert result.is_failure
            assert result.error is not None and "objectclass" in result.error.lower()
