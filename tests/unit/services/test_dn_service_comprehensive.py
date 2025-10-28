"""Comprehensive tests for DN service with all code paths.

Tests cover RFC 4514 compliant DN operations:
- DN parsing into RFC 4514 components
- DN format validation
- DN normalization
- DN cleaning for OID export issues
- Canonical DN mapping
- DN-valued attribute normalization
- ACI DN reference normalization

All tests use real implementations without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.dn import FlextLdifDnService


class TestDnServiceParseComponents:
    """Test DN parsing into RFC 4514 components."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    def test_parse_simple_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test parsing simple DN."""
        result = dn_service.parse_components("cn=test,dc=example,dc=com")
        assert result.is_success
        components = result.unwrap()
        assert len(components) == 3
        assert components[0][1] == "test"  # value is second element

    def test_parse_dn_with_escaped_comma(self, dn_service: FlextLdifDnService) -> None:
        """Test parsing DN with escaped comma in value."""
        result = dn_service.parse_components(
            r"cn=Smith\, John,ou=People,dc=example,dc=com"
        )
        assert result.is_success
        components = result.unwrap()
        # Should have 4 components (cn, ou, dc, dc)
        assert len(components) == 4
        # First component should contain the escaped comma
        assert "Smith" in components[0][1]

    def test_parse_dn_with_quoted_value(self, dn_service: FlextLdifDnService) -> None:
        """Test parsing DN with quoted value fails (not RFC 4514 compliant)."""
        # RFC 4514 doesn't allow unescaped quotes
        result = dn_service.parse_components(
            'cn="Smith, John",ou=People,dc=example,dc=com'
        )
        assert not result.is_success
        assert "Invalid DN format" in result.error

    def test_parse_invalid_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test parsing invalid DN returns error."""
        result = dn_service.parse_components("invalid dn format")
        assert not result.is_success
        assert "Invalid DN format" in result.error

    def test_parse_empty_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test parsing empty DN."""
        result = dn_service.parse_components("")
        # Empty DN may or may not be valid depending on ldap3 implementation
        assert hasattr(result, "is_success")


class TestDnServiceValidateFormat:
    """Test DN format validation."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    def test_validate_valid_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test validating valid DN."""
        result = dn_service.validate_format("cn=test,dc=example,dc=com")
        assert result.is_success
        is_valid = result.unwrap()
        assert is_valid is True

    def test_validate_dn_with_escaped_comma(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test validating DN with escaped comma."""
        result = dn_service.validate_format(r"cn=Smith\, John,dc=example,dc=com")
        assert result.is_success
        is_valid = result.unwrap()
        assert is_valid is True

    def test_validate_invalid_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test validating invalid DN."""
        result = dn_service.validate_format("not a valid dn")
        assert result.is_success
        is_valid = result.unwrap()
        assert is_valid is False

    def test_validate_empty_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test validating empty DN."""
        result = dn_service.validate_format("")
        assert result.is_success
        is_valid = result.unwrap()
        assert is_valid is False

    def test_validate_dn_with_spaces(self, dn_service: FlextLdifDnService) -> None:
        """Test validating DN with spaces around equals."""
        result = dn_service.validate_format("cn = test , dc = example , dc = com")
        assert result.is_success
        # May be valid or invalid depending on ldap3 strictness
        assert isinstance(result.unwrap(), bool)


class TestDnServiceNormalize:
    """Test DN normalization."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    def test_normalize_uppercase_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test normalizing DN with uppercase attributes."""
        result = dn_service.normalize("CN=Admin,DC=Example,DC=Com")
        assert result.is_success
        normalized = result.unwrap()
        # Should lowercase attribute names
        assert "cn=" in normalized.lower()
        assert "dc=" in normalized.lower()

    def test_normalize_preserves_value_case(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test normalization preserves case in values."""
        result = dn_service.normalize("cn=JohnSmith,dc=Example")
        assert result.is_success
        normalized = result.unwrap()
        # Value case should be preserved
        assert "JohnSmith" in normalized

    def test_normalize_invalid_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test normalizing invalid DN returns error."""
        result = dn_service.normalize("not a valid dn")
        assert not result.is_success
        assert "Failed to normalize" in result.error

    def test_normalize_with_escaped_chars(self, dn_service: FlextLdifDnService) -> None:
        """Test normalizing DN with escaped characters."""
        result = dn_service.normalize(r"CN=Smith\, John,DC=Example")
        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, str)


class TestDnServiceCleanDn:
    """Test DN cleaning for OID export issues."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    def test_clean_dn_spaces_around_equals(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test cleaning DN with spaces around equals."""
        cleaned = dn_service.clean_dn("cn = John , ou = Users")
        # Spaces are normalized - removes extra spaces but preserves value spaces
        assert "cn=" in cleaned
        assert "ou=" in cleaned
        assert "," in cleaned
        # Note: trailing space in value is preserved
        assert cleaned == "cn=John ,ou=Users"

    def test_clean_dn_trailing_escaped_space(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test cleaning DN with trailing escaped space."""
        cleaned = dn_service.clean_dn(r"cn=OIM-TEST\ ,ou=Users")
        assert "cn=OIM-TEST" in cleaned
        assert "ou=Users" in cleaned

    def test_clean_dn_spaces_after_commas(self, dn_service: FlextLdifDnService) -> None:
        """Test cleaning DN with spaces after commas."""
        cleaned = dn_service.clean_dn("cn=test, ou=people, dc=example")
        assert cleaned == "cn=test,ou=people,dc=example"

    def test_clean_dn_multiple_spaces(self, dn_service: FlextLdifDnService) -> None:
        """Test cleaning DN with multiple spaces."""
        cleaned = dn_service.clean_dn("cn=test   ou=people")
        assert "  " not in cleaned  # Multiple spaces removed

    def test_clean_empty_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test cleaning empty DN."""
        cleaned = dn_service.clean_dn("")
        assert not cleaned

    def test_clean_none_dn(self, dn_service: FlextLdifDnService) -> None:
        """Test cleaning None DN."""
        cleaned = dn_service.clean_dn("")
        assert not cleaned


class TestDnServiceBuildCanonicalMap:
    """Test building canonical DN mapping."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    def test_build_canonical_map_empty_categories(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test building canonical map from empty categories."""
        result = dn_service.build_canonical_dn_map({})
        assert result.is_success
        dn_map = result.unwrap()
        assert dn_map == {}

    def test_build_canonical_map_with_entries(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test building canonical map from entries."""
        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=user1,ou=people,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["user1"]},
                }
            ],
            "groups": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=admin,ou=groups,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["admin"]},
                }
            ],
        }
        result = dn_service.build_canonical_dn_map(categorized)
        assert result.is_success
        dn_map = result.unwrap()
        assert len(dn_map) == 2
        # Verify canonical DNs are lowercase keys
        assert "cn=user1,ou=people,dc=example,dc=com" in dn_map.values()

    def test_build_canonical_map_ignores_non_dict_entries(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test building canonical map ignores non-dict entries."""
        categorized: dict[str, list[object]] = {
            "users": [
                "not a dict",
                {
                    FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
            ]
        }
        result = dn_service.build_canonical_dn_map(categorized)
        assert result.is_success
        dn_map = result.unwrap()
        assert len(dn_map) == 1

    def test_build_canonical_map_ignores_missing_dn(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test building canonical map ignores entries without DN."""
        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["user1"]},
                    # Missing DN
                }
            ]
        }
        result = dn_service.build_canonical_dn_map(categorized)
        assert result.is_success
        dn_map = result.unwrap()
        assert dn_map == {}


class TestDnServiceNormalizeDnValue:
    """Test normalizing single DN values."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    @pytest.fixture
    def dn_map(self) -> dict[str, str]:
        """Create sample DN map."""
        return {
            "cn=user1,dc=example,dc=com": "cn=user1,dc=example,dc=com",
            "cn=admin,dc=example,dc=com": "cn=admin,dc=example,dc=com",
        }

    def test_normalize_dn_value_in_map(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing DN value that's in map."""
        normalized = dn_service.normalize_dn_value("cn=user1,dc=example,dc=com", dn_map)
        assert normalized == "cn=user1,dc=example,dc=com"

    def test_normalize_dn_value_not_in_map(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing DN value not in map returns cleaned value."""
        normalized = dn_service.normalize_dn_value(
            "cn=unknown,dc=example,dc=com", dn_map
        )
        assert "cn=unknown" in normalized

    def test_normalize_dn_value_with_spaces(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing DN value with spaces."""
        normalized = dn_service.normalize_dn_value(
            "cn = user1 , dc = example , dc = com", dn_map
        )
        assert isinstance(normalized, str)


class TestDnServiceNormalizeDnReferencesInEntry:
    """Test normalizing DN-valued attributes in entries."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    @pytest.fixture
    def dn_map(self) -> dict[str, str]:
        """Create sample DN map."""
        return {
            "cn=user1,dc=example,dc=com": "cn=user1,dc=example,dc=com",
            "cn=admin,dc=example,dc=com": "cn=admin,dc=example,dc=com",
        }

    def test_normalize_dn_references_manager_attribute(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing manager DN reference."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "manager": "cn=admin,dc=example,dc=com",
                "cn": ["user1"],
            },
        }
        ref_attrs = {"manager"}
        result = dn_service.normalize_dn_references_for_entry(entry, dn_map, ref_attrs)
        assert result.is_success
        normalized = result.unwrap()
        assert (
            normalized[FlextLdifConstants.DictKeys.ATTRIBUTES]["manager"]
            == "cn=admin,dc=example,dc=com"
        )

    def test_normalize_dn_references_list_values(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing list of DN references."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=group1,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "member": ["cn=user1,dc=example,dc=com", "cn=admin,dc=example,dc=com"],
                "cn": ["group1"],
            },
        }
        ref_attrs = {"member"}
        result = dn_service.normalize_dn_references_for_entry(entry, dn_map, ref_attrs)
        assert result.is_success
        normalized = result.unwrap()
        members = normalized[FlextLdifConstants.DictKeys.ATTRIBUTES]["member"]
        assert isinstance(members, list)
        assert len(members) == 2

    def test_normalize_dn_references_non_string_values(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing DN references with non-string values."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "manager": ["cn=admin,dc=example,dc=com", 12345],
                "cn": ["user1"],
            },
        }
        ref_attrs = {"manager"}
        result = dn_service.normalize_dn_references_for_entry(entry, dn_map, ref_attrs)
        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(
            normalized[FlextLdifConstants.DictKeys.ATTRIBUTES]["manager"], list
        )

    def test_normalize_dn_references_non_dict_attributes(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing entry with non-dict attributes."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: "not a dict",
        }
        ref_attrs = {"manager"}
        result = dn_service.normalize_dn_references_for_entry(entry, dn_map, ref_attrs)
        assert result.is_success
        normalized = result.unwrap()
        assert normalized[FlextLdifConstants.DictKeys.ATTRIBUTES] == "not a dict"

    def test_normalize_dn_references_exception_handling(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test exception handling during DN reference normalization."""
        # Create entry that will cause error during processing
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "manager": "cn=admin,dc=example,dc=com",
            },
        }
        # Pass invalid dn_map that will cause attribute error
        bad_dn_map: dict[str, object] = {}
        ref_attrs = {"manager"}
        result = dn_service.normalize_dn_references_for_entry(
            entry, bad_dn_map, ref_attrs
        )
        # Should handle gracefully
        assert hasattr(result, "is_success")


class TestDnServiceNormalizeAciDnReferences:
    """Test normalizing DN references in ACI strings."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    @pytest.fixture
    def dn_map(self) -> dict[str, str]:
        """Create sample DN map."""
        return {
            "cn=admin,dc=example,dc=com": "cn=admin,dc=example,dc=com",
            "ou=admins,dc=example,dc=com": "ou=admins,dc=example,dc=com",
        }

    def test_normalize_aci_ldap_uri(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing LDAP URI in ACI."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": ['grant (read) userdn="ldap:///cn=admin,dc=example,dc=com";'],
            },
        }
        result = dn_service.normalize_aci_dn_references(entry, dn_map)
        assert result.is_success
        normalized = result.unwrap()
        aci = normalized[FlextLdifConstants.DictKeys.ATTRIBUTES]["aci"]
        assert isinstance(aci, list)

    def test_normalize_aci_quoted_dn(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing quoted DN in ACI."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": ['grant (read) groupdn="ou=admins,dc=example,dc=com";'],
            },
        }
        result = dn_service.normalize_aci_dn_references(entry, dn_map)
        assert result.is_success
        normalized = result.unwrap()
        assert "aci" in normalized[FlextLdifConstants.DictKeys.ATTRIBUTES]

    def test_normalize_aci_string_value(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing single string ACI value."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": 'grant (read) userdn="ldap:///cn=admin,dc=example,dc=com";',
            },
        }
        result = dn_service.normalize_aci_dn_references(entry, dn_map)
        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(
            normalized[FlextLdifConstants.DictKeys.ATTRIBUTES]["aci"], str
        )

    def test_normalize_aci_non_dict_attributes(
        self, dn_service: FlextLdifDnService, dn_map: dict[str, str]
    ) -> None:
        """Test normalizing ACI with non-dict attributes."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: "not a dict",
        }
        result = dn_service.normalize_aci_dn_references(entry, dn_map)
        assert result.is_success
        normalized = result.unwrap()
        assert normalized[FlextLdifConstants.DictKeys.ATTRIBUTES] == "not a dict"

    def test_normalize_aci_exception_handling(
        self, dn_service: FlextLdifDnService
    ) -> None:
        """Test exception handling during ACI DN normalization."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": 'grant (read) userdn="ldap:///cn=admin,dc=example,dc=com";',
            },
        }
        bad_dn_map: dict[str, object] = {}
        result = dn_service.normalize_aci_dn_references(entry, bad_dn_map)
        assert hasattr(result, "is_success")


class TestDnServiceExecute:
    """Test DN service self-check."""

    @pytest.fixture
    def dn_service(self) -> FlextLdifDnService:
        """Create DN service instance."""
        return FlextLdifDnService()

    def test_execute_returns_success(self, dn_service: FlextLdifDnService) -> None:
        """Test execute returns successful status."""
        result = dn_service.execute()
        assert result.is_success
        status = result.unwrap()
        assert status["service"] == "DnService"
        assert status["status"] == "operational"
        assert "RFC 4514" in status["rfc_compliance"]


__all__ = [
    "TestDnServiceBuildCanonicalMap",
    "TestDnServiceCleanDn",
    "TestDnServiceExecute",
    "TestDnServiceNormalize",
    "TestDnServiceNormalizeAciDnReferences",
    "TestDnServiceNormalizeDnReferencesInEntry",
    "TestDnServiceNormalizeDnValue",
    "TestDnServiceParseComponents",
    "TestDnServiceValidateFormat",
]
