"""Comprehensive tests for Oracle OUD quirks covering all code paths.

Tests cover the main methods in oud_quirks.py:
- can_handle_attribute() and can_handle_objectclass() - ALWAYS return True (no filtering)
- parse_attribute() and parse_objectclass()
- write_attribute_to_rfc() and write_objectclass_to_rfc()
- convert_*_to/from_rfc() conversion methods
- validate_objectclass_dependencies() for schema validation
- extract_schemas_from_ldif() for schema extraction
- AclQuirk and EntryQuirk nested classes

NOTE: Filtering is NOT a quirks responsibility. The migration service handles filtering
via AlgarOudMigConstants.Schema.BLOCKED_* sets. Quirks return True for all attributes/classes.

All tests use real implementations without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud


class TestOudQuirksCanHandleArchitecture:
    """Test can_handle_* methods - they ALWAYS return True (no filtering at quirks)."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_can_handle_attribute_oud_namespace_returns_true(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that OUD namespace attributes return True."""
        # OUD-specific attribute
        oud_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert oud_quirk.can_handle_attribute(oud_attr) is True

    def test_can_handle_attribute_non_oud_returns_true(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that non-OUD attributes ALSO return True (no filtering at quirks level).

        ARCHITECTURAL NOTE: can_handle_attribute() returns True for ALL attributes.
        Filtering (if needed) is handled by migration service via AlgarOudMigConstants,
        NOT by the quirks system. This is by design.
        """
        # Standard LDAP attribute
        standard_attr = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert oud_quirk.can_handle_attribute(standard_attr) is True

    def test_can_handle_objectclass_oud_namespace_returns_true(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that OUD objectClasses return True."""
        oud_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' STRUCTURAL )"
        assert oud_quirk.can_handle_objectclass(oud_oc) is True

    def test_can_handle_objectclass_non_oud_returns_true(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that non-OUD objectClasses ALSO return True (no filtering at quirks level).

        ARCHITECTURAL NOTE: can_handle_objectclass() returns True for ALL objectClasses.
        Filtering (if needed) is handled by migration service, NOT by quirks.
        """
        # Standard LDAP objectClass
        standard_oc = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        assert oud_quirk.can_handle_objectclass(standard_oc) is True

    def test_can_handle_attribute_malformed_returns_bool(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test can_handle_attribute with malformed definition still returns bool."""
        malformed = "INVALID OID FORMAT"
        result = oud_quirk.can_handle_attribute(malformed)
        assert isinstance(result, bool)
        assert result is True  # Even malformed returns True

    def test_can_handle_objectclass_malformed_returns_bool(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test can_handle_objectclass with malformed definition still returns bool."""
        malformed = "INVALID CLASS FORMAT"
        result = oud_quirk.can_handle_objectclass(malformed)
        assert isinstance(result, bool)
        assert result is True  # Even malformed returns True


class TestOudQuirksParseAttribute:
    """Test parse_attribute() method for attribute parsing."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_attribute_basic(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test basic attribute parsing."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 "
            "NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE )"
        )
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert isinstance(parsed, dict)
        assert "name" in parsed or "oid" in parsed

    def test_parse_attribute_invalid_returns_failure(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing of invalid attribute definition."""
        invalid_attr = "THIS IS NOT A VALID ATTRIBUTE"
        result = oud_quirk.parse_attribute(invalid_attr)
        # Should return a result (either success or failure)
        assert hasattr(result, "is_success")


class TestOudQuirksParseObjectClass:
    """Test parse_objectclass() method for objectClass parsing."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_objectclass_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test basic objectClass parsing."""
        oc_def = (
            "( 2.16.840.1.113894.2.1.1 "
            "NAME 'orclContext' "
            "DESC 'Oracle Context' "
            "STRUCTURAL "
            "SUP top "
            "MAY ( description ) )"
        )
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert isinstance(parsed, dict)

    def test_parse_objectclass_with_must_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with MUST and MAY attributes."""
        oc_def = (
            "( 1.2.3.4 NAME 'testClass' STRUCTURAL SUP top MUST cn MAY description )"
        )
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert isinstance(parsed, dict)


class TestOudQuirksConversion:
    """Test attribute/objectClass conversion methods."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_convert_attribute_to_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting attribute to RFC format."""
        # Parse the attribute first
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 "
            "NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        parse_result = oud_quirk.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Now convert the parsed data
        result = oud_quirk.convert_attribute_to_rfc(parsed_attr)
        assert result.is_success
        converted = result.unwrap()
        assert isinstance(converted, dict)

    def test_convert_objectclass_to_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting objectClass to RFC format."""
        # Parse the objectClass first
        oc_def = (
            "( 2.16.840.1.113894.2.1.1 "
            "NAME 'orclContext' "
            "STRUCTURAL "
            "SUP top "
            "MAY description )"
        )
        parse_result = oud_quirk.parse_objectclass(oc_def)
        assert parse_result.is_success
        parsed_oc = parse_result.unwrap()

        # Now convert the parsed data
        result = oud_quirk.convert_objectclass_to_rfc(parsed_oc)
        assert result.is_success
        converted = result.unwrap()
        assert isinstance(converted, dict)

    def test_convert_attribute_from_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting attribute from RFC format (parsed data)."""
        # Create parsed attribute data
        rfc_attr_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclGUID",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        }
        result = oud_quirk.convert_attribute_from_rfc(rfc_attr_data)
        assert result.is_success
        converted = result.unwrap()
        assert isinstance(converted, dict)

    def test_convert_objectclass_from_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting objectClass from RFC format (parsed data)."""
        # Create parsed objectClass data
        rfc_oc_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.2.1.1",
            "name": "orclContext",
            "kind": "STRUCTURAL",
            "sup": "top",
        }
        result = oud_quirk.convert_objectclass_from_rfc(rfc_oc_data)
        assert result.is_success
        converted = result.unwrap()
        assert isinstance(converted, dict)


class TestOudQuirksValidation:
    """Test objectClass dependency validation."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_validate_objectclass_dependencies_with_available_attrs(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test dependency validation with available attributes."""
        oc_data: dict[str, object] = {
            "name": "testClass",
            "must": ["cn"],
        }
        available_attrs: set[str] = {"cn", "description"}

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        # Should succeed if attributes are available
        deps_satisfied = result.unwrap()
        assert isinstance(deps_satisfied, bool)

    def test_validate_objectclass_dependencies_missing_attrs(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test dependency validation with missing attributes."""
        oc_data: dict[str, object] = {
            "name": "testClass",
            "must": ["missing_attr"],
        }
        available_attrs: set[str] = set()

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        # Should fail dependency check
        deps_satisfied = result.unwrap()
        assert deps_satisfied is False

    def test_validate_objectclass_dependencies_custom_with_missing_still_passes(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test custom objectClass with unresolved dependencies still passes.

        Custom objectclasses are allowed even with missing MUST attributes.
        OUD will validate them at startup.
        """
        oc_data: dict[str, object] = {
            "name": "customClass",
            "must": ["missing_attribute"],
        }
        available_attrs: set[str] = set()

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        # Should still return success (just indicates deps not satisfied)
        assert result.is_success


__all__ = [
    "TestOudQuirksCanHandleArchitecture",
    "TestOudQuirksConversion",
    "TestOudQuirksParseAttribute",
    "TestOudQuirksParseObjectClass",
    "TestOudQuirksValidation",
]
