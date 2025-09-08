"""Comprehensive tests for format_validator_service.py to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


# ruff: noqa: PT018
# Reason: Multiple assertion checks are common in tests for comprehensive error validation

# pyright: reportArgumentType=false
# Reason: FlextLDIFModels.Entry accepts dict[str, FlextTypes.Core.StringList] via field validator mode="before" but pyright doesn't understand this

from flext_ldif.format_validators import (
    FlextLDIFFormatValidator,
)


class TestFlextLDIFFormatValidator:
    """Test FlextLDIFFormatValidator class methods."""

    def test_validate_ldap_attribute_name_valid(self) -> None:
        """Test attribute name validation through FlextLDIFFormatValidator."""
        # Standard attributes
        assert FlextLDIFFormatValidator._validate_ldap_attribute_name("cn") is True
        assert FlextLDIFFormatValidator._validate_ldap_attribute_name("sn") is True
        assert (
            FlextLDIFFormatValidator._validate_ldap_attribute_name("objectClass")
            is True
        )

        # Attributes with language tags
        assert (
            FlextLDIFFormatValidator._validate_ldap_attribute_name(
                "displayName;lang-en"
            )
            is True
        )
        assert (
            FlextLDIFFormatValidator._validate_ldap_attribute_name(
                "description;lang-pt_BR"
            )
            is True
        )

        # Attributes with OID extensions
        assert (
            FlextLDIFFormatValidator._validate_ldap_attribute_name("attr;oid-1.2.3.4")
            is True
        )

    def test_validate_ldap_attribute_name_invalid(self) -> None:
        """Test attribute name validation with invalid names."""
        # Invalid names
        assert FlextLDIFFormatValidator._validate_ldap_attribute_name("") is False
        assert (
            FlextLDIFFormatValidator._validate_ldap_attribute_name("123invalid")
            is False
        )
        assert (
            FlextLDIFFormatValidator._validate_ldap_attribute_name("invalid@name")
            is False
        )
        assert FlextLDIFFormatValidator._validate_ldap_attribute_name("") is False

    def test_validate_ldap_dn_valid(self) -> None:
        """Test DN validation through FlextLDIFFormatValidator."""
        # Valid DNs
        assert (
            FlextLDIFFormatValidator._validate_ldap_dn(
                "cn=John Doe,ou=people,dc=example,dc=com"
            )
            is True
        )
        assert (
            FlextLDIFFormatValidator._validate_ldap_dn(
                "uid=johndoe,ou=people,dc=example,dc=com"
            )
            is True
        )
        assert FlextLDIFFormatValidator._validate_ldap_dn("dc=example,dc=com") is True

    def test_validate_ldap_dn_invalid(self) -> None:
        """Test DN validation with invalid DNs."""
        # Invalid DNs
        assert FlextLDIFFormatValidator._validate_ldap_dn("") is False
        assert FlextLDIFFormatValidator._validate_ldap_dn("not a dn") is False
        assert FlextLDIFFormatValidator._validate_ldap_dn(None) is False

    def test_get_ldap_validators(self) -> None:
        """Test getting LDAP validators through class method."""
        attr_validator, dn_validator = FlextLDIFFormatValidator.get_ldap_validators()

        # Test that validators work correctly
        assert attr_validator("cn") is True
        assert attr_validator("invalid@name") is False

        assert dn_validator("cn=test,dc=example,dc=com") is True
        assert dn_validator("not a dn") is False
