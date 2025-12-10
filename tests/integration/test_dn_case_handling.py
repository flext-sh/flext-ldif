"""Integration tests for DN case handling during quirk conversions.

Tests the DN Case Registry system that ensures DN case consistency when
converting between quirks with different case sensitivity (OID vs OUD).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import ClassVar

import pytest

from flext_ldif.models import m
from tests import GenericFieldsDict, s


class TestDnCaseRegistry(s):
    """Test DN case registry functionality."""

    registry: ClassVar[m.Ldif.DnRegistry]  # pytest fixture

    @pytest.fixture
    def registry(self) -> m.Ldif.DnRegistry:
        """Create fresh DN registry."""
        return m.Ldif.DnRegistry()

    def test_register_dn_first_becomes_canonical(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test that first registered DN becomes canonical case."""
        canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")
        assert canonical == "CN=Admin,DC=Example,DC=Com"

        # Second registration with different case returns canonical
        second = registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert second == "CN=Admin,DC=Example,DC=Com"

    def test_register_dn_with_force_override(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test forcing new canonical case."""
        registry.register_dn("CN=Admin,DC=Com")
        canonical = registry.register_dn("cn=ADMIN,dc=COM", force=True)
        assert canonical == "cn=ADMIN,dc=COM"

    def test_get_canonical_dn_case_insensitive(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test case-insensitive DN lookup."""
        registry.register_dn("cn=test,dc=example,dc=com")

        # All case variants return same canonical
        assert (
            registry.get_canonical_dn("cn=test,dc=example,dc=com")
            == "cn=test,dc=example,dc=com"
        )
        assert (
            registry.get_canonical_dn("CN=Test,DC=Example,DC=Com")
            == "cn=test,dc=example,dc=com"
        )
        assert (
            registry.get_canonical_dn("cn=TEST,dc=EXAMPLE,dc=COM")
            == "cn=test,dc=example,dc=com"
        )

    def test_get_canonical_dn_unknown_returns_none(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test unknown DN returns None."""
        assert registry.get_canonical_dn("cn=unknown,dc=com") is None

    def test_has_dn_case_insensitive(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test DN existence check is case-insensitive."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert registry.has_dn("CN=Admin,DC=Com")
        assert registry.has_dn("cn=ADMIN,dc=COM")
        assert not registry.has_dn("cn=other,dc=com")

    def test_get_case_variants_tracks_all_cases(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test that all case variants are tracked."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")
        registry.register_dn("cn=ADMIN,dc=COM")

        variants = registry.get_case_variants("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert len(variants) == 3
        assert "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com" in variants
        assert "CN=Admin,DC=Com" in variants
        assert "cn=ADMIN,dc=COM" in variants

    def test_validate_oud_consistency_single_case(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test validation passes with single case variant."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.value is True

    def test_validate_oud_consistency_multiple_cases(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test validation detects multiple case variants."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")

        result = registry.validate_oud_consistency()
        assert result.is_success
        # validate_oud_consistency returns False when inconsistencies are detected
        assert result.value is False

    def test_normalize_dn_references_single_dn(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test normalizing single DN field."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        data: GenericFieldsDict = {"dn": "CN=Admin,DC=Com", "cn": ["REDACTED_LDAP_BIND_PASSWORD"]}
        result = registry.normalize_dn_references(data, ["dn"])

        assert result.is_success
        normalized = result.value
        assert normalized["dn"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        assert normalized["cn"] == ["REDACTED_LDAP_BIND_PASSWORD"]  # Non-DN field unchanged

    def test_normalize_dn_references_list_of_dns(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test normalizing list of DNs (e.g., group members)."""
        registry.register_dn("cn=user1,dc=com")
        registry.register_dn("cn=user2,dc=com")

        data: GenericFieldsDict = {
            "dn": "cn=group,dc=com",
            "member": ["CN=User1,DC=Com", "cn=USER2,dc=com"],
        }
        result = registry.normalize_dn_references(data, ["dn", "member"])

        assert result.is_success
        normalized = result.value
        assert normalized["member"] == ["cn=user1,dc=com", "cn=user2,dc=com"]

    def test_normalize_dn_references_unregistered_dn_unchanged(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test that unregistered DNs are left unchanged."""
        data: GenericFieldsDict = {"dn": "cn=unknown,dc=com"}
        result = registry.normalize_dn_references(data, ["dn"])

        assert result.is_success
        normalized = result.value
        assert normalized["dn"] == "cn=unknown,dc=com"  # Unchanged

    def test_clear_removes_all_registrations(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test clearing registry removes all DNs."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("cn=user,dc=com")

        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.clear()
        assert not registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert not registry.has_dn("cn=user,dc=com")

    def test_get_stats(self, registry: m.Ldif.DnRegistry) -> None:
        """Test registry statistics."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")  # Same DN, different case
        registry.register_dn("cn=user,dc=com")

        stats = registry.get_stats()
        assert stats["total_dns"] == 2  # Two unique DNs
        assert stats["total_variants"] == 3  # Three total variants
        assert stats["dns_with_multiple_variants"] == 1  # One DN with multiple variants


class TestDnCaseNormalizationScenarios:
    """Test various DN case normalization scenarios."""

    @pytest.fixture
    def registry(self) -> m.Ldif.DnRegistry:
        """Create DN registry."""
        return m.Ldif.DnRegistry()

    def test_multiple_references_to_same_dn_different_cases(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test tracking multiple case variants of same DN."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")  # First variant
        registry.register_dn("CN=Admin,DC=Com")  # Second variant
        registry.register_dn("cn=ADMIN,dc=COM")  # Third variant

        # All should resolve to first registered (canonical)
        canonical = registry.get_canonical_dn("CN=ADMIN,DC=COM")
        assert canonical == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"

        # Validation should detect inconsistencies
        result = registry.validate_oud_consistency()
        assert result.is_success
        # validate_oud_consistency returns False when inconsistencies are detected
        assert result.value is False

    def test_hierarchical_dn_references(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test DN case consistency in hierarchical structure."""
        # Register parent DN
        registry.register_dn("dc=example,dc=com")

        # Register child DN
        registry.register_dn("ou=users,dc=example,dc=com")

        # Register entry under child
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com")

        # All should be retrievable
        assert registry.has_dn("dc=example,dc=com")
        assert registry.has_dn("ou=users,dc=example,dc=com")
        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com")

        # No inconsistencies (each DN used once)
        result = registry.validate_oud_consistency()
        assert result.value is True


__all__ = [
    "TestConversionMatrixDnHandling",
    "TestDnCaseNormalizationScenarios",
    "TestDnCaseRegistry",
]
