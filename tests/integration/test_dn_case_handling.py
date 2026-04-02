"""Integration tests for DN case handling during quirk conversions.

Tests the DN Case Registry system that ensures DN case consistency when
converting between quirks with different case sensitivity (OID vs OUD).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from tests import m


class TestDnCaseRegistry:
    """Test DN case registry functionality."""

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
        second = registry.register_dn("cn=admin,dc=example,dc=com")
        assert second == "CN=Admin,DC=Example,DC=Com"

    def test_register_dn_with_force_override(self, registry: m.Ldif.DnRegistry) -> None:
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

    def test_validate_oud_consistency_single_case(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test validation passes with single case variant."""
        registry.register_dn("cn=admin,dc=com")
        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.value is True

    def test_validate_oud_consistency_multiple_cases(
        self,
        registry: m.Ldif.DnRegistry,
    ) -> None:
        """Test validation detects multiple case variants."""
        registry.register_dn("cn=admin,dc=com")
        registry.register_dn("CN=Admin,DC=Com")
        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.value is False

    def test_clear_removes_all_registrations(self, registry: m.Ldif.DnRegistry) -> None:
        """Test clearing registry removes all DNs."""
        registry.register_dn("cn=admin,dc=com")
        registry.register_dn("cn=user,dc=com")
        assert registry.get_canonical_dn("cn=admin,dc=com") is not None
        registry.clear()
        assert registry.get_canonical_dn("cn=admin,dc=com") is None
        assert registry.get_canonical_dn("cn=user,dc=com") is None


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
        registry.register_dn("cn=admin,dc=com")
        registry.register_dn("CN=Admin,DC=Com")
        registry.register_dn("cn=ADMIN,dc=COM")
        canonical = registry.get_canonical_dn("CN=ADMIN,DC=COM")
        assert canonical == "cn=admin,dc=com"
        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.value is False

    def test_hierarchical_dn_references(self, registry: m.Ldif.DnRegistry) -> None:
        """Test DN case consistency in hierarchical structure."""
        registry.register_dn("dc=example,dc=com")
        registry.register_dn("ou=users,dc=example,dc=com")
        registry.register_dn("cn=admin,ou=users,dc=example,dc=com")
        assert registry.get_canonical_dn("dc=example,dc=com") is not None
        assert registry.get_canonical_dn("ou=users,dc=example,dc=com") is not None
        assert (
            registry.get_canonical_dn("cn=admin,ou=users,dc=example,dc=com") is not None
        )
        result = registry.validate_oud_consistency()
        assert result.value is True


__all__ = ["TestDnCaseNormalizationScenarios", "TestDnCaseRegistry"]
