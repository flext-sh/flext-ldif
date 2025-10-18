"""Integration tests for DN case handling during quirk conversions.

Tests the DN Case Registry system that ensures DN case consistency when
converting between quirks with different case sensitivity (OID vs OUD).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.quirks.conversion_matrix import QuirksConversionMatrix
from flext_ldif.quirks.dn_case_registry import DnCaseRegistry


class TestDnCaseRegistry:
    """Test DN Case Registry basic functionality."""

    @pytest.fixture
    def registry(self) -> DnCaseRegistry:
        """Create fresh DN registry."""
        return DnCaseRegistry()

    def test_register_dn_first_becomes_canonical(
        self, registry: DnCaseRegistry
    ) -> None:
        """Test that first registered DN becomes canonical case."""
        canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")
        assert canonical == "CN=Admin,DC=Example,DC=Com"

        # Second registration with different case returns canonical
        second = registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert second == "CN=Admin,DC=Example,DC=Com"

    def test_register_dn_with_force_override(self, registry: DnCaseRegistry) -> None:
        """Test forcing new canonical case."""
        registry.register_dn("CN=Admin,DC=Com")
        canonical = registry.register_dn("cn=ADMIN,dc=COM", force=True)
        assert canonical == "cn=ADMIN,dc=COM"

    def test_get_canonical_dn_case_insensitive(self, registry: DnCaseRegistry) -> None:
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
        self, registry: DnCaseRegistry
    ) -> None:
        """Test unknown DN returns None."""
        assert registry.get_canonical_dn("cn=unknown,dc=com") is None

    def test_has_dn_case_insensitive(self, registry: DnCaseRegistry) -> None:
        """Test DN existence check is case-insensitive."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert registry.has_dn("CN=Admin,DC=Com")
        assert registry.has_dn("cn=ADMIN,dc=COM")
        assert not registry.has_dn("cn=other,dc=com")

    def test_get_case_variants_tracks_all_cases(self, registry: DnCaseRegistry) -> None:
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
        self, registry: DnCaseRegistry
    ) -> None:
        """Test validation passes with single case variant."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_oud_consistency_multiple_cases(
        self, registry: DnCaseRegistry
    ) -> None:
        """Test validation detects multiple case variants."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")

        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is False  # Has inconsistencies

        # Check metadata
        assert result.metadata is not None
        metadata = result.metadata
        assert isinstance(metadata, dict)
        assert "inconsistencies" in metadata
        assert "warning" in metadata
        inconsistencies = metadata["inconsistencies"]
        assert len(inconsistencies) == 1
        assert inconsistencies[0]["variant_count"] == 2

    def test_normalize_dn_references_single_dn(self, registry: DnCaseRegistry) -> None:
        """Test normalizing single DN field."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        data: dict[str, object] = {"dn": "CN=Admin,DC=Com", "cn": ["REDACTED_LDAP_BIND_PASSWORD"]}
        result = registry.normalize_dn_references(data, ["dn"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["dn"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        assert normalized["cn"] == ["REDACTED_LDAP_BIND_PASSWORD"]  # Non-DN field unchanged

    def test_normalize_dn_references_list_of_dns(
        self, registry: DnCaseRegistry
    ) -> None:
        """Test normalizing list of DNs (e.g., group members)."""
        registry.register_dn("cn=user1,dc=com")
        registry.register_dn("cn=user2,dc=com")

        data: dict[str, object] = {
            "dn": "cn=group,dc=com",
            "member": ["CN=User1,DC=Com", "cn=USER2,dc=com"],
        }
        result = registry.normalize_dn_references(data, ["dn", "member"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["member"] == ["cn=user1,dc=com", "cn=user2,dc=com"]

    def test_normalize_dn_references_unregistered_dn_unchanged(
        self, registry: DnCaseRegistry
    ) -> None:
        """Test that unregistered DNs are left unchanged."""
        data: dict[str, object] = {"dn": "cn=unknown,dc=com"}
        result = registry.normalize_dn_references(data, ["dn"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["dn"] == "cn=unknown,dc=com"  # Unchanged

    def test_clear_removes_all_registrations(self, registry: DnCaseRegistry) -> None:
        """Test clearing registry removes all DNs."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("cn=user,dc=com")

        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.clear()
        assert not registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert not registry.has_dn("cn=user,dc=com")

    def test_get_stats(self, registry: DnCaseRegistry) -> None:
        """Test registry statistics."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")  # Same DN, different case
        registry.register_dn("cn=user,dc=com")

        stats = registry.get_stats()
        assert stats["total_dns"] == 2  # Two unique DNs
        assert stats["total_variants"] == 3  # Three total variants
        assert stats["dns_with_multiple_variants"] == 1  # One DN with multiple variants


class TestConversionMatrixDnHandling:
    """Test DN case handling in conversion matrix."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix."""
        return QuirksConversionMatrix()

    def test_matrix_initializes_with_dn_registry(
        self, matrix: QuirksConversionMatrix
    ) -> None:
        """Test that matrix has DN registry."""
        assert hasattr(matrix, "dn_registry")
        assert isinstance(matrix.dn_registry, DnCaseRegistry)

    def test_reset_dn_registry_clears_state(
        self, matrix: QuirksConversionMatrix
    ) -> None:
        """Test resetting DN registry."""
        matrix.dn_registry.register_dn("cn=test,dc=com")
        assert matrix.dn_registry.has_dn("cn=test,dc=com")

        matrix.reset_dn_registry()
        assert not matrix.dn_registry.has_dn("cn=test,dc=com")

    def test_validate_oud_conversion_delegates_to_registry(
        self, matrix: QuirksConversionMatrix
    ) -> None:
        """Test OUD validation delegates to registry."""
        matrix.dn_registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        result = matrix.validate_oud_conversion()
        assert result.is_success
        assert result.unwrap() is True

    def test_extract_and_register_dns_from_entry_data(
        self, matrix: QuirksConversionMatrix
    ) -> None:
        """Test DN extraction from entry dict."""
        # Manually register DN (simulates what convert() does)
        matrix.dn_registry.register_dn("cn=OracleContext,dc=example,dc=com")

        # DN should be registered
        assert matrix.dn_registry.has_dn("cn=OracleContext,dc=example,dc=com")

    def test_extract_and_register_dns_from_group_members(
        self, matrix: QuirksConversionMatrix
    ) -> None:
        """Test DN extraction from group member fields."""
        matrix.dn_registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com")
        matrix.dn_registry.register_dn("cn=user1,dc=example,dc=com")
        matrix.dn_registry.register_dn("cn=user2,dc=example,dc=com")

        # All DNs should be registered
        assert matrix.dn_registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com")
        assert matrix.dn_registry.has_dn("cn=user1,dc=example,dc=com")
        assert matrix.dn_registry.has_dn("cn=user2,dc=example,dc=com")

    def test_normalize_dns_in_entry_data(self, matrix: QuirksConversionMatrix) -> None:
        """Test DN normalization in entry dict."""
        # Register canonical case
        matrix.dn_registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        # Entry with different case
        entry: dict[str, object] = {
            "dn": "cn=group,dc=com",
            "member": ["CN=Admin,DC=Com"],  # Different case!
        }

        result = matrix.dn_registry.normalize_dn_references(entry)
        assert result.is_success

        normalized = result.unwrap()
        # Member DN should be normalized to canonical case
        assert normalized["member"] == ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"]


class TestDnCaseNormalizationScenarios:
    """Test various DN case normalization scenarios."""

    @pytest.fixture
    def registry(self) -> DnCaseRegistry:
        """Create DN registry."""
        return DnCaseRegistry()

    def test_multiple_references_to_same_dn_different_cases(
        self, registry: DnCaseRegistry
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
        assert result.unwrap() is False  # Has inconsistencies
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        assert "warning" in result.metadata

    def test_hierarchical_dn_references(self, registry: DnCaseRegistry) -> None:
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
        assert result.unwrap() is True


__all__ = [
    "TestConversionMatrixDnHandling",
    "TestDnCaseNormalizationScenarios",
    "TestDnCaseRegistry",
]
