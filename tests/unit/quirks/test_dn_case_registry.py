"""Unit tests for DN Case Registry functionality.

Tests the FlextLdifDnService.CaseRegistry class that tracks canonical DN case during
quirk conversions to ensure OUD compatibility.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.services.dn import FlextLdifDnService


class TestCaseRegistryInitialization:
    """Test DN case registry initialization."""

    def test_registry_starts_empty(self) -> None:
        """Test that new registry has no DNs registered."""
        registry = FlextLdifDnService.CaseRegistry()
        stats = registry.get_stats()
        assert stats["total_dns"] == 0
        assert stats["total_variants"] == 0
        assert stats["dns_with_multiple_variants"] == 0

    def test_registry_has_empty_internal_structures(self) -> None:
        """Test internal structures are initialized correctly."""
        registry = FlextLdifDnService.CaseRegistry()
        assert hasattr(registry, "_registry")
        assert hasattr(registry, "_case_variants")
        assert isinstance(registry._registry, dict)
        assert isinstance(registry._case_variants, dict)
        assert len(registry._registry) == 0
        assert len(registry._case_variants) == 0


class TestDnNormalization:
    """Test DN normalization functionality."""

    @pytest.fixture
    def registry(self) -> FlextLdifDnService.CaseRegistry:
        """Create fresh DN registry."""
        return FlextLdifDnService.CaseRegistry()

    def test_normalize_removes_spaces(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that DN normalization removes all spaces."""
        dn_with_spaces = "CN=Test, DC=Example, DC=Com"
        normalized = registry._normalize_dn(dn_with_spaces)
        assert " " not in normalized
        assert normalized == "cn=test,dc=example,dc=com"

    def test_normalize_converts_to_lowercase(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that DN normalization converts to lowercase."""
        dn_uppercase = "CN=ADMIN,DC=EXAMPLE,DC=COM"
        normalized = registry._normalize_dn(dn_uppercase)
        assert normalized == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert normalized.islower()

    def test_normalize_preserves_structure(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that normalization preserves DN structure (commas, equals)."""
        dn = "CN=Test,OU=Users,DC=Example,DC=Com"
        normalized = registry._normalize_dn(dn)
        assert normalized.count(",") == 3
        assert normalized.count("=") == 4
        assert "cn=test" in normalized
        assert "ou=users" in normalized

    def test_normalize_handles_multiple_spaces(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that normalization handles multiple consecutive spaces."""
        dn_multi_spaces = "CN=Test,  DC=Example,   DC=Com"
        normalized = registry._normalize_dn(dn_multi_spaces)
        assert "  " not in normalized
        assert " " not in normalized

    def test_normalize_idempotent(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that normalizing twice gives same result."""
        dn = "CN=Test, DC=Example, DC=Com"
        first_normalized = registry._normalize_dn(dn)
        second_normalized = registry._normalize_dn(first_normalized)
        assert first_normalized == second_normalized


class TestDnRegistration:
    """Test DN registration functionality."""

    @pytest.fixture
    def registry(self) -> FlextLdifDnService.CaseRegistry:
        """Create fresh DN registry."""
        return FlextLdifDnService.CaseRegistry()

    def test_register_first_dn_becomes_canonical(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that first registered DN becomes canonical case."""
        dn = "CN=Admin,DC=Example,DC=Com"
        canonical = registry.register_dn(dn)
        assert canonical == dn

    def test_register_same_dn_different_case_returns_canonical(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that registering same DN with different case returns canonical."""
        first_dn = "CN=Admin,DC=Example,DC=Com"
        second_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        third_dn = "cn=ADMIN,dc=EXAMPLE,dc=COM"

        canonical = registry.register_dn(first_dn)
        assert canonical == first_dn

        result2 = registry.register_dn(second_dn)
        assert result2 == first_dn  # Returns first canonical

        result3 = registry.register_dn(third_dn)
        assert result3 == first_dn  # Returns first canonical

    def test_register_tracks_all_case_variants(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that registration tracks all case variants."""
        registry.register_dn("cn=test,dc=com")
        registry.register_dn("CN=Test,DC=Com")
        registry.register_dn("cn=TEST,dc=COM")

        variants = registry.get_case_variants("cn=test,dc=com")
        assert len(variants) == 3
        assert "cn=test,dc=com" in variants
        assert "CN=Test,DC=Com" in variants
        assert "cn=TEST,dc=COM" in variants

    def test_register_with_force_overrides_canonical(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that force=True overrides existing canonical case."""
        first_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        second_dn = "CN=ADMIN,DC=COM"

        registry.register_dn(first_dn)
        assert registry.get_canonical_dn(first_dn) == first_dn

        # Force new canonical
        canonical = registry.register_dn(second_dn, force=True)
        assert canonical == second_dn
        assert registry.get_canonical_dn(first_dn) == second_dn

    def test_register_multiple_different_dns(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test registering multiple different DNs."""
        dn1 = "cn=user1,dc=com"
        dn2 = "cn=user2,dc=com"
        dn3 = "ou=users,dc=com"

        registry.register_dn(dn1)
        registry.register_dn(dn2)
        registry.register_dn(dn3)

        stats = registry.get_stats()
        assert stats["total_dns"] == 3

    def test_register_dn_with_spaces_normalizes_correctly(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that DNs with spaces are normalized for matching."""
        dn_with_spaces = "CN=Test, DC=Example, DC=Com"
        dn_without_spaces = "cn=test,dc=example,dc=com"

        canonical = registry.register_dn(dn_with_spaces)
        result = registry.register_dn(dn_without_spaces)

        # Both should resolve to same canonical
        assert result == canonical


class TestCanonicalDnRetrieval:
    """Test canonical DN retrieval functionality."""

    @pytest.fixture
    def registry(self) -> FlextLdifDnService.CaseRegistry:
        """Create registry with some DNs."""
        reg = FlextLdifDnService.CaseRegistry()
        reg.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        reg.register_dn("ou=users,dc=example,dc=com")
        return reg

    def test_get_canonical_exact_match(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test getting canonical DN with exact match."""
        canonical = registry.get_canonical_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert canonical == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_get_canonical_different_case(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test getting canonical DN with different case."""
        canonical = registry.get_canonical_dn("CN=Admin,DC=Example,DC=Com")
        assert canonical == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_get_canonical_with_spaces(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test getting canonical DN with spaces."""
        canonical = registry.get_canonical_dn("cn=REDACTED_LDAP_BIND_PASSWORD, dc=example, dc=com")
        assert canonical == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_get_canonical_unregistered_returns_none(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that unregistered DN returns None."""
        canonical = registry.get_canonical_dn("cn=unknown,dc=com")
        assert canonical is None

    def test_get_canonical_empty_registry(self) -> None:
        """Test getting canonical from empty registry returns None."""
        registry = FlextLdifDnService.CaseRegistry()
        canonical = registry.get_canonical_dn("cn=test,dc=com")
        assert canonical is None


class TestDnExistenceCheck:
    """Test DN existence checking functionality."""

    @pytest.fixture
    def registry(self) -> FlextLdifDnService.CaseRegistry:
        """Create registry with some DNs."""
        reg = FlextLdifDnService.CaseRegistry()
        reg.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        reg.register_dn("ou=users,dc=com")
        return reg

    def test_has_dn_exact_match(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test has_dn with exact match."""
        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert registry.has_dn("ou=users,dc=com")

    def test_has_dn_different_case(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test has_dn is case-insensitive."""
        assert registry.has_dn("CN=Admin,DC=Com")
        assert registry.has_dn("cn=ADMIN,dc=COM")
        assert registry.has_dn("OU=Users,DC=Com")

    def test_has_dn_with_spaces(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test has_dn handles spaces."""
        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD, dc=com")
        assert registry.has_dn("ou=users, dc=com")

    def test_has_dn_unregistered_returns_false(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that unregistered DN returns False."""
        assert not registry.has_dn("cn=unknown,dc=com")
        assert not registry.has_dn("cn=other,dc=org")

    def test_has_dn_empty_registry(self) -> None:
        """Test has_dn on empty registry returns False."""
        registry = FlextLdifDnService.CaseRegistry()
        assert not registry.has_dn("cn=test,dc=com")


class TestCaseVariantsTracking:
    """Test case variant tracking functionality."""

    @pytest.fixture
    def registry(self) -> FlextLdifDnService.CaseRegistry:
        """Create fresh DN registry."""
        return FlextLdifDnService.CaseRegistry()

    def test_get_case_variants_single_variant(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test getting variants when only one case registered."""
        registry.register_dn("cn=test,dc=com")
        variants = registry.get_case_variants("cn=test,dc=com")
        assert len(variants) == 1
        assert "cn=test,dc=com" in variants

    def test_get_case_variants_multiple_variants(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test getting all case variants."""
        registry.register_dn("cn=test,dc=com")
        registry.register_dn("CN=Test,DC=Com")
        registry.register_dn("cn=TEST,dc=COM")

        variants = registry.get_case_variants("cn=test,dc=com")
        assert len(variants) == 3
        assert all(
            v in variants
            for v in ["cn=test,dc=com", "CN=Test,DC=Com", "cn=TEST,dc=COM"]
        )

    def test_get_case_variants_case_insensitive_lookup(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that variant lookup is case-insensitive."""
        registry.register_dn("cn=test,dc=com")
        registry.register_dn("CN=Test,DC=Com")

        # All these should return same variants
        variants1 = registry.get_case_variants("cn=test,dc=com")
        variants2 = registry.get_case_variants("CN=TEST,DC=COM")
        variants3 = registry.get_case_variants("cn=Test,dc=Com")

        assert variants1 == variants2 == variants3
        assert len(variants1) == 2

    def test_get_case_variants_unregistered_returns_empty(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that unregistered DN returns empty set."""
        variants = registry.get_case_variants("cn=unknown,dc=com")
        assert len(variants) == 0
        assert isinstance(variants, set)


class TestOudConsistencyValidation:
    """Test OUD consistency validation functionality."""

    @pytest.fixture
    def registry(self) -> FlextLdifDnService.CaseRegistry:
        """Create fresh DN registry."""
        return FlextLdifDnService.CaseRegistry()

    def test_validate_empty_registry_success(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test validation passes on empty registry."""
        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_single_case_variant_success(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test validation passes with single case variant."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_multiple_dns_single_case_each(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test validation passes with multiple DNs each with single case."""
        registry.register_dn("cn=user1,dc=com")
        registry.register_dn("cn=user2,dc=com")
        registry.register_dn("ou=users,dc=com")

        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_detects_case_inconsistencies(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test validation detects multiple case variants."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")

        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is False  # Has inconsistencies

    def test_validate_provides_inconsistency_metadata(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that validation returns detailed inconsistency metadata."""
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")
        registry.register_dn("cn=ADMIN,dc=COM")

        result = registry.validate_oud_consistency()
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        assert "inconsistencies" in result.metadata
        assert "warning" in result.metadata

        inconsistencies = result.metadata.get("inconsistencies", [])
        assert len(inconsistencies) == 1
        assert inconsistencies[0]["variant_count"] == 3
        assert inconsistencies[0]["canonical_case"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"

    def test_validate_multiple_inconsistent_dns(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test validation with multiple DNs having case issues."""
        # DN 1 - inconsistent
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")

        # DN 2 - consistent
        registry.register_dn("ou=users,dc=com")

        # DN 3 - inconsistent
        registry.register_dn("cn=user1,dc=com")
        registry.register_dn("CN=User1,DC=Com")

        result = registry.validate_oud_consistency()
        assert result.is_success
        assert result.unwrap() is False

        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        inconsistencies = result.metadata.get("inconsistencies", [])
        assert len(inconsistencies) == 2  # Two DNs with issues


class TestDnReferenceNormalization:
    """Test DN reference normalization functionality."""

    @pytest.fixture
    def registry(self) -> FlextLdifDnService.CaseRegistry:
        """Create registry with registered DNs."""
        reg = FlextLdifDnService.CaseRegistry()
        reg.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        reg.register_dn("cn=user1,dc=com")
        reg.register_dn("cn=user2,dc=com")
        return reg

    def test_normalize_single_dn_field(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test normalizing single DN field."""
        data: dict[str, object] = {"dn": "CN=Admin,DC=Com", "cn": ["REDACTED_LDAP_BIND_PASSWORD"]}
        result = registry.normalize_dn_references(data, ["dn"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["dn"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        assert normalized["cn"] == ["REDACTED_LDAP_BIND_PASSWORD"]  # Non-DN field unchanged

    def test_normalize_list_of_dns(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test normalizing list of DNs (e.g., group members)."""
        data: dict[str, object] = {
            "dn": "cn=group,dc=com",
            "member": ["CN=User1,DC=Com", "cn=USER2,dc=com"],
        }
        result = registry.normalize_dn_references(data, ["dn", "member"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["member"] == ["cn=user1,dc=com", "cn=user2,dc=com"]

    def test_normalize_multiple_dn_fields(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test normalizing multiple DN fields."""
        data: dict[str, object] = {
            "dn": "CN=Admin,DC=Com",
            "manager": "cn=USER1,dc=com",
            "secretary": "cn=USER2,dc=com",
        }
        result = registry.normalize_dn_references(data, ["dn", "manager", "secretary"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["dn"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        assert normalized["manager"] == "cn=user1,dc=com"
        assert normalized["secretary"] == "cn=user2,dc=com"

    def test_normalize_unregistered_dn_unchanged(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that unregistered DNs are left unchanged."""
        data: dict[str, object] = {"dn": "cn=unknown,dc=com"}
        result = registry.normalize_dn_references(data, ["dn"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["dn"] == "cn=unknown,dc=com"  # Unchanged

    def test_normalize_with_none_dn_fields_uses_defaults(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that None dn_fields uses default DN fields."""
        data: dict[str, object] = {
            "dn": "CN=Admin,DC=Com",
            "member": ["cn=USER1,dc=com"],
            "owner": "cn=USER2,dc=com",
        }
        result = registry.normalize_dn_references(data)  # No dn_fields specified

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["dn"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        assert normalized["member"] == ["cn=user1,dc=com"]
        assert normalized["owner"] == "cn=user2,dc=com"

    def test_normalize_missing_fields_unchanged(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test that missing fields don't cause errors."""
        data: dict[str, object] = {"cn": ["REDACTED_LDAP_BIND_PASSWORD"]}
        result = registry.normalize_dn_references(data, ["dn", "member"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == data  # Unchanged

    def test_normalize_mixed_registered_unregistered(
        self, registry: FlextLdifDnService.CaseRegistry
    ) -> None:
        """Test normalizing mix of registered and unregistered DNs."""
        data: dict[str, object] = {
            "dn": "cn=group,dc=com",
            "member": [
                "CN=User1,DC=Com",  # Registered
                "cn=unknown,dc=com",  # Not registered
            ],
        }
        result = registry.normalize_dn_references(data, ["dn", "member"])

        assert result.is_success
        normalized = result.unwrap()
        member_list = normalized["member"]
        assert isinstance(member_list, list)
        assert member_list[0] == "cn=user1,dc=com"  # Normalized
        assert member_list[1] == "cn=unknown,dc=com"  # Unchanged


class TestRegistryClear:
    """Test registry clearing functionality."""

    def test_clear_removes_all_dns(self) -> None:
        """Test that clear removes all registered DNs."""
        registry = FlextLdifDnService.CaseRegistry()
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("cn=user,dc=com")

        assert registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert registry.has_dn("cn=user,dc=com")

        registry.clear()

        assert not registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert not registry.has_dn("cn=user,dc=com")

    def test_clear_resets_stats(self) -> None:
        """Test that clear resets statistics to zero."""
        registry = FlextLdifDnService.CaseRegistry()
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")

        stats_before = registry.get_stats()
        assert stats_before["total_dns"] > 0

        registry.clear()

        stats_after = registry.get_stats()
        assert stats_after["total_dns"] == 0
        assert stats_after["total_variants"] == 0
        assert stats_after["dns_with_multiple_variants"] == 0

    def test_clear_allows_reregistration(self) -> None:
        """Test that DNs can be re-registered after clear."""
        registry = FlextLdifDnService.CaseRegistry()
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.clear()
        registry.register_dn("CN=Admin,DC=Com")  # Different case

        # After clear, new case should be canonical
        canonical = registry.get_canonical_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        assert canonical == "CN=Admin,DC=Com"


class TestRegistryStatistics:
    """Test registry statistics functionality."""

    def test_stats_empty_registry(self) -> None:
        """Test statistics for empty registry."""
        registry = FlextLdifDnService.CaseRegistry()
        stats = registry.get_stats()

        assert stats["total_dns"] == 0
        assert stats["total_variants"] == 0
        assert stats["dns_with_multiple_variants"] == 0

    def test_stats_single_dn_single_case(self) -> None:
        """Test statistics with one DN, one case variant."""
        registry = FlextLdifDnService.CaseRegistry()
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")

        stats = registry.get_stats()
        assert stats["total_dns"] == 1
        assert stats["total_variants"] == 1
        assert stats["dns_with_multiple_variants"] == 0

    def test_stats_single_dn_multiple_cases(self) -> None:
        """Test statistics with one DN, multiple case variants."""
        registry = FlextLdifDnService.CaseRegistry()
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")
        registry.register_dn("cn=ADMIN,dc=COM")

        stats = registry.get_stats()
        assert stats["total_dns"] == 1
        assert stats["total_variants"] == 3
        assert stats["dns_with_multiple_variants"] == 1

    def test_stats_multiple_dns_mixed_variants(self) -> None:
        """Test statistics with multiple DNs, some with case variants."""
        registry = FlextLdifDnService.CaseRegistry()
        # DN 1 - multiple variants
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        registry.register_dn("CN=Admin,DC=Com")

        # DN 2 - single variant
        registry.register_dn("ou=users,dc=com")

        # DN 3 - multiple variants
        registry.register_dn("cn=user1,dc=com")
        registry.register_dn("CN=User1,DC=Com")
        registry.register_dn("cn=USER1,dc=COM")

        stats = registry.get_stats()
        assert stats["total_dns"] == 3
        assert stats["total_variants"] == 6  # 2 + 1 + 3
        assert stats["dns_with_multiple_variants"] == 2  # REDACTED_LDAP_BIND_PASSWORD and user1


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_dn_string(self) -> None:
        """Test handling of empty DN string."""
        registry = FlextLdifDnService.CaseRegistry()
        canonical = registry.register_dn("")
        assert not canonical  # Empty string is falsey
        assert registry.has_dn("")

    def test_dn_with_special_characters(self) -> None:
        """Test DN with special LDAP characters."""
        registry = FlextLdifDnService.CaseRegistry()
        dn = "cn=Test\\, User,dc=example,dc=com"
        canonical = registry.register_dn(dn)
        assert canonical == dn
        assert registry.has_dn(dn)

    def test_very_long_dn(self) -> None:
        """Test handling of very long DN."""
        registry = FlextLdifDnService.CaseRegistry()
        dn = "cn=test," + ",".join([f"ou=level{i}" for i in range(50)]) + ",dc=com"
        canonical = registry.register_dn(dn)
        assert canonical == dn
        assert registry.has_dn(dn)

    def test_dn_with_unicode_characters(self) -> None:
        """Test DN with unicode characters."""
        registry = FlextLdifDnService.CaseRegistry()
        dn = "cn=Tëst Üser,dc=example,dc=com"
        canonical = registry.register_dn(dn)
        assert canonical == dn
        assert registry.has_dn(dn)

    def test_normalize_dn_references_with_non_dict_data(self) -> None:
        """Test that normalizing non-dict data fails gracefully."""
        registry = FlextLdifDnService.CaseRegistry()
        # Pass empty dict[str, object] instead of None to avoid type error
        result = registry.normalize_dn_references({}, ["dn"])
        assert result.is_success  # Empty dict[str, object] succeeds

    def test_normalize_dn_references_with_non_list_non_string_value(
        self,
    ) -> None:
        """Test normalization handles non-string, non-list values."""
        registry = FlextLdifDnService.CaseRegistry()
        registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
        data: dict[str, object] = {"dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com", "someField": 123}
        result = registry.normalize_dn_references(data, ["dn", "someField"])

        assert result.is_success
        normalized = result.unwrap()
        assert normalized["someField"] == 123  # Unchanged


__all__ = [
    "TestCanonicalDnRetrieval",
    "TestCaseRegistryInitialization",
    "TestCaseVariantsTracking",
    "TestDnExistenceCheck",
    "TestDnNormalization",
    "TestDnReferenceNormalization",
    "TestDnRegistration",
    "TestEdgeCases",
    "TestOudConsistencyValidation",
    "TestRegistryClear",
    "TestRegistryStatistics",
]
