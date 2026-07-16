"""Behavioral tests for DN case handling during server conversions.

Exercises the public contract of ``m.Ldif.DnRegistry`` — the registry that
keeps DN case consistent when converting between servers with different case
sensitivity (OID vs OUD). Every assertion targets observable public behavior:
returned canonical strings, ``r[bool]`` outcomes, and lookup results — never
internal state.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import m


class TestsFlextLdifDnCaseHandling:
    """Public-contract behavior of the DN case registry."""

    @pytest.fixture
    def registry(self) -> p.Ldif.DnRegistry:
        """Provide a fresh, empty DN registry."""
        return m.Ldif.DnRegistry()

    # -- registration --------------------------------------------------------

    def test_first_registered_dn_becomes_canonical(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """The first registration fixes the canonical case for that DN."""
        canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")

        tm.that(canonical, eq="CN=Admin,DC=Example,DC=Com")

    @pytest.mark.parametrize(
        "variant",
        [
            "cn=admin,dc=example,dc=com",
            "CN=ADMIN,DC=EXAMPLE,DC=COM",
            "Cn=Admin,Dc=Example,Dc=Com",
        ],
    )
    def test_later_variants_return_the_original_canonical(
        self,
        registry: p.Ldif.DnRegistry,
        variant: str,
    ) -> None:
        """Registering any case variant returns the already-canonical form."""
        registry.register_dn("CN=Admin,DC=Example,DC=Com")

        tm.that(registry.register_dn(variant), eq="CN=Admin,DC=Example,DC=Com")

    def test_registration_is_idempotent_for_identical_case(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """Re-registering the exact same DN keeps the same canonical form."""
        first = registry.register_dn("cn=admin,dc=com")
        second = registry.register_dn("cn=admin,dc=com")

        tm.that(first, eq=second)

    def test_force_overrides_the_canonical_case(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """``force=True`` promotes a new variant to canonical."""
        registry.register_dn("CN=Admin,DC=Com")

        forced = registry.register_dn("cn=ADMIN,dc=COM", force=True)

        tm.that(forced, eq="cn=ADMIN,dc=COM")
        tm.that(registry.resolve_canonical_dn("CN=Admin,DC=Com"), eq="cn=ADMIN,dc=COM")

    def test_without_force_canonical_case_is_preserved(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """A non-forced re-registration never changes the canonical case."""
        registry.register_dn("CN=Admin,DC=Com")

        unchanged = registry.register_dn("cn=admin,dc=com")

        tm.that(unchanged, eq="CN=Admin,DC=Com")
        tm.that(registry.resolve_canonical_dn("cn=admin,dc=com"), eq="CN=Admin,DC=Com")

    # -- resolution ----------------------------------------------------------

    @pytest.mark.parametrize(
        "lookup",
        [
            "cn=test,dc=example,dc=com",
            "CN=Test,DC=Example,DC=Com",
            "cn=TEST,dc=EXAMPLE,dc=COM",
        ],
    )
    def test_resolution_is_case_insensitive(
        self,
        registry: p.Ldif.DnRegistry,
        lookup: str,
    ) -> None:
        """Any case variant resolves to the registered canonical DN."""
        registry.register_dn("cn=test,dc=example,dc=com")

        tm.that(registry.resolve_canonical_dn(lookup), eq="cn=test,dc=example,dc=com")

    @pytest.mark.parametrize(
        "lookup",
        [
            "cn=admin, dc=com",
            "cn=admin,  dc=com",
            "CN=Admin , DC=Com",
        ],
    )
    def test_resolution_ignores_whitespace_between_components(
        self,
        registry: p.Ldif.DnRegistry,
        lookup: str,
    ) -> None:
        """Insignificant whitespace does not affect canonical resolution."""
        registry.register_dn("cn=admin,dc=com")

        tm.that(registry.resolve_canonical_dn(lookup), eq="cn=admin,dc=com")

    def test_resolution_of_unknown_dn_returns_none(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """An unregistered DN resolves to ``None``."""
        tm.that(registry.resolve_canonical_dn("cn=unknown,dc=com"), none=True)

    # -- consistency validation ---------------------------------------------

    def test_empty_registry_is_consistent(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """A registry with no DNs reports consistent (vacuously true)."""
        result = registry.validate_oud_consistency()

        tm.ok(result)
        tm.that(result.unwrap(), eq=True)

    def test_single_case_per_dn_is_consistent(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """One case variant per DN yields a consistent result."""
        registry.register_dn("cn=admin,dc=com")
        registry.register_dn("cn=user,dc=com")

        result = registry.validate_oud_consistency()

        tm.ok(result)
        tm.that(result.unwrap(), eq=True)

    @pytest.mark.parametrize(
        "variants",
        [
            ("cn=admin,dc=com", "CN=Admin,DC=Com"),
            ("cn=admin,dc=com", "CN=Admin,DC=Com", "cn=ADMIN,dc=COM"),
        ],
    )
    def test_multiple_cases_for_one_dn_is_inconsistent(
        self,
        registry: p.Ldif.DnRegistry,
        variants: tuple[str, ...],
    ) -> None:
        """Two or more case variants of the same DN report inconsistency."""
        for variant in variants:
            registry.register_dn(variant)

        result = registry.validate_oud_consistency()

        tm.ok(result)
        tm.that(result.unwrap(), eq=False)

    def test_inconsistency_does_not_break_resolution(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """Even with conflicting variants, resolution returns the canonical DN."""
        registry.register_dn("cn=admin,dc=com")
        registry.register_dn("CN=Admin,DC=Com")
        registry.register_dn("cn=ADMIN,dc=COM")

        tm.that(registry.resolve_canonical_dn("CN=ADMIN,DC=COM"), eq="cn=admin,dc=com")
        tm.that(registry.validate_oud_consistency().unwrap(), eq=False)

    def test_hierarchical_dns_track_independently_and_stay_consistent(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """Distinct DNs in a hierarchy each resolve and remain consistent."""
        hierarchy = (
            "dc=example,dc=com",
            "ou=users,dc=example,dc=com",
            "cn=admin,ou=users,dc=example,dc=com",
        )
        for dn in hierarchy:
            registry.register_dn(dn)

        for dn in hierarchy:
            tm.that(registry.resolve_canonical_dn(dn), eq=dn)
        tm.that(registry.validate_oud_consistency().unwrap(), eq=True)

    # -- clearing ------------------------------------------------------------

    def test_clear_removes_all_registrations(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """After ``clear`` every previously known DN resolves to ``None``."""
        registry.register_dn("cn=admin,dc=com")
        registry.register_dn("cn=user,dc=com")

        registry.clear()

        tm.that(registry.resolve_canonical_dn("cn=admin,dc=com"), none=True)
        tm.that(registry.resolve_canonical_dn("cn=user,dc=com"), none=True)

    def test_clear_resets_consistency_state(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """Clearing an inconsistent registry restores a consistent result."""
        registry.register_dn("cn=admin,dc=com")
        registry.register_dn("CN=Admin,DC=Com")
        tm.that(registry.validate_oud_consistency().unwrap(), eq=False)

        registry.clear()

        tm.that(registry.validate_oud_consistency().unwrap(), eq=True)

    def test_registry_is_reusable_after_clear(
        self,
        registry: p.Ldif.DnRegistry,
    ) -> None:
        """A cleared registry accepts new registrations as if fresh."""
        registry.register_dn("cn=old,dc=com")
        registry.clear()

        canonical = registry.register_dn("CN=New,DC=Com")

        tm.that(canonical, eq="CN=New,DC=Com")
        tm.that(registry.resolve_canonical_dn("cn=new,dc=com"), eq="CN=New,DC=Com")


__all__: list[str] = ["TestsFlextLdifDnCaseHandling"]
