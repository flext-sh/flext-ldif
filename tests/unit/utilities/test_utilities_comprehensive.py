"""Behavioral contract tests for the FlextLdifUtilities.Ldif public surface.

Exercises observable behaviour (return values, r[T] outcomes, raised
exceptions, invariants) of the public LDIF utility helpers. No private
attributes, internal collaborators, or implementation details are touched.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import c
from flext_ldif.utilities import u


class TestsFlextLdifUtilitiesComprehensive:
    """Public-contract behaviour of FlextLdifUtilities.Ldif helpers."""

    # --- server type normalization -------------------------------------

    @staticmethod
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("oud", "oud"),
            ("OUD", "oud"),
            ("Oud", "oud"),
            ("oid", "oid"),
            ("OID", "oid"),
            ("generic", "generic"),
            ("OpenLDAP", "openldap2"),
        ],
    )
    def test_normalize_server_type_is_case_insensitive(
        raw: str,
        expected: str,
    ) -> None:
        """Map any casing to the canonical enum value (aliases resolved)."""
        normalized = u.Ldif.normalize_server_type(raw)

        tm.that(str(normalized), eq=expected)

    @staticmethod
    def test_normalize_server_type_rejects_unknown_type() -> None:
        """An unknown server type raises ValueError naming the invalid input."""
        with pytest.raises(ValueError, match="bogus"):
            u.Ldif.normalize_server_type("bogus")

    @staticmethod
    def test_get_all_server_types_matches_valid_set() -> None:
        """get_all_server_types enumerates exactly the VALID_SERVER_TYPES set."""
        all_types = u.Ldif.get_all_server_types()

        tm.that(set(all_types), eq=set(c.Ldif.VALID_SERVER_TYPES))

    # --- DN value escaping ---------------------------------------------

    @staticmethod
    @pytest.mark.parametrize(
        "value",
        ["a,b+c", 'quote"here', "back\\slash", "semi;colon", "plain", ""],
    )
    def test_esc_unesc_roundtrip_is_lossless(value: str) -> None:
        """Round-trip esc then unesc restores the original DN value (invariant)."""
        tm.that(u.Ldif.unesc(u.Ldif.esc(value)), eq=value)

    @staticmethod
    def test_esc_encodes_reserved_characters() -> None:
        """A reserved character (comma) is escaped, not left literal."""
        escaped = u.Ldif.esc("a,b")

        tm.that(escaped, lacks=",")
        tm.that(escaped, ne="a,b")

    # --- base64 detection ----------------------------------------------

    @staticmethod
    @pytest.mark.parametrize(
        ("value", "expected"),
        [("hello", False), (" leading", True), ("café", True)],
    )
    def test_needs_base64_encoding(value: str, *, expected: bool) -> None:
        """needs_base64_encoding flags unsafe values, clears safe ASCII."""
        assert u.Ldif.needs_base64_encoding(value) is expected

    @staticmethod
    def test_needs_base64_encoding_ignores_trailing_space_when_disabled() -> None:
        """Disabling the trailing-space check clears an otherwise-flagged value."""
        assert (
            u.Ldif.needs_base64_encoding("safe ", check_trailing_space=False) is False
        )

    # --- attribute name normalization ----------------------------------

    @staticmethod
    def test_normalize_attribute_name_lowercases_by_default() -> None:
        """Without case sensitivity, attribute names are lowercased."""
        tm.that(u.Ldif.normalize_attribute_name("CN"), eq="cn")

    @staticmethod
    def test_normalize_attribute_name_preserves_case_when_requested() -> None:
        """case_sensitive=True keeps the original casing."""
        tm.that(u.Ldif.normalize_attribute_name("CN", case_sensitive=True), eq="CN")

    @staticmethod
    def test_normalize_attribute_name_passes_none_through() -> None:
        """A None attribute name normalizes to None (no fabricated value)."""
        tm.that(u.Ldif.normalize_attribute_name(None), none=True)

    # --- DN cleaning ----------------------------------------------------

    @staticmethod
    def test_clean_dn_collapses_component_spacing() -> None:
        """clean_dn removes incidental spacing between RDN components."""
        cleaned = u.Ldif.clean_dn("CN=Admin, DC=Example, DC=Com")

        tm.that(cleaned, eq="CN=Admin,DC=Example,DC=Com")

    # --- DN normalization result (r[T]) --------------------------------

    @staticmethod
    def test_norm_returns_success_with_normalized_dn() -> None:
        """Norm yields a success result carrying the normalized DN string."""
        result = u.Ldif.norm("CN=Admin,DC=Example")

        tm.that(result.success, eq=True)
        tm.that(result.value, eq="cn=Admin,dc=Example")

    @staticmethod
    def test_norm_fails_on_empty_dn() -> None:
        """An empty DN yields a failure result with an explanatory message."""
        result = u.Ldif.norm("")

        tm.that(result.failure, eq=True)
        assert result.error is not None
        tm.that(result.error.lower(), has="empty")

    # --- DN parsing (r[T]) ---------------------------------------------

    @staticmethod
    def test_parse_dn_returns_ordered_component_pairs() -> None:
        """parse_dn yields the (attr, value) pairs in DN order on success."""
        result = u.Ldif.parse_dn("cn=admin,dc=example,dc=com")

        tm.that(result.success, eq=True)
        tm.that(result.value, eq=[("cn", "admin"), ("dc", "example"), ("dc", "com")])

    @staticmethod
    def test_parse_dn_fails_on_malformed_dn() -> None:
        """A DN missing the '=' separator fails rather than silently parsing."""
        result = u.Ldif.parse_dn("no-equals")

        tm.that(result.failure, eq=True)
        assert result.error is not None

    @staticmethod
    def test_parse_rdn_returns_single_component() -> None:
        """parse_rdn yields the single (attr, value) pair for a lone RDN."""
        result = u.Ldif.parse_rdn("cn=admin")

        tm.that(result.success, eq=True)
        tm.that(result.value, eq=[("cn", "admin")])

    # --- line folding / unfolding --------------------------------------

    @staticmethod
    def test_fold_line_respects_width_and_marks_continuations() -> None:
        """fold_line keeps the first chunk within width; continuations start ' '."""
        fold_width = 76
        folded = u.Ldif.fold_line("a" * 100, fold_width)

        assert len(folded) > 1
        assert len(folded[0]) <= fold_width
        assert all(cont.startswith(" ") for cont in folded[1:])

    @staticmethod
    def test_unfold_lines_rejoins_continuation_lines() -> None:
        """unfold_lines merges leading-space continuations into their logical line."""
        unfolded = u.Ldif.unfold_lines("dn: cn=a\n b\nfoo: bar")

        tm.that(unfolded, eq=["dn: cn=ab", "foo: bar"])
