"""RFC 4514 DN identity is shared by planning, policy and pruning.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import c, tm, u


class TestsFlextLdifDnIdentity:
    """Native RDN parsing has one decoded, AVA-order-independent identity."""

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("left", "right"),
        [
            ("cn=alpha+uid=123,dc=example", "UID=123+CN=ALPHA,DC=EXAMPLE"),
            (r"cn=alpha\,beta,dc=example", r"cn=alpha\2cbeta,dc=example"),
            (r"cn=alpha\+beta,dc=example", r"cn=alpha\2bbeta,dc=example"),
            ("cn=café,dc=example", r"cn=caf\c3\a9,dc=example"),
            (r"cn=literal\\ab,dc=example", r"cn=literal\5cab,dc=example"),
        ],
    )
    def test_equivalent_spellings_have_one_identity(left: str, right: str) -> None:
        """Equivalent RFC 4514 spellings share one comparison key."""
        tm.that(tm.ok(u.Ldif.dn_key(left)), eq=tm.ok(u.Ldif.dn_key(right)))
        tm.that(tm.ok(u.Ldif.compare_dns(left, right)), eq=0)

    @staticmethod
    def test_root_dse_has_the_empty_identity() -> None:
        """The root DSE is a legitimate identity, distinct from an upsert target."""
        tm.that(tm.ok(u.Ldif.dn_key("")), eq="")

    @staticmethod
    def test_identity_does_not_rewrite_the_presentation_normalizer() -> None:
        """Presentation normalization still preserves value case."""
        tm.that(tm.ok(u.Ldif.norm("CN=Mixed,DC=Example")), eq="cn=Mixed,dc=Example")

    @staticmethod
    def test_invalid_utf8_escapes_fail_at_the_parser_boundary() -> None:
        """Malformed encoded values remain failures, never invented identities."""
        tm.fail(u.Ldif.dn_key(r"cn=invalid\ff,dc=example"))
