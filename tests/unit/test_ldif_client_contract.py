"""Unit tests for the public LDIF client contract of the facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import tm

from flext_ldif import ldif, settings
from tests import p


class TestsFlextLdifClientContract:
    """The public facade structurally satisfies ``p.Ldif.LdifClient``."""

    @staticmethod
    def test_facade_satisfies_ldif_client() -> None:
        """Test the facade serves as a client carrying the LDIF settings branch."""
        client: p.Ldif.LdifClient = ldif()
        branch = client.settings.ldif
        tm.that(branch.ldif_encoding, eq=settings.ldif.ldif_encoding)
        tm.that(
            branch.ldif_strict_validation,
            eq=settings.ldif.ldif_strict_validation,
        )
