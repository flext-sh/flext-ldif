"""Unit tests for the public LDIF client contract of the facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import ldif
from tests import p


class TestsFlextLdifClientContract:
    """The public facade structurally satisfies ``p.Ldif.LdifClient``."""

    @staticmethod
    def test_facade_satisfies_ldif_client() -> None:
        """Test the facade is a client whose settings carry the LDIF branch."""
        client: p.Ldif.LdifClient = ldif()
        tm.that(isinstance(client, p.Ldif.LdifClient), eq=True)
        tm.that(isinstance(client.settings, p.Ldif.Settings), eq=True)
        tm.that(isinstance(client.settings.ldif, p.Ldif.LdifSettings), eq=True)
