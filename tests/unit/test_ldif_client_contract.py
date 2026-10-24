"""Unit tests for the public LDIF client contract of the facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys

from flext_ldif import ldif, settings
from tests import c, m, p, tm, u


class TestsFlextLdifClientContract:
    """The public facade structurally satisfies ``p.Ldif.LdifClient``."""

    @staticmethod
    def test_uppercase_namespace_reads_existing_nested_environment_keys() -> None:
        """Existing environment keys configure the actual uppercase settings field."""
        encoding = "latin-1"
        result = tm.ok(
            u.Cli.run(
                (
                    sys.executable,
                    "-c",
                    (
                        "from flext_ldif import ldif, settings; "
                        "client = ldif(); "
                        "print(client.settings.Ldif is settings.Ldif, "
                        "client.settings.Ldif.ldif_encoding, "
                        "client.settings.Ldif.ldif_strict_validation)"
                    ),
                ),
                options=m.Cli.ProcessOptions(
                    env={
                        "FLEXT_LDIF_LDIF__LDIF_ENCODING": encoding,
                        "FLEXT_LDIF_LDIF__LDIF_STRICT_VALIDATION": (
                            c.ParserBooleanToken.FALSE
                        ),
                    },
                ),
            ),
        )
        tm.that(result.stdout, eq=f"True {encoding} False\n")

    @staticmethod
    def test_facade_satisfies_ldif_client() -> None:
        """Test the facade serves as a client carrying the LDIF settings branch."""
        client: p.Ldif.LdifClient = ldif()
        branch = client.settings.Ldif
        tm.that(branch.ldif_encoding, eq=settings.Ldif.ldif_encoding)
        tm.that(
            branch.ldif_strict_validation,
            eq=settings.Ldif.ldif_strict_validation,
        )
