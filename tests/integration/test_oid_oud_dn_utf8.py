"""UTF-8 RDN values through the public oid→oud pipeline (RFC 4514 UTFMB).

RFC 4514 admits multibyte UTF-8 characters as lead, string and trail
characters of an attribute value (``leadchar = LUTF1 / UTFMB``). The Nov13 OID
dump carries such DNs (``uid=gilbertojosé.hermann,…``); the migration keeps them.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudDnUtf8:
    """A DN with UTF-8 characters in any position migrates unchanged."""

    @staticmethod
    def test_utf8_rdn_values_migrate(tmp_path: Path) -> None:
        """Lead, inner and trail UTF-8 characters are valid RDN characters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        names = ("gilbertojosé.hermann", "Élio", "joão")
        entries = "".join(
            f"dn: uid={name},dc=ctbc\nobjectClass: top\nobjectClass: account\n"
            f"uid: {name}\n\n"
            for name in names
        )
        (input_dir / "data.ldif").write_text(
            "dn: dc=ctbc\nobjectClass: top\nobjectClass: domain\ndc: ctbc\n\n"
            + entries,
            encoding="utf-8",
        )
        tm.ok(
            FlextLdif()
            .migration_pipeline(
                input_dir=input_dir,
                output_dir=output_dir,
                settings=m.Ldif.TransformConfig.servers(
                    source_server=c.Tests.OID,
                    target_server=c.Tests.OUD,
                    base_dn="dc=ctbc",
                ),
                options=m.Ldif.MigrateOptions(output_filename="data.ldif"),
            )
            .execute(),
        )
        dns: set[str] = set()
        for line in (output_dir / "data.ldif").read_text(encoding="utf-8").splitlines():
            if line.startswith("dn:: "):
                dns.add(base64.b64decode(line.removeprefix("dn:: ")).decode("utf-8"))
            elif line.startswith("dn: "):
                dns.add(line.removeprefix("dn: "))
        for name in names:
            tm.that(f"uid={name},dc=ctbc" in dns, eq=True)
