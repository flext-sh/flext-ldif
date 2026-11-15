"""OID ``group=`` subject with a ``*`` naming no source group, through the pipeline.

``group="G"`` names a literal DN (OID-A7 §A.7.1). Oracle's seeded ACLs carry
``group="cn=bindaplicacao,ou=*,…"``: no group has that literal DN, so OID grants
and denies nothing to it. The conversion keeps the entry, emits no ``groupdn``
for that subject and converts the rest of the policy.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudAclAbsentWildcardGroup:
    """A wildcard group DN absent from the source matches no session."""

    INPUT: ClassVar[str] = (
        "dn: cn=app-server,dc=ctbc\n"
        "objectClass: top\n"
        "objectClass: container\n"
        "cn: app-server\n"
        'orclaci: access to entry by group="cn=bindaplicacao,ou=*,cn=app-server,'
        'dc=ctbc" (browse,noadd,nodelete) by * (none)\n'
    )

    def test_absent_wildcard_group_converts_without_its_groupdn(
        self, tmp_path: Path
    ) -> None:
        """The migration succeeds and no ACI names the wildcard group."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "acl.ldif").write_text(self.INPUT, encoding="utf-8")

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
                options=m.Ldif.MigrateOptions(output_filename="acls.ldif"),
            )
            .execute(),
        )

        written = (output_dir / "acls.ldif").read_text(encoding="utf-8")
        tm.that(written, has="dn: cn=app-server,dc=ctbc")
        tm.that(written.lower(), lacks="bindaplicacao")
