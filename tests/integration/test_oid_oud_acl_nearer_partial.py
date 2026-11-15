"""A nearer grant on part of the denied attributes, through the oid→oud pipeline.

An OID entry-level grant of write on one attribute decides that attribute
before the farther ACP's ``by * (nowrite)``. Its subject leaves the farther OUD
denial whole when no farther ACP grants it the right: elsewhere it holds no OUD
grant, so the default denies as the OID's farther denial does (R5).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudAclNearerPartial:
    """A partial nearer grant leaves its subject out of the farther denial."""

    INPUT: ClassVar[str] = (
        "dn: dc=ctbc\nobjectClass: top\nobjectClass: domain\ndc: ctbc\n\n"
        "dn: cn=membro,dc=ctbc\nobjectClass: top\nobjectClass: person\n"
        "cn: membro\nsn: membro\n\n"
        "dn: cn=g,dc=ctbc\nobjectClass: top\nobjectClass: groupOfUniqueNames\n"
        "objectClass: orclPrivilegeGroup\ncn: g\nuniqueMember: cn=x,dc=ctbc\n\n"
        "dn: cn=p,dc=ctbc\nobjectClass: top\nobjectClass: orclContainer\ncn: p\n"
        'orclaci: access to attr=(*) by group="cn=g,dc=ctbc" '
        "(read,search,write,compare) by * (read,search,nowrite,compare)\n\n"
        "dn: cn=e,cn=p,dc=ctbc\nobjectClass: top\nobjectClass: orclContainer\n"
        "cn: e\ndescription: d\n"
        'orclentrylevelaci: access to attr=(description) by dn="cn=membro,dc=ctbc" '
        "(read,search,write,compare)\n"
    )

    @classmethod
    def test_partial_grant_subject_leaves_the_farther_denial(
        cls, tmp_path: Path
    ) -> None:
        """The member is excluded from the ACP denial and granted on one attribute."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "acl.ldif").write_text(cls.INPUT, encoding="utf-8")
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
        acis: dict[str, list[str]] = {}
        dn = ""
        for line in (output_dir / "acls.ldif").read_text(encoding="utf-8").splitlines():
            if line.startswith("dn: "):
                dn = line.removeprefix("dn: ")
            elif line.startswith("aci: ") and "write" in line:
                acis.setdefault(dn, []).append(line.removeprefix("aci: "))
        tm.that(
            acis["cn=p,dc=ctbc"],
            has=(
                '(targetattr="*")(version 3.0; acl "orclaci 1.2 R5"; deny (write) '
                '(userdn="ldap:///anyone" and not (groupdn="ldap:///cn=g,dc=ctbc" '
                'or userdn="ldap:///cn=membro,dc=ctbc"));)'
            ),
        )
        tm.that(
            acis["cn=e,cn=p,dc=ctbc"],
            eq=[
                (
                    '(targetattr="description")(targetscope="base")(version 3.0; '
                    'acl "orclentrylevelaci 1.1 R2"; allow (search,write) '
                    'userdn="ldap:///cn=membro,dc=ctbc";)'
                )
            ],
        )
