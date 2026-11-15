"""A filtered privilege-group grant over a nearer denial, through oid→oud.

Measured on OID 12.2.1.4: a farther ACP grant to a privilege group under
``filter=`` lifts a nearer denial only where the filter matches: the entry
itself for browse and delete, the parent for add. The OUD denial splits by
``targetfilter``; the add denial stays whole while no existing parent matches
and fails when one does.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path

    from flext_ldif import p


class TestsFlextLdifOidOudAclFilteredOverride:
    """The override applies where the farther filter matches."""

    INPUT: ClassVar[str] = (
        "dn: dc=ctbc\nobjectClass: top\nobjectClass: domain\ndc: ctbc\n\n"
        "dn: cn=g,dc=ctbc\nobjectClass: top\nobjectClass: groupOfUniqueNames\n"
        "objectClass: orclPrivilegeGroup\ncn: g\nuniqueMember: cn=x,dc=ctbc\n\n"
        "dn: cn=z,dc=ctbc\nobjectClass: top\nobjectClass: orclContainer\ncn: z\n"
        "orclaci: access to entry filter=(objectclass=organizationalUnit) "
        'by group="cn=g,dc=ctbc" (browse,add,delete)\n\n'
        "dn: cn=p,cn=z,dc=ctbc\nobjectClass: top\nobjectClass: orclContainer\n"
        "cn: p\norclaci: access to entry by * (none)\n\n"
        "dn: cn=b,cn=p,cn=z,dc=ctbc\nobjectClass: top\nobjectClass: orclContainer\n"
        "cn: b\n"
    )
    MATCHING_PARENT: ClassVar[str] = (
        "\ndn: ou=a,cn=p,cn=z,dc=ctbc\nobjectClass: top\n"
        "objectClass: organizationalUnit\nou: a\n"
    )

    @staticmethod
    def _migrate(tmp_path: Path, content: str) -> p.Result[object]:
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "acl.ldif").write_text(content, encoding="utf-8")
        return (
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
            .execute()
        )

    def test_denial_splits_by_the_farther_filter(self, tmp_path: Path) -> None:
        """Browse and delete are denied to the group only outside the filter."""
        tm.ok(self._migrate(tmp_path, self.INPUT))
        acis = [
            line.removeprefix("aci: ")
            for line in (tmp_path / "output" / "acls.ldif")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.startswith("aci: ") and "R5" in line
        ]
        tm.that(
            acis,
            has=(
                '(targetattr="*")(targetfilter="(!(objectclass=organizationalUnit))")'
                '(version 3.0; acl "orclaci 1.1 R5"; deny (read,compare,delete) '
                'userdn="ldap:///anyone";)'
            ),
        )
        tm.that(
            acis,
            has=(
                '(targetattr="*")(targetfilter="(objectclass=organizationalUnit)")'
                '(version 3.0; acl "orclaci 1.1 R5"; deny (read,compare,delete) '
                '(userdn="ldap:///anyone" and not groupdn="ldap:///cn=g,dc=ctbc");)'
            ),
        )
        tm.that(
            acis,
            has=(
                '(targetattr="*")(targetscope="subordinate")(version 3.0; acl '
                '"orclaci 1.1 R5"; deny (add) userdn="ldap:///anyone";)'
            ),
        )

    def test_add_override_on_an_existing_parent_fails(self, tmp_path: Path) -> None:
        """A parent the filter matches inside the add denial has no OUD form."""
        result = self._migrate(tmp_path, self.INPUT + self.MATCHING_PARENT)
        tm.that(result.failure, eq=True)
        tm.that(result.error or "", has="override the denial at cn=p,cn=z,dc=ctbc")
