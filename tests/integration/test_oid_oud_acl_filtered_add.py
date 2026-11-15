"""OID entry ACI ``filter=`` with ``add`` through the public oid→oud pipeline (E7).

OID decides an entry ACI's filter on the entry the operation acts on; for add
that is the parent, and in an ACP every parent of the subtree counts (measured
on OID 12.2.1.4). The OUD add ``targetfilter`` matches the new entry, so the
conversion places the add ``onelevel`` on each existing parent the filter
matches. Measured on OUD 14.1.2.1: the converted policy admits and refuses the
same adds as the OID.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudAclFilteredAdd:
    """A filtered add is placed onelevel on every existing parent it matches."""

    INPUT: ClassVar[str] = (
        "dn: dc=ctbc\nobjectClass: top\nobjectClass: domain\ndc: ctbc\n\n"
        "dn: cn=membro,dc=ctbc\nobjectClass: top\nobjectClass: person\n"
        "objectClass: inetOrgPerson\ncn: membro\nsn: membro\n\n"
        "dn: cn=app,dc=ctbc\nobjectClass: top\nobjectClass: orclContainer\n"
        "cn: app\norclaci: access to entry filter=(objectclass=organizationalUnit)"
        ' by dn="cn=membro,dc=ctbc" (browse,add) by * (browse,noadd)\n\n'
        "dn: ou=casa,cn=app,dc=ctbc\nobjectClass: top\n"
        "objectClass: organizationalUnit\nou: casa\n\n"
        "dn: cn=naocasa,cn=app,dc=ctbc\nobjectClass: top\n"
        "objectClass: orclContainer\ncn: naocasa\n\n"
        "dn: ou=neto,ou=casa,cn=app,dc=ctbc\nobjectClass: top\n"
        "objectClass: organizationalUnit\nou: neto\n\n"
        "dn: cn=grupos,dc=ctbc\nobjectClass: top\nobjectClass: orclContainer\n"
        "cn: grupos\norclaci: access to entry"
        " filter=(&(objectclass=orclContainer)(!(cn=fechado)))"
        " by * (browse,noadd,nodelete)\n\n"
        "dn: cn=aberto,cn=grupos,dc=ctbc\nobjectClass: top\n"
        "objectClass: orclContainer\ncn: aberto\n\n"
        "dn: cn=fechado,cn=grupos,dc=ctbc\nobjectClass: top\n"
        "objectClass: orclContainer\ncn: fechado\n"
    )
    GRANT: ClassVar[str] = (
        '(targetattr="*")(targetscope="onelevel")(version 3.0; acl "orclaci 1.1 '
        'R4a"; allow (add) userdn="ldap:///cn=membro,dc=ctbc";)'
    )
    DENY_ALL: ClassVar[str] = (
        '(targetattr="*")(targetscope="onelevel")(version 3.0; acl "orclaci 1.1 '
        'R5"; deny (add) userdn="ldap:///anyone";)'
    )

    @staticmethod
    def _add_acis(tmp_path: Path, content: str) -> dict[str, list[str]]:
        """Migrate one OID input and return each entry's add ACIs.

        Returns:
            DN to the ``aci`` values that decide add.

        """
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "acl.ldif").write_text(content, encoding="utf-8")
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
        found: dict[str, list[str]] = {}
        dn = ""
        for line in (output_dir / "acls.ldif").read_text(encoding="utf-8").splitlines():
            if line.startswith("dn: "):
                dn = line.removeprefix("dn: ")
            elif line.startswith("aci: ") and "(add)" in line:
                found.setdefault(dn, []).append(line.removeprefix("aci: "))
        return found

    def test_filtered_add_lands_on_every_matching_parent(self, tmp_path: Path) -> None:
        """Matching parents and descendants get the add; others get nothing."""
        acis = self._add_acis(tmp_path, self.INPUT)
        tm.that(acis.get("ou=casa,cn=app,dc=ctbc", []), has=self.GRANT)
        tm.that(acis.get("ou=neto,ou=casa,cn=app,dc=ctbc", []), has=self.GRANT)
        tm.that("cn=app,dc=ctbc" in acis, eq=False)
        tm.that("cn=naocasa,cn=app,dc=ctbc" in acis, eq=False)

    def test_filtered_add_denial_converts_instead_of_failing(
        self, tmp_path: Path
    ) -> None:
        """A noadd under a filter is denied on the matching parents only."""
        acis = self._add_acis(tmp_path, self.INPUT)
        tm.that(acis.get("cn=grupos,dc=ctbc", []), has=self.DENY_ALL)
        tm.that(acis.get("cn=aberto,cn=grupos,dc=ctbc", []), has=self.DENY_ALL)
        tm.that("cn=fechado,cn=grupos,dc=ctbc" in acis, eq=False)
