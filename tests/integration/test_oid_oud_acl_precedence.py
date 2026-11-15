"""OID clause precedence (R6a) through the public oid→oud pipeline.

Measured on OID 12.2.1.4: when a specific subject matches the session, the
level's ``*`` clauses are not consulted; among the clauses that apply a denial
beats a grant in any order; a right they leave undecided falls to the next
level. ``self`` on add is the parent itself, ``parent[1].entryDN`` on OUD.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudAclPrecedence:
    """Specific subjects decide before ``*``; a denial beats a grant."""

    BASE: ClassVar[str] = (
        "dn: dc=ctbc\nobjectClass: top\nobjectClass: domain\ndc: ctbc\n\n"
        "dn: cn=membro,dc=ctbc\nobjectClass: top\nobjectClass: person\n"
        "cn: membro\nsn: membro\n\n"
        "dn: cn=g,dc=ctbc\nobjectClass: top\nobjectClass: groupOfUniqueNames\n"
        "objectClass: orclPrivilegeGroup\ncn: g\nuniqueMember: cn=membro,dc=ctbc\n\n"
        "dn: cn=t,dc=ctbc\nobjectClass: top\nobjectClass: orclContainer\ncn: t\n"
    )

    @classmethod
    def _migrate(cls, tmp_path: Path, acl: str) -> tuple[bool, str, list[str]]:
        """Migrate one ACI on ``cn=t`` and return its outcome and ACIs.

        Returns:
            Success, the failure text, and the ``aci`` values of ``cn=t``.

        """
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "acl.ldif").write_text(
            f"{cls.BASE}orclaci: {acl}\n", encoding="utf-8"
        )
        result = (
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
        if result.failure:
            return False, result.error or "", []
        acis: list[str] = []
        dn = ""
        for line in (output_dir / "acls.ldif").read_text(encoding="utf-8").splitlines():
            if line.startswith("dn: "):
                dn = line.removeprefix("dn: ")
            elif line.startswith("aci: ") and dn == "cn=t,dc=ctbc":
                acis.append(line.removeprefix("aci: "))
        return True, "", acis

    def test_specific_denial_beats_a_group_grant(self, tmp_path: Path) -> None:
        """C1: the member's denial is not lifted by the group's grant."""
        ok, _, acis = self._migrate(
            tmp_path,
            'access to entry by dn="cn=membro,dc=ctbc" (nobrowse) '
            'by group="cn=g,dc=ctbc" (browse) by * (none)',
        )
        tm.that(ok, eq=True)
        tm.that(
            acis,
            has='(targetattr="*")(version 3.0; acl "orclaci 1.1 R5"; deny '
            '(read,compare) userdn="ldap:///cn=membro,dc=ctbc";)',
        )

    def test_specific_denial_beats_a_star_grant(self, tmp_path: Path) -> None:
        """W2: the group's denial stays beside the grant to everyone."""
        ok, _, acis = self._migrate(
            tmp_path,
            'access to entry by group="cn=g,dc=ctbc" (nobrowse) by * (browse)',
        )
        tm.that(ok, eq=True)
        tm.that(
            acis,
            has='(targetattr="*")(version 3.0; acl "orclaci 1.1 R5"; deny '
            '(read,compare) groupdn="ldap:///cn=g,dc=ctbc";)',
        )

    def test_star_grant_leaves_out_undecided_subjects(self, tmp_path: Path) -> None:
        """X1: ``*`` grants add to everyone but the subject that leaves it open."""
        ok, _, acis = self._migrate(
            tmp_path,
            'access to entry by dn="cn=membro,dc=ctbc" (browse) by * (browse,add)',
        )
        tm.that(ok, eq=True)
        tm.that(
            [item for item in acis if "allow (add)" in item],
            eq=[
                (
                    '(targetattr="*")(targetscope="subordinate")(version 3.0; acl '
                    '"orclaci 1.2 R4a"; allow (add) (userdn="ldap:///all" and not '
                    'userdn="ldap:///cn=membro,dc=ctbc");)'
                )
            ],
        )

    def test_self_on_add_binds_to_the_parent_entry_dn(self, tmp_path: Path) -> None:
        """``self`` on add is the parent itself: ``parent[1].entryDN``."""
        ok, _, acis = self._migrate(
            tmp_path, "access to entry by self (browse,add) by * (browse)"
        )
        tm.that(ok, eq=True)
        tm.that(
            [item for item in acis if "allow (add)" in item],
            eq=[
                (
                    '(targetattr="*")(targetscope="subordinate")(version 3.0; acl '
                    '"orclaci 1.1 R4a"; allow (add) '
                    'userattr="parent[1].entryDN#USERDN";)'
                )
            ],
        )

    def test_self_left_to_the_next_level_on_add_is_excluded(
        self, tmp_path: Path
    ) -> None:
        """S3: ``*`` denies add to everyone but the parent, which falls through."""
        ok, _, acis = self._migrate(
            tmp_path, "access to entry by self (browse) by * (none)"
        )
        tm.that(ok, eq=True)
        tm.that(
            [item for item in acis if "deny (add)" in item],
            eq=[
                (
                    '(targetattr="*")(targetscope="subordinate")(version 3.0; acl '
                    '"orclaci 1.2 R5"; deny (add) (userdn="ldap:///anyone" and not '
                    'userattr="parent[1].entryDN#USERDN");)'
                )
            ],
        )
