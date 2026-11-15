"""OID subject ``.*<dn>`` through the public oid→oud migration pipeline.

Oracle's own seeded OID ACLs write ``by dn=".*cn=Reports,cn=Products,..."``
without a comma: the DN itself and its subtree. The written OUD ACI must grant
that subject as the subtree LDAP URL ``userdn``, never refuse the entry.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudAclRegexTree:
    """The Oracle ``.*<dn>`` subject converts to the DN and its subtree."""

    INPUT: ClassVar[str] = (
        "dn: cn=reports-tree,dc=ctbc\n"
        "objectClass: top\n"
        "objectClass: container\n"
        "cn: reports-tree\n"
        'orclaci: access to entry by dn=".*cn=Reports,cn=Products,dc=ctbc" '
        "(browse,add,delete) by * (none)\n"
    )
    SUBTREE_USERDN: ClassVar[str] = (
        'userdn="ldap:///cn=Reports,cn=Products,dc=ctbc??sub?(objectclass=*)"'
    )

    def test_regex_tree_subject_is_granted_as_its_subtree(self, tmp_path: Path) -> None:
        """The written ACIs grant the subtree URL and never exclude the DN."""
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
        tm.that(written, has=self.SUBTREE_USERDN)
        tm.that(
            written,
            lacks='userdn!="ldap:///cn=Reports,cn=Products,dc=ctbc"',
        )
