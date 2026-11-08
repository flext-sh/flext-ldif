"""End-to-end OID→OUD ACL conversion through the public migration pipeline.

The source directory converts as a whole (``migration_pipeline(...)
.migrate_entries``): OID ``orclaci``/``orclentrylevelaci`` values become OUD
``aci`` values placed on the entry each region decides, and the source ACL
attributes are consumed. A negation-only clause yields denials, never a grant
of the remaining rights (flext-ws7iv). Converting one entry outside the
directory conversion fails loud.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_ldif import FlextLdif
from flext_ldif.services import FlextLdifConversion
from tests import c, m, p, tm, u


class TestsFlextLdifOidAclEndToEnd:
    """Directory-wide OID→OUD ACL conversion over the public pipeline."""

    SUFFIX = "dc=ctbc"
    ADMINS = "cn=admins,dc=ctbc"

    @classmethod
    def _migrate(
        cls,
        entries: Sequence[p.Ldif.Entry],
    ) -> p.Result[Sequence[p.Ldif.Entry]]:
        return (
            FlextLdif()
            .migration_pipeline(
                settings=m.Ldif.TransformConfig.servers(
                    source_server=c.Ldif.ServerTypes.OID,
                    target_server=c.Ldif.ServerTypes.OUD,
                    base_dn=cls.SUFFIX,
                ),
            )
            .migrate_entries(entries)
        )

    @classmethod
    def _directory(
        cls,
        acls: Mapping[str, Mapping[str, Sequence[str]]],
    ) -> list[p.Ldif.Entry]:
        """Build the suffix, the admins security group and the ACL carriers.

        Returns:
            The directory entries in source order.

        """
        return [
            u.Tests.create_real_entry(
                dn=cls.SUFFIX,
                attributes={"objectClass": ["top", "domain"], "dc": ["ctbc"]},
            ),
            u.Tests.oid_security_group_entry(cls.ADMINS),
            *(
                u.Tests.create_real_entry(
                    dn=dn,
                    attributes={"objectClass": ["top", "container"], **attrs},
                )
                for dn, attrs in acls.items()
            ),
        ]

    @staticmethod
    def _acis(entries: Sequence[p.Ldif.Entry]) -> dict[str, list[str]]:
        return {
            entry.dn_str: list(entry.attributes_dict.get(c.Ldif.ACI_ATTR_NAME, ()))
            for entry in entries
        }

    def test_source_acl_attributes_are_consumed(self) -> None:
        """Converted entries carry ``aci`` and no OID ACL attribute."""
        converted = tm.ok(
            self._migrate(
                self._directory({
                    "cn=users,dc=ctbc": {
                        "orclaci": ["access to attr=(cn,sn,mail) by * (read,search)"],
                    },
                }),
            ),
        )
        for entry in converted:
            names = {name.lower() for name in entry.attributes_dict}
            tm.that(names & {"orclaci", "orclentrylevelaci"}, eq=set())
        tm.that(self._acis(converted)["cn=users,dc=ctbc"], ne=[])

    def test_negation_only_clause_never_grants_the_complement(self) -> None:
        """``by * (no...)`` yields denials, no grant to anyone (flext-ws7iv)."""
        converted = tm.ok(
            self._migrate(
                self._directory({
                    "cn=users,dc=ctbc": {
                        "orclaci": [
                            (
                                f'access to entry by group="{self.ADMINS}" '
                                "(browse,add,delete) by * (nobrowse,noadd,nodelete)"
                            ),
                        ],
                    },
                }),
            ),
        )
        anyone = ('userdn="ldap:///anyone"', 'userdn="ldap:///all"')
        values = [value for acis in self._acis(converted).values() for value in acis]
        tm.that(values, ne=[])
        for value in values:
            tm.that(
                value,
                where=lambda aci: (
                    not any(subject in aci for subject in anyone) or "deny (" in aci
                ),
            )

    def test_acl_lands_on_the_entry_its_region_decides(self) -> None:
        """A parent ACL denial reaches a child carrying its own entry-level ACL."""
        converted = tm.ok(
            self._migrate(
                self._directory({
                    "ou=people,dc=ctbc": {
                        "orclentrylevelaci": [
                            "access to entry by self (browse) by * (none)"
                        ],
                    },
                    "cn=parent-acl,dc=ctbc": {
                        "orclaci": [
                            (
                                f'access to entry by group="{self.ADMINS}" (browse) '
                                "by * (nobrowse)"
                            ),
                        ],
                    },
                }),
            ),
        )
        acis = self._acis(converted)
        tm.that(acis["ou=people,dc=ctbc"], ne=[])

    def test_oracle_internal_entry_denial_fails(self) -> None:
        """Dropping an Oracle-internal denial would grant in OUD; it fails."""
        tm.fail(
            self._migrate(
                self._directory({
                    "cn=OracleContext,dc=ctbc": {
                        "orclaci": ["access to entry by * (nobrowse)"],
                    },
                }),
            ),
        )

    @staticmethod
    def test_single_entry_conversion_of_oid_acls_fails_loud() -> None:
        """OID ACLs converted outside a directory conversion fail, never pass raw."""
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": ["access to attr=(cn) by * (read)"],
            },
        )
        tm.fail(
            FlextLdifConversion(registry=FlextLdif().registry).convert_model(
                c.Ldif.ServerTypes.OID,
                c.Ldif.ServerTypes.OUD,
                entry,
            ),
        )
