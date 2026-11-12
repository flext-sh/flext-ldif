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

    @c.Tests.MARK.parametrize(
        ("acl", "expected"),
        [
            u.Tests.param(
                "access to attr=(member) by groupattr=(uniquemember) (read,search)",
                'userattr="uniquemember#GROUPDN"',
                id="groupattr-becomes-groupdn-userattr",
            ),
            u.Tests.param(
                'access to entry by group="cn=admins,dc=ctbc" (proxy)',
                "allow (proxy)",
                id="proxy-grant-kept-r4c",
            ),
        ],
    )
    def test_subject_and_right_conversions(self, acl: str, expected: str) -> None:
        """Spec v4.2 R8 groupattr and R4c proxy grants convert, not refuse."""
        converted = tm.ok(
            self._migrate(self._directory({"cn=users,dc=ctbc": {"orclaci": [acl]}})),
        )
        values = self._acis(converted)["cn=users,dc=ctbc"]
        tm.that(values, where=lambda acis: any(expected in aci for aci in acis))

    @c.Tests.MARK.parametrize(
        "acl",
        [
            u.Tests.param(
                "access to entry by * bindmode=(Simple) (browse)",
                id="bindmode",
            ),
            u.Tests.param(
                "access to entry by * bindipfilter=(orclipaddress=10.*) (browse)",
                id="bindipfilter",
            ),
            u.Tests.param(
                'access to entry by group="cn=*,dc=ctbc" (browse)',
                id="wildcard-group",
            ),
        ],
    )
    def test_subjects_without_an_oud_mapping_fail(self, acl: str) -> None:
        """R8 forms with no measured OUD mapping fail, never pass raw."""
        entries = self._directory({"cn=users,dc=ctbc": {"orclaci": [acl]}})
        entries.append(u.Tests.oid_security_group_entry("cn=*,dc=ctbc"))
        tm.fail(
            self._migrate(entries),
        )

    def test_absent_literal_star_group_matches_no_session(self) -> None:
        """A group DN is not expanded as a wildcard over unrelated groups."""
        converted = tm.ok(
            self._migrate(
                self._directory({
                    "cn=users,dc=ctbc": {
                        "orclaci": ['access to entry by group="cn=*,dc=ctbc" (browse)'],
                    },
                })
            ),
        )
        tm.that(self._acis(converted)["cn=users,dc=ctbc"], eq=[])

    @c.Tests.MARK.parametrize("right", ["browse", "nobrowse"])
    def test_proxy_threshold_keeps_only_authenticated_sessions(
        self, right: str
    ) -> None:
        """Proxy is an authentication threshold, not an unconditioned anyone."""
        converted = tm.ok(
            self._migrate(
                self._directory({
                    "cn=users,dc=ctbc": {
                        "orclaci": [f"access to entry by * bindmode=(Proxy) ({right})"],
                    },
                })
            )
        )
        acis = "\n".join(self._acis(converted)["cn=users,dc=ctbc"])
        tm.that(acis, has='userdn="ldap:///all"')
        tm.that(acis, lacks='userdn="ldap:///anyone"')

    def test_retained_oracle_internal_entry_keeps_its_denial(self) -> None:
        """An Oracle-specific name does not remove a retained entry's policy."""
        converted = tm.ok(
            self._migrate(
                self._directory({
                    "cn=OracleContext,dc=ctbc": {
                        "orclaci": ["access to entry by * (nobrowse)"],
                    },
                }),
            ),
        )
        acis = self._acis(converted)["cn=OracleContext,dc=ctbc"]
        tm.that(bool(acis), truth=True)
        tm.that("\n".join(acis), has="deny")

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
