"""Source-policy filtering preserves structurally valid directory data.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import c, ldif, p, tm, u


class TestsFlextLdifDataCategorization:
    """Compose the real public filter and classifier without source ACL policy."""

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("objectclass", "members", "expected"),
        [
            ("groupOfUniqueNames", (), c.Ldif.Category.GROUPS),
            (
                "groupOfUniqueNames",
                ("cn=member,dc=example,dc=invalid",),
                c.Ldif.Category.GROUPS,
            ),
            ("orclContainerOC", (), c.Ldif.Category.HIERARCHY),
        ],
    )
    def test_filtering_source_acl_preserves_data_category_and_members(
        objectclass: str,
        members: tuple[str, ...],
        expected: str,
    ) -> None:
        """An ACL marker cannot remove a group or container from data output."""
        attributes = {
            "objectClass": ["top", objectclass],
            "cn": ["sample"],
            "orclACI": ["access to entry by * (browse)"],
        }
        if members:
            attributes["uniqueMember"] = list(members)
        original = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_USER,
            attributes=attributes,
        )
        api = ldif()
        client: p.Ldif.LdifClient = api
        filtered = client.filter_entry_attributes(
            original,
            forbidden_attrs=tuple(c.Ldif.ACL_ATTR_NAMES),
            forbidden_ocs=(),
        )
        categorizer = api.categorization(server_type=c.Ldif.ServerTypes.OID)
        category, reason = categorizer.categorize_entry(filtered)
        tm.that(category, eq=expected)
        tm.that(reason, none=True)
        tm.that(filtered.attributes_dict.get("uniqueMember", []), eq=list(members))
        tm.that("orclACI" in original.attributes_dict, truth=True)
        tm.that("orclACI" in filtered.attributes_dict, truth=False)

    @staticmethod
    def test_filtering_does_not_admit_an_unmapped_structural_class() -> None:
        """Removing policy markers does not invent a data-class fallback."""
        api = ldif()
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_USER,
            attributes={
                "objectClass": ["top", "unmappedObjectClass"],
                "cn": ["sample"],
                "orclACI": ["access to entry by * (browse)"],
            },
        )
        filtered = api.filter_entry_attributes(
            entry,
            forbidden_attrs=tuple(c.Ldif.ACL_ATTR_NAMES),
            forbidden_ocs=(),
        )
        category, reason = api.categorization(
            server_type=c.Ldif.ServerTypes.OID,
        ).categorize_entry(filtered)
        tm.that(category, eq=c.Ldif.Category.REJECTED)
        tm.that(reason, eq=c.Ldif.REJECTION_REASON_NO_CATEGORY_MATCH)
