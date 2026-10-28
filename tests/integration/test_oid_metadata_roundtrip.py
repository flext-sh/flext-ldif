"""OID metadata remains typed through phase-aware OUD serialization.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from tests import c, m, p, tm


class TestsFlextLdifOidMetadataRoundtrip:
    """Exercise the public parse/write boundary used by OID migrations."""

    @staticmethod
    @pytest.mark.parametrize("acl", ["", "orclaci: access to entry by * (browse)\n"])
    @pytest.mark.parametrize("comment_acl", [False, True])
    def test_oid_metadata_survives_oud_phase_write(
        api: p.Ldif.LdifClient,
        acl: str,
        *,
        comment_acl: bool,
    ) -> None:
        """Parsing must produce serializable metadata before any target write."""
        source = (
            "dn: cn=synthetic,dc=example,dc=invalid\n"
            "objectClass: person\ncn: synthetic\nsn: Sample\n"
            f"{acl}\n"
        )
        parsed = tm.ok(api.parse_ldif(source, server_type=c.Ldif.ServerTypes.OID))
        entry = parsed.entries[0]
        metadata = tm.not_none(entry.metadata)
        tm.that(metadata.server_type is c.Ldif.ServerTypes.OID, truth=True)
        serialized = metadata.model_dump(warnings="error")
        tm.that(serialized["server_type"] is c.Ldif.ServerTypes.OID, truth=True)

        written = tm.ok(
            api.write(
                list(parsed.entries),
                server_type=c.Ldif.ServerTypes.OUD,
                format_options=m.Ldif.WriteFormatOptions(
                    entry_category=c.Ldif.Categories.USERS,
                    comment_acl_in_non_acl_phases=comment_acl,
                    acl_attribute_names=frozenset({"aci", "orclaci"}),
                ),
            ),
        )
        content = tm.not_none(written.content)
        tm.that(content, truth=True)
        converted = tm.ok(
            api.parse_ldif(content, server_type=c.Ldif.ServerTypes.OUD),
        )
        tm.that(len(converted.entries), eq=len(parsed.entries))
        tm.that(converted.entries[0].dn_str, eq=entry.dn_str)
        tm.that(converted.entries[0].attributes_dict["sn"], eq=["Sample"])
