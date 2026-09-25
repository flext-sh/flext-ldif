"""OID metadata remains typed through phase-aware OUD serialization."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from tests import c, m

if TYPE_CHECKING:
    from tests import p


class TestsFlextLdifOidMetadataRoundtrip:
    """Exercise the public parse/write boundary used by OID migrations."""

    @pytest.mark.parametrize("acl", ["", "orclaci: access to entry by * (browse)\n"])
    @pytest.mark.parametrize("comment_acl", [False, True])
    def test_oid_metadata_survives_oud_phase_write(
        self, api: p.Ldif.LdifClient, acl: str, *, comment_acl: bool
    ) -> None:
        """Parsing must produce serializable metadata before any target write."""
        source = (
            "dn: cn=synthetic,dc=example,dc=invalid\n"
            "objectClass: person\ncn: synthetic\nsn: Sample\n"
            f"{acl}\n"
        )
        parsed = tm.ok(api.parse_ldif(source, server_type=c.Ldif.ServerTypes.OID))
        entry = parsed.entries[0]
        assert entry.metadata is not None
        assert entry.metadata.server_type is c.Ldif.ServerTypes.OID
        serialized = entry.metadata.model_dump(warnings="error")
        assert serialized["server_type"] is c.Ldif.ServerTypes.OID

        written = tm.ok(
            api.write(
                list(parsed.entries),
                server_type=c.Ldif.ServerTypes.OUD,
                format_options=m.Ldif.WriteFormatOptions(
                    entry_category=c.Ldif.Categories.USERS,
                    comment_acl_in_non_acl_phases=comment_acl,
                    acl_attribute_names=frozenset({"aci", "orclaci"}),
                ),
            )
        )
        assert written.content
        converted = tm.ok(
            api.parse_ldif(written.content, server_type=c.Ldif.ServerTypes.OUD)
        )
        assert len(converted.entries) == len(parsed.entries)
        assert converted.entries[0].dn_str == entry.dn_str
        assert converted.entries[0].attributes_dict["sn"] == ["Sample"]
