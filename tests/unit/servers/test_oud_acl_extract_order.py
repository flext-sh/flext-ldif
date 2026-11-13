"""The OUD writer comments ACL attributes in the entry's own order.

The written ACL comments follow the order the entry declares; taking it from
the set of ACL attribute names made the output depend on the process hash seed.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from itertools import permutations

from flext_ldif import FlextLdif
from tests import c, m, tm


class TestsFlextLdifOudAclExtractOrder:
    """Public contract of the commented ACL attribute order."""

    @staticmethod
    def test_commented_acl_attributes_follow_the_entry_order() -> None:
        """Every ordering of the entry is preserved, whatever the name set."""
        api = FlextLdif()
        values = {
            "orclaci": "access to entry by * (browse)",
            "orclentrylevelaci": "access to entry by * (browse, noadd)",
        }
        for order in permutations(values):
            parsed = api.parse_string(
                "dn: cn=synthetic\nobjectClass: person\ncn: synthetic\nsn: Sample\n"
                + "".join(f"{name}: {values[name]}\n" for name in order)
                + "\n",
                server_type=c.Ldif.ServerTypes.OID,
            ).unwrap()
            response = api.write(
                parsed,
                server_type=c.Ldif.ServerTypes.OUD,
                format_options=m.Ldif.WriteFormatOptions(
                    entry_category=c.Ldif.Categories.USERS,
                    comment_acl_in_non_acl_phases=True,
                    acl_attribute_names=frozenset(values),
                ),
            ).unwrap()
            content = response.content
            written = [
                name
                for line in content.splitlines()
                for name in values
                if line.startswith("#") and f"{name}:" in line
            ]
            tm.that(written, eq=list(order))
