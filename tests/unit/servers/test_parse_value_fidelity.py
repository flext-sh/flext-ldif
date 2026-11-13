"""Parsed attributes keep every value exactly as the LDIF carries it.

Every test goes through the public ``parse_ldif`` and ``write`` facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import c, ldif, tm

_SERVER_TYPES = (c.Tests.RFC, c.Tests.OID, c.Tests.OUD)


class TestsFlextLdifParseValueFidelity:
    """No value is lost, overwritten or altered between parse and write."""

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    @c.Tests.MARK.parametrize(
        ("first", "second"),
        [("objectclass", "objectClass"), ("objectClass", "objectclass")],
        ids=["lower_then_camel", "camel_then_lower"],
    )
    def test_attribute_names_differing_only_in_case_are_one_attribute(
        server_type: str,
        first: str,
        second: str,
    ) -> None:
        """Both spellings' values are kept, in order, under one attribute."""
        content = f"dn: cn=a,dc=example\n{first}: top\n{second}: person\ncn: a\nCN: b\n"
        entry = tm.ok(ldif().parse_ldif(content, server_type=server_type)).entries[0]
        attributes = tm.not_none(entry.attributes).attributes
        by_lower = {name.lower(): values for name, values in attributes.items()}
        tm.that(len(attributes), eq=len(by_lower))
        tm.that(by_lower["objectclass"], eq=["top", "person"])
        tm.that(by_lower["cn"], eq=["a", "b"])
