"""Parsed attributes keep every value exactly as the LDIF carries it.

Every test goes through the public ``parse_ldif`` and ``write`` facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64

from tests import c, ldif, m, tm

_SERVER_TYPES = (c.Tests.RFC, c.Tests.OID, c.Tests.OUD)
_DN = "cn=a,dc=example"
_BINARY = b"\xff\xd8\xff\xe0\x00\x10JFIF\x80"
_BINARY_B64 = base64.b64encode(_BINARY).decode("ascii")


def _value_bytes(value: str) -> bytes:
    """Return the bytes a parsed value stands for.

    Returns:
        The value encoded with the library's lossless UTF-8 handler.

    """
    return value.encode(c.Ldif.DEFAULT_ENCODING, c.Ldif.LOSSLESS_BYTES_ERRORS)


def _written_lines(value: str, server_type: str) -> list[str]:
    """Write one entry holding ``value``.

    Returns:
        The written ``description`` lines.

    """
    entry = m.Ldif.Entry(
        dn=m.Ldif.DN(value=_DN),
        attributes=m.Ldif.Attributes(
            attributes={"objectClass": ["top"], "description": [value]},
        ),
    )
    content = tm.not_none(
        tm.ok(ldif().write([entry], server_type=server_type)).content,
    )
    return [line for line in content.split("\n") if line.startswith("description")]


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

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    def test_non_utf8_base64_value_stays_bytes_through_parse_and_write(
        server_type: str,
    ) -> None:
        """A binary payload is never decoded with replacement characters."""
        content = f"dn: {_DN}\nobjectClass: top\ndescription:: {_BINARY_B64}\n"
        entry = tm.ok(ldif().parse_ldif(content, server_type=server_type)).entries[0]
        value = tm.not_none(entry.attributes).attributes["description"][0]
        tm.that(value, lacks="�")
        tm.that(_value_bytes(value), eq=_BINARY)
        tm.that(
            _written_lines(value, server_type),
            eq=[f"description:: {_BINARY_B64}"],
        )

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    @c.Tests.MARK.parametrize(
        "payload",
        ["abc", "YW*j", "YWJj ZA=="],
        ids=["bad_length", "outside_alphabet", "inner_space"],
    )
    def test_invalid_base64_value_fails_the_parse(
        server_type: str,
        payload: str,
    ) -> None:
        """Invalid base64 is a positioned failure, never kept as its text."""
        content = f"dn: {_DN}\nobjectClass: top\ndescription:: {payload}\n"
        error = tm.fail(ldif().parse_ldif(content, server_type=server_type))
        tm.that(error, has="line 3")
        tm.that(error, has="base64")

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    @c.Tests.MARK.parametrize(
        ("value_spec", "expected"),
        [
            (" abc  ", "abc  "),
            (" abc ", "abc "),
            (" abc\t", "abc\t"),
            (" abc\x0b", "abc\x0b"),
            ("\tabc", "\tabc"),
            ("   abc", "abc"),
        ],
        ids=[
            "trailing_spaces",
            "trailing_nbsp",
            "trailing_tab",
            "trailing_vertical_tab",
            "leading_tab_is_value",
            "fill_spaces_are_not_value",
        ],
    )
    def test_plain_value_whitespace_is_kept(
        server_type: str,
        value_spec: str,
        expected: str,
    ) -> None:
        """Only the FILL spaces after the colon are dropped from a plain value."""
        content = f"dn: {_DN}\nobjectClass: top\ndescription:{value_spec}\n"
        entry = tm.ok(ldif().parse_ldif(content, server_type=server_type)).entries[0]
        tm.that(
            tm.not_none(entry.attributes).attributes["description"],
            eq=[expected],
        )

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    @c.Tests.MARK.parametrize(
        "value",
        ["\tabc", "abc\t", "abc ", " abc", "abc\x0b", "abc ", "a\tb"],
        ids=[
            "leading_tab",
            "trailing_tab",
            "trailing_space",
            "leading_space",
            "trailing_vertical_tab",
            "trailing_nbsp",
            "inner_tab",
        ],
    )
    def test_value_round_trips_byte_exact(server_type: str, value: str) -> None:
        """What is written is read back unchanged."""
        lines = _written_lines(value, server_type)
        content = f"dn: {_DN}\nobjectClass: top\n" + "\n".join(lines) + "\n"
        entry = tm.ok(ldif().parse_ldif(content, server_type=server_type)).entries[0]
        tm.that(
            tm.not_none(entry.attributes).attributes["description"],
            eq=[value],
        )

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    @c.Tests.MARK.parametrize("value", ["\tabc", "abc\t"], ids=["leading", "trailing"])
    def test_edge_tab_is_written_base64(server_type: str, value: str) -> None:
        """A TAB at a value edge is never left to a reader's whitespace rules."""
        encoded = base64.b64encode(value.encode()).decode("ascii")
        tm.that(_written_lines(value, server_type), eq=[f"description:: {encoded}"])
