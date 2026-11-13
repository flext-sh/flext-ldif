"""Parsed attributes keep every value exactly as the LDIF carries it.

Every test goes through the public ``parse_ldif`` and ``write`` facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from typing import ClassVar

from tests import c, ldif, m, tm


class TestsFlextLdifParseValueFidelity:
    """No value is lost, overwritten or altered between parse and write."""

    SERVER_TYPES: ClassVar[Sequence[str]] = (c.Tests.RFC, c.Tests.OID, c.Tests.OUD)
    DN: ClassVar[str] = "cn=a,dc=example"
    BINARY: ClassVar[bytes] = b"\xff\xd8\xff\xe0\x00\x10JFIF\x80"
    BINARY_B64: ClassVar[str] = "/9j/4AAQSkZJRoA="
    NBSP: ClassVar[str] = "\N{NO-BREAK SPACE}"
    REPLACEMENT: ClassVar[str] = "\N{REPLACEMENT CHARACTER}"

    @staticmethod
    def value_bytes(value: str) -> bytes:
        """Return the bytes a parsed value stands for.

        Returns:
            The value encoded with the library's lossless UTF-8 handler.

        """
        return value.encode(c.Ldif.DEFAULT_ENCODING, c.Ldif.LOSSLESS_BYTES_ERRORS)

    @staticmethod
    def written_lines(value: str, server_type: str) -> list[str]:
        """Write one entry holding ``value``.

        Returns:
            The written ``description`` lines.

        """
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=TestsFlextLdifParseValueFidelity.DN),
            attributes=m.Ldif.Attributes(
                attributes={"objectClass": ["top"], "description": [value]},
            ),
        )
        content = tm.not_none(
            tm.ok(ldif().write([entry], server_type=server_type)).content,
        )
        return [line for line in content.split("\n") if line.startswith("description")]

    @staticmethod
    def parsed_description(content: str, server_type: str) -> list[str]:
        """Parse one record.

        Returns:
            The record's ``description`` values.

        """
        entry = tm.ok(ldif().parse_ldif(content, server_type=server_type)).entries[0]
        return list(tm.not_none(entry.attributes).attributes["description"])

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", SERVER_TYPES)
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
    @c.Tests.MARK.parametrize("server_type", SERVER_TYPES)
    def test_non_utf8_base64_value_stays_bytes_through_parse_and_write(
        server_type: str,
    ) -> None:
        """A binary payload is never decoded with replacement characters."""
        cls = TestsFlextLdifParseValueFidelity
        tm.that(base64.b64decode(cls.BINARY_B64), eq=cls.BINARY)
        content = f"dn: {cls.DN}\nobjectClass: top\ndescription:: {cls.BINARY_B64}\n"
        value = cls.parsed_description(content, server_type)[0]
        tm.that(value, lacks=cls.REPLACEMENT)
        tm.that(cls.value_bytes(value), eq=cls.BINARY)
        tm.that(
            cls.written_lines(value, server_type),
            eq=[f"description:: {cls.BINARY_B64}"],
        )

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", SERVER_TYPES)
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
        content = (
            f"dn: {TestsFlextLdifParseValueFidelity.DN}\nobjectClass: top\n"
            f"description:: {payload}\n"
        )
        error = tm.fail(ldif().parse_ldif(content, server_type=server_type))
        tm.that(error, has="line 3")
        tm.that(error, has="base64")

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", SERVER_TYPES)
    @c.Tests.MARK.parametrize(
        ("value_spec", "expected"),
        [
            (" abc  ", "abc  "),
            (f" abc{NBSP}", f"abc{NBSP}"),
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
        cls = TestsFlextLdifParseValueFidelity
        content = f"dn: {cls.DN}\nobjectClass: top\ndescription:{value_spec}\n"
        tm.that(cls.parsed_description(content, server_type), eq=[expected])

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", SERVER_TYPES)
    @c.Tests.MARK.parametrize(
        "value",
        ["\tabc", "abc\t", "abc ", " abc", "abc\x0b", f"abc{NBSP}", "a\tb"],
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
        cls = TestsFlextLdifParseValueFidelity
        lines = cls.written_lines(value, server_type)
        content = f"dn: {cls.DN}\nobjectClass: top\n" + "\n".join(lines) + "\n"
        tm.that(cls.parsed_description(content, server_type), eq=[value])

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", SERVER_TYPES)
    def test_crlf_separated_folded_value_is_unfolded_exactly(server_type: str) -> None:
        """A CRLF line separator never leaks into a folded value."""
        cls = TestsFlextLdifParseValueFidelity
        content = (
            f"dn: {cls.DN}\r\nobjectClass: top\r\ndescription: abc\r\n def\r\n\r\n"
        )
        tm.that(cls.parsed_description(content, server_type), eq=["abcdef"])

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", SERVER_TYPES)
    @c.Tests.MARK.parametrize(
        ("flag", "expected"),
        [("1", True), ("0", False)],
        ids=["delete", "keep"],
    )
    def test_deleteoldrdn_after_fill_is_read(
        server_type: str,
        flag: str,
        *,
        expected: bool,
    ) -> None:
        """``deleteoldrdn: 1`` deletes the old RDN; the FILL space is no value."""
        content = (
            f"dn: {TestsFlextLdifParseValueFidelity.DN}\nchangetype: modrdn\n"
            f"newrdn: cn=b\ndeleteoldrdn: {flag}\n"
        )
        entry = tm.ok(ldif().parse_ldif(content, server_type=server_type)).entries[0]
        tm.that(entry.deleteoldrdn, eq=expected)

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", SERVER_TYPES)
    @c.Tests.MARK.parametrize("value", ["\tabc", "abc\t"], ids=["leading", "trailing"])
    def test_edge_tab_is_written_base64(server_type: str, value: str) -> None:
        """A TAB at a value edge is never left to a reader's whitespace rules."""
        encoded = base64.b64encode(value.encode()).decode("ascii")
        tm.that(
            TestsFlextLdifParseValueFidelity.written_lines(value, server_type),
            eq=[f"description:: {encoded}"],
        )
