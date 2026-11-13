"""Parsing never drops or merges a record silently.

A record that cannot become an entry, a record line without a separator and a
second ``dn:`` line inside one record all fail the whole parse with the
physical line number and the cause. Every test goes through the public
``parse_ldif`` facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import c, ldif, tm

_GOOD_RECORD = "dn: cn=b,dc=example\nobjectClass: top\ncn: b\n"
_SERVER_TYPES = (c.Tests.RFC, c.Tests.OID, c.Tests.OUD)


class TestsFlextLdifParseNeverDrops:
    """A malformed record is a positioned parse failure, never a skip."""

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    @c.Tests.MARK.parametrize(
        ("content", "line", "cause"),
        [
            (f"{_GOOD_RECORD}\nobjectClass: top\ncn: a\n", 5, "DN"),
            (f"﻿dn: cn=a,dc=example\ncn: a\n\n{_GOOD_RECORD}", 1, "DN"),
            (f"{_GOOD_RECORD}\ndn: not-a-dn\ncn: a\n", 5, "not-a-dn"),
        ],
        ids=["no_dn_line", "bom_before_first_dn", "dn_refused_by_model"],
    )
    def test_record_that_cannot_become_an_entry_fails_the_parse(
        server_type: str,
        content: str,
        line: int,
        cause: str,
    ) -> None:
        """The failure names the record's first line and why it is no entry."""
        error = tm.fail(ldif().parse_ldif(content, server_type=server_type))
        tm.that(error, has=f"line {line}")
        tm.that(error, has=cause)

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    def test_record_line_without_separator_fails_the_parse(server_type: str) -> None:
        """A line with no ``:`` is malformed, never ignored."""
        content = f"{_GOOD_RECORD}\ndn: cn=a,dc=example\ncn: a\nbroken line\n"
        error = tm.fail(ldif().parse_ldif(content, server_type=server_type))
        tm.that(error, has="line 7")
        tm.that(error, has="broken line")

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    def test_second_dn_line_in_one_record_fails_the_parse(server_type: str) -> None:
        """Two records with no blank line between them are never merged."""
        content = f"dn: cn=a,dc=example\nobjectClass: top\ncn: a\n{_GOOD_RECORD}"
        error = tm.fail(ldif().parse_ldif(content, server_type=server_type))
        tm.that(error, has="line 4")
        tm.that(error, has="cn=b,dc=example")

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    def test_position_is_the_physical_line_after_folded_lines(
        server_type: str,
    ) -> None:
        """Line numbers count physical lines, folded continuations included."""
        content = (
            "dn: cn=a,dc=example\ndescription: folded\n  value\ncn: a\nbroken line\n"
        )
        error = tm.fail(ldif().parse_ldif(content, server_type=server_type))
        tm.that(error, has="line 5")

    @staticmethod
    @c.Tests.MARK.parametrize("server_type", _SERVER_TYPES)
    def test_comments_and_version_header_are_not_records(server_type: str) -> None:
        """Comment-only blocks and a commented version header drop no entry."""
        content = (
            "# exported by a directory server\n"
            "version: 1\n"
            "\n"
            "# a comment block on its own\n"
            "\n"
            f"{_GOOD_RECORD}"
            "\n"
            "# trailing comment\n"
        )
        entries = tm.ok(ldif().parse_ldif(content, server_type=server_type)).entries
        tm.that(
            [entry.dn.value for entry in entries if entry.dn],
            eq=["cn=b,dc=example"],
        )
