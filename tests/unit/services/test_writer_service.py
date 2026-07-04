"""Unit tests for writer service using flat, data-driven constants."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
from flext_tests import tm

from tests.constants import c
from tests.models import m
from tests.utilities import u

if TYPE_CHECKING:
    from pathlib import Path

    from tests.protocols import p
    from tests.typings import t


class TestsFlextLdifWriterService:
    """Cover writer service branches with reusable constants."""

    @staticmethod
    def _build_entries() -> t.MutableSequenceOf[m.Ldif.Entry]:
        return [
            u.Tests.create_real_entry(dn=dn) for dn in sorted(c.Tests.WRITER_ENTRY_DNS)
        ]

    @pytest.mark.parametrize(
        ("scenario", "server_type"),
        tuple(c.Tests.WRITER_SERVER_CASES.items()),
    )
    def test_write_to_string_success_for_registered_servers(
        self,
        scenario: str,
        server_type: str,
        writer: p.Ldif.LdifClient,
    ) -> None:
        entries = self._build_entries()

        result = writer.write_to_string(entries, server_type=server_type)
        content = u.Tests.assert_success(result)

        tm.that(bool(scenario), eq=True)
        tm.that(c.Tests.WRITER_OUTPUT_REGEX.search(content) is not None, eq=True)

    def test_write_accepts_parse_response_input(
        self,
        writer: p.Ldif.LdifClient,
    ) -> None:
        entries = self._build_entries()
        parse_response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(
                total_entries=len(entries),
                processed_entries=len(entries),
            ),
        )

        result = writer.write(parse_response, server_type=c.Tests.RFC)
        payload = u.Tests.assert_success(result)

        tm.that(payload.statistics.total_entries, eq=len(entries))
        tm.that(payload.statistics.processed_entries, eq=len(entries))

    def test_write_to_string_fails_for_unknown_server(
        self,
        writer: p.Ldif.LdifClient,
    ) -> None:
        entries = self._build_entries()
        unknown_server = f"{c.Tests.WRITER_UNKNOWN_SERVER_PREFIX}_{uuid4().hex}"

        result = writer.write_to_string(entries, server_type=unknown_server)

        tm.fail(result, has="Invalid server type")

    def test_write_to_string_keeps_dn_prefix_before_folding(
        self,
        writer: p.Ldif.LdifClient,
    ) -> None:
        long_dn = "cn=writer-fold-target,ou=department-with-an-exceptionally-long-name-for-folding-checks,ou=subdivision-with-another-exceptionally-long-name,dc=example,dc=com"
        result = writer.write_to_string(
            [u.Tests.create_real_entry(dn=long_dn)],
            server_type=c.Tests.RFC,
        )

        content = u.Tests.assert_success(result)

        tm.that(content.startswith("dn: cn=writer-fold-target"), eq=True)
        tm.that("\n " in content, eq=True)

    def test_write_ldif_file_success_persists_output(
        self,
        writer: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        output_file = tmp_path / c.Tests.WRITER_OUTPUT_FILENAME

        result = writer.write_ldif_file(
            self._build_entries(),
            output_file,
            server_type=c.Tests.RFC,
        )
        payload = u.Tests.assert_success(result)

        tm.that(output_file.exists(), eq=True)
        tm.that(payload.output_path, eq=str(output_file))
        tm.that(payload.statistics.total_entries, eq=len(self._build_entries()))

    def test_write_ldif_file_fails_when_parent_is_not_directory(
        self,
        writer: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        blocking_file = tmp_path / c.Tests.WRITER_BLOCKING_PARENT_NAME
        blocking_file.write_text("x", encoding="utf-8")
        target = blocking_file / c.Tests.WRITER_OUTPUT_FILENAME

        result = writer.write_ldif_file(
            self._build_entries(),
            target,
            server_type=c.Tests.RFC,
        )

        # atomic_write_text_file creates parents + writes as one operation; the
        # blocked-parent failure surfaces under the unified write error with the
        # parent cause (ensure_dir) preserved.
        tm.fail(result, has="Failed to write LDIF file")

    def test_write_ldif_file_fails_when_target_is_directory(
        self,
        writer: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        directory_target = tmp_path / c.Tests.WRITER_DIRECTORY_TARGET_NAME
        directory_target.mkdir(parents=True, exist_ok=True)

        result = writer.write_ldif_file(
            self._build_entries(),
            directory_target,
            server_type=c.Tests.RFC,
        )

        tm.fail(result, has="Failed to write LDIF file")

    def test_write_fails_with_unknown_server_type(
        self,
        writer: p.Ldif.LdifClient,
    ) -> None:
        entries = self._build_entries()
        result = writer.write(entries, server_type=c.Tests.WRITER_UNKNOWN_SERVER_PREFIX)
        tm.fail(result, has="Invalid server type")

    def test_write_ldif_file_fails_with_unknown_server_type(
        self,
        writer: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        output_file = tmp_path / c.Tests.WRITER_OUTPUT_FILENAME
        result = writer.write_ldif_file(
            self._build_entries(),
            output_file,
            server_type=c.Tests.WRITER_UNKNOWN_SERVER_PREFIX,
        )
        tm.fail(result, has="Invalid server type")
