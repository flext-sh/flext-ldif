"""Unit tests for writer service using flat, data-driven constants."""

from __future__ import annotations

from collections.abc import MutableSequence
from pathlib import Path
from uuid import uuid4

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifWriter, m
from tests import c, u


class TestsFlextLdifWriterService:
    """Cover writer service branches with reusable constants."""

    @staticmethod
    def _build_entries() -> MutableSequence[m.Ldif.Entry]:
        return [
            u.Ldif.Tests.create_real_entry(dn=dn)
            for dn in sorted(c.Ldif.Tests.WRITER_ENTRY_DNS)
        ]

    @pytest.mark.parametrize(
        ("scenario", "server_type"),
        tuple(c.Ldif.Tests.WRITER_SERVER_CASES.items()),
    )
    def test_write_to_string_success_for_registered_servers(
        self,
        scenario: str,
        server_type: str,
        writer: FlextLdifWriter,
    ) -> None:
        entries = self._build_entries()

        result = writer.write_to_string(entries, server_type=server_type)
        content = u.Tests.assert_success(result)

        tm.that(bool(scenario), eq=True)
        tm.that(c.Ldif.Tests.WRITER_OUTPUT_REGEX.search(content) is not None, eq=True)

    def test_write_accepts_parse_response_input(self, writer: FlextLdifWriter) -> None:
        entries = self._build_entries()
        parse_response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(
                total_entries=len(entries),
                processed_entries=len(entries),
            ),
        )

        result = writer.write(parse_response, server_type=c.Ldif.Tests.RFC)
        payload = u.Tests.assert_success(result)

        tm.that(payload.statistics.total_entries, eq=len(entries))
        tm.that(payload.statistics.processed_entries, eq=len(entries))

    def test_write_to_string_fails_for_unknown_server(
        self,
        writer: FlextLdifWriter,
    ) -> None:
        entries = self._build_entries()
        unknown_server = f"{c.Ldif.Tests.WRITER_UNKNOWN_SERVER_PREFIX}_{uuid4().hex}"

        result = writer.write_to_string(entries, server_type=unknown_server)

        tm.fail(result, has="Failed to resolve LDIF server quirk")

    def test_write_ldif_file_success_persists_output(
        self,
        writer: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        output_file = tmp_path / c.Ldif.Tests.WRITER_OUTPUT_FILENAME

        result = writer.write_ldif_file(
            self._build_entries(),
            output_file,
            server_type=c.Ldif.Tests.RFC,
        )
        payload = u.Tests.assert_success(result)

        tm.that(output_file.exists(), eq=True)
        tm.that(payload.output_path, eq=str(output_file))
        tm.that(payload.statistics.total_entries, eq=len(self._build_entries()))

    def test_write_ldif_file_fails_when_parent_is_not_directory(
        self,
        writer: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        blocking_file = tmp_path / "blocking_parent"
        blocking_file.write_text("x", encoding="utf-8")
        target = blocking_file / c.Ldif.Tests.WRITER_OUTPUT_FILENAME

        result = writer.write_ldif_file(
            self._build_entries(),
            target,
            server_type=c.Ldif.Tests.RFC,
        )

        tm.fail(result, has="Failed to create parent directories")

    def test_write_ldif_file_fails_when_target_is_directory(
        self,
        writer: FlextLdifWriter,
        tmp_path: Path,
    ) -> None:
        directory_target = tmp_path / "dir_target"
        directory_target.mkdir(parents=True, exist_ok=True)

        result = writer.write_ldif_file(
            self._build_entries(),
            directory_target,
            server_type=c.Ldif.Tests.RFC,
        )

        tm.fail(result, has="Failed to write LDIF file")
