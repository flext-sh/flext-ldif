"""Behavioral tests for the LDIF writer service public contract.

Every test exercises only the observable contract of ``FlextLdifWriter``
(``write`` / ``write_to_string`` / ``write_ldif_file``): the ``r[T]`` outcome,
the serialized LDIF text, the persisted file, and the public ``WriteResponse``
fields. No private attribute, collaborator spying, or internal patching.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import errno
from collections.abc import MutableSequence
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import pytest

from tests import c, ldif, m, p, tm, u


class TestsFlextLdifWriterService:
    """Assert the observable writing behavior promised by the public API."""

    @staticmethod
    def _entries() -> MutableSequence[m.Ldif.Entry]:
        return [
            u.Tests.create_real_entry(dn=dn) for dn in sorted(c.Tests.WRITER_ENTRY_DNS)
        ]

    @staticmethod
    def _dns() -> tuple[str, ...]:
        return tuple(sorted(c.Tests.WRITER_ENTRY_DNS))

    # ── write_to_string: success contract ────────────────────────────────

    @pytest.mark.parametrize(
        ("scenario", "server_type"),
        tuple(c.Tests.WRITER_SERVER_CASES.items()),
    )
    def test_write_to_string_serializes_every_entry_dn_for_each_server(
        self,
        scenario: str,
        server_type: str,
        writer: p.Ldif.LdifClient,
    ) -> None:
        """Test write to string serializes every entry dn for each server."""
        result = writer.write_to_string(self._entries(), server_type=server_type)

        content = tm.ok(
            result,
            msg=f"writing must succeed for {scenario}",
        )

        tm.not_none(c.Tests.WRITER_OUTPUT_REGEX.search(content))
        for dn in self._dns():
            tm.that(content, has=f"dn: {dn}")

    def test_write_to_string_is_idempotent_for_identical_input(
        self,
        writer: p.Ldif.LdifClient,
    ) -> None:
        """Test write to string is idempotent for identical input."""
        entries = self._entries()

        first = tm.ok(
            writer.write_to_string(entries, server_type=c.Tests.RFC),
        )
        second = tm.ok(
            writer.write_to_string(entries, server_type=c.Tests.RFC),
        )

        tm.that(first, eq=second)

    @staticmethod
    def test_write_to_string_returns_empty_content_for_no_entries(
        writer: p.Ldif.LdifClient,
    ) -> None:
        """Test write to string returns empty content for no entries."""
        content = tm.ok(
            writer.write_to_string([], server_type=c.Tests.RFC),
        )

        tm.that(content, eq="")

    @staticmethod
    def test_write_to_string_keeps_dn_prefix_before_folding(
        writer: p.Ldif.LdifClient,
    ) -> None:
        """Test write to string keeps dn prefix before folding."""
        long_dn = (
            "cn=writer-fold-target,"
            "ou=department-with-an-exceptionally-long-name-for-folding-checks,"
            "ou=subdivision-with-another-exceptionally-long-name,"
            "dc=example,dc=com"
        )

        content = tm.ok(
            writer.write_to_string(
                [u.Tests.create_real_entry(dn=long_dn)],
                server_type=c.Tests.RFC,
            ),
        )

        tm.that(content, starts="dn: cn=writer-fold-target", has="\n ")

    # ── write: WriteResponse contract ────────────────────────────────────

    def test_write_returns_content_and_statistics_for_entry_sequence(
        self,
        writer: p.Ldif.LdifClient,
    ) -> None:
        """Test write returns content and statistics for entry sequence."""
        entries = self._entries()

        payload = tm.ok(writer.write(entries, server_type=c.Tests.RFC))

        content = tm.not_none(payload.content)
        for dn in self._dns():
            tm.that(content, has=f"dn: {dn}")
        tm.that(payload.statistics.total_entries, eq=len(entries))
        tm.that(payload.statistics.processed_entries, eq=len(entries))
        tm.that(payload.output_path, eq=None)

    def test_write_accepts_parse_response_input(
        self,
        writer: p.Ldif.LdifClient,
    ) -> None:
        """Test write accepts parse response input."""
        entries = self._entries()
        parse_response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(
                total_entries=len(entries),
                processed_entries=len(entries),
            ),
        )

        payload = tm.ok(
            writer.write(parse_response.entries, server_type=c.Tests.RFC),
        )

        tm.that(payload.statistics.total_entries, eq=len(entries))
        tm.that(payload.statistics.processed_entries, eq=len(entries))

    # ── write_ldif_file: persistence contract ────────────────────────────

    def test_write_ldif_file_persists_content_and_reports_path(
        self,
        writer: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        """Test write ldif file persists content and reports path."""
        entries = self._entries()
        output_file = tmp_path / c.Tests.WRITER_OUTPUT_FILENAME

        payload = tm.ok(
            writer.write_ldif_file(entries, output_file, server_type=c.Tests.RFC),
        )

        tm.that(output_file.exists())
        tm.that(payload.output_path, eq=str(output_file))
        tm.that(payload.statistics.total_entries, eq=len(entries))
        # Every entry the caller handed in must be serialized to disk.
        persisted = output_file.read_text(encoding="utf-8")
        for dn in self._dns():
            tm.that(persisted, has=f"dn: {dn}")

    # ── error paths: r[T] failure contract ───────────────────────────────

    def test_write_ldif_file_accepts_relative_destinations(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        """Relative public destinations persist text and retain caller metadata."""
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            destination = (
                Path(directory) / c.Tests.WRITER_OUTPUT_FILENAME
            ).relative_to(Path.cwd())
            written = tm.ok(writer.write_ldif_file(self._entries(), destination))
            tm.that(
                destination.read_text(encoding=c.DEFAULT_ENCODING), eq=written.content
            )
            tm.that(written.output_path, eq=str(destination))

    def test_relative_destinations_do_not_resolve_symbolic_links(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        """Absolute admission retains the atomic writer's symlink refusal."""
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            original = Path(directory) / "original.ldif"
            original.write_text("unchanged", encoding=c.DEFAULT_ENCODING)
            destination = Path(directory) / "destination.ldif"
            destination.symlink_to(original)
            tm.fail(
                writer.write_ldif_file(
                    self._entries(), destination.relative_to(Path.cwd())
                )
            )
            tm.that(original.read_text(encoding=c.DEFAULT_ENCODING), eq="unchanged")
            tm.that(destination.is_symlink())

    def test_write_to_string_fails_for_unknown_server(
        self,
        writer: p.Ldif.LdifClient,
    ) -> None:
        """Test write to string fails for unknown server."""
        unknown_server = f"{c.Tests.WRITER_UNKNOWN_SERVER_PREFIX}_{uuid4().hex}"

        result = writer.write_to_string(self._entries(), server_type=unknown_server)

        tm.fail(result, has="Invalid server type")

    def test_write_fails_for_unknown_server(self, writer: p.Ldif.LdifClient) -> None:
        """Test write fails for unknown server."""
        result = writer.write(
            self._entries(),
            server_type=c.Tests.WRITER_UNKNOWN_SERVER_PREFIX,
        )

        tm.fail(result, has="Invalid server type")

    def test_write_ldif_file_fails_for_unknown_server(
        self,
        writer: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        """Test write ldif file fails for unknown server."""
        output_file = tmp_path / c.Tests.WRITER_OUTPUT_FILENAME

        result = writer.write_ldif_file(
            self._entries(),
            output_file,
            server_type=c.Tests.WRITER_UNKNOWN_SERVER_PREFIX,
        )

        tm.fail(result, has="Invalid server type")
        tm.fail(output_file.exists())

    def test_write_ldif_file_fails_when_parent_is_not_a_directory(
        self,
        writer: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        """Test write ldif file fails when parent is not a directory."""
        blocking_file = tmp_path / c.Tests.WRITER_BLOCKING_PARENT_NAME
        blocking_file.write_text("x", encoding="utf-8")
        target = blocking_file / c.Tests.WRITER_OUTPUT_FILENAME

        result = writer.write_ldif_file(
            self._entries(),
            target,
            server_type=c.Tests.RFC,
        )

        tm.fail(result, has=str(blocking_file))
        with pytest.raises(FileExistsError):
            result.unwrap()
        tm.that(blocking_file.read_text(encoding="utf-8"), eq="x")

    def test_write_ldif_file_fails_when_target_is_a_directory(
        self,
        writer: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        """Test write ldif file fails when target is a directory."""
        directory_target = tmp_path / c.Tests.WRITER_DIRECTORY_TARGET_NAME
        directory_target.mkdir(parents=True, exist_ok=True)

        result = writer.write_ldif_file(
            self._entries(),
            directory_target,
            server_type=c.Tests.RFC,
        )

        tm.fail(result, has=str(directory_target))
        with pytest.raises(
            OSError, match="atomic destination is not a regular file"
        ) as failure:
            result.unwrap()
        tm.that(failure.value.errno, eq=errno.EINVAL)
        tm.that(directory_target.is_dir())

    @pytest.mark.parametrize("server_type", [c.Tests.RFC, "oud"])
    def test_rejection_comments_are_opt_in_and_cannot_inject_entries(
        self,
        writer: p.Ldif.LdifClient,
        server_type: str,
    ) -> None:
        """Rejection metadata changes comments only, including multiline reasons."""
        entry = self._entries()[0]
        reason = (
            "Outside requested base\r\ndn: cn=injected,dc=example,dc=com\n\ncn: "
            "injected"
        )
        rejected = u.Ldif.update_entry_statistics(
            entry,
            mark_rejected=("base_dn_filter", reason),
        )
        disabled = m.Ldif.WriteFormatOptions(write_rejection_reasons=False)
        enabled = m.Ldif.WriteFormatOptions(write_rejection_reasons=True)
        original = tm.ok(
            writer.write([entry], server_type=server_type, format_options=disabled),
        )
        without_comments = tm.ok(
            writer.write([rejected], server_type=server_type, format_options=disabled),
        )
        with_comments = tm.ok(
            writer.write([rejected], server_type=server_type, format_options=enabled),
        )
        original_text = tm.not_none(original.content)
        disabled_text = tm.not_none(without_comments.content)
        enabled_text = tm.not_none(with_comments.content)
        tm.that(disabled_text, eq=original_text)
        accepted_output = tm.ok(
            writer.write([entry], server_type=server_type, format_options=enabled),
        )
        tm.that(accepted_output.content, eq=original_text)
        tm.that(enabled_text, has="# Rejection category: base_dn_filter")
        for line in reason.splitlines():
            tm.that(enabled_text, has=f"# Rejection reason: {line}")

        def active_lines(text: str) -> list[str]:
            return [line for line in text.splitlines() if not line.startswith("#")]

        tm.that(active_lines(enabled_text), eq=active_lines(original_text))
        tm.that(tm.not_none(entry.metadata).processing_stats, none=True)
        stats = tm.not_none(tm.not_none(rejected.metadata).processing_stats)
        tm.that(stats.rejection_reason, eq=reason)

    def test_rejection_statistics_survive_later_category_updates(self) -> None:
        """Updating category metadata must not discard the earlier rejection."""
        entry = self._entries()[0]
        rejected = u.Ldif.update_entry_statistics(
            entry,
            mark_rejected=("base_dn_filter", "Outside requested base"),
        )
        updated = u.Ldif.update_entry_statistics(rejected, category="rejected")
        stats = tm.not_none(tm.not_none(updated.metadata).processing_stats)
        tm.that(stats.was_rejected)
        tm.that(stats.rejection_reason, eq="Outside requested base")
        tm.that(stats.category_assigned, eq="rejected")

    @staticmethod
    def test_base_dn_rejection_is_preserved_in_export(
        writer: p.Ldif.LdifClient,
    ) -> None:
        """A real categorization filter must retain its reason through export."""
        base_dn = "dc=allowed,dc=invalid"
        entry = u.Tests.create_real_entry(dn="cn=outside,dc=other,dc=invalid")
        categorizer = ldif.categorization(base_dn=base_dn)
        categories = m.Ldif.FlexibleCategories.model_validate({
            "categories": {c.Ldif.Categories.USERS: [entry]},
        })
        filtered = categorizer.filter_by_base_dn(categories)
        rejected = filtered.get(c.Ldif.Categories.REJECTED, [])
        tm.that(len(rejected), eq=1)
        response = tm.ok(
            writer.write(
                rejected,
                server_type="oud",
                format_options=m.Ldif.WriteFormatOptions(write_rejection_reasons=True),
            ),
        )
        content = tm.not_none(response.content)
        tm.that(content, has=f"# Rejection reason: DN not under base DN: {base_dn}")
        tm.that(content, has="dn: cn=outside,dc=other,dc=invalid")
