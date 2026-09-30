"""Behavioral tests for the LDIF writer service public contract.

Every test exercises only the observable contract of ``FlextLdifWriter``
(``write`` / ``write_to_string`` / ``write_ldif_file``): the ``r[T]`` outcome,
the serialized LDIF text, the persisted file, and the public ``WriteResponse``
fields. No private attribute, collaborator spying, or internal patching.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
from flext_tests import tm

from flext_ldif import ldif
from tests import c, m, u

if TYPE_CHECKING:
    from pathlib import Path

    from tests import p, t


class TestsFlextLdifWriterService:
    """Assert the observable writing behavior promised by the public API."""

    @staticmethod
    def _entries() -> t.MutableSequenceOf[m.Ldif.Entry]:
        return [
            u.Tests.create_real_entry(dn=dn) for dn in sorted(c.Tests.WRITER_ENTRY_DNS)
        ]

    @staticmethod
    def _dns() -> t.VariadicTuple[str]:
        return tuple(sorted(c.Tests.WRITER_ENTRY_DNS))

    # ── write_to_string: success contract ────────────────────────────────

    @pytest.mark.parametrize(
        ("scenario", "server_type"), tuple(c.Tests.WRITER_SERVER_CASES.items())
    )
    def test_write_to_string_serializes_every_entry_dn_for_each_server(
        self, scenario: str, server_type: str, writer: p.Ldif.LdifClient
    ) -> None:
        result = writer.write_to_string(self._entries(), server_type=server_type)

        content = u.Tests.assert_success(
            result, error_msg=f"writing must succeed for {scenario}"
        )

        tm.that(c.Tests.WRITER_OUTPUT_REGEX.search(content) is not None, eq=True)
        for dn in self._dns():
            tm.that(f"dn: {dn}" in content, eq=True)

    def test_write_to_string_is_idempotent_for_identical_input(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        entries = self._entries()

        first = u.Tests.assert_success(
            writer.write_to_string(entries, server_type=c.Tests.RFC)
        )
        second = u.Tests.assert_success(
            writer.write_to_string(entries, server_type=c.Tests.RFC)
        )

        tm.that(first, eq=second)

    def test_write_to_string_returns_empty_content_for_no_entries(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        content = u.Tests.assert_success(
            writer.write_to_string([], server_type=c.Tests.RFC)
        )

        tm.that(content, eq="")

    def test_write_to_string_keeps_dn_prefix_before_folding(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        long_dn = (
            "cn=writer-fold-target,"
            "ou=department-with-an-exceptionally-long-name-for-folding-checks,"
            "ou=subdivision-with-another-exceptionally-long-name,"
            "dc=example,dc=com"
        )

        content = u.Tests.assert_success(
            writer.write_to_string(
                [u.Tests.create_real_entry(dn=long_dn)], server_type=c.Tests.RFC
            )
        )

        tm.that(content.startswith("dn: cn=writer-fold-target"), eq=True)
        tm.that("\n " in content, eq=True)

    # ── write: WriteResponse contract ────────────────────────────────────

    def test_write_returns_content_and_statistics_for_entry_sequence(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        entries = self._entries()

        payload = u.Tests.assert_success(writer.write(entries, server_type=c.Tests.RFC))

        tm.that(payload.content is not None, eq=True)
        assert payload.content is not None
        for dn in self._dns():
            tm.that(f"dn: {dn}" in payload.content, eq=True)
        tm.that(payload.statistics.total_entries, eq=len(entries))
        tm.that(payload.statistics.processed_entries, eq=len(entries))
        tm.that(payload.output_path, eq=None)

    def test_write_accepts_parse_response_input(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        entries = self._entries()
        parse_response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(
                total_entries=len(entries), processed_entries=len(entries)
            ),
        )

        payload = u.Tests.assert_success(
            writer.write(parse_response.entries, server_type=c.Tests.RFC)
        )

        tm.that(payload.statistics.total_entries, eq=len(entries))
        tm.that(payload.statistics.processed_entries, eq=len(entries))

    # ── write_ldif_file: persistence contract ────────────────────────────

    def test_write_ldif_file_persists_content_and_reports_path(
        self, writer: p.Ldif.LdifClient, tmp_path: Path
    ) -> None:
        entries = self._entries()
        output_file = tmp_path / c.Tests.WRITER_OUTPUT_FILENAME

        payload = u.Tests.assert_success(
            writer.write_ldif_file(entries, output_file, server_type=c.Tests.RFC)
        )

        tm.that(output_file.exists(), eq=True)
        tm.that(payload.output_path, eq=str(output_file))
        tm.that(payload.statistics.total_entries, eq=len(entries))
        # Every entry the caller handed in must be serialized to disk.
        persisted = output_file.read_text(encoding="utf-8")
        for dn in self._dns():
            tm.that(f"dn: {dn}" in persisted, eq=True)

    # ── error paths: r[T] failure contract ───────────────────────────────

    def test_write_to_string_fails_for_unknown_server(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        unknown_server = f"{c.Tests.WRITER_UNKNOWN_SERVER_PREFIX}_{uuid4().hex}"

        result = writer.write_to_string(self._entries(), server_type=unknown_server)

        tm.fail(result, has="Invalid server type")

    def test_write_fails_for_unknown_server(self, writer: p.Ldif.LdifClient) -> None:
        result = writer.write(
            self._entries(), server_type=c.Tests.WRITER_UNKNOWN_SERVER_PREFIX
        )

        tm.fail(result, has="Invalid server type")

    def test_write_ldif_file_fails_for_unknown_server(
        self, writer: p.Ldif.LdifClient, tmp_path: Path
    ) -> None:
        output_file = tmp_path / c.Tests.WRITER_OUTPUT_FILENAME

        result = writer.write_ldif_file(
            self._entries(),
            output_file,
            server_type=c.Tests.WRITER_UNKNOWN_SERVER_PREFIX,
        )

        tm.fail(result, has="Invalid server type")
        tm.that(output_file.exists(), eq=False)

    def test_write_ldif_file_fails_when_parent_is_not_a_directory(
        self, writer: p.Ldif.LdifClient, tmp_path: Path
    ) -> None:
        blocking_file = tmp_path / c.Tests.WRITER_BLOCKING_PARENT_NAME
        blocking_file.write_text("x", encoding="utf-8")
        target = blocking_file / c.Tests.WRITER_OUTPUT_FILENAME

        result = writer.write_ldif_file(
            self._entries(), target, server_type=c.Tests.RFC
        )

        tm.fail(result, has="Failed to write LDIF file")

    def test_write_ldif_file_fails_when_target_is_a_directory(
        self, writer: p.Ldif.LdifClient, tmp_path: Path
    ) -> None:
        directory_target = tmp_path / c.Tests.WRITER_DIRECTORY_TARGET_NAME
        directory_target.mkdir(parents=True, exist_ok=True)

        result = writer.write_ldif_file(
            self._entries(), directory_target, server_type=c.Tests.RFC
        )

        tm.fail(result, has="Failed to write LDIF file")

    @pytest.mark.parametrize("server_type", [c.Tests.RFC, "oud"])
    def test_rejection_comments_are_opt_in_and_cannot_inject_entries(
        self, writer: p.Ldif.LdifClient, server_type: str
    ) -> None:
        """Rejection metadata changes comments only, including multiline reasons."""
        entry = self._entries()[0]
        reason = "Outside requested base\r\ndn: cn=injected,dc=example,dc=com\n\ncn: injected"
        rejected = u.Ldif.update_entry_statistics(
            entry, mark_rejected=("base_dn_filter", reason)
        )
        disabled = m.Ldif.WriteFormatOptions(write_rejection_reasons=False)
        enabled = m.Ldif.WriteFormatOptions(write_rejection_reasons=True)
        original = u.Tests.assert_success(writer.write(
            [entry], server_type=server_type, format_options=disabled
        ))
        without_comments = u.Tests.assert_success(writer.write(
            [rejected], server_type=server_type, format_options=disabled
        ))
        with_comments = u.Tests.assert_success(writer.write(
            [rejected], server_type=server_type, format_options=enabled
        ))
        original_text = original.content
        disabled_text = without_comments.content
        enabled_text = with_comments.content
        assert original_text is not None
        assert disabled_text is not None
        assert enabled_text is not None
        assert disabled_text == original_text
        accepted_output = u.Tests.assert_success(writer.write(
            [entry], server_type=server_type, format_options=enabled
        ))
        assert accepted_output.content == original_text
        assert "# Rejection category: base_dn_filter" in enabled_text
        for line in reason.splitlines():
            assert f"# Rejection reason: {line}" in enabled_text

        def active_lines(text: str) -> list[str]:
            return [line for line in text.splitlines() if not line.startswith("#")]
        assert active_lines(enabled_text) == active_lines(original_text)
        assert entry.metadata is not None
        assert entry.metadata.processing_stats is None
        assert rejected.metadata is not None
        assert rejected.metadata.processing_stats is not None
        assert rejected.metadata.processing_stats.model_dump()["rejection_reason"] == reason

    def test_rejection_statistics_survive_later_category_updates(self) -> None:
        """Updating category metadata must not discard the earlier rejection."""
        entry = self._entries()[0]
        rejected = u.Ldif.update_entry_statistics(
            entry, mark_rejected=("base_dn_filter", "Outside requested base")
        )
        updated = u.Ldif.update_entry_statistics(rejected, category="rejected")
        assert updated.metadata is not None
        assert updated.metadata.processing_stats is not None
        stats = updated.metadata.processing_stats.model_dump()
        assert stats["was_rejected"] is True
        assert stats["rejection_reason"] == "Outside requested base"
        assert stats["category_assigned"] == "rejected"

    def test_base_dn_rejection_is_preserved_in_export(
        self, writer: p.Ldif.LdifClient
    ) -> None:
        """A real categorization filter must retain its reason through export."""
        base_dn = "dc=allowed,dc=invalid"
        entry = u.Tests.create_real_entry(dn="cn=outside,dc=other,dc=invalid")
        categorizer = ldif.categorization(base_dn=base_dn)
        categories = m.Ldif.FlexibleCategories.model_validate({
            "categories": {c.Ldif.Categories.USERS: [entry]}
        })
        filtered = categorizer.filter_by_base_dn(categories)
        rejected = filtered.get(c.Ldif.Categories.REJECTED, [])
        assert len(rejected) == 1
        response = u.Tests.assert_success(writer.write(
            list(rejected), server_type="oud",
            format_options=m.Ldif.WriteFormatOptions(write_rejection_reasons=True),
        ))
        assert response.content is not None
        assert f"# Rejection reason: DN not under base DN: {base_dn}" in response.content
        assert "dn: cn=outside,dc=other,dc=invalid" in response.content
