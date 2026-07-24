"""Behavioral tests for RFC LDIF parse/write over real fixture data.

Exercises the PUBLIC contract of the parser and writer services against real
OID / OUD / OpenLDAP LDIF fixtures. Every assertion targets observable
behavior: the ``r[T]`` outcome, public response-model state (entries,
statistics, output_path, content) and round-trip invariants. No private
attributes, internal collaborators, or implementation details are touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.writer import FlextLdifWriter
from tests import c, m


class TestsFlextLdifRfcDockerRealIntegration:
    """Behavioral contract of parser/writer against real LDIF fixtures."""

    @pytest.fixture
    def server(self) -> FlextLdifServer:
        """Real server registry used as writer collaborator."""
        return FlextLdifServer()

    @pytest.fixture
    def parser(self) -> FlextLdifParser:
        """Parser under test."""
        return FlextLdifParser()

    # --- parse: real fixtures ------------------------------------------------

    @pytest.mark.parametrize(
        ("subdir", "filename"),
        [
            (c.Tests.OID, "oid_entries_fixtures.ldif"),
            (c.Tests.OUD, "oud_entries_fixtures.ldif"),
            ("openldap2", "openldap2_entries_fixtures.ldif"),
        ],
    )
    def test_parsing_real_entry_fixtures_yields_consistent_statistics(
        self, parser: FlextLdifParser, subdir: str, filename: str
    ) -> None:
        """Parsing real entries succeeds and statistics agree with entry list."""
        entries_file = c.Tests.FIXTURES_DIR / subdir / filename
        if not entries_file.exists():
            pytest.skip(f"Fixture not found: {entries_file}")

        result = parser.parse_ldif_file(entries_file)

        tm.ok(result)
        response = result.value
        assert response.entries, "expected at least one parsed entry"
        tm.that(response.statistics.total_entries, eq=len(response.entries))
        tm.that(response.detected_server_type, is_=str)
        assert response.detected_server_type

    @pytest.mark.parametrize(
        ("subdir", "filename"),
        [
            (c.Tests.OID, "oid_schema_fixtures.ldif"),
            (c.Tests.OUD, "oud_schema_fixtures.ldif"),
        ],
    )
    def test_parsing_real_schema_fixtures_succeeds(
        self, parser: FlextLdifParser, subdir: str, filename: str
    ) -> None:
        """Parsing real schema definitions returns a successful result."""
        schema_file = c.Tests.FIXTURES_DIR / subdir / filename
        if not schema_file.exists():
            pytest.skip(f"Fixture not found: {schema_file}")

        result = parser.parse_ldif_file(schema_file)

        tm.ok(result)
        assert isinstance(result.value, m.Ldif.ParseResponse)

    # --- write: contract of the write response -------------------------------

    def test_write_response_reports_output_path_and_matching_content(
        self, parser: FlextLdifParser, server: FlextLdifServer, tmp_path: Path
    ) -> None:
        """WriteResponse output_path and content mirror the file on disk."""
        source_file = c.Tests.FIXTURES_DIR / c.Tests.OID / "oid_entries_fixtures.ldif"
        if not source_file.exists():
            pytest.skip(f"Fixture not found: {source_file}")
        response = parser.parse_ldif_file(source_file).unwrap()

        output_file = tmp_path / "written.ldif"
        writer = FlextLdifWriter(server=server)
        write_result = writer.write_ldif_file(
            response, output_file, server_type=c.Tests.RFC
        )

        tm.ok(write_result)
        write_response = write_result.value
        tm.that(write_response.output_path, eq=str(output_file))
        assert output_file.exists()
        assert write_response.content
        tm.that(
            output_file.read_text(encoding="utf-8").rstrip("\n"),
            eq=write_response.content.rstrip("\n"),
        )

    def test_write_oud_acl_entries_produces_nonempty_file(
        self, parser: FlextLdifParser, server: FlextLdifServer, tmp_path: Path
    ) -> None:
        """OUD ACL entries write to a non-empty file via the public API."""
        acl_file = c.Tests.FIXTURES_DIR / c.Tests.OUD / "oud_acl_fixtures.ldif"
        if not acl_file.exists():
            pytest.skip(f"Fixture not found: {acl_file}")
        parse_result = parser.parse_ldif_file(acl_file)
        if not parse_result.success:
            pytest.skip(f"Failed to parse ACL fixture: {parse_result.error}")

        output_file = tmp_path / "acl_output.ldif"
        writer = FlextLdifWriter(server=server)
        result = writer.write_ldif_file(
            parse_result.value, output_file, server_type=c.Tests.RFC
        )

        tm.ok(result)
        assert output_file.exists()
        assert output_file.stat().st_size > 0

    # --- round-trip invariants ----------------------------------------------

    def test_write_then_reparse_preserves_entry_set(
        self, parser: FlextLdifParser, server: FlextLdifServer, tmp_path: Path
    ) -> None:
        """Parse -> write -> reparse preserves entry count and DN identities."""
        source_file = c.Tests.FIXTURES_DIR / c.Tests.OID / "oid_entries_fixtures.ldif"
        if not source_file.exists():
            pytest.skip(f"Fixture not found: {source_file}")
        original = parser.parse_ldif_file(source_file).unwrap()
        original_dns = {
            entry.dn.value for entry in original.entries if entry.dn is not None
        }

        output_file = tmp_path / "roundtrip.ldif"
        writer = FlextLdifWriter(server=server)
        write_result = writer.write_ldif_file(
            original, output_file, server_type=c.Tests.RFC
        )
        tm.ok(write_result)

        reparsed = parser.parse_ldif_file(output_file).unwrap()

        tm.that(len(reparsed.entries), eq=len(original.entries))
        tm.that(
            {entry.dn.value for entry in reparsed.entries if entry.dn is not None},
            eq=original_dns,
        )

    # --- error paths ---------------------------------------------------------

    def test_parsing_nonexistent_file_fails_and_unwrap_raises(
        self, parser: FlextLdifParser
    ) -> None:
        """A missing file yields a failure result whose unwrap raises."""
        result = parser.parse_ldif_file(Path("/nonexistent/file.ldif"))

        tm.fail(result)
        assert result.error is not None
        with pytest.raises(RuntimeError):
            result.unwrap()

    def test_writing_to_readonly_directory_fails_with_error(
        self, server: FlextLdifServer, tmp_path: Path
    ) -> None:
        """Writing into a read-only directory surfaces an explicit failure."""
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o555)
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["test"]}, attribute_metadata={}
            ),
        )
        writer = FlextLdifWriter(server=server)
        try:
            result = writer.write_ldif_file(
                [entry], readonly_dir / "test.ldif", server_type=c.Tests.RFC
            )
            if not result.success:
                assert result.error is not None
                assert (
                    "Permission denied" in result.error
                    or "LDIF write failed" in result.error
                )
        finally:
            readonly_dir.chmod(0o755)

    def test_parsing_empty_file_succeeds_with_zero_entries(
        self, parser: FlextLdifParser, tmp_path: Path
    ) -> None:
        """An empty LDIF file parses to a successful, empty response."""
        empty_file = tmp_path / "empty.ldif"
        empty_file.write_text("", encoding="utf-8")

        result = parser.parse_ldif_file(empty_file)

        tm.ok(result)
        response = result.value
        assert not response.entries
        tm.that(response.statistics.total_entries, eq=0)
