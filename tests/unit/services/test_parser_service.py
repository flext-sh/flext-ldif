"""Unit tests for parser service branch coverage."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from flext_tests import tm

from tests import c, m, p, u


class TestsFlextLdifParserService:
    """Cover parser service error and path-resolution branches."""

    def test_parse_ldif_from_path_uses_file_flow(
        self, api: p.Ldif.Client, tmp_path: Path
    ) -> None:
        fixture_file = tmp_path / c.Tests.PARSER_PATH_FLOW_FILENAME
        fixture_file.write_text(c.Tests.RFC_SAMPLE_LDIF_BASIC, encoding="utf-8")

        result = api.parse_ldif(fixture_file, server_type=c.Tests.RFC)
        parsed = u.Tests.assert_success(result)

        tm.that(parsed, is_=m.Ldif.ParseResponse)
        tm.that(len(parsed.entries) > 0, eq=True)

    def test_parse_ldif_file_rejects_src_root_fallback(
        self, api: p.Ldif.Client
    ) -> None:
        relative_package_path = Path("flext_ldif") / "__init__.py"

        result = api.parse_ldif_file(relative_package_path, server_type=c.Tests.RFC)

        tm.fail(result, has="File not found")

    def test_parse_ldif_file_returns_failure_when_path_is_missing(
        self, api: p.Ldif.Client
    ) -> None:
        missing_path = Path(f"{c.Tests.PARSER_MISSING_PREFIX}_{uuid4().hex}.ldif")

        result = api.parse_ldif_file(missing_path, server_type=c.Tests.RFC)

        tm.fail(result, has="File not found")

    def test_parse_ldif_file_returns_failure_when_decode_fails(
        self, api: p.Ldif.Client, tmp_path: Path
    ) -> None:
        invalid_utf8_path = tmp_path / c.Tests.PARSER_INVALID_UTF8_FILENAME
        invalid_utf8_path.write_bytes(c.Tests.WRITER_INVALID_UTF8_BYTES)

        result = api.parse_ldif_file(
            invalid_utf8_path, server_type=c.Tests.RFC, encoding="utf-8"
        )

        tm.fail(result, has="utf-8")

    def test_parse_string_returns_failure_for_unknown_server_type(
        self, api: p.Ldif.Client
    ) -> None:
        result = api.parse_string(
            c.Tests.RFC_SAMPLE_LDIF_BASIC,
            server_type=f"{c.Tests.PARSER_UNKNOWN_PREFIX}_{uuid4().hex}",
        )

        tm.fail(result, has="Invalid server type")
