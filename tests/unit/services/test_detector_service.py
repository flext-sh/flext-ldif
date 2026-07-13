"""Data-driven unit tests for FlextLdifDetector service."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from tests import c, m, u

if TYPE_CHECKING:
    from pathlib import Path

    from tests import p


class TestsFlextLdifDetectorService:
    """Cover detector service branches using flat constants."""

    def test_detect_fails_when_no_inputs_given(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.detect_server_type()
        tm.fail(result, has="must be provided")

    def test_detect_fails_when_file_is_missing(
        self,
        api: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        missing = tmp_path / c.Tests.DETECTOR_MISSING_PATH_NAME
        result = api.detect_server_type(ldif_path=missing)
        tm.fail(result, has="not found")

    def test_detect_fails_when_file_has_invalid_utf8(
        self,
        api: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        bad_file = tmp_path / c.Tests.DETECTOR_BAD_ENCODING_FILENAME
        bad_file.write_bytes(c.Tests.DETECTOR_INVALID_UTF8_BYTES)
        result = api.detect_server_type(ldif_path=bad_file)
        tm.fail(result)

    def test_detect_from_file_succeeds(
        self,
        api: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        ldif_file = tmp_path / c.Tests.DETECTOR_RFC_FILENAME
        ldif_file.write_text(c.Tests.DETECTOR_RFC_SNIPPET, encoding="utf-8")

        result = api.detect_server_type(ldif_path=ldif_file)
        detection = u.Tests.assert_success(result)

        tm.that(detection, is_=m.Ldif.ServerDetectionResult)
        tm.that(detection.detected_server_type, none=False)
        tm.that(detection.confidence >= c.Tests.DETECTOR_CONFIDENCE_THRESHOLD, eq=True)

    def test_detect_from_string_returns_detection_result(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.detect_server_type(
            ldif_content=c.Tests.DETECTOR_RFC_SNIPPET,
        )
        detection = u.Tests.assert_success(result)

        tm.that(detection, is_=m.Ldif.ServerDetectionResult)
        tm.that(detection.is_confident, none=False)

    def test_detect_rfc_snippet_keeps_generic_score_and_no_patterns(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.detect_server_type(ldif_content=c.Tests.DETECTOR_RFC_SNIPPET)
        detection = u.Tests.assert_success(result)

        generic_server_type = u.Ldif.get_server_type_value("GENERIC")
        tm.that(bool(detection.detected_server_type), eq=True)
        tm.that(detection.scores[generic_server_type], eq=1)
        tm.that(detection.patterns_found, eq=[])

    def test_detect_oid_snippet_reports_acl_patterns(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.detect_server_type(ldif_content=c.Tests.DETECTOR_OID_SNIPPET)
        detection = u.Tests.assert_success(result)

        tm.that(
            any("ACL" in pattern for pattern in detection.patterns_found),
            eq=True,
        )

    @pytest.mark.parametrize(
        ("scenario", "snippet", "expected_type"),
        tuple(
            (scenario, data[0], data[1])
            for scenario, data in c.Tests.DETECTOR_SERVER_SNIPPETS.items()
        ),
    )
    def test_detect_recognises_server_types_from_snippets(
        self,
        scenario: str,
        snippet: str,
        expected_type: str,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.detect_server_type(ldif_content=snippet)
        detection = u.Tests.assert_success(
            result, error_msg=f"detection failed for {scenario}"
        )

        tm.that(detection, is_=m.Ldif.ServerDetectionResult)
        tm.that(detection.detected_server_type.lower(), has=expected_type.lower())

    def test_detect_respects_max_lines_limit(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        long_content = (c.Tests.DETECTOR_OID_SNIPPET + "\n") * 50
        result = api.detect_server_type(
            ldif_content=long_content,
            max_lines=c.Tests.DETECTOR_MAX_LINES_SMALL,
        )
        detection = u.Tests.assert_success(result)

        tm.that(detection, is_=m.Ldif.ServerDetectionResult)
        tm.that(0.0 <= detection.confidence <= 1.0, eq=True)

    @pytest.mark.parametrize(
        ("scenario", "snippet"),
        [
            ("oud", c.Tests.DETECTOR_OUD_SNIPPET),
            ("openldap", c.Tests.DETECTOR_OPENLDAP_SNIPPET),
        ],
    )
    def test_detect_additional_snippets_return_detection(
        self,
        scenario: str,
        snippet: str,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.detect_server_type(ldif_content=snippet)
        detection = u.Tests.assert_success(
            result, error_msg=f"detection failed for {scenario}"
        )

        tm.that(detection, is_=m.Ldif.ServerDetectionResult)
        tm.that(bool(detection.detected_server_type), eq=True)

    def test_detect_is_idempotent_for_same_content(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        first = u.Tests.assert_success(
            api.detect_server_type(ldif_content=c.Tests.DETECTOR_OID_SNIPPET),
        )
        second = u.Tests.assert_success(
            api.detect_server_type(ldif_content=c.Tests.DETECTOR_OID_SNIPPET),
        )

        tm.that(
            first.detected_server_type,
            eq=second.detected_server_type,
        )
        tm.that(first.patterns_found, eq=second.patterns_found)

    def test_resolve_effective_server_type_from_content(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.resolve_effective_server_type(
            ldif_content=c.Tests.DETECTOR_RFC_SNIPPET,
        )
        server_type = u.Tests.assert_success(result)

        tm.that(bool(server_type), eq=True)

    def test_resolve_effective_server_type_without_input_falls_back_to_rfc(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.resolve_effective_server_type()
        server_type = u.Tests.assert_success(result)

        tm.that(server_type, eq=c.Tests.RFC)

    def test_resolve_effective_server_type_missing_file_falls_back_to_rfc(
        self,
        api: p.Ldif.LdifClient,
        tmp_path: Path,
    ) -> None:
        missing = tmp_path / c.Tests.DETECTOR_MISSING_PATH_NAME

        result = api.resolve_effective_server_type(ldif_path=missing)
        server_type = u.Tests.assert_success(result)

        tm.that(server_type, eq=c.Tests.RFC)
