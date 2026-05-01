"""Data-driven unit tests for FlextLdifDetector service."""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifDetector, m
from tests import c, u


class TestsFlextLdifDetectorService:
    """Cover detector service branches using flat constants."""

    @pytest.fixture
    def detector(self) -> FlextLdifDetector:
        return FlextLdifDetector()

    def test_detect_fails_when_no_inputs_given(
        self,
        detector: FlextLdifDetector,
    ) -> None:
        result = detector.detect_server_type()
        tm.fail(result, has="must be provided")

    def test_detect_fails_when_file_is_missing(
        self,
        detector: FlextLdifDetector,
        tmp_path: Path,
    ) -> None:
        missing = tmp_path / c.Tests.DETECTOR_MISSING_PATH_NAME
        result = detector.detect_server_type(ldif_path=missing)
        tm.fail(result, has="not found")

    def test_detect_fails_when_file_has_invalid_utf8(
        self,
        detector: FlextLdifDetector,
        tmp_path: Path,
    ) -> None:
        bad_file = tmp_path / c.Tests.DETECTOR_BAD_ENCODING_FILENAME
        bad_file.write_bytes(c.Tests.DETECTOR_INVALID_UTF8_BYTES)
        result = detector.detect_server_type(ldif_path=bad_file)
        tm.fail(result)

    def test_detect_from_file_succeeds(
        self,
        detector: FlextLdifDetector,
        tmp_path: Path,
    ) -> None:
        ldif_file = tmp_path / c.Tests.DETECTOR_RFC_FILENAME
        ldif_file.write_text(c.Tests.DETECTOR_RFC_SNIPPET, encoding="utf-8")

        result = detector.detect_server_type(ldif_path=ldif_file)
        detection = u.Tests.assert_success(result)

        tm.that(detection, is_=m.Ldif.ServerDetectionResult)
        tm.that(detection.detected_server_type, none=False)
        tm.that(detection.confidence >= c.Tests.DETECTOR_CONFIDENCE_THRESHOLD, eq=True)

    def test_detect_from_string_returns_detection_result(
        self,
        detector: FlextLdifDetector,
    ) -> None:
        result = detector.detect_server_type(
            ldif_content=c.Tests.DETECTOR_RFC_SNIPPET,
        )
        detection = u.Tests.assert_success(result)

        tm.that(detection, is_=m.Ldif.ServerDetectionResult)
        tm.that(detection.is_confident, none=False)

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
        detector: FlextLdifDetector,
    ) -> None:
        result = detector.detect_server_type(ldif_content=snippet)
        detection = u.Tests.assert_success(result)

        tm.that(bool(scenario), eq=True)
        tm.that(detection.detected_server_type.lower(), has=expected_type.lower())

    def test_detect_respects_max_lines_limit(
        self,
        detector: FlextLdifDetector,
    ) -> None:
        long_content = (c.Tests.DETECTOR_OID_SNIPPET + "\n") * 50
        result = detector.detect_server_type(
            ldif_content=long_content,
            max_lines=c.Tests.DETECTOR_MAX_LINES_SMALL,
        )
        u.Tests.assert_success(result)

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
        detector: FlextLdifDetector,
    ) -> None:
        result = detector.detect_server_type(ldif_content=snippet)
        detection = u.Tests.assert_success(result)
        tm.that(bool(scenario), eq=True)
        tm.that(bool(detection.detected_server_type), eq=True)

    def test_resolve_effective_server_type_from_content(
        self,
        detector: FlextLdifDetector,
    ) -> None:
        result = detector.resolve_effective_server_type(
            ldif_content=c.Tests.DETECTOR_RFC_SNIPPET,
        )
        server_type = u.Tests.assert_success(result)

        tm.that(bool(server_type), eq=True)

    def test_resolve_effective_server_type_without_input_falls_back_to_rfc(
        self,
        detector: FlextLdifDetector,
    ) -> None:
        result = detector.resolve_effective_server_type()
        server_type = u.Tests.assert_success(result)

        tm.that(server_type, eq=c.Tests.RFC)

    def test_get_effective_server_type_value_returns_string(
        self,
        detector: FlextLdifDetector,
    ) -> None:
        value = detector._get_effective_server_type_value()
        tm.that(isinstance(value, str), eq=True)
        tm.that(bool(value), eq=True)
