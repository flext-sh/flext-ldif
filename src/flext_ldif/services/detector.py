"""Detector Service - LDAP Server Type Auto-Detection from LDIF Content.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from flext_ldif import c, m, p, r, s, u
from flext_ldif.services.detector_scoring import FlextLdifDetectorScoring

if TYPE_CHECKING:
    from pathlib import Path


class FlextLdifDetector(FlextLdifDetectorScoring, s):
    """Detector service composed directly into the LDIF facade via MRO.

    Overrides ``_get_effective_server_type_value`` from parser and writer
    services so the facade can auto-detect the active server type.
    """

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
        max_lines: int | None = None,
    ) -> p.Result[m.Ldif.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content.

        Returns:
            The resulting ``p.Result[m.Ldif.ServerDetectionResult]``.
        """
        max_lines = max_lines or u.Ldif.get_server_detection_default_max_lines()
        if ldif_content is None:
            if ldif_path is None:
                return r[m.Ldif.ServerDetectionResult].fail_op(
                    "detect server type",
                    "Either ldif_path or ldif_content must be provided",
                )
            if not ldif_path.exists():
                return r[m.Ldif.ServerDetectionResult].fail_op(
                    "read detection source",
                    f"LDIF file not found: {ldif_path}",
                )
            read = u.Cli.files_read_text(ldif_path)
            if read.failure:
                return r[m.Ldif.ServerDetectionResult].fail_op(
                    "read detection source",
                    read.error,
                )
            resolved_content: str = read.value
        else:
            resolved_content = ldif_content
        lines = resolved_content.splitlines()
        content_sample = "\n".join(lines[:max_lines])
        scores_dict = self._calculate_scores(content_sample)
        detected_type_raw, confidence = self._determine_server_type(scores_dict)
        patterns_found = self._extract_patterns(content_sample)
        detected_type = u.Ldif.normalize_server_type(detected_type_raw)
        scores_model = m.Ldif.DynamicCounts(**scores_dict)
        detection_result = m.Ldif.ServerDetectionResult.model_validate({
            "detected_server_type": detected_type,
            "confidence": confidence,
            "scores": scores_model,
            "patterns_found": patterns_found,
        })
        return r[m.Ldif.ServerDetectionResult].ok(detection_result)

    def resolve_effective_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> p.Result[str]:
        """Resolve the effective LDAP server type to use for processing.

        Returns:
            The resulting ``p.Result[str]``.
        """
        if ldif_path is not None or ldif_content is not None:
            detection_result = self.detect_server_type(
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
            if detection_result.success:
                return r[str].ok(detection_result.value.detected_server_type)
        return r[str].ok(c.Ldif.ServerTypes.RFC.value)

    @override
    def _get_effective_server_type_value(self) -> str:
        """Resolve effective server type via detector (overrides ParserMixin default).

        Returns:
            The resulting ``str``.
        """
        result: p.Result[str] = self.resolve_effective_server_type()
        if result.success:
            effective_server_type: str = result.unwrap()
            return effective_server_type
        rfc_server_type: str = str(c.Ldif.ServerTypes.RFC.value)
        return rfc_server_type


__all__: list[str] = ["FlextLdifDetector"]
