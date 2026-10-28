"""Detector Service - LDAP Server Type Auto-Detection from LDIF Content.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from typing import TYPE_CHECKING

from flext_ldif import c, m, p, r, u
from flext_ldif.services import FlextLdifDetectorScoring

if TYPE_CHECKING:
    from pathlib import Path


class FlextLdifDetector(FlextLdifDetectorScoring):
    """Detector service composed directly into the LDIF facade via MRO."""

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
        max_lines: int | None = None,
    ) -> p.Result[p.Ldif.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content.

        Returns:
            The resulting ``p.Result[p.Ldif.ServerDetectionResult]``.

        """
        max_lines = max_lines or u.Ldif.resolve_server_detection_default_max_lines()
        if ldif_content is None:
            if ldif_path is None:
                return r[p.Ldif.ServerDetectionResult].fail_op(
                    "detect server type",
                    "Either ldif_path or ldif_content must be provided",
                )
            if not ldif_path.exists():
                return r[p.Ldif.ServerDetectionResult].fail_op(
                    "read detection source",
                    f"LDIF file not found: {ldif_path}",
                )
            read = u.Cli.files_read_text(ldif_path)
            if read.failure:
                return r[p.Ldif.ServerDetectionResult].fail_op(
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
        scores_model = m.Ldif.DynamicCounts(root=scores_dict)
        detection_result = m.Ldif.ServerDetectionResult.model_validate({
            "detected_server_type": detected_type,
            "confidence": confidence,
            "scores": scores_model,
            "patterns_found": patterns_found,
        })
        return r[p.Ldif.ServerDetectionResult].ok(detection_result)

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


__all__: list[str] = ["FlextLdifDetector"]
