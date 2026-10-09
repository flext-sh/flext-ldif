"""Detector scoring concern: pattern constants, scores, and extraction.

Owns the scoring half of the LDIF server detector (pattern compilation,
per-server score updates, and pattern extraction); ``FlextLdifDetector``
composes it via MRO and keeps the public detection surface.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_ldif import c, p, s, t, u


class FlextLdifDetectorScoring(s):
    """Detection scoring and pattern extraction helpers."""

    @staticmethod
    def _add_pattern_if_match(
        *,
        condition: bool,
        description: str,
        patterns: t.MutableSequenceOf[str],
    ) -> None:
        """Add pattern description if condition is met."""
        if condition:
            patterns.append(description)

    @staticmethod
    def _get_all_server_types() -> t.MutableSequenceOf[str]:
        """Get all supported server types from constants.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        types: t.MutableSequenceOf[str] = u.Ldif.resolve_all_server_types()
        return types

    @staticmethod
    def _detection_pattern_value(
        pattern_value: t.JsonValue | re.Pattern[str] | None,
    ) -> t.JsonValue:
        """Normalize a detection pattern constant into its source text.

        Args:
            pattern_value: Raw constant value read through ``getattr``; only
                ``str`` and ``re.Pattern[str]`` members carry a usable pattern.

        Returns:
            The resulting ``t.JsonValue`` (``str`` when well-typed).
        """
        return (
            pattern_value.pattern
            if isinstance(pattern_value, re.Pattern)
            else pattern_value or ""
        )

    def _get_server_constants(
        self,
        server_type: str,
    ) -> type[p.Ldif.ServerConstants] | None:
        """Get server Constants class dynamically via FlextLdifServer registry.

        Returns:
            The resulting ``type[p.Ldif.ServerConstants] | None``.
        """
        constants_result: p.Result[type[p.Ldif.ServerConstants]] = (
            self._server.resolve_server_constants(server_type)
        )
        if constants_result.success:
            constants: type[p.Ldif.ServerConstants] = constants_result.value
            pattern_values = (
                constants.DETECTION_PATTERN,
                constants.DETECTION_OID_PATTERN,
            )
            has_detection_pattern = any(
                bool(
                    pattern_value
                    if isinstance(pattern_value, str)
                    else ""
                    if pattern_value is None
                    else pattern_value.pattern,
                )
                for pattern_value in pattern_values
            )
            if (
                constants.DETECTION_WEIGHT > 0
                and constants.DETECTION_ATTRIBUTES
                and has_detection_pattern
            ):
                return constants
        return None

    def _calculate_scores(self, content: str) -> t.MutableIntMapping:
        """Calculate detection scores for each server type.

        Returns:
            The resulting ``t.MutableIntMapping``.
        """
        scores: t.MutableIntMapping = dict.fromkeys(self._get_all_server_types(), 0)
        scores[u.Ldif.resolve_server_type_value("GENERIC")] = 1
        for score_spec in c.Ldif.DETECTION_SCORE_SPECS:
            server_type, _pattern_attr, _case_sensitive = score_spec
            constants = self._get_server_constants(server_type)
            if constants:
                self._update_server_scores(constants, score_spec, content, scores)
        return scores

    @staticmethod
    def _determine_server_type(scores: t.MutableIntMapping) -> tuple[str, float]:
        """Determine the most likely server type from scores.

        Returns:
            The resulting ``tuple[str, float]``.
        """
        rfc_server_type = c.Ldif.ServerTypes.RFC.value
        if not scores:
            return (rfc_server_type, 0.0)
        max_score: int = max(scores.values())
        if max_score == 0:
            return (rfc_server_type, 0.0)
        total_score: int = sum(scores.values())
        confidence = max_score / total_score if total_score > 0 else 0.0
        detected_key: str = max(scores, key=scores.__getitem__)
        if (
            confidence < u.Ldif.resolve_confidence_threshold()
            or detected_key == c.Ldif.ServerTypes.GENERIC.value
        ):
            return (rfc_server_type, confidence)
        return (detected_key, confidence)

    def _extract_oid_specific_patterns(
        self,
        constants: type[p.Ldif.ServerConstants] | None,
        content: str,
        patterns: t.MutableSequenceOf[str],
    ) -> None:
        """Extract OID-specific patterns (ACLs, etc.)."""
        if not constants:
            return
        acl_attrs = (
            getattr(constants, "ORCLACI", None),
            getattr(constants, "ORCLENTRYLEVELACI", None),
        )
        if any(isinstance(attr, str) and attr in content for attr in acl_attrs):
            self._add_pattern_if_match(
                condition=c.Ldif.DETECTION_OID_ACL_DESCRIPTION not in patterns,
                description=c.Ldif.DETECTION_OID_ACL_DESCRIPTION,
                patterns=patterns,
            )

    def _extract_pattern_with_attr(
        self,
        constants: type[p.Ldif.ServerConstants] | None,
        pattern_spec: tuple[c.Ldif.ServerTypes, str, str, bool],
        content: str,
        patterns: t.MutableSequenceOf[str],
    ) -> None:
        """Extract pattern using pattern attribute from constants."""
        _, pattern_attr, description, case_sensitive = pattern_spec
        pattern = self._detection_pattern_value(
            getattr(constants, pattern_attr, None) if constants else None,
        )
        if not isinstance(pattern, str):
            return
        search_content = content if case_sensitive else content.lower()
        self._add_pattern_if_match(
            condition=bool(c.Ldif.compile_pattern(pattern).search(search_content)),
            description=description,
            patterns=patterns,
        )

    def _extract_patterns(self, content: str) -> t.MutableSequenceOf[str]:
        """Extract detected patterns from content.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        patterns: t.MutableSequenceOf[str] = []
        content_lower = content.lower()
        for pattern_spec in c.Ldif.DETECTION_PATTERN_SPECS:
            server_type, _pattern_attr, _description, _case_sensitive = pattern_spec
            constants = self._get_server_constants(server_type)
            if constants is None:
                continue
            self._extract_pattern_with_attr(constants, pattern_spec, content, patterns)
            if server_type == c.Ldif.ServerTypes.OID:
                self._extract_oid_specific_patterns(constants, content, patterns)
            if server_type == c.Ldif.ServerTypes.AD:
                self._add_pattern_if_match(
                    condition=(
                        c.Ldif.DETECTION_ACTIVE_DIRECTORY_ATTRIBUTE in content_lower
                    ),
                    description=c.Ldif.DETECTION_ACTIVE_DIRECTORY_DESCRIPTION,
                    patterns=patterns,
                )
        return patterns

    @staticmethod
    def _update_server_scores(
        constants: type[p.Ldif.ServerConstants] | None,
        score_spec: tuple[c.Ldif.ServerTypes, str, bool],
        content: str,
        scores: t.MutableIntMapping,
    ) -> None:
        """Update scores for a server type based on constants-defined detection.

        signals.
        """
        _, pattern_attr, case_sensitive = score_spec
        pattern = FlextLdifDetectorScoring._detection_pattern_value(
            getattr(constants, pattern_attr, None) if constants else None,
        )
        server_type_raw = getattr(constants, "SERVER_TYPE", "") if constants else ""
        if not isinstance(pattern, str) or not isinstance(server_type_raw, str):
            return
        server_type = u.Ldif.normalize_server_type(server_type_raw)
        if not server_type:
            return
        search_content = content if case_sensitive else content.lower()
        weight = constants.DETECTION_WEIGHT if constants else 0
        if c.Ldif.compile_pattern(pattern).search(search_content):
            scores[server_type] += weight
        score_attr_match = u.Ldif.resolve_attribute_match_score()
        attributes = constants.DETECTION_ATTRIBUTES if constants else ()
        objectclasses = constants.DETECTION_OBJECTCLASS_NAMES or () if constants else ()
        server_type_lower = server_type.lower()
        scores[server_type] += sum(
            score_attr_match
            for item in (*attributes, *objectclasses)
            if (server_type_lower in (item_lower := item.lower()))
            or (item_lower in server_type_lower)
        )


__all__: list[str] = ["FlextLdifDetectorScoring"]
