"""Detector Service - LDAP Server Type Auto-Detection from LDIF Content."""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_ldif import (
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)


class FlextLdifDetector(s):
    """Detector service composed directly into the LDIF facade via MRO.

    Overrides ``_get_effective_server_type_value`` from parser and writer
    services so the facade can auto-detect the active server type.
    """

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
        """Get all supported server types from constants."""
        types: t.MutableSequenceOf[str] = u.Ldif.get_all_server_types()
        return types

    def _get_server_constants(
        self,
        server_type: str,
    ) -> type[p.Ldif.ServerConstants] | None:
        """Get server Constants class dynamically via FlextLdifServer registry."""
        constants_result: p.Result[type[p.Ldif.ServerConstants]] = (
            self._server.resolve_server_constants(server_type)
        )
        if constants_result.failure:
            return None
        constants: type[p.Ldif.ServerConstants] = constants_result.unwrap()
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
                else pattern_value.pattern
            )
            for pattern_value in pattern_values
        )
        if (
            constants.DETECTION_WEIGHT <= 0
            or not constants.DETECTION_ATTRIBUTES
            or not has_detection_pattern
        ):
            return None
        return constants

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
        max_lines: int | None = None,
    ) -> p.Result[m.Ldif.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content."""
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
            try:
                ldif_content = ldif_path.read_text(encoding="utf-8")
            except UnicodeDecodeError as e:
                return r[m.Ldif.ServerDetectionResult].fail_op(
                    "read detection source",
                    e,
                )
        lines = ldif_content.splitlines()
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
        """Resolve the effective LDAP server type to use for processing."""
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
        """Resolve effective server type via detector (overrides ParserMixin default)."""
        result: p.Result[str] = self.resolve_effective_server_type()
        if result.success:
            effective_server_type: str = result.unwrap()
            return effective_server_type
        return c.Ldif.ServerTypes.RFC.value

    def _calculate_scores(self, content: str) -> t.MutableIntMapping:
        """Calculate detection scores for each server type."""
        scores: t.MutableIntMapping = dict.fromkeys(self._get_all_server_types(), 0)
        scores[u.Ldif.get_server_type_value("GENERIC")] = 1
        for score_spec in c.Ldif.DETECTION_SCORE_SPECS:
            server_type, _pattern_attr, _case_sensitive = score_spec
            constants = self._get_server_constants(server_type)
            if constants:
                self._update_server_scores(constants, score_spec, content, scores)
        return scores

    def _determine_server_type(
        self,
        scores: t.MutableIntMapping,
    ) -> tuple[str, float]:
        """Determine the most likely server type from scores."""
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
            confidence < u.Ldif.get_confidence_threshold()
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
        pattern_value = getattr(constants, pattern_attr, None) if constants else None
        pattern = (
            getattr(pattern_value, "pattern")
            if getattr(pattern_value, "pattern", None) is not None
            else pattern_value
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
        """Extract detected patterns from content."""
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

    def _update_server_scores(
        self,
        constants: type[p.Ldif.ServerConstants] | None,
        score_spec: tuple[c.Ldif.ServerTypes, str, bool],
        content: str,
        scores: t.MutableIntMapping,
    ) -> None:
        """Update scores for a server type based on constants-defined detection signals."""
        _, pattern_attr, case_sensitive = score_spec
        pattern_value = getattr(constants, pattern_attr, None) if constants else None
        pattern = (
            getattr(pattern_value, "pattern")
            if getattr(pattern_value, "pattern", None) is not None
            else pattern_value
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
        score_attr_match = u.Ldif.get_attribute_match_score()
        attributes = constants.DETECTION_ATTRIBUTES if constants else ()
        objectclasses = constants.DETECTION_OBJECTCLASS_NAMES or () if constants else ()
        server_type_lower = server_type.lower()
        scores[server_type] += sum(
            score_attr_match
            for item in (*attributes, *objectclasses)
            if (server_type_lower in (item_lower := item.lower()))
            or (item_lower in server_type_lower)
        )


__all__: list[str] = ["FlextLdifDetector"]
