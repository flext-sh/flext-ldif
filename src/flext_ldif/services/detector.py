"""Detector Service - LDAP Server Type Auto-Detection from LDIF Content."""

from __future__ import annotations

import re
from pathlib import Path
from typing import override

from flext_ldif import (
    FlextLdifServer,
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

    @staticmethod
    def _get_server_constants(
        server_type: str,
    ) -> type[p.Ldif.ServerDetectionConstants] | None:
        """Get server Constants class dynamically via FlextLdifServer registry."""
        registry = FlextLdifServer.fetch_global_instance()
        server_server_result = registry.server(server_type)
        if not server_server_result.success:
            return None
        server_server = server_server_result.value
        server_class = type(server_server)
        if not getattr(server_class, "Constants", None) is not None:
            return None
        constants = getattr(server_class, "Constants", None)
        if constants is None:
            return None
        if (
            issubclass(constants.__class__, type)
            and getattr(constants, "DETECTION_WEIGHT", None) is not None
            and (getattr(constants, "DETECTION_ATTRIBUTES", None) is not None)
            and (
                getattr(constants, "DETECTION_PATTERN", None) is not None
                or getattr(constants, "DETECTION_OID_PATTERN", None) is not None
            )
        ):
            typed_constants: type[p.Ldif.ServerDetectionConstants] = constants
            return typed_constants
        return None

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
        max_lines: int | None = None,
    ) -> p.Result[m.Ldif.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content."""
        max_lines = max_lines or u.Ldif.get_server_detection_default_max_lines()
        if ldif_path is None and ldif_content is None:
            return r[m.Ldif.ServerDetectionResult].fail_op(
                "detect server type",
                "Either ldif_path or ldif_content must be provided",
            )
        if ldif_content is None and ldif_path is not None:
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
        if ldif_content is None:
            return r[m.Ldif.ServerDetectionResult].fail_op(
                "detect server type",
                "No LDIF content provided",
            )
        lines = ldif_content.split("\n")
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
            "is_confident": confidence >= u.Ldif.get_confidence_threshold(),
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
            return result.unwrap()
        return c.Ldif.ServerTypes.RFC.value

    def _calculate_scores(self, content: str) -> dict[str, int]:
        """Calculate detection scores for each server type."""
        scores: dict[str, int] = dict.fromkeys(self._get_all_server_types(), 0)
        scores[u.Ldif.get_server_type_value("GENERIC")] = 1
        content_lower = content.lower()
        oid_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("OID"),
        )
        oid_constants = self._get_server_constants(oid_server_type)
        if oid_constants:
            self._process_server_with_oid_pattern(
                oid_server_type,
                oid_constants,
                content,
                content_lower,
                scores,
                case_sensitive=True,
            )
        oud_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("OUD"),
        )
        oud_constants = self._get_server_constants(oud_server_type)
        if oud_constants:
            self._process_server_with_oid_pattern(
                oud_server_type,
                oud_constants,
                content,
                content_lower,
                scores,
            )
        openldap_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("OPENLDAP"),
        )
        openldap_constants = self._get_server_constants(openldap_server_type)
        if (
            openldap_constants
            and getattr(openldap_constants, "DETECTION_PATTERN", None) is not None
        ):
            openldap_pattern = getattr(openldap_constants, "DETECTION_PATTERN", None)
            if openldap_pattern and issubclass(openldap_pattern.__class__, str):
                self._update_server_scores(
                    openldap_server_type,
                    openldap_pattern,
                    getattr(openldap_constants, "DETECTION_WEIGHT", 8),
                    getattr(openldap_constants, "DETECTION_ATTRIBUTES", []),
                    content,
                    content_lower,
                    scores,
                    objectclasses=getattr(
                        openldap_constants,
                        "DETECTION_OBJECTCLASS_NAMES",
                        None,
                    ),
                )
        ad_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("AD"),
        )
        ad_constants = self._get_server_constants(ad_server_type)
        if (
            ad_constants
            and getattr(ad_constants, "DETECTION_PATTERN", None) is not None
        ):
            ad_pattern = getattr(ad_constants, "DETECTION_PATTERN", None)
            if ad_pattern and issubclass(ad_pattern.__class__, str):
                self._update_server_scores(
                    ad_server_type,
                    ad_pattern,
                    getattr(ad_constants, "DETECTION_WEIGHT", 8),
                    getattr(ad_constants, "DETECTION_ATTRIBUTES", frozenset()),
                    content,
                    content_lower,
                    scores,
                    case_sensitive=True,
                    objectclasses=getattr(
                        ad_constants,
                        "DETECTION_OBJECTCLASS_NAMES",
                        None,
                    ),
                )
        for server_type_str in (
            "novell_edirectory",
            "ibm_tivoli",
            "389ds",
            "apache_directory",
        ):
            server_literal = u.Ldif.normalize_server_type(server_type_str)
            constants = self._get_server_constants(server_literal)
            if constants:
                self._process_server_with_pattern(
                    server_literal,
                    constants,
                    content_lower,
                    scores,
                )
        return scores

    def _determine_server_type(
        self,
        scores: dict[str, int],
    ) -> tuple[str, float]:
        """Determine the most likely server type from scores."""
        rfc_server_type = c.Ldif.ServerTypes.RFC.value
        if not scores:
            return (rfc_server_type, 0.0)
        max_score: int = max(scores.values()) if scores else 0
        scores_values: t.MutableSequenceOf[int] = (
            list(scores.values()) if scores else []
        )
        total_score: int = sum(scores_values)
        if max_score == 0:
            return (rfc_server_type, 0.0)
        confidence = max_score / total_score if total_score > 0 else 0.0
        detected_key: str = max(scores, key=lambda k: scores[k])
        if confidence < u.Ldif.get_confidence_threshold():
            return (rfc_server_type, confidence)
        if detected_key == "generic":
            return (rfc_server_type, confidence)
        return (detected_key, confidence)

    def _extract_oid_patterns(
        self,
        _constants: type[p.Ldif.ServerDetectionConstants] | None,
        pattern: str | None,
        description: str,
        content: str,
        content_lower: str,
        patterns: t.MutableSequenceOf[str],
        *,
        case_sensitive: bool = False,
    ) -> None:
        """Extract patterns using OID pattern."""
        if not pattern:
            return
        search_content = content if case_sensitive else content_lower
        self._add_pattern_if_match(
            condition=bool(re.search(pattern, search_content)),
            description=description,
            patterns=patterns,
        )

    def _extract_oid_specific_patterns(
        self,
        constants: type[p.Ldif.ServerDetectionConstants] | None,
        content: str,
        patterns: t.MutableSequenceOf[str],
    ) -> None:
        """Extract OID-specific patterns (ACLs, etc.)."""
        if not constants:
            return
        acl_attrs = [
            getattr(constants, "ORCLACI", None),
            getattr(constants, "ORCLENTRYLEVELACI", None),
        ]
        if any(isinstance(attr, str) and attr in content for attr in acl_attrs):
            self._add_pattern_if_match(
                condition="Oracle OID ACLs" not in patterns,
                description="Oracle OID ACLs",
                patterns=patterns,
            )

    def _extract_pattern_with_attr(
        self,
        server_type: str,
        pattern_attr: str,
        description: str,
        content_lower: str,
        patterns: t.MutableSequenceOf[str],
    ) -> None:
        """Extract pattern using pattern attribute from constants."""
        constants = self._get_server_constants(server_type)
        pattern = getattr(constants, pattern_attr, None) if constants else None
        if pattern and isinstance(pattern, str):
            self._add_pattern_if_match(
                condition=bool(re.search(pattern, content_lower)),
                description=description,
                patterns=patterns,
            )

    def _extract_patterns(self, content: str) -> t.MutableSequenceOf[str]:
        """Extract detected patterns from content."""
        patterns: t.MutableSequenceOf[str] = []
        content_lower = content.lower()
        oid_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("OID"),
        )
        oid_constants = self._get_server_constants(oid_server_type)
        if oid_constants:
            oid_pattern = getattr(oid_constants, "DETECTION_OID_PATTERN", None)
            self._extract_oid_patterns(
                oid_constants,
                oid_pattern,
                "Oracle OID namespace (2.16.840.1.113894.*)",
                content,
                content_lower,
                patterns,
                case_sensitive=True,
            )
            self._extract_oid_specific_patterns(oid_constants, content, patterns)
        oud_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("OUD"),
        )
        oud_constants = self._get_server_constants(oud_server_type)
        if oud_constants:
            oud_pattern = getattr(oud_constants, "DETECTION_OID_PATTERN", None)
            self._extract_oid_patterns(
                oud_constants,
                oud_pattern,
                "Oracle OUD attributes (ds-sync-*)",
                content,
                content_lower,
                patterns,
            )
        openldap_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("OPENLDAP"),
        )
        openldap_constants = self._get_server_constants(openldap_server_type)
        if openldap_constants:
            openldap_pattern = getattr(
                openldap_constants,
                "DETECTION_OID_PATTERN",
                None,
            )
            self._extract_oid_patterns(
                openldap_constants,
                openldap_pattern,
                "OpenLDAP configuration (olc*)",
                content,
                content_lower,
                patterns,
            )
        ad_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("AD"),
        )
        ad_constants = self._get_server_constants(ad_server_type)
        if ad_constants:
            ad_pattern = getattr(ad_constants, "DETECTION_OID_PATTERN", None)
            self._extract_oid_patterns(
                ad_constants,
                ad_pattern,
                "Active Directory namespace (1.2.840.113556.*)",
                content,
                content_lower,
                patterns,
                case_sensitive=True,
            )
            contains_result = "samaccountname" in content.lower()
            self._add_pattern_if_match(
                condition=contains_result is True,
                description="Active Directory attributes",
                patterns=patterns,
            )
        for server_type_str, description in [
            (
                u.Ldif.get_server_type_value("NOVELL"),
                "Novell eDirectory attributes (GUID, Modifiers, etc.)",
            ),
            (
                u.Ldif.get_server_type_value("DS389"),
                "389 Directory Server attributes (389ds, redhat-ds, dirsrv)",
            ),
            (
                u.Ldif.get_server_type_value("APACHE"),
                "Apache DS attributes (apacheDS, apache-*)",
            ),
        ]:
            server_type = u.Ldif.normalize_server_type(server_type_str)
            self._extract_pattern_with_attr(
                server_type,
                "DETECTION_PATTERN",
                description,
                content_lower,
                patterns,
            )
        tivoli_server_type = u.Ldif.normalize_server_type(
            u.Ldif.get_server_type_value("IBM_TIVOLI"),
        )
        tivoli_constants = self._get_server_constants(tivoli_server_type)
        if tivoli_constants:
            tivoli_pattern = getattr(tivoli_constants, "DETECTION_PATTERN", None)
            if tivoli_pattern is not None and re.search(
                str(tivoli_pattern),
                content_lower,
            ):
                patterns.append("IBM Tivoli attributes (ibm-*, tivoli, ldapdb)")
        return patterns

    def _process_server_with_oid_pattern(
        self,
        server_type: str,
        constants: type[p.Ldif.ServerDetectionConstants] | None,
        content: str,
        content_lower: str,
        scores: dict[str, int],
        *,
        case_sensitive: bool = False,
    ) -> None:
        """Process server detection using OID pattern."""
        pattern = (
            getattr(constants, "DETECTION_OID_PATTERN", None) if constants else None
        )
        if not pattern or not isinstance(pattern, str):
            return
        self._update_server_scores(
            server_type,
            pattern,
            getattr(constants, "DETECTION_WEIGHT", 10),
            getattr(constants, "DETECTION_ATTRIBUTES", []),
            content,
            content_lower,
            scores,
            case_sensitive=case_sensitive,
            objectclasses=getattr(constants, "DETECTION_OBJECTCLASS_NAMES", None),
        )

    def _process_server_with_pattern(
        self,
        server_type: str,
        constants: type[p.Ldif.ServerDetectionConstants] | None,
        content_lower: str,
        scores: dict[str, int],
        *,
        pattern_attr: str = "DETECTION_PATTERN",
    ) -> None:
        """Process server detection using pattern attribute."""
        pattern = getattr(constants, pattern_attr, None) if constants else None
        if not pattern:
            return
        weight = getattr(constants, "DETECTION_WEIGHT", 6) if constants else 6
        if re.search(str(pattern), content_lower):
            scores[server_type] += weight

    def _update_server_scores(
        self,
        server_type: str,
        pattern: str,
        weight: int,
        attributes: t.MutableSequenceOf[str] | frozenset[str],
        content: str,
        content_lower: str,
        scores: dict[str, int],
        *,
        case_sensitive: bool = False,
        objectclasses: t.MutableSequenceOf[str] | frozenset[str] | None = None,
    ) -> None:
        """Update scores for a server type based on pattern, attribute, and objectClass matches."""
        search_content = content if case_sensitive else content_lower
        if re.search(pattern, search_content) and server_type:
            scores[server_type] += weight
        score_attr_match = u.Ldif.get_attribute_match_score()
        for item in (*attributes, *(objectclasses or [])):
            server_type_lower = server_type.lower() if server_type else ""
            item_lower = item.lower()
            if server_type_lower in item_lower or item_lower in server_type_lower:
                scores[server_type] += score_attr_match


__all__: list[str] = ["FlextLdifDetector"]
