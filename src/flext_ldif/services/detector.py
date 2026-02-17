"""Detector Service - LDAP Server Type Auto-Detection from LDIF Content."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol, override

from flext_core import r

from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.settings import FlextLdifSettings
from flext_ldif.utilities import u


def _get_server_registry() -> FlextLdifServer:
    """Get server registry instance."""
    return FlextLdifServer.get_global_instance()


class ServerDetectionConstants(Protocol):
    """Protocol for server Constants classes with detection attributes."""

    DETECTION_PATTERN: str
    DETECTION_WEIGHT: int
    DETECTION_ATTRIBUTES: frozenset[str] | list[str]
    DETECTION_OID_PATTERN: str | None
    DETECTION_OBJECTCLASS_NAMES: frozenset[str] | list[str] | None


class FlextLdifDetector(s[m.Ldif.LdifResults.ClientStatus]):
    """Service for detecting LDAP server type from LDIF content."""

    @staticmethod
    def _get_all_server_types() -> list[str]:
        """Get all supported server types from constants."""
        return u.Ldif.Server.get_all_server_types()

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
        max_lines: int | None = None,
    ) -> r[m.Ldif.LdifResults.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content."""
        max_lines = max_lines or u.Ldif.Server.get_server_detection_default_max_lines()

        match (ldif_path, ldif_content):
            case (None, None):
                return r[m.Ldif.LdifResults.ServerDetectionResult].fail(
                    "Either ldif_path or ldif_content must be provided",
                )
            case (path, None) if path is not None and not path.exists():
                return r[m.Ldif.LdifResults.ServerDetectionResult].fail(
                    f"LDIF file not found: {path}",
                )
            case (path, None) if path is not None:
                try:
                    ldif_content = path.read_text(encoding="utf-8")
                except UnicodeDecodeError as e:
                    return r[m.Ldif.LdifResults.ServerDetectionResult].fail(
                        f"LDIF file is not valid UTF-8 (RFC 2849 violation): {e}",
                    )
            case (_, content) if isinstance(content, str):
                pass

        if ldif_content is None:
            return r[m.Ldif.LdifResults.ServerDetectionResult].fail(
                "No LDIF content provided",
            )
        lines = ldif_content.split("\n")
        content_sample = "\n".join(lines[:max_lines])

        scores_dict = self._calculate_scores(content_sample)
        detected_type_raw, confidence = self._determine_server_type(scores_dict)
        patterns_found = self._extract_patterns(content_sample)

        detected_type = u.Ldif.Server.normalize_server_type(detected_type_raw)

        scores_model = m.Ldif.Results.DynamicCounts(**scores_dict)

        detection_result = m.Ldif.LdifResults.ServerDetectionResult(
            detected_server_type=detected_type,
            confidence=confidence,
            scores=scores_model,
            patterns_found=patterns_found,
            is_confident=confidence
            >= u.Ldif.Server.get_server_detection_confidence_threshold(),
        )
        return r[m.Ldif.LdifResults.ServerDetectionResult].ok(
            detection_result,
        )

    @override
    def execute(self) -> r[m.Ldif.LdifResults.ClientStatus]:
        """Execute server detector self-check (required by FlextService)."""
        config_settings = m.Ldif.Results.ConfigSettings()
        config_settings.set_setting("service", "FlextLdifDetector")
        status_result = m.Ldif.LdifResults.ClientStatus(
            status="initialized",
            services=["detect_server_type"],
            config=config_settings,
        )
        return r[m.Ldif.LdifResults.ClientStatus].ok(status_result)

    @staticmethod
    def resolve_from_config(
        config: FlextLdifSettings,
        target_server_type: str | None = None,
    ) -> str:
        """Determine effective server type based on a prioritized configuration hierarchy."""
        if target_server_type:
            return target_server_type

        if getattr(
            config,
            "enable_relaxed_parsing",
            getattr(getattr(config, "ldif", None), "enable_relaxed_parsing", False),
        ):
            return u.Ldif.Server.get_server_type_value("RELAXED")

        if config.quirks_detection_mode == "manual":
            if config.quirks_server_type is None:
                return u.Ldif.Server.get_server_type_value("RFC")
            if not config.quirks_server_type.strip():
                return u.Ldif.Server.get_server_type_value("RFC")
            return config.quirks_server_type

        if config.quirks_detection_mode == "disabled":
            return u.Ldif.Server.get_server_type_value("RFC")

        return config.ldif_default_server_type

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> r[str]:
        """Resolve the effective LDAP server type to use for processing."""
        if ldif_path is not None or ldif_content is not None:
            detection_result = self.detect_server_type(
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
            if detection_result.is_success:
                result = detection_result.value
                if isinstance(result, m.Ldif.LdifResults.ServerDetectionResult):
                    return r[str].ok(result.detected_server_type)

        return r[str].ok("rfc")

    def _update_server_scores(
        self,
        server_type: str,
        pattern: str,
        weight: int,
        attributes: list[str] | frozenset[str],
        content: str,
        content_lower: str,
        scores: dict[str, int],
        *,
        case_sensitive: bool = False,
        objectclasses: list[str] | frozenset[str] | None = None,
    ) -> None:
        """Update scores for a server type based on pattern, attribute, and objectClass matches."""
        search_content = content if case_sensitive else content_lower
        if re.search(pattern, search_content):
            scores[server_type] += weight

        score_attr_match = u.Ldif.Server.get_server_detection_attribute_match_score()
        for item in (*attributes, *(objectclasses or [])):
            server_type_lower = server_type.lower() if server_type else ""
            item_lower = item.lower() if isinstance(item, str) else str(item).lower()
            if server_type_lower in item_lower or item_lower in server_type_lower:
                scores[server_type] += score_attr_match

    def _process_server_with_oid_pattern(
        self,
        server_type: str,
        constants: type[ServerDetectionConstants] | None,
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
        constants: type[ServerDetectionConstants] | None,
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
        if isinstance(pattern, re.Pattern):
            if pattern.search(content_lower):
                scores[server_type] += weight
        elif isinstance(pattern, str) and re.search(pattern, content_lower):
            scores[server_type] += weight

    def _calculate_scores(self, content: str) -> dict[str, int]:
        """Calculate detection scores for each server type."""
        scores: dict[str, int] = dict.fromkeys(self._get_all_server_types(), 0)
        scores[u.Ldif.Server.get_server_type_value("GENERIC")] = 1
        content_lower = content.lower()

        oid_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("OID"),
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

        oud_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("OUD"),
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

        openldap_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("OPENLDAP"),
        )
        openldap_constants = self._get_server_constants(openldap_server_type)
        if openldap_constants and hasattr(openldap_constants, "DETECTION_PATTERN"):
            openldap_pattern = getattr(openldap_constants, "DETECTION_PATTERN", None)
            if openldap_pattern and isinstance(openldap_pattern, str):
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

        ad_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("AD"),
        )
        ad_constants = self._get_server_constants(ad_server_type)
        if ad_constants and hasattr(ad_constants, "DETECTION_PATTERN"):
            ad_pattern = getattr(ad_constants, "DETECTION_PATTERN", None)
            if ad_pattern and isinstance(ad_pattern, str):
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
            server_literal = u.Ldif.Server.normalize_server_type(
                server_type_str,
            )
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
        if not scores:
            return "rfc", 0.0

        max_score: int = max(scores.values()) if scores else 0

        scores_values: list[int] = list(scores.values()) if scores else []
        total_score: int = sum(scores_values)

        if max_score == 0:
            return "rfc", 0.0

        confidence = max_score / total_score if total_score > 0 else 0.0

        detected_key: str = max(scores, key=lambda k: scores[k])

        if confidence < u.Ldif.Server.get_server_detection_confidence_threshold():
            return "rfc", confidence

        if detected_key == "generic":
            return "rfc", confidence

        server_type_map: dict[
            str,
            str,
        ] = {
            "oid": "oid",
            "oud": "oud",
            "openldap": "openldap",
            "openldap1": "openldap1",
            "openldap2": "openldap2",
            "active_directory": "active_directory",
            "apache_directory": "apache_directory",
            "novell_edirectory": "novell_edirectory",
            "ibm_tivoli": "ibm_tivoli",
            "389ds": "ds389",
            "relaxed": "relaxed",
            "rfc": "rfc",
            "generic": "rfc",
        }

        detected: str = server_type_map.get(detected_key, "rfc")
        return detected, confidence

    @staticmethod
    def _add_pattern_if_match(
        *,
        condition: bool,
        description: str,
        patterns: list[str],
    ) -> None:
        """Add pattern description if condition is met."""
        if condition:
            patterns.append(description)

    def _extract_oid_patterns(
        self,
        _constants: type[ServerDetectionConstants] | None,
        pattern: str | None,
        description: str,
        content: str,
        content_lower: str,
        patterns: list[str],
        *,
        case_sensitive: bool = False,
    ) -> None:
        """Extract patterns using OID pattern."""
        if not pattern or not isinstance(pattern, str):
            return

        search_content = content if case_sensitive else content_lower
        self._add_pattern_if_match(
            condition=bool(re.search(pattern, search_content)),
            description=description,
            patterns=patterns,
        )

    def _extract_oid_specific_patterns(
        self,
        constants: type[ServerDetectionConstants] | None,
        content: str,
        patterns: list[str],
    ) -> None:
        """Extract OID-specific patterns (ACLs, etc.)."""
        if not constants:
            return

        acl_attrs = [
            getattr(constants, "ORCLACI", None),
            getattr(constants, "ORCLENTRYLEVELACI", None),
        ]

        if any(
            (attr in content)
            if isinstance(attr, str) and isinstance(content, str)
            else False
            for attr in acl_attrs
        ):
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
        patterns: list[str],
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

    def _extract_patterns(self, content: str) -> list[str]:
        """Extract detected patterns from content."""
        patterns: list[str] = []
        content_lower = content.lower()

        oid_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("OID"),
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

        oud_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("OUD"),
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

        openldap_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("OPENLDAP"),
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

        ad_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("AD"),
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
                u.Ldif.Server.get_server_type_value("NOVELL"),
                "Novell eDirectory attributes (GUID, Modifiers, etc.)",
            ),
            (
                u.Ldif.Server.get_server_type_value("DS389"),
                "389 Directory Server attributes (389ds, redhat-ds, dirsrv)",
            ),
            (
                u.Ldif.Server.get_server_type_value("APACHE"),
                "Apache DS attributes (apacheDS, apache-*)",
            ),
        ]:
            server_type = u.Ldif.Server.normalize_server_type(
                server_type_str,
            )
            self._extract_pattern_with_attr(
                server_type,
                "DETECTION_PATTERN",
                description,
                content_lower,
                patterns,
            )

        tivoli_server_type = u.Ldif.Server.normalize_server_type(
            u.Ldif.Server.get_server_type_value("IBM_TIVOLI"),
        )
        tivoli_constants = self._get_server_constants(tivoli_server_type)
        if tivoli_constants:
            tivoli_pattern = getattr(tivoli_constants, "DETECTION_PATTERN", None)
            if isinstance(tivoli_pattern, re.Pattern) and tivoli_pattern.search(
                content_lower,
            ):
                patterns.append("IBM Tivoli attributes (ibm-*, tivoli, ldapdb)")

        return patterns

    @staticmethod
    def _get_server_constants(
        server_type: str,
    ) -> type[ServerDetectionConstants] | None:
        """Get server Constants class dynamically via FlextLdifServer registry."""
        registry = _get_server_registry()
        server_quirk_result = registry.quirk(server_type)
        if not server_quirk_result.is_success:
            return None

        server_quirk = server_quirk_result.value
        quirk_class = type(server_quirk)
        if not hasattr(quirk_class, "Constants"):
            return None

        constants = getattr(quirk_class, "Constants", None)
        if constants is None:
            return None

        if (
            isinstance(constants, type)
            and hasattr(constants, "DETECTION_WEIGHT")
            and hasattr(constants, "DETECTION_ATTRIBUTES")
            and (
                hasattr(constants, "DETECTION_PATTERN")
                or hasattr(constants, "DETECTION_OID_PATTERN")
            )
        ):
            return constants

        return None


__all__ = ["FlextLdifDetector"]
