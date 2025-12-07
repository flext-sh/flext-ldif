"""Detector Service - LDAP Server Type Auto-Detection from LDIF Content.

Analyzes LDIF content to automatically detect the source LDAP server type using
pattern matching and heuristics for server-specific features (OIDs, attributes,
objectClasses, patterns).

Scope: Server type detection from LDIF files/content, pattern matching for
server-specific features (Oracle OID/OUD, OpenLDAP, Active Directory, 389 DS,
Apache DS, Novell eDirectory, IBM Tivoli), confidence scoring, effective server
type resolution based on config hierarchy.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol, cast, override

from flext_core import r

from flext_ldif._models.results import _ConfigSettings, _DynamicCounts
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
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


class FlextLdifDetector(FlextLdifServiceBase[m.Ldif.ClientStatus]):
    """Service for detecting LDAP server type from LDIF content.

    Uses pattern matching to identify server-specific features across all supported
    LDAP server types. Detection is based on:

    - Oracle OID: 2.16.840.1.113894.* OIDs, orclaci, orclentrylevelaci
    - Oracle OUD: ds-sync-*, entryUUID, ds-pwp-account-disabled
    - OpenLDAP: olc* attributes, cn=config entries
    - Active Directory: objectGUID, samAccountName, sIDHistory
    - 389 DS: 389ds, redhat-ds, dirsrv patterns
    - Apache DS: apacheDS, apache-* patterns
    - Novell eDirectory: GUID, Modifiers, nrpDistributionPassword
    - IBM Tivoli: ibm-*, tivoli, ldapdb patterns

    All server types are defined in c.ServerTypes and patterns
    are centralized in c.Ldif.ServerDetection.

    Detection Priority (by score):
    1. Most specific patterns (Oracle OID/OUD - weight 10)
    2. Medium specificity (OpenLDAP, AD - weight 8)
    3. Generic patterns (Novell, IBM, Apache, 389DS - weight 6)
    4. Fallback to RFC if no patterns found
    5. Return RFC if detection confidence is below threshold

    DN Handling Integration:
    - Returns detected server type compatible with u.DN operations
    - Detected server type can be used for server-specific DN normalization/validation
    - Use result with FlextLdifUtilities for RFC 4514 compliant DN processing
    - Supports migration workflows via conversion matrix with detected server type
    """

    # Detection score weights and patterns imported from constants
    # All server detection constants are now centralized in c.ServerDetection

    @staticmethod
    def _get_all_server_types() -> list[c.Ldif.LiteralTypes.ServerTypeLiteral]:
        """Get all supported server types from constants.

        Returns:
            List of all server type identifiers

        """
        # Get all string attributes from ServerTypes class (excluding private ones)
        return [
            getattr(c.ServerTypes, attr)
            for attr in dir(c.ServerTypes)
            if not attr.startswith("_")
            and isinstance(getattr(c.ServerTypes, attr), str)
        ]

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
        max_lines: int = c.Ldif.ServerDetection.DEFAULT_MAX_LINES,
    ) -> r[m.Ldif.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content.

        Business Rule: Server detection uses weighted pattern matching across multiple
        server-specific features (OIDs, attributes, objectClasses). Detection confidence
        is calculated based on pattern match strength and quantity. If confidence falls
        below threshold (CONFIDENCE_THRESHOLD), detection defaults to "rfc" for safe
        RFC-compliant processing.

        Implication: Detection results influence quirk selection and server-specific
        processing. Low confidence detections may result in generic RFC processing,
        potentially missing server-specific optimizations. High confidence detections
        enable full server-specific quirk capabilities.

        Args:
            ldif_path: Path to LDIF file (alternative to ldif_content)
            ldif_content: Raw LDIF content as string
            max_lines: Maximum lines to scan for detection (default: ServerDetection.DEFAULT_MAX_LINES)

        Returns:
            r with detection results:
            {
                "detected_server_type": server type from c.ServerTypes,
                "confidence": 0.0-1.0,
                "scores": dict of scores for each server type,
                "patterns_found": list of detected pattern descriptions,
                "is_confident": bool indicating if confidence >= CONFIDENCE_THRESHOLD,
            }

        """
        if ldif_content is None:
            if ldif_path is None:
                return r[m.Ldif.ServerDetectionResult].fail(
                    "Either ldif_path or ldif_content must be provided",
                )
            if not ldif_path.exists():
                return r[m.Ldif.ServerDetectionResult].fail(
                    f"LDIF file not found: {ldif_path}",
                )
            try:
                ldif_content = ldif_path.read_text(encoding="utf-8")
            except UnicodeDecodeError as e:
                return r[m.Ldif.ServerDetectionResult].fail(
                    f"LDIF file is not valid UTF-8 (RFC 2849 violation): {e}",
                )

        lines = ldif_content.split("\n")
        content_sample = "\n".join(lines[:max_lines])

        scores_dict = self._calculate_scores(content_sample)
        detected_type, confidence = self._determine_server_type(scores_dict)
        patterns_found = self._extract_patterns(content_sample)

        # Convert dict to _DynamicCounts model (supports extra fields via Pydantic)
        scores_model = _DynamicCounts(**scores_dict)

        detection_result = m.Ldif.ServerDetectionResult(
            detected_server_type=detected_type,
            confidence=confidence,
            scores=scores_model,
            patterns_found=patterns_found,
            is_confident=confidence >= c.Ldif.ServerDetection.CONFIDENCE_THRESHOLD,
        )
        return r[m.Ldif.ServerDetectionResult].ok(
            detection_result,
        )

    @override
    def execute(self) -> r[m.Ldif.ClientStatus]:
        """Execute server detector self-check (required by FlextService).

        Returns:
            r with detector status

        """
        config_settings = _ConfigSettings()
        config_settings.set_setting("service", "FlextLdifDetector")
        status_result = m.Ldif.ClientStatus(
            status="initialized",
            services=["detect_server_type"],
            config=config_settings,
        )
        return r[m.Ldif.ClientStatus].ok(status_result)

    @staticmethod
    def resolve_from_config(
        config: FlextLdifConfig,
        target_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> str:
        """Determine effective server type based on a prioritized configuration hierarchy.

        Business Rule: Server type resolution follows strict priority order:
        1. Direct override parameter (highest priority)
        2. Relaxed parsing mode (enables lenient RFC processing)
        3. Manual mode with configured server type
        4. Disabled mode (forces RFC-only processing)
        5. Default server type from config (lowest priority)

        Implication: This hierarchy ensures predictable server type selection across
        different configuration scenarios. Manual mode requires explicit server type
        configuration or defaults to RFC. Auto-detection is only used when not in
        manual/disabled mode.

        """
        # Priority 1: Direct override from a service-level parameter
        if target_server_type:
            return target_server_type

        # Priority 2: Relaxed parsing mode takes precedence
        if getattr(
            config,
            "enable_relaxed_parsing",
            getattr(getattr(config, "ldif", None), "enable_relaxed_parsing", False),
        ):
            return c.ServerTypes.RELAXED.value

        # Priority 3: Manual configuration mode
        if config.quirks_detection_mode == "manual":
            # Validate that quirks_server_type is provided in manual mode
            if config.quirks_server_type is None:
                return c.ServerTypes.RFC.value
            if not config.quirks_server_type.strip():
                return c.ServerTypes.RFC.value
            return config.quirks_server_type

        # Priority 4: Disabled mode falls back to RFC
        if config.quirks_detection_mode == "disabled":
            return c.ServerTypes.RFC.value

        # Default: Use the configured default server type
        return config.ldif_default_server_type

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> r[c.Ldif.LiteralTypes.ServerTypeLiteral]:
        """Resolve the effective LDAP server type to use for processing.

        Business Rule: Effective server type combines configuration hierarchy with
        optional auto-detection. If LDIF content is provided and auto-detection is
        enabled, detection results override configuration defaults. Falls back to
        "rfc" if detection fails or content is not provided.

        Implication: This method bridges configuration-driven and content-driven
        server type selection. Services should use this method to determine the
        final server type for quirk selection, ensuring consistency across the
        processing pipeline.

        Applies priority resolution based on config settings:
        1. Relaxed mode enabled → "relaxed"
        2. Manual mode → configured server type
        3. Auto mode → detected server type from content
        4. Disabled mode → "rfc"

        Args:
            ldif_path: Optional path to LDIF file for auto-detection
            ldif_content: Optional LDIF content string for auto-detection

        Returns:
            r with the server type literal to use

        """
        if ldif_path is not None or ldif_content is not None:
            detection_result = self.detect_server_type(
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
            if detection_result.is_success:
                result = detection_result.unwrap()
                if isinstance(result, m.Ldif.ServerDetectionResult):
                    return r.ok(result.detected_server_type)

        return r.ok("rfc")

    def _update_server_scores(
        self,
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
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

        score_attr_match = c.Ldif.ServerDetection.ATTRIBUTE_MATCH_SCORE
        for item in (*attributes, *(objectclasses or [])):
            # normalize() auto-detects contains when two strings are passed
            if u.normalize_ldif(server_type, item):
                scores[server_type] += score_attr_match

    def _process_server_with_oid_pattern(
        self,
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
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
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
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
        """Calculate detection scores for each server type.

        Args:
            content: LDIF content to analyze

        Returns:
            Dict with server type scores

        """
        scores: dict[str, int] = dict.fromkeys(self._get_all_server_types(), 0)
        scores[c.ServerTypes.GENERIC.value] = 1
        content_lower = content.lower()

        # Server processing configuration mapping
        # Use normalize_server_type for proper type narrowing
        oid_server_type = c.normalize_server_type(
            c.ServerTypes.OID.value,
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

        oud_server_type = c.normalize_server_type(
            c.ServerTypes.OUD.value,
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

        openldap_server_type = c.normalize_server_type(
            c.ServerTypes.OPENLDAP.value,
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

        ad_server_type = c.normalize_server_type(
            c.ServerTypes.AD.value,
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

        # Process additional server types using literal strings
        for server_type_str in (
            "novell_edirectory",
            "ibm_tivoli",
            "389ds",
            "apache_directory",
        ):
            server_literal = c.normalize_server_type(server_type_str)
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
    ) -> tuple[c.Ldif.LiteralTypes.ServerTypeLiteral, float]:
        """Determine the most likely server type from scores.

        Args:
            scores: Detection scores for each server type

        Returns:
            Tuple of (server_type, confidence)

        """
        if not scores:
            return "rfc", 0.0

        # Find max score
        max_score: int = max(scores.values()) if scores else 0
        # Type narrowing: scores is dict[str, int], convert to list[int] for sum
        scores_values: list[int] = list(scores.values()) if scores else []
        total_score: int = sum(scores_values)

        # If no signals, default to RFC
        if max_score == 0:
            return "rfc", 0.0

        # Calculate confidence
        confidence = max_score / total_score if total_score > 0 else 0.0

        # Find server type with highest score - returns str from dict keys
        detected_key: str = max(scores, key=lambda k: scores[k])

        # If low confidence, return RFC
        if confidence < c.Ldif.ServerDetection.CONFIDENCE_THRESHOLD:
            return "rfc", confidence

        # Map "generic" fallback to "rfc" (generic is not a registered quirk)
        if detected_key == "generic":
            return "rfc", confidence

        # Map string key to ServerTypeLiteral - validated server types only
        server_type_map: dict[
            str,
            c.Ldif.LiteralTypes.ServerTypeLiteral,
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
            "389ds": "ds389",  # Normalized to canonical form
            "relaxed": "relaxed",
            "rfc": "rfc",
            "generic": "rfc",
        }
        detected_raw = u.Mapper.get(server_type_map, detected_key, default="rfc")
        detected: c.Ldif.LiteralTypes.ServerTypeLiteral = cast(
            "c.Ldif.LiteralTypes.ServerTypeLiteral",
            detected_raw,
        )
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
        # Use any() with comprehension - u.in_() expects collection as second arg
        # Type narrowing: content is str, check if attr is in content string
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
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
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
        """Extract detected patterns from content.

        Args:
            content: LDIF content to analyze

        Returns:
            List of detected patterns

        """
        patterns: list[str] = []
        content_lower = content.lower()

        # Oracle OID
        oid_server_type = c.normalize_server_type(
            c.ServerTypes.OID.value,
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

        # Oracle OUD
        oud_server_type = c.normalize_server_type(
            c.ServerTypes.OUD.value,
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

        # OpenLDAP
        openldap_server_type = c.normalize_server_type(
            c.ServerTypes.OPENLDAP.value,
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

        # Active Directory
        ad_server_type = c.normalize_server_type(
            c.ServerTypes.AD.value,
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
            # Check if string contains substring - u.contains() doesn't exist, use 'in' operator
            contains_result = "samaccountname" in content.lower()
            self._add_pattern_if_match(
                condition=contains_result is True,
                description="Active Directory attributes",
                patterns=patterns,
            )

        # Pattern-based servers
        for server_type_enum, description in [
            (
                c.ServerTypes.NOVELL,
                "Novell eDirectory attributes (GUID, Modifiers, etc.)",
            ),
            (
                c.ServerTypes.DS389,
                "389 Directory Server attributes (389ds, redhat-ds, dirsrv)",
            ),
            (
                c.ServerTypes.APACHE,
                "Apache DS attributes (apacheDS, apache-*)",
            ),
        ]:
            server_type = c.normalize_server_type(
                server_type_enum.value,
            )
            self._extract_pattern_with_attr(
                server_type,
                "DETECTION_PATTERN",
                description,
                content_lower,
                patterns,
            )

        # Special handling for IBM Tivoli (compiled pattern)
        tivoli_server_type = c.normalize_server_type(
            c.ServerTypes.IBM_TIVOLI.value,
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
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
    ) -> type[ServerDetectionConstants] | None:
        """Get server Constants class dynamically via FlextLdifServer registry.

        Uses runtime attribute access to get detection constants from server quirk classes.

        Args:
            server_type: Server type identifier (e.g., "oid", "oud", "openldap")

        Returns:
            Server Constants class if available, None otherwise

        """
        registry = _get_server_registry()
        server_quirk_result = registry.quirk(server_type)
        if not server_quirk_result.is_success:
            return None

        server_quirk = server_quirk_result.unwrap()
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
