"""Server Type Auto-Detection Service for LDIF Files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Analyzes LDIF content to automatically detect the source LDAP server type.
Uses pattern matching and heuristics to identify server-specific features.

Detection Strategy:
1. Scan for server-specific OIDs, attributes, and patterns
2. Count matches for each server type
3. Return highest-scoring server type
4. Fall back to RFC or RELAXED if inconclusive
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol, cast

from flext_core import FlextResult, FlextRuntime

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer


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


class FlextLdifDetector(FlextLdifServiceBase[FlextLdifModels.ClientStatus]):
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

    All server types are defined in FlextLdifConstants.ServerTypes and patterns
    are centralized in FlextLdifConstants.ServerDetection.

    Detection Priority (by score):
    1. Most specific patterns (Oracle OID/OUD - weight 10)
    2. Medium specificity (OpenLDAP, AD - weight 8)
    3. Generic patterns (Novell, IBM, Apache, 389DS - weight 6)
    4. Fallback to RFC if no patterns found
    5. Return RFC if detection confidence is below threshold

    DN Handling Integration:
    - Returns detected server type compatible with FlextLdifUtilities.DN operations
    - Detected server type can be used for server-specific DN normalization/validation
    - Use result with FlextLdifUtilities for RFC 4514 compliant DN processing
    - Supports migration workflows via conversion matrix with detected server type
    """

    # Detection score weights and patterns imported from constants
    # All server detection constants are now centralized in FlextLdifConstants.ServerDetection

    @staticmethod
    def _get_all_server_types() -> list[str]:
        """Get all supported server types from constants.

        Returns:
            List of all server type identifiers

        """
        # Get all string attributes from ServerTypes class (excluding private ones)
        return [
            getattr(FlextLdifConstants.ServerTypes, attr)
            for attr in dir(FlextLdifConstants.ServerTypes)
            if not attr.startswith("_")
            and isinstance(getattr(FlextLdifConstants.ServerTypes, attr), str)
        ]

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
        max_lines: int = FlextLdifConstants.ServerDetection.DEFAULT_MAX_LINES,
    ) -> FlextResult[FlextLdifModels.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content.

        Args:
            ldif_path: Path to LDIF file (alternative to ldif_content)
            ldif_content: Raw LDIF content as string
            max_lines: Maximum lines to scan for detection (default: ServerDetection.DEFAULT_MAX_LINES)

        Returns:
            FlextResult with detection results:
            {
                "detected_server_type": server type from FlextLdifConstants.ServerTypes,
                "confidence": 0.0-1.0,
                "scores": dict of scores for each server type,
                "patterns_found": list of detected pattern descriptions,
                "is_confident": bool indicating if confidence >= CONFIDENCE_THRESHOLD,
            }

        """
        try:
            # Read LDIF content if path provided
            if ldif_content is None:
                if ldif_path is None:
                    return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                        "Either ldif_path or ldif_content must be provided",
                    )
                # RFC 2849 mandates UTF-8 encoding - fail on invalid encoding or missing file
                try:
                    ldif_content = ldif_path.read_text(encoding="utf-8")
                except FileNotFoundError:
                    return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                        f"LDIF file not found: {ldif_path}",
                    )
                except UnicodeDecodeError as e:
                    return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                        f"LDIF file is not valid UTF-8 (RFC 2849 violation): {e}",
                    )

            # Limit content for performance
            lines = ldif_content.split("\n")
            content_sample = "\n".join(lines[:max_lines])

            # Run detection - let exceptions propagate with clear error messages
            scores = self._calculate_scores(content_sample)
            detected_type, confidence = self._determine_server_type(scores)

            patterns_found = self._extract_patterns(content_sample)

            detection_result = FlextLdifModels.ServerDetectionResult(
                detected_server_type=detected_type,
                confidence=confidence,
                scores=scores,
                patterns_found=patterns_found,
                is_confident=confidence
                >= FlextLdifConstants.ServerDetection.CONFIDENCE_THRESHOLD,
            )
            return FlextResult[FlextLdifModels.ServerDetectionResult].ok(
                detection_result,
            )
        except (ValueError, TypeError, AttributeError) as e:
            error_msg = f"Server detection failed: {e.__class__.__name__}: {e}"
            self.logger.exception(error_msg)
            return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                error_msg,
            )

    def execute(self, **_kwargs: object) -> FlextResult[FlextLdifModels.ClientStatus]:
        """Execute server detector self-check (required by FlextService).

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with detector status

        """
        status_result = FlextLdifModels.ClientStatus(
            status="initialized",
            services=["detect_server_type"],
            config={"service": "FlextLdifDetector"},
        )
        return FlextResult[FlextLdifModels.ClientStatus].ok(status_result)

    @staticmethod
    def resolve_from_config(
        config: FlextLdifConfig,
        target_server_type: str | None = None,
    ) -> str:
        """Determine effective server type based on a prioritized configuration hierarchy."""
        # Priority 1: Direct override from a service-level parameter
        if target_server_type:
            return target_server_type

        # Priority 2: Relaxed parsing mode takes precedence
        if config.enable_relaxed_parsing:
            return FlextLdifConstants.ServerTypes.RELAXED

        # Priority 3: Manual configuration mode
        if config.quirks_detection_mode == "manual":
            # Validate that quirks_server_type is provided in manual mode
            if config.quirks_server_type is None:
                return FlextLdifConstants.ServerTypes.RFC
            if not config.quirks_server_type.strip():
                return FlextLdifConstants.ServerTypes.RFC
            return config.quirks_server_type

        # Priority 4: Disabled mode falls back to RFC
        if config.quirks_detection_mode == "disabled":
            return FlextLdifConstants.ServerTypes.RFC

        # Default: Use the configured default server type
        return config.ldif_default_server_type

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> FlextResult[str]:
        """Resolve the effective LDAP server type to use for processing.

        Applies priority resolution based on config settings:
        1. Relaxed mode enabled → "relaxed"
        2. Manual mode → configured server type
        3. Auto mode → detected server type from content
        4. Disabled mode → "rfc"

        Args:
            ldif_path: Optional path to LDIF file for auto-detection
            ldif_content: Optional LDIF content string for auto-detection

        Returns:
            FlextResult with the server type string to use

        """
        try:
            # Priority 3: Auto-detection
            if ldif_path is not None or ldif_content is not None:
                detection_result = self.detect_server_type(
                    ldif_path=ldif_path,
                    ldif_content=ldif_content,
                )
                if detection_result.is_success:
                    result = detection_result.unwrap()
                    if (
                        FlextRuntime.is_dict_like(result)
                        and "detected_server_type" in result
                    ):
                        server_type = result["detected_server_type"]
                        return FlextResult[str].ok(cast("str", server_type))

            # Default to RFC
            return FlextResult[str].ok(FlextLdifConstants.ServerTypes.RFC)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(
                f"Failed to resolve effective server type: {e}",
            )

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

        for attr in attributes:
            if attr.lower() in content_lower:
                scores[server_type] += (
                    FlextLdifConstants.ServerDetection.ATTRIBUTE_MATCH_SCORE
                )

        # Also score objectClass matches
        if objectclasses:
            for objclass in objectclasses:
                if objclass.lower() in content_lower:
                    scores[server_type] += (
                        FlextLdifConstants.ServerDetection.ATTRIBUTE_MATCH_SCORE
                    )

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
        if not constants or not hasattr(constants, "DETECTION_OID_PATTERN"):
            return

        pattern = getattr(constants, "DETECTION_OID_PATTERN", None)
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
        if not constants or not hasattr(constants, pattern_attr):
            return

        pattern = getattr(constants, pattern_attr, None)
        if not pattern:
            return

        if isinstance(pattern, re.Pattern):
            if pattern.search(content_lower):
                scores[server_type] += getattr(constants, "DETECTION_WEIGHT", 6)
        elif isinstance(pattern, str) and re.search(pattern, content_lower):
            scores[server_type] += getattr(constants, "DETECTION_WEIGHT", 6)

    def _calculate_scores(self, content: str) -> dict[str, int]:
        """Calculate detection scores for each server type.

        Args:
            content: LDIF content to analyze

        Returns:
            Dict with server type scores

        """
        # Initialize scores for all supported server types
        scores: dict[str, int] = dict.fromkeys(self._get_all_server_types(), 0)

        # Set base score for generic (fallback)
        scores[FlextLdifConstants.ServerTypes.GENERIC] = 1

        # Lowercase content for case-insensitive matching
        content_lower = content.lower()

        # Process servers with OID patterns
        oid_constants = self._get_server_constants(FlextLdifConstants.ServerTypes.OID)
        self._process_server_with_oid_pattern(
            FlextLdifConstants.ServerTypes.OID,
            oid_constants,
            content,
            content_lower,
            scores,
            case_sensitive=True,
        )

        oud_constants = self._get_server_constants(FlextLdifConstants.ServerTypes.OUD)
        self._process_server_with_oid_pattern(
            FlextLdifConstants.ServerTypes.OUD,
            oud_constants,
            content,
            content_lower,
            scores,
        )

        # Process servers with standard patterns
        openldap_constants = self._get_server_constants(
            FlextLdifConstants.ServerTypes.OPENLDAP,
        )
        if openldap_constants and hasattr(openldap_constants, "DETECTION_PATTERN"):
            openldap_pattern = getattr(openldap_constants, "DETECTION_PATTERN", None)
            if openldap_pattern and isinstance(openldap_pattern, str):
                self._update_server_scores(
                    FlextLdifConstants.ServerTypes.OPENLDAP,
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

        ad_constants = self._get_server_constants(FlextLdifConstants.ServerTypes.AD)
        if ad_constants and hasattr(ad_constants, "DETECTION_PATTERN"):
            ad_pattern = getattr(ad_constants, "DETECTION_PATTERN", None)
            if ad_pattern and isinstance(ad_pattern, str):
                self._update_server_scores(
                    FlextLdifConstants.ServerTypes.AD,
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

        # Process simple pattern-based servers
        novell_constants = self._get_server_constants(
            FlextLdifConstants.ServerTypes.NOVELL,
        )
        self._process_server_with_pattern(
            FlextLdifConstants.ServerTypes.NOVELL,
            novell_constants,
            content_lower,
            scores,
        )

        tivoli_constants = self._get_server_constants(
            FlextLdifConstants.ServerTypes.IBM_TIVOLI,
        )
        self._process_server_with_pattern(
            FlextLdifConstants.ServerTypes.IBM_TIVOLI,
            tivoli_constants,
            content_lower,
            scores,
        )

        ds389_constants = self._get_server_constants(
            FlextLdifConstants.ServerTypes.DS_389,
        )
        self._process_server_with_pattern(
            FlextLdifConstants.ServerTypes.DS_389,
            ds389_constants,
            content_lower,
            scores,
        )

        apache_constants = self._get_server_constants(
            FlextLdifConstants.ServerTypes.APACHE,
        )
        self._process_server_with_pattern(
            FlextLdifConstants.ServerTypes.APACHE,
            apache_constants,
            content_lower,
            scores,
        )

        return scores

    def _determine_server_type(self, scores: dict[str, int]) -> tuple[str, float]:
        """Determine the most likely server type from scores.

        Args:
            scores: Detection scores for each server type

        Returns:
            Tuple of (server_type, confidence)

        """
        if not scores:
            return FlextLdifConstants.ServerTypes.RFC, 0.0

        # Find max score
        max_score: int = max(scores.values()) if scores.values() else 0
        total_score: int = sum(scores.values()) if scores.values() else 0

        # If no signals, default to RFC
        if max_score == 0:
            return FlextLdifConstants.ServerTypes.RFC, 0.0

        # Calculate confidence
        confidence = max_score / total_score if total_score > 0 else 0.0

        # Find server type with highest score
        detected: str = max(scores, key=lambda k: scores[k])

        # If low confidence, return RFC
        if confidence < FlextLdifConstants.ServerDetection.CONFIDENCE_THRESHOLD:
            return FlextLdifConstants.ServerTypes.RFC, confidence

        # Map "generic" fallback to "rfc" (generic is not a registered quirk)
        if detected == FlextLdifConstants.ServerTypes.GENERIC:
            return FlextLdifConstants.ServerTypes.RFC, confidence

        return detected, confidence

    @staticmethod
    def _check_regex_pattern(
        pattern: str,
        content: str,
        description: str,
        patterns: list[str],
    ) -> None:
        """Check if pattern exists in content, append description if found."""
        if re.search(pattern, content):
            patterns.append(description)

    @staticmethod
    def _check_substring_pattern(
        value: str,
        content_lower: str,
        description: str,
        patterns: list[str],
    ) -> None:
        """Check if substring exists in content (case-insensitive), append if found."""
        if value.lower() in content_lower:
            patterns.append(description)

    def _extract_oid_patterns(
        self,
        constants: type[ServerDetectionConstants] | None,
        pattern: str | None,
        description: str,
        content: str,
        content_lower: str,
        patterns: list[str],
        *,
        case_sensitive: bool = False,
    ) -> None:
        """Extract patterns using OID pattern."""
        if not constants or not pattern or not isinstance(pattern, str):
            return

        search_content = content if case_sensitive else content_lower
        self._check_regex_pattern(pattern, search_content, description, patterns)

    def _extract_oid_specific_patterns(
        self,
        constants: type[ServerDetectionConstants] | None,
        content_lower: str,
        patterns: list[str],
    ) -> None:
        """Extract OID-specific patterns (ACLs, etc.)."""
        if not constants:
            return

        orclaci = getattr(constants, "ORCLACI", None)
        if orclaci and isinstance(orclaci, str):
            self._check_substring_pattern(
                orclaci,
                content_lower,
                "Oracle OID ACLs",
                patterns,
            )
        orclentrylevelaci = getattr(constants, "ORCLENTRYLEVELACI", None)
        if (
            orclentrylevelaci
            and isinstance(orclentrylevelaci, str)
            and orclentrylevelaci.lower() in content_lower
            and "Oracle OID ACLs" not in patterns
        ):
            patterns.append("Oracle OID ACLs")

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
        if not constants or not hasattr(constants, pattern_attr):
            return

        pattern = getattr(constants, pattern_attr, None)
        if pattern and isinstance(pattern, str):
            self._check_regex_pattern(pattern, content_lower, description, patterns)

    def _extract_patterns(self, content: str) -> list[str]:
        """Extract detected patterns from content.

        Args:
            content: LDIF content to analyze

        Returns:
            List of detected patterns

        """
        patterns: list[str] = []
        content_lower = content.lower()

        # Oracle OID detection
        oid_constants = self._get_server_constants(FlextLdifConstants.ServerTypes.OID)
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
            self._extract_oid_specific_patterns(oid_constants, content_lower, patterns)

        # Oracle OUD detection
        oud_constants = self._get_server_constants(FlextLdifConstants.ServerTypes.OUD)
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

        # OpenLDAP detection
        openldap_constants = self._get_server_constants(
            FlextLdifConstants.ServerTypes.OPENLDAP,
        )
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

        # Active Directory detection
        ad_constants = self._get_server_constants(FlextLdifConstants.ServerTypes.AD)
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
            self._check_substring_pattern(
                "samaccountname",
                content_lower,
                "Active Directory attributes",
                patterns,
            )

        # Pattern-based detections
        self._extract_pattern_with_attr(
            FlextLdifConstants.ServerTypes.NOVELL,
            "DETECTION_PATTERN",
            "Novell eDirectory attributes (GUID, Modifiers, etc.)",
            content_lower,
            patterns,
        )

        # IBM Tivoli detection (uses compiled pattern)
        tivoli_constants = self._get_server_constants(
            FlextLdifConstants.ServerTypes.IBM_TIVOLI,
        )
        if tivoli_constants:
            tivoli_pattern = tivoli_constants.DETECTION_PATTERN
            if isinstance(tivoli_pattern, re.Pattern) and tivoli_pattern.search(
                content_lower,
            ):
                patterns.append("IBM Tivoli attributes (ibm-*, tivoli, ldapdb)")

        self._extract_pattern_with_attr(
            FlextLdifConstants.ServerTypes.DS_389,
            "DETECTION_PATTERN",
            "389 Directory Server attributes (389ds, redhat-ds, dirsrv)",
            content_lower,
            patterns,
        )

        self._extract_pattern_with_attr(
            FlextLdifConstants.ServerTypes.APACHE,
            "DETECTION_PATTERN",
            "Apache DS attributes (apacheDS, apache-*)",
            content_lower,
            patterns,
        )

        return patterns

    @staticmethod
    def _get_server_constants(
        server_type: str,
    ) -> type[ServerDetectionConstants] | None:
        """Get server Constants class dynamically via FlextLdifServer registry.

        Uses runtime attribute access to get detection constants from server quirk classes.

        Args:
            server_type: Server type identifier (e.g., "oid", "oud", "openldap")

        Returns:
            Server Constants class if available, None otherwise

        """
        try:
            registry = _get_server_registry()
            server_quirk = registry.quirk(server_type)
            if not server_quirk:
                return None

            quirk_class = type(server_quirk)
            # Type guard: ensure Constants exists and is not from base class
            if not hasattr(quirk_class, "Constants"):
                return None

            # Get Constants - only concrete server classes have Constants, not base
            constants = getattr(quirk_class, "Constants", None)
            if constants is None:
                return None

            # Type cast to Protocol for type safety
            return cast("type[ServerDetectionConstants]", constants)
        except ValueError:
            # Unknown server type
            return None


__all__ = ["FlextLdifDetector"]
