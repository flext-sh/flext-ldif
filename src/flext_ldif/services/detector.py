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

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

logger = FlextLogger(__name__)


class FlextLdifDetector(FlextService[FlextLdifModels.ClientStatus]):
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

            # Run detection
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
        except (ValueError, TypeError, AttributeError):
            logger.exception("Server detection failed")
            fallback_result = FlextLdifModels.ServerDetectionResult(
                detected_server_type=FlextLdifConstants.ServerTypes.RFC,
                confidence=0.0,
                scores={},
                patterns_found=[],
                is_confident=False,
                detection_error="Detection failed with exception",
                fallback_reason="Detection failed with exception",
            )
            return FlextResult[FlextLdifModels.ServerDetectionResult].ok(
                fallback_result,
            )

    def execute(self) -> FlextResult[FlextLdifModels.ClientStatus]:
        """Execute server detector self-check (required by FlextService).

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
            return config.quirks_server_type or FlextLdifConstants.ServerTypes.RFC

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
                    if isinstance(result, dict) and "detected_server_type" in result:
                        server_type = result["detected_server_type"]
                        return FlextResult[str].ok(server_type)

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
    ) -> None:
        """Update scores for a server type based on pattern and attribute matches."""
        search_content = content if case_sensitive else content_lower
        if re.search(pattern, search_content):
            scores[server_type] += weight

        for attr in attributes:
            if attr.lower() in content_lower:
                scores[server_type] += (
                    FlextLdifConstants.ServerDetection.ATTRIBUTE_MATCH_SCORE
                )

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

        # Oracle OID detection - use server Constants
        from flext_ldif.servers.oid import (
            FlextLdifServersOid,
        )

        self._update_server_scores(
            FlextLdifConstants.ServerTypes.OID,
            FlextLdifServersOid.Constants.DETECTION_OID_PATTERN,
            FlextLdifServersOid.Constants.DETECTION_WEIGHT,
            FlextLdifServersOid.Constants.DETECTION_ATTRIBUTES,
            content,
            content_lower,
            scores,
            case_sensitive=True,
        )

        # Oracle OUD detection - use server Constants
        from flext_ldif.servers.oud import (
            FlextLdifServersOud,
        )

        self._update_server_scores(
            FlextLdifConstants.ServerTypes.OUD,
            FlextLdifServersOud.Constants.DETECTION_OID_PATTERN,
            FlextLdifServersOud.Constants.DETECTION_WEIGHT,
            FlextLdifServersOud.Constants.DETECTION_ATTRIBUTES,
            content,
            content_lower,
            scores,
        )

        # OpenLDAP detection - use server Constants
        from flext_ldif.servers.openldap import (
            FlextLdifServersOpenldap,
        )

        self._update_server_scores(
            FlextLdifConstants.ServerTypes.OPENLDAP,
            FlextLdifServersOpenldap.Constants.DETECTION_PATTERN,
            FlextLdifServersOpenldap.Constants.DETECTION_WEIGHT,
            FlextLdifServersOpenldap.Constants.DETECTION_ATTRIBUTES,
            content,
            content_lower,
            scores,
        )

        # Active Directory detection - use server Constants
        from flext_ldif.servers.ad import (
            FlextLdifServersAd,
        )

        self._update_server_scores(
            FlextLdifConstants.ServerTypes.AD,
            FlextLdifServersAd.Constants.DETECTION_PATTERN,
            FlextLdifServersAd.Constants.DETECTION_WEIGHT,
            FlextLdifServersAd.Constants.DETECTION_ATTRIBUTES,
            content,
            content_lower,
            scores,
            case_sensitive=True,
        )

        # Novell eDirectory detection - use server Constants
        from flext_ldif.servers.novell import (
            FlextLdifServersNovell,
        )

        if re.search(
            FlextLdifServersNovell.Constants.DETECTION_PATTERN,
            content_lower,
        ):
            scores[FlextLdifConstants.ServerTypes.NOVELL] += (
                FlextLdifServersNovell.Constants.DETECTION_WEIGHT
            )

        # IBM Tivoli detection - use server Constants
        from flext_ldif.servers.tivoli import (
            FlextLdifServersTivoli,
        )

        # Tivoli uses compiled Pattern, others use string
        tivoli_pattern = FlextLdifServersTivoli.Constants.DETECTION_PATTERN
        if isinstance(tivoli_pattern, re.Pattern):
            if tivoli_pattern.search(content_lower):
                scores[FlextLdifConstants.ServerTypes.IBM_TIVOLI] += (
                    FlextLdifServersTivoli.Constants.DETECTION_WEIGHT
                )
        elif isinstance(tivoli_pattern, str) and re.search(
            tivoli_pattern,
            content_lower,
        ):
            scores[FlextLdifConstants.ServerTypes.IBM_TIVOLI] += (
                FlextLdifServersTivoli.Constants.DETECTION_WEIGHT
            )

        # 389 DS detection - use server Constants
        from flext_ldif.servers.ds389 import FlextLdifServersDs389

        if re.search(FlextLdifServersDs389.Constants.DETECTION_PATTERN, content_lower):
            scores[FlextLdifConstants.ServerTypes.DS_389] += (
                FlextLdifServersDs389.Constants.DETECTION_WEIGHT
            )

        # Apache DS detection - use server Constants
        from flext_ldif.servers.apache import (
            FlextLdifServersApache,
        )

        if re.search(
            FlextLdifServersApache.Constants.DETECTION_PATTERN,
            content_lower,
        ):
            scores[FlextLdifConstants.ServerTypes.APACHE] += (
                FlextLdifServersApache.Constants.DETECTION_WEIGHT
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

    def _extract_patterns(self, content: str) -> list[str]:
        """Extract detected patterns from content.

        Args:
            content: LDIF content to analyze

        Returns:
            List of detected patterns

        """
        patterns: list[str] = []
        content_lower = content.lower()

        # Oracle OID detection - use server Constants
        from flext_ldif.servers.oid import (
            FlextLdifServersOid,
        )

        self._check_regex_pattern(
            FlextLdifServersOid.Constants.DETECTION_OID_PATTERN,
            content,
            "Oracle OID namespace (2.16.840.1.113894.*)",
            patterns,
        )
        self._check_substring_pattern(
            FlextLdifServersOid.Constants.ORCLACI,
            content_lower,
            "Oracle OID ACLs",
            patterns,
        )
        if (
            FlextLdifServersOid.Constants.ORCLENTRYLEVELACI.lower() in content_lower
        ) and "Oracle OID ACLs" not in patterns:
            patterns.append("Oracle OID ACLs")

        # Oracle OUD detection - use server Constants
        from flext_ldif.servers.oud import (
            FlextLdifServersOud,
        )

        self._check_regex_pattern(
            FlextLdifServersOud.Constants.DETECTION_OID_PATTERN,
            content_lower,
            "Oracle OUD attributes (ds-sync-*)",
            patterns,
        )

        # OpenLDAP detection - use server Constants
        from flext_ldif.servers.openldap import (
            FlextLdifServersOpenldap,
        )

        self._check_regex_pattern(
            FlextLdifServersOpenldap.Constants.DETECTION_OID_PATTERN,
            content_lower,
            "OpenLDAP configuration (olc*)",
            patterns,
        )

        # Active Directory detection - use server Constants
        from flext_ldif.servers.ad import (
            FlextLdifServersAd,
        )

        self._check_regex_pattern(
            FlextLdifServersAd.Constants.DETECTION_OID_PATTERN,
            content,
            "Active Directory namespace (1.2.840.113556.*)",
            patterns,
        )
        self._check_substring_pattern(
            "samaccountname",
            content_lower,
            "Active Directory attributes",
            patterns,
        )

        # Novell eDirectory detection - use server Constants
        from flext_ldif.servers.novell import (
            FlextLdifServersNovell,
        )

        self._check_regex_pattern(
            FlextLdifServersNovell.Constants.DETECTION_PATTERN,
            content_lower,
            "Novell eDirectory attributes (GUID, Modifiers, etc.)",
            patterns,
        )

        # IBM Tivoli detection - use server Constants
        from flext_ldif.servers.tivoli import (
            FlextLdifServersTivoli,
        )

        # Tivoli uses compiled regex pattern
        tivoli_pattern = FlextLdifServersTivoli.Constants.DETECTION_PATTERN
        if isinstance(tivoli_pattern, re.Pattern) and tivoli_pattern.search(
            content_lower,
        ):
            patterns.append("IBM Tivoli attributes (ibm-*, tivoli, ldapdb)")

        # 389 DS detection - use server Constants
        from flext_ldif.servers.ds389 import FlextLdifServersDs389

        self._check_regex_pattern(
            FlextLdifServersDs389.Constants.DETECTION_PATTERN,
            content_lower,
            "389 Directory Server attributes (389ds, redhat-ds, dirsrv)",
            patterns,
        )

        # Apache DS detection - use server Constants
        from flext_ldif.servers.apache import (
            FlextLdifServersApache,
        )

        self._check_regex_pattern(
            FlextLdifServersApache.Constants.DETECTION_PATTERN,
            content_lower,
            "Apache DS attributes (apacheDS, apache-*)",
            patterns,
        )

        return patterns


__all__ = ["FlextLdifDetector"]
