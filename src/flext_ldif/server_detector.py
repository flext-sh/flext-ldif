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

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

logger = FlextLogger(__name__)


class FlextLdifServerDetector(FlextService[FlextLdifModels.ClientStatus]):
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
                        "Either ldif_path or ldif_content must be provided"
                    )
                # RFC 2849 mandates UTF-8 encoding - fail on invalid encoding
                try:
                    ldif_content = ldif_path.read_text(encoding="utf-8")
                except UnicodeDecodeError as e:
                    return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                        f"LDIF file is not valid UTF-8 (RFC 2849 violation): {e}"
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
                detection_result
            )
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Server detection failed: {e}")
            fallback_result = FlextLdifModels.ServerDetectionResult(
                detected_server_type=FlextLdifConstants.ServerTypes.RFC,
                confidence=0.0,
                scores={},
                patterns_found=[],
                is_confident=False,
                detection_error=str(e),
                fallback_reason="Detection failed with exception",
            )
            return FlextResult[FlextLdifModels.ServerDetectionResult].ok(
                fallback_result
            )

    def execute(self) -> FlextResult[FlextLdifModels.ClientStatus]:
        """Execute server detector self-check (required by FlextService).

        Returns:
            FlextResult with detector status

        """
        status_result = FlextLdifModels.ClientStatus(
            status="initialized",
            services=["detect_server_type"],
            config={"service": "FlextLdifServerDetector"},
        )
        return FlextResult[FlextLdifModels.ClientStatus].ok(status_result)

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

        # Oracle OID detection
        if re.search(FlextLdifConstants.ServerDetection.ORACLE_OID_PATTERN, content):
            scores[FlextLdifConstants.ServerTypes.OID] += (
                FlextLdifConstants.ServerDetection.ORACLE_OID_WEIGHT
            )
        for attr in FlextLdifConstants.ServerDetection.ORACLE_OID_ATTRIBUTES:
            if attr.lower() in content_lower:
                scores[FlextLdifConstants.ServerTypes.OID] += (
                    FlextLdifConstants.ServerDetection.ATTRIBUTE_MATCH_SCORE
                )

        # Oracle OUD detection
        if re.search(
            FlextLdifConstants.ServerDetection.ORACLE_OUD_PATTERN, content_lower
        ):
            scores[FlextLdifConstants.ServerTypes.OUD] += (
                FlextLdifConstants.ServerDetection.ORACLE_OUD_WEIGHT
            )
        for attr in FlextLdifConstants.ServerDetection.ORACLE_OUD_ATTRIBUTES:
            if attr.lower() in content_lower:
                scores[FlextLdifConstants.ServerTypes.OUD] += (
                    FlextLdifConstants.ServerDetection.ATTRIBUTE_MATCH_SCORE
                )

        # OpenLDAP detection
        if re.search(
            FlextLdifConstants.ServerDetection.OPENLDAP_PATTERN, content_lower
        ):
            scores[FlextLdifConstants.ServerTypes.OPENLDAP] += (
                FlextLdifConstants.ServerDetection.OPENLDAP_WEIGHT
            )
        for attr in FlextLdifConstants.ServerDetection.OPENLDAP_ATTRIBUTES:
            if attr.lower() in content_lower:
                scores[FlextLdifConstants.ServerTypes.OPENLDAP] += (
                    FlextLdifConstants.ServerDetection.ATTRIBUTE_MATCH_SCORE
                )

        # Active Directory detection
        if re.search(
            FlextLdifConstants.ServerDetection.ACTIVE_DIRECTORY_PATTERN, content
        ):
            scores[FlextLdifConstants.ServerTypes.AD] += (
                FlextLdifConstants.ServerDetection.ACTIVE_DIRECTORY_WEIGHT
            )
        for attr in FlextLdifConstants.ServerDetection.ACTIVE_DIRECTORY_ATTRIBUTES:
            if attr.lower() in content_lower:
                scores[FlextLdifConstants.ServerTypes.AD] += (
                    FlextLdifConstants.ServerDetection.ATTRIBUTE_MATCH_SCORE
                )

        # Novell eDirectory detection
        if re.search(
            FlextLdifConstants.ServerDetection.NOVELL_EDIR_PATTERN, content_lower
        ):
            scores[FlextLdifConstants.ServerTypes.NOVELL] += (
                FlextLdifConstants.ServerDetection.NOVELL_EDIR_WEIGHT
            )

        # IBM Tivoli detection
        if re.search(
            FlextLdifConstants.ServerDetection.IBM_TIVOLI_PATTERN, content_lower
        ):
            scores[FlextLdifConstants.ServerTypes.IBM_TIVOLI] += (
                FlextLdifConstants.ServerDetection.IBM_TIVOLI_WEIGHT
            )

        # 389 DS detection
        if re.search(FlextLdifConstants.ServerDetection.DS_389_PATTERN, content_lower):
            scores[FlextLdifConstants.ServerTypes.DS_389] += (
                FlextLdifConstants.ServerDetection.DS_389_WEIGHT
            )

        # Apache DS detection
        if re.search(
            FlextLdifConstants.ServerDetection.APACHE_DS_PATTERN, content_lower
        ):
            scores[FlextLdifConstants.ServerTypes.APACHE] += (
                FlextLdifConstants.ServerDetection.APACHE_DS_WEIGHT
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

        return detected, confidence

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
        if re.search(FlextLdifConstants.ServerDetection.ORACLE_OID_PATTERN, content):
            patterns.append("Oracle OID namespace (2.16.840.1.113894.*)")
        if "orclaci" in content_lower or "orclentrylevelaci" in content_lower:
            patterns.append("Oracle OID ACLs")

        # Oracle OUD detection
        if re.search(
            FlextLdifConstants.ServerDetection.ORACLE_OUD_PATTERN, content_lower
        ):
            patterns.append("Oracle OUD attributes (ds-sync-*)")

        # OpenLDAP detection
        if re.search(
            FlextLdifConstants.ServerDetection.OPENLDAP_PATTERN, content_lower
        ):
            patterns.append("OpenLDAP configuration (olc*)")

        # Active Directory detection
        if re.search(
            FlextLdifConstants.ServerDetection.ACTIVE_DIRECTORY_PATTERN, content
        ):
            patterns.append("Active Directory namespace (1.2.840.113556.*)")
        if "samaccountname" in content_lower:
            patterns.append("Active Directory attributes")

        # Novell eDirectory detection
        if re.search(
            FlextLdifConstants.ServerDetection.NOVELL_EDIR_PATTERN, content_lower
        ):
            patterns.append("Novell eDirectory attributes (GUID, Modifiers, etc.)")

        # IBM Tivoli detection
        if re.search(
            FlextLdifConstants.ServerDetection.IBM_TIVOLI_PATTERN, content_lower
        ):
            patterns.append("IBM Tivoli attributes (ibm-*, tivoli, ldapdb)")

        # 389 DS detection
        if re.search(FlextLdifConstants.ServerDetection.DS_389_PATTERN, content_lower):
            patterns.append(
                "389 Directory Server attributes (389ds, redhat-ds, dirsrv)"
            )

        # Apache DS detection
        if re.search(
            FlextLdifConstants.ServerDetection.APACHE_DS_PATTERN, content_lower
        ):
            patterns.append("Apache DS attributes (apacheDS, apache-*)")

        return patterns


__all__ = ["FlextLdifServerDetector"]
