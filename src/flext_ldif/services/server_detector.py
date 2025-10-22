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

import logging
import re
from pathlib import Path
from typing import ClassVar, Final

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.typings import FlextLdifTypes

logger = logging.getLogger(__name__)


class FlextLdifServerDetector(FlextService[FlextLdifTypes.Models.CustomDataDict]):
    """Service for detecting LDAP server type from LDIF content.

    Uses pattern matching to identify server-specific features:
    - Oracle OID: 2.16.840.1.113894.* OIDs, orclaci, orclentrylevelaci
    - Oracle OUD: ds-sync-*, entryUUID, ds-pwp-account-disabled
    - OpenLDAP: olc* attributes, cn=config entries
    - Active Directory: objectGUID, samAccountName, sIDHistory
    - 389 DS: 389ds-specific attributes
    - Apache DS: apacheDS-specific patterns
    - Novell eDirectory: novell-specific patterns
    - IBM Tivoli: tivoli-specific patterns

    Detection Priority (by score):
    1. Most specific patterns (Oracle OID, OUD)
    2. Medium specificity (OpenLDAP, AD)
    3. Generic patterns (GENERIC)
    4. Fallback to RFC if no patterns found
    5. Return RELAXED if detection is inconclusive
    """

    # Detection score weights (higher = more specific)
    ORACLE_OID_PATTERN: ClassVar[Final[str]] = r"2\.16\.840\.1\.113894\."
    ORACLE_OID_ATTRIBUTES: ClassVar[Final[frozenset[str]]] = frozenset([
        "orclOID",
        "orclGUID",
        "orclPassword",
        "orclaci",
        "orclentrylevelaci",
        "orcldaslov",
    ])
    ORACLE_OID_WEIGHT: ClassVar[Final[int]] = 10

    ORACLE_OUD_PATTERN: ClassVar[Final[str]] = r"(ds-sync-|ds-pwp-|ds-cfg-)"
    ORACLE_OUD_ATTRIBUTES: ClassVar[Final[frozenset[str]]] = frozenset([
        "ds-sync-hist",
        "ds-sync-state",
        "ds-pwp-account-disabled",
        "ds-cfg-backend-id",
        "entryUUID",
    ])
    ORACLE_OUD_WEIGHT: ClassVar[Final[int]] = 10

    OPENLDAP_PATTERN: ClassVar[Final[str]] = r"\b(olc[A-Z][a-zA-Z]+|cn=config)\b"
    OPENLDAP_ATTRIBUTES: ClassVar[Final[frozenset[str]]] = frozenset([
        "olcDatabase",
        "olcAccess",
        "olcOverlay",
        "olcModule",
    ])
    OPENLDAP_WEIGHT: ClassVar[Final[int]] = 8

    ACTIVE_DIRECTORY_PATTERN: ClassVar[Final[str]] = r"1\.2\.840\.113556\."
    ACTIVE_DIRECTORY_ATTRIBUTES: ClassVar[Final[frozenset[str]]] = frozenset([
        "objectGUID",
        "samAccountName",
        "sIDHistory",
        "nTSecurityDescriptor",
    ])
    ACTIVE_DIRECTORY_WEIGHT: ClassVar[Final[int]] = 8

    NOVELL_EDIR_PATTERN: ClassVar[Final[str]] = (
        r"\b(GUID|Modifiers|nrpDistributionPassword)\b"
    )
    NOVELL_EDIR_WEIGHT: ClassVar[Final[int]] = 6

    IBM_TIVOLI_PATTERN: ClassVar[Final[str]] = r"\b(ibm|tivoli|ldapdb)\b"
    IBM_TIVOLI_WEIGHT: ClassVar[Final[int]] = 6

    APACHE_DS_PATTERN: ClassVar[Final[str]] = r"\b(apacheDS|apache-.*)\b"
    APACHE_DS_WEIGHT: ClassVar[Final[int]] = 6

    DS_389_PATTERN: ClassVar[Final[str]] = r"\b(389ds|redhat-ds|dirsrv)\b"
    DS_389_WEIGHT: ClassVar[Final[int]] = 6

    # Detection thresholds
    DETECTION_THRESHOLD: ClassVar[Final[int]] = 5
    CONFIDENCE_THRESHOLD: ClassVar[Final[float]] = 0.6

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
        max_lines: int = 1000,
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Detect LDAP server type from LDIF file or content.

        Args:
            ldif_path: Path to LDIF file (alternative to ldif_content)
            ldif_content: Raw LDIF content as string
            max_lines: Maximum lines to scan for detection

        Returns:
            FlextResult with detection results:
            {
                "detected_server_type": "oid" | "oud" | "openldap" | ...,
                "confidence": 0.0-1.0,
                "scores": {"oid": 10, "oud": 5, ...},
                "patterns_found": ["pattern1", "pattern2", ...],
                "is_confident": bool,
            }

        """
        try:
            # Read LDIF content if path provided
            if ldif_content is None:
                if ldif_path is None:
                    return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                        "Either ldif_path or ldif_content must be provided"
                    )
                # RFC 2849 mandates UTF-8 encoding - fail on invalid encoding
                try:
                    ldif_content = ldif_path.read_text(encoding="utf-8")
                except UnicodeDecodeError as e:
                    return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                        f"LDIF file is not valid UTF-8 (RFC 2849 violation): {e}"
                    )

            # Limit content for performance
            lines = ldif_content.split("\n")
            content_sample = "\n".join(lines[:max_lines])

            # Run detection
            scores = self._calculate_scores(content_sample)
            detected_type, confidence = self._determine_server_type(scores)

            patterns_found = self._extract_patterns(content_sample)

            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "detected_server_type": detected_type,
                "confidence": confidence,
                "scores": scores,
                "patterns_found": patterns_found,
                "is_confident": confidence >= self.CONFIDENCE_THRESHOLD,
            })
        except Exception as e:
            logger.warning(f"Server detection failed: {e}")
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "detected_server_type": FlextLdifConstants.ServerTypes.RFC,
                "confidence": 0.0,
                "scores": {},
                "patterns_found": [],
                "is_confident": False,
                "detection_error": str(e),
            })

    def execute(self) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Execute server detector self-check (required by FlextService).

        Returns:
            FlextResult with detector status

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
            "status": "initialized",
            "service": "FlextLdifServerDetector",
            "capabilities": ["detect_server_type"],
        })

    def _calculate_scores(self, content: str) -> dict[str, int]:
        """Calculate detection scores for each server type.

        Args:
            content: LDIF content to analyze

        Returns:
            Dict with server type scores

        """
        scores: dict[str, int] = {
            FlextLdifConstants.ServerTypes.OID: 0,
            FlextLdifConstants.ServerTypes.OUD: 0,
            FlextLdifConstants.ServerTypes.OPENLDAP: 0,
            FlextLdifConstants.ServerTypes.OPENLDAP1: 0,
            FlextLdifConstants.ServerTypes.AD: 0,
            FlextLdifConstants.ServerTypes.DS_389: 0,
            FlextLdifConstants.ServerTypes.APACHE: 0,
            FlextLdifConstants.ServerTypes.GENERIC: 1,  # Base score for generic
            FlextLdifConstants.ServerTypes.RFC: 0,
        }

        # Lowercase content for case-insensitive matching
        content_lower = content.lower()

        # Oracle OID detection
        if re.search(self.ORACLE_OID_PATTERN, content):
            scores[FlextLdifConstants.ServerTypes.OID] += self.ORACLE_OID_WEIGHT
        for attr in self.ORACLE_OID_ATTRIBUTES:
            if attr.lower() in content_lower:
                scores[FlextLdifConstants.ServerTypes.OID] += 2

        # Oracle OUD detection
        if re.search(self.ORACLE_OUD_PATTERN, content_lower):
            scores[FlextLdifConstants.ServerTypes.OUD] += self.ORACLE_OUD_WEIGHT
        for attr in self.ORACLE_OUD_ATTRIBUTES:
            if attr.lower() in content_lower:
                scores[FlextLdifConstants.ServerTypes.OUD] += 2

        # OpenLDAP detection
        if re.search(self.OPENLDAP_PATTERN, content_lower):
            scores[FlextLdifConstants.ServerTypes.OPENLDAP] += self.OPENLDAP_WEIGHT
        for attr in self.OPENLDAP_ATTRIBUTES:
            if attr.lower() in content_lower:
                scores[FlextLdifConstants.ServerTypes.OPENLDAP] += 2

        # Active Directory detection
        if re.search(self.ACTIVE_DIRECTORY_PATTERN, content):
            scores[FlextLdifConstants.ServerTypes.AD] += self.ACTIVE_DIRECTORY_WEIGHT
        for attr in self.ACTIVE_DIRECTORY_ATTRIBUTES:
            if attr.lower() in content_lower:
                scores[FlextLdifConstants.ServerTypes.AD] += 2

        # 389 DS detection
        if re.search(self.DS_389_PATTERN, content_lower):
            scores[FlextLdifConstants.ServerTypes.DS_389] += self.DS_389_WEIGHT

        # Apache DS detection
        if re.search(self.APACHE_DS_PATTERN, content_lower):
            scores[FlextLdifConstants.ServerTypes.APACHE] += self.APACHE_DS_WEIGHT

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
        if confidence < self.CONFIDENCE_THRESHOLD:
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

        if re.search(self.ORACLE_OID_PATTERN, content):
            patterns.append("Oracle OID namespace (2.16.840.1.113894.*)")
        if "orclaci" in content_lower or "orclentrylevelaci" in content_lower:
            patterns.append("Oracle OID ACLs")

        if re.search(self.ORACLE_OUD_PATTERN, content_lower):
            patterns.append("Oracle OUD attributes (ds-sync-*)")

        if re.search(self.OPENLDAP_PATTERN, content_lower):
            patterns.append("OpenLDAP configuration (olc*)")

        if re.search(self.ACTIVE_DIRECTORY_PATTERN, content):
            patterns.append("Active Directory namespace (1.2.840.113556.*)")
        if "samaccountname" in content_lower:
            patterns.append("Active Directory attributes")

        return patterns


__all__ = ["FlextLdifServerDetector"]
