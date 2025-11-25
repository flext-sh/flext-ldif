"""FLEXT-LDIF ACL Extractor Service - ACL entry detection and extraction.

This service handles extraction of entries with ACL attributes,
excluding schema entries.

Extracted from FlextLdifFilters to follow Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.base import LdifServiceBase
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifAclExtractor(
    LdifServiceBase,
):
    """Service for ACL entry extraction.

    Provides methods for:
    - Extracting entries with ACL attributes
    - Filtering out schema entries
    - Supporting multiple ACL attribute names (acl, aci, olcAccess)

    Example:
        extractor_service = FlextLdifAclExtractor()

        # Extract entries with default ACL attributes
        result = extractor_service.extract_acl_entries(entries)
        acl_entries = result.unwrap()

        # Extract entries with custom ACL attributes
        result = extractor_service.extract_acl_entries(
            entries,
            acl_attributes=["orclaci", "aci"]
        )

    """

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (extract_acl_entries, etc.)
        rather than a generic execute operation.

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult.fail(
            "FlextLdifAclExtractor does not support generic execute(). Use specific methods instead.",
        )

    @staticmethod
    def _is_schema_entry(entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a schema definition.

        Schema entries are detected by presence of attributeTypes, objectClasses,
        ldapSyntaxes, or matchingRules attributes (case-insensitive).

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema definition

        """
        schema_attrs = {
            "attributetypes",
            "objectclasses",
            "ldapsyntaxes",
            "matchingrules",
        }
        entry_attrs = {attr.lower() for attr in entry.attributes.attributes}
        return bool(schema_attrs & entry_attrs)

    def extract_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Extract entries with ACL attributes.

        Filters entries to find those with ACL attributes (acl, aci, olcAccess),
        while excluding schema entries.

        Args:
            entries: List of entries to filter
            acl_attributes: List of ACL attribute names to look for
                          Default: ["acl", "aci", "olcAccess"]

        Returns:
            FlextResult with list of entries containing ACL attributes
            (excluding schema entries)

        Example:
            # Extract with default ACL attributes
            result = extractor.extract_acl_entries(entries)

            # Extract with Oracle OID ACL attributes
            result = extractor.extract_acl_entries(
                entries,
                acl_attributes=["orclaci"]
            )

        """
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        # Use provided acl_attributes or default
        if acl_attributes is None:
            filter_acl_attrs = ["acl", "aci", "olcAccess"]
        else:
            filter_acl_attrs = acl_attributes

        # Exclude schema entries first
        non_schema_entries = [e for e in entries if not self._is_schema_entry(e)]

        # Filter entries by ACL attributes (match ANY attribute)
        filtered = [
            entry
            for entry in non_schema_entries
            if FlextLdifUtilities.Entry.has_any_attributes(entry, filter_acl_attrs)
        ]

        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)


__all__ = ["FlextLdifAclExtractor"]
