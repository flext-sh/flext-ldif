"""FLEXT-LDIF Schema Detector Service - Schema entry detection and OID-based filtering.

This service handles detection of schema entries and filtering of schema
definitions by allowed OID patterns.

Extracted from FlextLdifFilters to follow Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import fnmatch

from flext_core import FlextResult

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifSchemaDetector(
    FlextLdifServiceBase[FlextLdifTypes.Models.ServiceResponseTypes],
):
    """Service for schema entry detection and OID-based filtering.

    Provides methods for:
    - Detecting schema entries (attributeTypes, objectClasses, etc.)
    - Filtering schema entries by allowed OID patterns
    - Filtering individual schema definitions within entries
    - OID pattern matching with wildcards

    Example:
        detector_service = FlextLdifSchemaDetector()

        # Check if entry is schema
        if detector_service.is_schema(entry):
            print("Entry is a schema definition")

        # Filter schema entries by allowed OIDs
        allowed_oids = {
            "allowed_attribute_oids": ["2.16.840.1.113894.*", "1.3.6.1.4.1.*"],
            "allowed_objectclass_oids": ["2.16.840.1.113894.*"],
        }
        result = detector_service.filter_by_oids(entries, allowed_oids)
        filtered = result.unwrap()

    """

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (is_schema, filter_by_oids, etc.)
        rather than a generic execute operation.

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult.fail(
            "FlextLdifSchemaDetector does not support generic execute(). Use specific methods instead.",
        )

    @staticmethod
    def is_schema(entry: FlextLdifModels.Entry) -> bool:
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

    @staticmethod
    def _extract_allowed_oids(
        allowed_oids: dict[str, list[str]],
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        """Extract allowed OIDs for each schema type from config dict.

        Supports both long-form keys (allowed_attribute_oids) and short-form
        keys (attributes) for backwards compatibility.

        Args:
            allowed_oids: Dict with allowed OID patterns per schema type

        Returns:
            Tuple of (attr_oids, oc_oids, mr_oids, mru_oids)

        """
        attr_oids = allowed_oids.get("allowed_attribute_oids")
        if attr_oids is None:
            attr_oids = allowed_oids.get("attributes")
        allowed_attr_oids = attr_oids if attr_oids is not None else []

        oc_oids = allowed_oids.get("allowed_objectclass_oids")
        if oc_oids is None:
            oc_oids = allowed_oids.get("objectclasses")
        allowed_oc_oids = oc_oids if oc_oids is not None else []

        mr_oids = allowed_oids.get("allowed_matchingrule_oids")
        if mr_oids is None:
            mr_oids = allowed_oids.get("matchingrules")
        allowed_mr_oids = mr_oids if mr_oids is not None else []

        mru_oids = allowed_oids.get("allowed_matchingruleuse_oids")
        if mru_oids is None:
            mru_oids = allowed_oids.get("matchingruleuse")
        allowed_mru_oids = mru_oids if mru_oids is not None else []

        return allowed_attr_oids, allowed_oc_oids, allowed_mr_oids, allowed_mru_oids

    @staticmethod
    def _filter_definitions(
        definitions: list[str] | str,
        allowed_oids: list[str],
    ) -> list[str]:
        """Filter individual schema definitions by OID patterns and sort by OID.

        Keeps only definitions whose OIDs match one of the allowed patterns.
        Results are sorted by OID for consistent output.

        Args:
            definitions: List of schema definitions or single definition string
            allowed_oids: List of allowed OID patterns (supports wildcards like "99.*")
                         Empty list means NO definitions are allowed (strict filtering)

        Returns:
            List of filtered definitions matching allowed OIDs, sorted by OID.
            Returns empty list if allowed_oids is empty.

        """
        if isinstance(definitions, str):
            definitions = [definitions]

        # If no allowed OIDs, return empty list (nothing is allowed)
        if not allowed_oids:
            return []

        if not definitions:
            return []

        filtered = []
        for definition in definitions:
            # Extract OID from definition (first OID in parentheses)
            oid = (
                FlextLdifUtilities.OID.extract_from_definition(definition) or definition
            )

            # Check if OID matches any allowed pattern
            for pattern in allowed_oids:
                if fnmatch.fnmatch(oid, pattern):
                    filtered.append(definition)
                    break  # Found a match, no need to check other patterns

        # Sort filtered results by OID
        return sorted(
            filtered,
            key=lambda d: FlextLdifUtilities.OID.extract_from_definition(d) or d,
        )

    @classmethod
    def _filter_schema_attribute(
        cls,
        attrs_copy: dict[str, list[str]],
        attr_names: tuple[str, str],
        allowed_oids: list[str],
    ) -> None:
        """Filter a single schema attribute type in-place.

        Modifies attrs_copy dictionary to remove schema definitions that don't
        match allowed OID patterns.

        Args:
            attrs_copy: Dictionary of attributes to modify (modified in-place)
            attr_names: Tuple of (capitalized_name, lowercase_name)
            allowed_oids: List of allowed OID patterns

        """
        cap_name, low_name = attr_names
        if cap_name in attrs_copy or low_name in attrs_copy:
            key = cap_name if cap_name in attrs_copy else low_name
            filtered = cls._filter_definitions(attrs_copy[key], allowed_oids)
            attrs_copy[key] = filtered

    @staticmethod
    def _has_remaining_definitions(attrs_copy: dict[str, list[str]]) -> bool:
        """Check if entry has any schema definitions remaining after filtering.

        Args:
            attrs_copy: Dictionary of attributes to check

        Returns:
            True if any schema definitions remain

        """
        return any(
            [
                attrs_copy.get("attributeTypes") or attrs_copy.get("attributetypes"),
                attrs_copy.get("objectClasses") or attrs_copy.get("objectclasses"),
                attrs_copy.get("matchingRules") or attrs_copy.get("matchingrules"),
                attrs_copy.get("matchingRuleUse") or attrs_copy.get("matchingruleuse"),
            ],
        )

    def filter_by_oids(
        self,
        entries: list[FlextLdifModels.Entry],
        allowed_oids: dict[str, list[str]],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter schema entries by allowed OID patterns.

        Filters INDIVIDUAL DEFINITIONS within schema attributes (attributeTypes,
        objectClasses, matchingRules, matchingRuleUse) to keep only those with
        OIDs matching the allowed patterns.

        Key improvement: Instead of filtering entire entries based on whether they
        contain ANY whitelisted OID, this method filters the DEFINITIONS WITHIN
        each attribute to keep only whitelisted ones.

        Args:
            entries: List of entries to filter
            allowed_oids: Dict with allowed OID patterns per schema type
                         Keys: allowed_attribute_oids, allowed_objectclass_oids,
                               allowed_matchingrule_oids, allowed_matchingruleuse_oids
                         Or short forms: attributes, objectclasses, matchingrules, matchingruleuse

        Returns:
            FlextResult with list of filtered entries (only entries with remaining
            definitions after filtering)

        Example:
            allowed_oids = {
                "allowed_attribute_oids": ["2.16.840.1.113894.*"],
                "allowed_objectclass_oids": ["2.16.840.1.113894.*"],
            }
            result = detector.filter_by_oids(entries, allowed_oids)

        """
        if not entries or not allowed_oids:
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        # Extract allowed OIDs for each schema type
        allowed_attr_oids, allowed_oc_oids, allowed_mr_oids, allowed_mru_oids = (
            self._extract_allowed_oids(allowed_oids)
        )

        filtered = []
        for entry in entries:
            # Skip entries without attributes or DN
            if not entry.attributes or not entry.dn:
                continue

            attrs_copy = dict(entry.attributes.attributes)

            # Filter each schema type
            self._filter_schema_attribute(
                attrs_copy,
                ("attributeTypes", "attributetypes"),
                allowed_attr_oids,
            )
            self._filter_schema_attribute(
                attrs_copy,
                ("objectClasses", "objectclasses"),
                allowed_oc_oids,
            )
            self._filter_schema_attribute(
                attrs_copy,
                ("matchingRules", "matchingrules"),
                allowed_mr_oids,
            )
            self._filter_schema_attribute(
                attrs_copy,
                ("matchingRuleUse", "matchingruleuse"),
                allowed_mru_oids,
            )

            # Only keep entry if it has definitions remaining after filtering
            if self._has_remaining_definitions(attrs_copy):
                # Create new entry with filtered attributes
                # Convert dict to LdifAttributes for Entry.create
                # RFC Compliance: Pass metadata
                filtered_attrs = FlextLdifModels.LdifAttributes(attributes=attrs_copy)
                filtered_entry_result = FlextLdifModels.Entry.create(
                    dn=entry.dn.value,
                    attributes=filtered_attrs,
                    metadata=entry.metadata if hasattr(entry, "metadata") else None,
                )
                if filtered_entry_result.is_success:
                    filtered_entry_domain = filtered_entry_result.unwrap()
                    # Type narrowing: convert Domain.Entry to Models.Entry
                    if isinstance(filtered_entry_domain, FlextLdifModels.Entry):
                        filtered.append(filtered_entry_domain)
                    else:
                        # This should not happen, but handle defensively
                        continue

        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)


__all__ = ["FlextLdifSchemaDetector"]
