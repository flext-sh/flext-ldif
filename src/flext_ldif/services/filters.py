"""Filters service - LDIF Entry Filtering Operations.

Provides filtering operations for LDIF entries including schema OID filtering.
Follows FlextService patterns from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from flext_core import FlextLogger, r

from flext_ldif.models import m

logger: Final = FlextLogger(__name__)


class FlextLdifFilters:
    """LDIF entry filtering service.

    Provides static/classmethod-based filtering operations for LDIF entries.
    Designed for use by FlextLdifCategorization and other services that need
    to filter entries based on various criteria.
    """

    @classmethod
    def _extract_allowed_oids(
        cls,
        allowed_oids: Mapping[str, frozenset[str]],
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
        """Extract allowed OID sets from mapping."""
        return (
            allowed_oids.get("allowed_attribute_oids", frozenset()),
            allowed_oids.get("allowed_objectclass_oids", frozenset()),
            allowed_oids.get("allowed_matchingrule_oids", frozenset()),
            allowed_oids.get("allowed_matchingruleuse_oids", frozenset()),
        )

    @classmethod
    def _check_schema_oid(
        cls,
        attrs: Mapping[str, list[str]],
        attr_keys: tuple[str, str],
        allowed_set: frozenset[str],
    ) -> tuple[bool, bool]:
        """Check if schema OID matches allowed set.

        Returns:
            Tuple of (is_schema_entry, should_include)

        """
        key1, key2 = attr_keys
        if key1 not in attrs and key2 not in attrs:
            return False, True

        oid = cls._extract_oid_from_schema_attr(attrs.get(key1, attrs.get(key2, [])))
        if oid and allowed_set and oid not in allowed_set:
            return True, False

        return True, True

    @classmethod
    def _should_include_entry(
        cls,
        entry: m.Ldif.Entry,
        allowed_attr: frozenset[str],
        allowed_oc: frozenset[str],
        allowed_mr: frozenset[str],
        allowed_mru: frozenset[str],
    ) -> bool:
        """Check if entry should be included based on OID filters."""
        attrs = entry.attributes
        if attrs is None:
            return True

        # Extract attributes dict from Attributes if needed
        if hasattr(attrs, "attributes"):
            # Type narrowing: attrs.attributes is Mapping[str, list[str]]
            attrs_dict: Mapping[str, list[str]] = attrs.attributes
        else:
            # attrs is neither Attributes nor Mapping, return True (include entry)
            return True

        # Check each schema type
        is_attr, include_attr = cls._check_schema_oid(
            attrs_dict,
            ("attributeTypes", "attributetypes"),
            allowed_attr,
        )
        is_oc, include_oc = cls._check_schema_oid(
            attrs_dict,
            ("objectClasses", "objectclasses"),
            allowed_oc,
        )
        is_mr, include_mr = cls._check_schema_oid(
            attrs_dict,
            ("matchingRules", "matchingrules"),
            allowed_mr,
        )
        is_mru, include_mru = cls._check_schema_oid(
            attrs_dict,
            ("matchingRuleUse", "matchingruleuse"),
            allowed_mru,
        )

        is_schema_entry = is_attr or is_oc or is_mr or is_mru
        should_include = include_attr and include_oc and include_mr and include_mru

        return not is_schema_entry or should_include

    @classmethod
    def filter_schema_by_oids(
        cls,
        entries: list[m.Ldif.Entry],
        allowed_oids: Mapping[str, frozenset[str]],
    ) -> r[list[m.Ldif.Entry]]:
        """Filter schema entries by allowed OIDs.

        Filters schema entries based on OID whitelists for:
        - attributeTypes (allowed_attribute_oids)
        - objectClasses (allowed_objectclass_oids)
        - matchingRules (allowed_matchingrule_oids)
        - matchingRuleUse (allowed_matchingruleuse_oids)

        Args:
            entries: List of schema entries to filter
            allowed_oids: Mapping of OID category to frozenset of allowed OIDs:
                - allowed_attribute_oids: frozenset of allowed attribute OIDs
                - allowed_objectclass_oids: frozenset of allowed objectclass OIDs
                - allowed_matchingrule_oids: frozenset of allowed matching rule OIDs
                - allowed_matchingruleuse_oids: frozenset of allowed matching rule use OIDs

        Returns:
            FlextResult containing filtered list of entries

        """
        try:
            allowed_attr, allowed_oc, allowed_mr, allowed_mru = (
                cls._extract_allowed_oids(allowed_oids)
            )

            # If no OID filters specified, return all entries
            if not any([allowed_attr, allowed_oc, allowed_mr, allowed_mru]):
                return r[list[m.Ldif.Entry]].ok(entries)

            filtered: list[m.Ldif.Entry] = [
                entry
                for entry in entries
                if cls._should_include_entry(
                    entry,
                    allowed_attr,
                    allowed_oc,
                    allowed_mr,
                    allowed_mru,
                )
            ]

            logger.debug(
                "Filtered schema entries by OIDs",
                total_entries=len(entries),
                filtered_count=len(filtered),
            )

            return r[list[m.Ldif.Entry]].ok(filtered)

        except Exception as e:
            logger.exception("Failed to filter schema entries by OIDs")
            return r[list[m.Ldif.Entry]].fail(f"Schema OID filter failed: {e}")

    @classmethod
    def _extract_oid_from_schema_attr(
        cls,
        values: list[str],
    ) -> str | None:
        """Extract OID from schema attribute value.

        Schema attributes like attributeTypes contain definitions with OIDs.
        Format: ( OID NAME ... )

        Args:
            values: List of schema attribute values

        Returns:
            Extracted OID string or None if not found

        """
        if not values:
            return None

        # Get first value (schema definitions are usually single-valued)
        value = values[0] if values else ""

        # OID is typically the first token after opening parenthesis
        # Format: ( 1.2.3.4 NAME 'foo' ... )
        value = value.strip()
        if value.startswith("("):
            # Remove opening parenthesis and split
            parts = value[1:].strip().split()
            if parts:
                # First part should be the OID
                oid = parts[0]
                # Validate it looks like an OID (starts with digit)
                if oid and oid[0].isdigit():
                    return oid

        return None


__all__ = ["FlextLdifFilters"]
