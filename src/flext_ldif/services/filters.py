"""Filters service - LDIF Entry Filtering Operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from flext_core import FlextLogger, r

from flext_ldif.models import m

logger: Final = FlextLogger(__name__)


class FlextLdifFilters:
    """LDIF entry filtering service."""

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
        """Check if schema OID matches allowed set."""
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

        if hasattr(attrs, "attributes"):
            attrs_dict: Mapping[str, list[str]] = attrs.attributes
        else:
            return True

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
        """Filter schema entries by allowed OIDs."""
        try:
            allowed_attr, allowed_oc, allowed_mr, allowed_mru = (
                cls._extract_allowed_oids(allowed_oids)
            )

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
        """Extract OID from schema attribute value."""
        if not values:
            return None

        value = values[0] if values else ""

        value = value.strip()
        if value.startswith("("):
            parts = value[1:].strip().split()
            if parts:
                oid = parts[0]

                if oid and oid[0].isdigit():
                    return oid

        return None


__all__ = ["FlextLdifFilters"]
