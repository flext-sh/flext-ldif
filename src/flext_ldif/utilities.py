"""Utility classes for LDIF processing pipeline.

Provides normalized, reusable utility components:
 - Normalizer: DN and attribute normalization
 - Sorter: Entry sorting and ordering
 - Statistics: Pipeline statistics generation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services import FlextLdifDnService


class FlextLdifUtilities:
    """Unified utilities for LDIF processing pipeline.

    Provides three main utility components:
    - Normalizer: DN and attribute normalization
    - Sorter: Entry sorting and ordering
    - Statistics: Pipeline statistics generation

    """

    class Normalizer:
        """DN and attribute normalization utilities.

        Provides methods for normalizing DN values and DN-valued attributes
        in LDIF entries according to canonical DN mappings.

        """

        @staticmethod
        def build_canonical_dn_map(
            categorized: dict[str, list[dict[str, object]]],
        ) -> dict[str, str]:
            """Build mapping of lowercase(cleaned DN) -> canonical cleaned DN.

            Uses FlextLdifDnService.clean_dn to normalize formatting and ensures
            case-consistent canonical values based on parsed entries.

            Args:
                categorized: Dictionary mapping category to entry list

            Returns:
                Dictionary mapping lowercase cleaned DN to canonical cleaned DN

            """
            dn_map: dict[str, str] = {}
            for entries in categorized.values():
                for entry in entries:
                    if isinstance(entry, dict):
                        dn_value = entry.get(FlextLdifConstants.DictKeys.DN)
                        if isinstance(dn_value, str) and dn_value:
                            cleaned = FlextLdifDnService.clean_dn(dn_value)
                            if cleaned:
                                dn_map[cleaned.lower()] = cleaned
            return dn_map

        @staticmethod
        def normalize_dn_value(value: str, dn_map: dict[str, str]) -> str:
            """Normalize a single DN value using canonical map, fallback to cleaned DN.

            Args:
                value: DN value to normalize
                dn_map: Canonical DN mapping

            Returns:
                Normalized DN value

            """
            cleaned = FlextLdifDnService.clean_dn(value)
            return dn_map.get(cleaned.lower(), cleaned)

        @staticmethod
        def normalize_dn_references_for_entry(
            entry: dict[str, object],
            dn_map: dict[str, str],
            ref_attrs_lower: set[str],
        ) -> dict[str, object]:
            """Normalize DN-valued attributes in an entry according to dn_map.

            Handles both str and list[str] attribute values.

            Args:
                entry: Entry to normalize
                dn_map: Canonical DN mapping
                ref_attrs_lower: Set of lowercase DN reference attribute names

            Returns:
                Entry with normalized DN attributes

            """
            normalized = entry.copy()
            attrs = normalized.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attrs, dict):
                return normalized

            new_attrs: dict[str, object] = {}
            for attr_name, attr_value in attrs.items():
                if attr_name.lower() in ref_attrs_lower:
                    if isinstance(attr_value, list):
                        new_attrs[attr_name] = [
                            FlextLdifUtilities.Normalizer.normalize_dn_value(v, dn_map)
                            if isinstance(v, str)
                            else v
                            for v in attr_value
                        ]
                    elif isinstance(attr_value, str):
                        new_attrs[attr_name] = (
                            FlextLdifUtilities.Normalizer.normalize_dn_value(
                                attr_value, dn_map
                            )
                        )
                    else:
                        new_attrs[attr_name] = attr_value
                else:
                    new_attrs[attr_name] = attr_value

            normalized[FlextLdifConstants.DictKeys.ATTRIBUTES] = new_attrs
            return normalized

        @staticmethod
        def normalize_aci_dn_references(
            entry: dict[str, object], dn_map: dict[str, str]
        ) -> dict[str, object]:
            """Normalize DNs embedded in ACI attribute strings using dn_map.

            Attempts to detect DN substrings in common OUD ACI patterns and
            replace them with canonical DNs.

            Args:
                entry: Entry with ACI attributes to normalize
                dn_map: Canonical DN mapping

            Returns:
                Entry with normalized ACI DN references

            """
            try:
                attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                if not isinstance(attrs, dict):
                    return entry

                def normalize_in_text(text: str) -> str:
                    """Normalize DNs in ACI text."""

                    def repl_ldap(m: re.Match[str]) -> str:
                        dn_part = m.group(1)
                        norm = FlextLdifUtilities.Normalizer.normalize_dn_value(
                            dn_part, dn_map
                        )
                        return f"ldap:///{norm}"

                    text2 = re.sub(r"ldap:///([^\"]+?)", repl_ldap, text)

                    # Also handle bare quoted DN-like sequences (best-effort)
                    def repl_quoted(m: re.Match[str]) -> str:
                        dn_part = m.group(1)
                        norm = FlextLdifUtilities.Normalizer.normalize_dn_value(
                            dn_part, dn_map
                        )
                        return f'"{norm}"'

                    return re.sub(
                        r'"((?:[a-zA-Z]+=[^,\";\)]+)(?:,[a-zA-Z]+=[^,\";\)]+)*)"',
                        repl_quoted,
                        text2,
                    )

                aci_value = attrs.get("aci")
                if isinstance(aci_value, list):
                    attrs["aci"] = [
                        normalize_in_text(v) if isinstance(v, str) else v
                        for v in aci_value
                    ]
                elif isinstance(aci_value, str):
                    attrs["aci"] = normalize_in_text(aci_value)

                entry_out = entry.copy()
                entry_out[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs
                return entry_out
            except Exception:
                return entry

    class Sorter:
        """Entry sorting and ordering utilities.

        Provides sorting methods for LDIF entries with hierarchy-aware ordering.

        """

        @staticmethod
        def sort_entries_by_hierarchy_and_name(
            entries: list[dict[str, object]],
        ) -> list[dict[str, object]]:
            """Sort entries by DN hierarchy depth, then case-insensitive DN.

            Ordering rules:
            - First key: DN depth (fewer RDN components first)
            - Second key: Case-insensitive DN string for stable ordering

            This ensures deterministic ordering across all categories.

            Args:
                entries: List of entries to sort

            Returns:
                Sorted entries by hierarchy and name

            """

            def sort_key(entry: dict[str, object]) -> tuple[int, str]:
                dn_value = entry.get(FlextLdifConstants.DictKeys.DN, "")
                dn = dn_value if isinstance(dn_value, str) else ""
                dn_clean = FlextLdifDnService.clean_dn(dn)
                depth = dn_clean.count(",") + (1 if dn_clean else 0)
                return (depth, dn_clean.lower())

            # Filter only entries with a DN string to avoid exceptions during sort
            sortable = [
                e
                for e in entries
                if isinstance(e.get(FlextLdifConstants.DictKeys.DN, ""), str)
            ]
            nonsortable = [
                e
                for e in entries
                if not isinstance(e.get(FlextLdifConstants.DictKeys.DN, ""), str)
            ]

            # Sort sortable entries and keep any non-sortable at the end in original order
            return sorted(sortable, key=sort_key) + nonsortable

    class Statistics:
        """Pipeline statistics generation utilities.

        Provides methods for generating comprehensive statistics about
        categorized and migrated LDIF entries.

        """

        @staticmethod
        def generate_statistics(
            categorized: dict[str, list[dict[str, object]]],
            written_counts: dict[str, int],
            output_dir: object,  # Path object
            output_files: dict[
                str, object
            ],  # category -> filename mapping (flexible type for compatibility)
        ) -> dict[str, object]:
            """Generate complete statistics for categorized migration.

            Args:
                categorized: Dictionary mapping category to entry list
                written_counts: Dictionary mapping category to count written
                output_dir: Output directory path
                output_files: Dictionary mapping category to output filename

            Returns:
                Statistics dictionary with counts, rejection info, and metadata

            """
            # Calculate total entries
            total_entries = sum(len(entries) for entries in categorized.values())

            # Build categorized counts
            categorized_counts: dict[str, object] = {}
            for category, entries in categorized.items():
                categorized_counts[category] = len(entries)

            # Count rejections and gather reasons
            rejected_entries = categorized.get("rejected", [])
            rejection_count = len(rejected_entries)
            rejection_reasons: list[str] = []

            for entry in rejected_entries:
                attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                if isinstance(attrs, dict) and "rejectionReason" in attrs:
                    reason_value = attrs["rejectionReason"]
                    if (
                        isinstance(reason_value, str)
                        and reason_value not in rejection_reasons
                    ):
                        rejection_reasons.append(reason_value)

            # Calculate rejection rate
            rejection_rate = (
                rejection_count / total_entries if total_entries > 0 else 0.0
            )

            # Build output files info (LDIF files, not directories)
            output_files_info: dict[str, object] = {}
            for category in written_counts:
                filename_obj = output_files.get(category, f"{category}.ldif")
                category_filename = (
                    filename_obj
                    if isinstance(filename_obj, str)
                    else f"{category}.ldif"
                )
                output_path = output_dir / category_filename  # type: ignore[operator]
                output_files_info[category] = str(output_path)

            return {
                "total_entries": total_entries,
                "categorized": categorized_counts,
                "rejection_rate": rejection_rate,
                "rejection_count": rejection_count,
                "rejection_reasons": rejection_reasons,
                "written_counts": written_counts,
                "output_files": output_files_info,
            }


__all__ = ["FlextLdifUtilities"]
