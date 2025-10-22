"""File writing service for LDIF categorized migration pipeline.

Handles all file I/O operations including:
- Writing category files with RFC-compliant formatting
- Schema entry processing and transformation
- Target-compatible schema entry creation

Uses FlextLdifRfcLdifWriter with quirks registry for proper server-specific
transformations during writing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter

if TYPE_CHECKING:
    from flext_ldif.quirks.base import (
        FlextLdifQuirksBaseSchemaQuirk,
    )


class FlextLdifFileWriterService:
    """File writing service for LDIF pipeline.

    Handles all file I/O operations with RFC-compliant formatting and
    server-specific quirks transformation.

    """

    def __init__(
        self,
        output_dir: Path,
        output_files: dict[
            str, object
        ],  # category -> filename mapping (flexible type for compatibility)
        target_server: str,
        target_schema_quirk: FlextLdifQuirksBaseSchemaQuirk | None,
        source_schema_quirk: FlextLdifQuirksBaseSchemaQuirk | None,
        schema_whitelist_rules: dict[str, object] | None = None,
    ) -> None:
        """Initialize file writer service.

        Args:
            output_dir: Output directory for LDIF files
            output_files: Mapping of category to output filename
            target_server: Target server type
            target_schema_quirk: Target schema quirk instance
            source_schema_quirk: Source schema quirk instance
            schema_whitelist_rules: Optional whitelist rules for schema

        """
        self._output_dir = output_dir
        self._output_files = output_files
        self._target_server = target_server
        self._target_schema_quirk = target_schema_quirk
        self._source_schema_quirk = source_schema_quirk
        self._schema_whitelist_rules = schema_whitelist_rules or {}

    def write_categorized_output(
        self, categorized: dict[str, list[dict[str, object]]]
    ) -> FlextResult[dict[str, int]]:
        """Write categorized entries to structured LDIF files.

        Args:
            categorized: Dictionary mapping category to entry list

        Returns:
            FlextResult containing dict[str, object] of category to count written

        """
        written_counts: dict[str, int] = {}

        # Write each category to its LDIF file
        for category, entries in categorized.items():
            filename_obj = self._output_files.get(category, f"{category}.ldif")
            category_filename = (
                filename_obj if isinstance(filename_obj, str) else f"{category}.ldif"
            )

            write_result = self.write_category_file(
                category, entries, category_filename
            )

            if write_result.is_failure:
                return FlextResult[dict[str, int]].fail(
                    f"Failed to write {category}: {write_result.error}"
                )

            written_counts[category] = write_result.unwrap()

        return FlextResult[dict[str, int]].ok(written_counts)

    def write_category_file(
        self,
        category: str,
        entries: list[dict[str, object]],
        category_filename: str,
    ) -> FlextResult[int]:
        """Write entries for single category to LDIF file with RFC writer and quirks.

        CRITICAL: Uses FlextLdifRfcLdifWriter with quirks registry to ensure
        proper server-specific transformations are applied during writing.

        Args:
            category: Category name (schema, hierarchy, users, groups, acl, rejected)
            entries: List of entries to write
            category_filename: LDIF filename (e.g., "00-schema.ldif")

        Returns:
            FlextResult containing count of entries written

        """
        if not entries:
            return FlextResult[int].ok(0)

        try:
            # Special handling for schema category
            if category == "schema" and self._schema_whitelist_rules:
                # Apply whitelist filtering and sorting to schema entries
                processed_entries = self.process_schema_entries(entries)
                if processed_entries:
                    # Create target-compatible schema entry format
                    entries = self.create_target_schema_entry(processed_entries)
                else:
                    entries = []
            else:
                # Apply hierarchy + name sorting for all non-schema categories
                entries = self._sort_entries_by_hierarchy_and_name(entries)

            # Write directly to output directory
            output_file = self._output_dir / category_filename

            # Get quirk registry for proper RFC writing with quirks
            quirk_registry = FlextLdifQuirksRegistry()

            # Register injected target schema quirk
            if self._target_schema_quirk:
                quirk_registry.register_schema_quirk(self._target_schema_quirk)

                # Register ACL and Entry quirks if available
                # Note: Server-specific quirk subclasses may define nested AclQuirk and EntryQuirk classes
                target_quirk_obj = self._target_schema_quirk

                # Register ACL quirk if defined in server-specific implementation
                if hasattr(target_quirk_obj, "AclQuirk") and callable(
                    getattr(target_quirk_obj, "AclQuirk", None)
                ):
                    acl_quirk_class = getattr(target_quirk_obj, "AclQuirk")
                    acl_instance = acl_quirk_class(server_type=self._target_server)
                    quirk_registry.register_acl_quirk(acl_instance)

                # Register Entry quirk if defined in server-specific implementation
                if hasattr(target_quirk_obj, "EntryQuirk") and callable(
                    getattr(target_quirk_obj, "EntryQuirk", None)
                ):
                    entry_quirk_class = getattr(target_quirk_obj, "EntryQuirk")
                    entry_instance = entry_quirk_class(server_type=self._target_server)
                    quirk_registry.register_entry_quirk(entry_instance)

            # Prepare writer parameters
            writer_params: dict[str, object] = {
                FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
                FlextLdifConstants.DictKeys.ENTRIES: entries,
                "encoding": "utf-8",
            }

            # Use RFC writer with quirks
            writer = FlextLdifRfcLdifWriter(
                params=writer_params,
                quirk_registry=quirk_registry,
                target_server_type=self._target_server,
            )

            # Execute RFC-compliant writing
            write_result = writer.execute()

            if write_result.is_failure:
                return FlextResult[int].fail(
                    f"Failed to write {category} file: {write_result.error}"
                )

            return FlextResult[int].ok(len(entries))

        except (OSError, UnicodeEncodeError) as e:
            return FlextResult[int].fail(f"Failed to write {category} file: {e}")

    def process_schema_entries(
        self, entries: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        """Process schema entries: apply whitelist filtering and sort by OID.

        RFC-COMPLIANT: Works with RFC 4512 schema format (attributetypes/objectclasses).
        Applies OID pattern matching from whitelist rules.

        Args:
            entries: List of RFC format schema entries

        Returns:
            Filtered and sorted schema entries

        """
        if not entries or not self._schema_whitelist_rules:
            return entries

        # Get whitelist rules for OID patterns
        allowed_attr_oids = self._schema_whitelist_rules.get(
            "allowed_attribute_oids", []
        )
        allowed_obj_oids = self._schema_whitelist_rules.get(
            "allowed_objectclass_oids", []
        )

        if not isinstance(allowed_attr_oids, list):
            allowed_attr_oids = []
        if not isinstance(allowed_obj_oids, list):
            allowed_obj_oids = []

        processed_entries = []

        for entry in entries:
            attributes = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attributes, dict):
                processed_entries.append(entry)
                continue

            # Get attributetypes and objectclasses
            attr_types = attributes.get("attributetypes", [])
            obj_classes = attributes.get("objectclasses", [])

            if not isinstance(attr_types, list):
                attr_types = [attr_types] if attr_types else []
            if not isinstance(obj_classes, list):
                obj_classes = [obj_classes] if obj_classes else []

            def extract_oid(schema_line: str) -> str:
                """Extract OID from RFC 4512 schema definition."""
                match = re.match(r"\(\s*([0-9.]+)", str(schema_line))
                return match.group(1) if match else ""

            def matches_pattern(oid: str, patterns: list[str]) -> bool:
                """Check if OID matches any whitelist pattern."""
                if not patterns:
                    return True

                for pattern in patterns:
                    pattern_str = str(pattern).replace("*", ".*")
                    if re.match(f"^{pattern_str}$", oid):
                        return True
                return False

            # Filter and sort attributetypes
            filtered_attr_types = [
                line
                for line in attr_types
                if matches_pattern(extract_oid(line), allowed_attr_oids)
            ]
            sorted_attr_types = sorted(filtered_attr_types, key=extract_oid)

            # Filter and sort objectclasses
            filtered_obj_classes = [
                line
                for line in obj_classes
                if matches_pattern(extract_oid(line), allowed_obj_oids)
            ]
            sorted_obj_classes = sorted(filtered_obj_classes, key=extract_oid)

            # Rebuild entry with filtered and sorted schema
            new_attributes = {}
            if sorted_attr_types:
                new_attributes["attributetypes"] = sorted_attr_types
            if sorted_obj_classes:
                new_attributes["objectclasses"] = sorted_obj_classes

            # Keep other attributes unchanged
            new_attributes.update({
                key: value
                for key, value in attributes.items()
                if key not in {"attributetypes", "objectclasses"}
            })

            processed_entry = entry.copy()
            processed_entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = new_attributes
            processed_entries.append(processed_entry)

        return processed_entries

    def create_target_schema_entry(
        self, processed_entries: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        """Create schema entry from processed schema entries.

        Target server requires schema modifications in LDIF modify format:
        - dn: cn=schema
        - changetype: modify
        - add: attributetypes / add: objectclasses directives

        Args:
            processed_entries: List of processed schema entries

        Returns:
            List containing single target-compatible schema entry

        """
        if not processed_entries:
            return []

        # Collect all attributetypes and objectclasses
        all_attributetypes: list[str] = []
        all_objectclasses: list[str] = []

        for entry in processed_entries:
            # Check both nested "attributes" key and flat top-level attributes
            attributes = entry.get("attributes", entry)
            if not isinstance(attributes, dict):
                continue

            # Get attributetypes and filter using target quirk
            attr_types = attributes.get("attributetypes", [])
            if isinstance(attr_types, list):
                for attr_type in attr_types:
                    # Filter OUT Oracle internal attributes using target schema quirk
                    # E.g., OUD quirk filters changenumber, targetdn, etc.
                    if self._target_schema_quirk and hasattr(
                        self._target_schema_quirk, "should_filter_out_attribute"
                    ):
                        # Only include if NOT filtered out
                        if not self._target_schema_quirk.should_filter_out_attribute(str(attr_type)):
                            all_attributetypes.append(attr_type)
                    else:
                        # No filtering if quirk doesn't support it - include all
                        all_attributetypes.append(attr_type)
            elif attr_types:
                # Single attribute - check if it should be filtered
                if self._target_schema_quirk and hasattr(
                    self._target_schema_quirk, "should_filter_out_attribute"
                ):
                    # Only include if NOT filtered out
                    if not self._target_schema_quirk.should_filter_out_attribute(str(attr_types)):
                        all_attributetypes.append(str(attr_types))
                else:
                    all_attributetypes.append(str(attr_types))

            # Get objectclasses and filter using target quirk
            obj_classes = attributes.get("objectclasses", [])
            if isinstance(obj_classes, list):
                for obj_class in obj_classes:
                    # Filter OUT Oracle internal objectClasses using target schema quirk
                    # E.g., OUD quirk filters changeLogEntry, orclchangesubscriber, etc.
                    if self._target_schema_quirk and hasattr(
                        self._target_schema_quirk, "should_filter_out_objectclass"
                    ):
                        # Only include if NOT filtered out
                        if not self._target_schema_quirk.should_filter_out_objectclass(str(obj_class)):
                            all_objectclasses.append(obj_class)
                    else:
                        # No filtering if quirk doesn't support it - include all
                        all_objectclasses.append(obj_class)
            elif obj_classes:
                # Single objectClass - check if it should be filtered
                if self._target_schema_quirk and hasattr(
                    self._target_schema_quirk, "should_filter_out_objectclass"
                ):
                    # Only include if NOT filtered out
                    if not self._target_schema_quirk.should_filter_out_objectclass(str(obj_classes)):
                        all_objectclasses.append(str(obj_classes))
                else:
                    all_objectclasses.append(str(obj_classes))

        # Transform schema definitions via RFC canonical format
        transformed_attributetypes = self._transform_schema_via_rfc(
            all_attributetypes, "attribute"
        )
        transformed_objectclasses = self._transform_schema_via_rfc(
            all_objectclasses, "objectclass"
        )

        # Remove duplicates while preserving order
        seen_attributetypes = set()
        unique_attributetypes = []
        for attr_type in transformed_attributetypes:
            if attr_type not in seen_attributetypes:
                unique_attributetypes.append(attr_type)
                seen_attributetypes.add(attr_type)

        seen_objectclasses = set()
        unique_objectclasses = []
        for obj_class in transformed_objectclasses:
            if obj_class not in seen_objectclasses:
                unique_objectclasses.append(obj_class)
                seen_objectclasses.add(obj_class)

        # Sort by OID
        def extract_oid(schema_line: str) -> str:
            """Extract OID from RFC 4512 schema definition."""
            match = re.match(r"\(\s*([0-9.]+)", str(schema_line))
            return match.group(1) if match else ""

        sorted_attributetypes = sorted(unique_attributetypes, key=extract_oid)
        sorted_objectclasses = sorted(unique_objectclasses, key=extract_oid)

        # Create OUD schema entry with MODIFY changetype
        schema_entry: dict[str, object] = {
            "dn": "cn=schema",
            "changetype": ["modify"],
        }

        if sorted_attributetypes:
            schema_entry["_modify_add_attributetypes"] = sorted_attributetypes

        if sorted_objectclasses:
            schema_entry["_modify_add_objectclasses"] = sorted_objectclasses

        return [schema_entry]

    def _transform_schema_via_rfc(
        self, schema_list: list[str], schema_type: str
    ) -> list[str]:
        """Transform schema definitions via RFC canonical format.

        Implements SOURCE quirk → RFC canonical → TARGET quirk transformation.

        Args:
            schema_list: List of schema definition strings (in source format)
            schema_type: Either "attribute" or "objectclass"

        Returns:
            List of transformed schema definition strings (in target format)

        """
        if not self._source_schema_quirk or not self._target_schema_quirk:
            return list(schema_list)

        source_quirk = self._source_schema_quirk
        target_quirk = self._target_schema_quirk

        transformed = []

        for schema_str in schema_list:
            try:
                # Step 1: Parse with SOURCE quirk
                if schema_type == "attribute":
                    parse_result = source_quirk.parse_attribute(str(schema_str))
                else:
                    parse_result = source_quirk.parse_objectclass(str(schema_str))

                if parse_result.is_failure:
                    transformed.append(str(schema_str))
                    continue

                schema_data = parse_result.unwrap()

                # Step 2: Convert to RFC canonical format
                if schema_type == "attribute":
                    to_rfc_result = source_quirk.convert_attribute_to_rfc(schema_data)
                else:
                    to_rfc_result = source_quirk.convert_objectclass_to_rfc(schema_data)

                if to_rfc_result.is_failure:
                    transformed.append(str(schema_str))
                    continue

                rfc_data = to_rfc_result.unwrap()

                # Step 3: Add X-ORIGIN if not present
                if "x_origin" not in rfc_data:
                    rfc_data["x_origin"] = "user defined"

                # Step 4: Convert from RFC to TARGET format
                if schema_type == "attribute":
                    from_rfc_result = target_quirk.convert_attribute_from_rfc(rfc_data)
                else:
                    from_rfc_result = target_quirk.convert_objectclass_from_rfc(
                        rfc_data
                    )

                if from_rfc_result.is_failure:
                    transformed.append(str(schema_str))
                    continue

                target_data = from_rfc_result.unwrap()

                # Step 5: Format to LDIF string
                if schema_type == "attribute":
                    format_result = target_quirk.write_attribute_to_rfc(target_data)
                else:
                    format_result = target_quirk.write_objectclass_to_rfc(target_data)

                if format_result.is_success:
                    transformed.append(format_result.unwrap())
                else:
                    transformed.append(str(schema_str))

            except Exception:
                transformed.append(str(schema_str))

        return transformed

    def _sort_entries_by_hierarchy_and_name(
        self, entries: list[dict[str, object]]
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
            # Use simple string operations since this is just for sorting display
            # The actual DN parsing happens elsewhere in the pipeline
            depth = dn.count(",") + (1 if dn else 0)
            return (depth, dn.lower())

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


__all__ = ["FlextLdifFileWriterService"]
