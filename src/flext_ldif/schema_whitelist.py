"""Schema whitelisting and transformation service.

Provides enterprise-grade schema filtering for LDIF migration operations.
Applies OID-based whitelist rules and server-specific transformations using
the quirks system.

Architecture:
- Phase 1 of MIGRATION_ENHANCEMENT_PLAN.md
- Uses Railway-Oriented Programming (FlextCore.Result)
- Integrates with quirks system for transformations
- Follows FLEXT domain separation pattern

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_core import FlextCore

from flext_ldif.quirks.manager import FlextLdifQuirksManager


class FlextLdifSchemaWhitelistService(FlextCore.Service[FlextCore.Types.Dict]):
    """Whitelist and transform schema definitions.

    Features:
    - Parse RFC 4512 schema LDIF files
    - Apply whitelist rules (OID patterns, blocked names)
    - Transform using server-specific quirks
    - Generate whitelisted schema output

    Architecture:
    - Uses FlextLdifQuirksManager for transformations
    - Returns dictionary with statistics and schema entries
    - Follows Railway-Oriented Programming pattern
    """

    @override
    def __init__(
        self,
        schema_file: Path,
        whitelist_rules: FlextCore.Types.Dict,
        source_server: str = "oracle_oid",
        target_server: str = "oracle_oud",
        quirks_manager: FlextLdifQuirksManager | None = None,
    ) -> None:
        """Initialize schema whitelist service.

        Args:
            schema_file: Path to schema LDIF file
            whitelist_rules: Whitelist configuration dictionary
            source_server: Source LDAP server type
            target_server: Target LDAP server type
            quirks_manager: Optional quirks manager instance

        """
        super().__init__()
        self._schema_file = Path(schema_file)
        self._whitelist_rules = whitelist_rules
        self._source_server = source_server
        self._target_server = target_server
        self._quirks = quirks_manager or FlextLdifQuirksManager(
            server_type=source_server
        )

    @override
    def execute(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Execute schema whitelisting and transformation.

        Returns:
            FlextCore.Result containing schema whitelist result dictionary

        """
        # Step 1: Parse schema file
        parse_result = self._parse_schema_file()
        if parse_result.is_failure:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to parse schema: {parse_result.error}"
            )

        schema_entries = parse_result.unwrap()

        # Step 2: Apply whitelist rules
        whitelist_result = self._apply_whitelist(schema_entries)
        if whitelist_result.is_failure:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to apply whitelist: {whitelist_result.error}"
            )

        whitelisted = whitelist_result.unwrap()

        # Step 3: Transform to target server format
        transform_result = self._transform_to_target(whitelisted)
        if transform_result.is_failure:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to transform: {transform_result.error}"
            )

        transformed = transform_result.unwrap()

        # Step 4: Build result statistics
        result_dict: FlextCore.Types.Dict = {
            "total_input": len(schema_entries),
            "total_output": len(transformed),
            "blocked_count": len(schema_entries) - len(transformed),
            "source_server": self._source_server,
            "target_server": self._target_server,
            "schema_entries": transformed,
        }

        return FlextCore.Result[FlextCore.Types.Dict].ok(result_dict)

    def _parse_schema_file(
        self,
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Parse schema LDIF file.

        Returns:
            FlextCore.Result containing list of schema entries

        """
        # Verify file exists
        if not self._schema_file.exists():
            return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                f"Schema file not found: {self._schema_file}"
            )

        try:
            with self._schema_file.open("r", encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                f"Failed to read schema file: {e}"
            )

        # Parse schema entries
        schema_entries: list[FlextCore.Types.Dict] = []

        # Parse attributeTypes
        schema_entries.extend(self._parse_attribute_types(content))

        # Parse objectClasses
        schema_entries.extend(self._parse_object_classes(content))

        return FlextCore.Result[list[FlextCore.Types.Dict]].ok(schema_entries)

    def _parse_attribute_types(self, content: str) -> list[FlextCore.Types.Dict]:
        """Parse attributeTypes from schema content.

        Args:
            content: Schema LDIF content

        Returns:
            List of parsed attributeType entries

        """
        entries: list[FlextCore.Types.Dict] = []

        # Find all attributeTypes lines
        for line in content.split("\n"):
            if line.strip().startswith("attributeTypes:"):
                # Extract the definition between parentheses
                start_idx = line.find("(")
                end_idx = line.rfind(")")

                if start_idx != -1 and end_idx != -1:
                    definition = line[start_idx + 1 : end_idx].strip()

                    # Parse OID (first token)
                    tokens = definition.split()
                    if tokens:
                        oid = tokens[0]

                        # Parse NAME
                        name = self._extract_name(definition)

                        entry: FlextCore.Types.Dict = {
                            "type": "attributeType",
                            "oid": oid,
                            "name": name,
                            "definition": definition,
                        }
                        entries.append(entry)

        return entries

    def _parse_object_classes(self, content: str) -> list[FlextCore.Types.Dict]:
        """Parse objectClasses from schema content.

        Args:
            content: Schema LDIF content

        Returns:
            List of parsed objectClass entries

        """
        entries: list[FlextCore.Types.Dict] = []

        # Find all objectClasses lines
        for line in content.split("\n"):
            if line.strip().startswith("objectClasses:"):
                # Extract the definition between parentheses
                start_idx = line.find("(")
                end_idx = line.rfind(")")

                if start_idx != -1 and end_idx != -1:
                    definition = line[start_idx + 1 : end_idx].strip()

                    # Parse OID (first token)
                    tokens = definition.split()
                    if tokens:
                        oid = tokens[0]

                        # Parse NAME
                        name = self._extract_name(definition)

                        entry: FlextCore.Types.Dict = {
                            "type": "objectClass",
                            "oid": oid,
                            "name": name,
                            "definition": definition,
                        }
                        entries.append(entry)

        return entries

    def _extract_name(self, definition: str) -> str:
        """Extract NAME from schema definition.

        Args:
            definition: Schema definition string

        Returns:
            Extracted name or empty string

        """
        # Find NAME keyword
        name_idx = definition.find("NAME")
        if name_idx == -1:
            return ""

        # Find the quoted name after NAME keyword
        start_quote = definition.find("'", name_idx)
        if start_quote == -1:
            return ""

        end_quote = definition.find("'", start_quote + 1)
        if end_quote == -1:
            return ""

        return definition[start_quote + 1 : end_quote]

    def _apply_whitelist(
        self, schema_entries: list[FlextCore.Types.Dict]
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Apply whitelist rules to schema entries.

        Args:
            schema_entries: Parsed schema entries

        Returns:
            FlextCore.Result containing whitelisted entries

        """
        # Use list comprehension for performance (PERF401)
        whitelisted = [
            entry for entry in schema_entries if self._passes_whitelist(entry)
        ]

        return FlextCore.Result[list[FlextCore.Types.Dict]].ok(whitelisted)

    def _passes_whitelist(self, entry: FlextCore.Types.Dict) -> bool:
        """Check if schema entry passes whitelist rules.

        Args:
            entry: Schema entry to check

        Returns:
            True if entry passes whitelist, False otherwise

        """
        # Extract entry type and identifier with type narrowing
        entry_type_raw = entry.get("type", "")
        entry_name_raw = entry.get("name", "")
        entry_oid_raw = entry.get("oid", "")

        # Type narrowing for string values
        entry_type = str(entry_type_raw) if entry_type_raw else ""
        entry_name = str(entry_name_raw) if entry_name_raw else ""
        entry_oid = str(entry_oid_raw) if entry_oid_raw else ""

        # Determine which whitelist rules to use
        if entry_type == "attributeType":
            allowed_oids_raw = self._whitelist_rules.get("allowed_attribute_oids", [])
            blocked_names_raw = self._whitelist_rules.get("blocked_attributes", [])
        elif entry_type == "objectClass":
            allowed_oids_raw = self._whitelist_rules.get("allowed_objectclass_oids", [])
            blocked_names_raw = self._whitelist_rules.get("blocked_objectclasses", [])
        else:
            # Unknown entry type - allow by default
            return True

        # Type narrowing for list values
        allowed_oids: list[str] = (
            list(allowed_oids_raw) if isinstance(allowed_oids_raw, list) else []
        )
        blocked_names: list[str] = (
            list(blocked_names_raw) if isinstance(blocked_names_raw, list) else []
        )

        # Check blocked names first (explicit deny)
        if entry_name and entry_name in blocked_names:
            return False

        # Check OID patterns (wildcard support)
        if entry_oid and allowed_oids:
            return self._matches_oid_pattern(entry_oid, allowed_oids)

        # If no OID and no blocking, allow by default
        return True

    def _matches_oid_pattern(self, oid: str, patterns: list[str]) -> bool:
        """Check if OID matches any allowed pattern.

        Args:
            oid: OID to check (e.g., "2.5.4.3")
            patterns: List of OID patterns (e.g., ["2.5.4.*", "2.5.18.*"])

        Returns:
            True if OID matches any pattern, False otherwise

        """
        for pattern in patterns:
            if pattern.endswith(".*"):
                # Wildcard pattern - check prefix match
                prefix = pattern[:-2]  # Remove ".*"
                if oid.startswith(prefix):
                    return True
            elif pattern == oid:
                # Exact match
                return True

        return False

    def _transform_to_target(
        self, entries: list[FlextCore.Types.Dict]
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Transform entries to target server format using quirks.

        Args:
            entries: Whitelisted schema entries

        Returns:
            FlextCore.Result containing transformed entries

        """
        # Get target server quirks for context
        quirks_result = self._quirks.get_server_quirks(self._target_server)
        if quirks_result.is_failure:
            return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                f"Failed to get target server quirks: {quirks_result.error}"
            )

        target_quirks = quirks_result.unwrap()

        # Extract target server schema configuration from quirks
        schema_subentry = target_quirks.get("schema_subentry", "cn=schema")
        supports_operational = target_quirks.get("supports_operational_attrs", True)

        # Apply transformations to each entry
        transformed: list[FlextCore.Types.Dict] = []

        for entry in entries:
            # Basic transformation: preserve entry structure
            transformed_entry = entry.copy()

            # Apply server-specific transformations based on quirks
            # Phase 1: Schema attribute and objectClass name adjustments
            entry_type = entry.get("type", "")

            if entry_type == "attributeType":
                # OID → OUD: No schema syntax changes needed (both RFC compliant)
                # Future: Apply server-specific attribute name mappings
                pass

            elif entry_type == "objectClass":
                # OID → OUD: No objectClass name changes needed
                # Future: Apply server-specific objectClass mappings
                pass

            # Add server context metadata (using quirks)
            transformed_entry["source_server"] = self._source_server
            transformed_entry["target_server"] = self._target_server
            transformed_entry["schema_subentry"] = schema_subentry
            transformed_entry["supports_operational_attrs"] = supports_operational
            transformed_entry["transformed"] = True

            transformed.append(transformed_entry)

        # Phase 1 Complete: Basic quirks integration with metadata
        # Phase 2 TODO(FLEXT Team): Advanced transformations
        #   - Schema syntax conversions (X-ORIGIN, X-SCHEMA-FILE)
        #   - Attribute name remapping (orclaci → ds-privilege-name)
        #   - ObjectClass hierarchy adjustments

        return FlextCore.Result[list[FlextCore.Types.Dict]].ok(transformed)


__all__ = ["FlextLdifSchemaWhitelistService"]
