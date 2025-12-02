"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from flext_core import FlextLogger, FlextRuntime
from flext_core.typings import FlextTypes

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

logger = FlextLogger(__name__)


class FlextLdifUtilitiesEntry:
    """Entry transformation utilities - pure helper functions.

    Common entry transformations extracted from server quirks.
    Servers can use these for consistent attribute handling.
    """

    # Minimum length for base64 pattern matching (use constant from FlextLdifConstants.Rfc directly in methods)
    # Note: Cannot use class attribute assignment with constants due to import order

    @staticmethod
    def _convert_single_boolean_value(
        value: str,
        source_format: str,
        target_format: str,
    ) -> str:
        """Convert a single boolean value between formats.

        Args:
            value: Boolean value to convert
            source_format: Input format ("0/1" or "TRUE/FALSE")
            target_format: Output format ("0/1" or "TRUE/FALSE")

        Returns:
            Converted boolean value or original value if no conversion needed

        """
        if source_format == "0/1" and target_format == "TRUE/FALSE":
            return "TRUE" if value == "1" else "FALSE"
        if source_format == "TRUE/FALSE" and target_format == "0/1":
            return "1" if value.upper() == "TRUE" else "0"
        return value

    @staticmethod
    def _convert_attribute_values(
        values: list[str],
        source_format: str,
        target_format: str,
    ) -> list[str]:
        """Convert all boolean values in an attribute's value list.

        Args:
            values: List of attribute values as strings (bytes already converted)
            source_format: Input format ("0/1" or "TRUE/FALSE")
            target_format: Output format ("0/1" or "TRUE/FALSE")

        Returns:
            List of converted boolean values as strings

        """
        return [
            FlextLdifUtilitiesEntry._convert_single_boolean_value(
                value,
                source_format,
                target_format,
            )
            for value in values
        ]

    @staticmethod
    def convert_boolean_attributes(
        attributes: Mapping[str, list[str] | list[bytes] | bytes | str],
        boolean_attr_names: set[str],
        *,
        source_format: str = "0/1",
        target_format: str = "TRUE/FALSE",
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Convert boolean attribute values between formats.

        Args:
            attributes: Entry attributes {attr_name: [values]} - values can be str, bytes, or list
            boolean_attr_names: Set of attribute names (lowercase) to convert
            source_format: Input format ("0/1" or "TRUE/FALSE")
            target_format: Output format ("0/1" or "TRUE/FALSE")

        Returns:
            New attributes dict with converted boolean values as strings

        """
        if not attributes or not boolean_attr_names:
            # Convert bytes to str in return value - fast-fail if attributes is empty
            if not attributes:
                return {}
            normalized_result: FlextLdifTypes.CommonDict.AttributeDict = {}
            for attr_name, values in attributes.items():
                # Normalize to list[str] - handle all input types
                if FlextRuntime.is_list_like(values):
                    normalized_result[attr_name] = [
                        v.decode("utf-8", errors="replace")
                        if isinstance(v, bytes)
                        else str(v)
                        for v in values
                    ]
                elif isinstance(values, bytes):
                    normalized_result[attr_name] = [
                        values.decode("utf-8", errors="replace"),
                    ]
                else:
                    normalized_result[attr_name] = [str(values)]
            return normalized_result

        result: FlextLdifTypes.CommonDict.AttributeDict = {}

        for attr_name, values in attributes.items():
            # Normalize values to list[str] first - convert bytes to str immediately
            str_values: list[str]
            if FlextRuntime.is_list_like(values):
                # Convert bytes to str if needed
                str_values = [
                    v.decode("utf-8", errors="replace")
                    if isinstance(v, bytes)
                    else str(v)
                    for v in values
                ]
            # Single value - convert bytes to str if needed, then wrap in list
            elif isinstance(values, bytes):
                str_values = [values.decode("utf-8", errors="replace")]
            else:
                str_values = [str(values)]

            if attr_name.lower() in boolean_attr_names:
                # Convert boolean values
                result[attr_name] = FlextLdifUtilitiesEntry._convert_attribute_values(
                    str_values,
                    source_format,
                    target_format,
                )
            else:
                # Keep non-boolean attributes as-is (already converted to str)
                result[attr_name] = str_values

        return result

    @staticmethod
    def normalize_attribute_names(
        attributes: FlextLdifTypes.CommonDict.AttributeDict,
        case_map: dict[str, str],
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Normalize attribute names using case mapping.

        Args:
            attributes: Entry attributes dict
            case_map: Dict mapping lowercase names → proper case

        Returns:
            New attributes dict with normalized attribute names

        """
        if not attributes or not case_map:
            return attributes

        result: FlextLdifTypes.CommonDict.AttributeDict = {}

        for attr_name, values in attributes.items():
            # Check if this attribute needs case normalization
            normalized_name = case_map.get(attr_name.lower(), attr_name)
            result[normalized_name] = values

        return result

    @staticmethod
    def is_schema_entry(entry: FlextLdifModels.Entry, *, strict: bool = True) -> bool:
        """Check if entry is a REAL schema entry with schema definitions.

        CRITICAL: This method detects ONLY real LDAP schema entries that
        contain attributetypes or objectclasses definitions. Entries with
        "cn=schema" in DN but NO schema attributes (like ODIP config
        entries) are NOT schema in strict mode.

        Args:
            entry: Entry to check (FlextLdifModels.Entry)
            strict: If True, requires BOTH schema attrs AND DN pattern (default).
                   If False, any of: DN pattern OR objectClass OR schema attrs.

        Returns:
            True if entry is a schema entry, False otherwise

        """
        # Entry with no attributes cannot be a schema entry
        if entry.attributes is None:
            return False

        # Get attributes as lowercase set
        attrs_lower = {k.lower() for k in entry.attributes.attributes}

        # Check for actual schema definition attributes
        schema_field_names = ["attributetypes", "objectclasses"]
        has_schema_attrs = any(sf.lower() in attrs_lower for sf in schema_field_names)

        # Check DN patterns
        dn_lower = entry.dn.value.lower() if entry.dn else ""
        schema_dn_patterns = ["cn=subschemasubentry", "cn=subschema", "cn=schema"]
        has_schema_dn = any(pattern in dn_lower for pattern in schema_dn_patterns)

        # Check objectClass
        object_classes = entry.attributes.get("objectClass", [])
        has_schema_objectclass = any(
            oc.lower() in {"subschema", "subentry"} for oc in object_classes
        )

        if strict:
            # Strict mode: MUST have schema attrs AND DN pattern
            # (filters.py logic - avoids false positives)
            if not has_schema_attrs:
                return False
            return has_schema_dn
        # Permissive mode: ANY of the criteria is sufficient
        # (parser.py logic - more inclusive)
        return has_schema_dn or has_schema_objectclass or has_schema_attrs

    @staticmethod
    def has_objectclass(
        entry: FlextLdifModels.Entry,
        objectclasses: str | tuple[str, ...],
    ) -> bool:
        """Check if entry has any of the specified objectClasses.

        Args:
            entry: Entry to check
            objectclasses: Single objectClass or tuple of objectClasses to check

        Returns:
            True if entry has at least one of the specified objectClasses

        """
        if not entry.attributes:
            return False

        # Normalize to tuple
        if isinstance(objectclasses, str):
            objectclasses = (objectclasses,)

        # Get objectClass values (case-insensitive comparison)
        entry_ocs = entry.attributes.get("objectClass", [])
        entry_ocs_lower = {oc.lower() for oc in entry_ocs}

        # Check if any requested objectClass matches
        return any(oc.lower() in entry_ocs_lower for oc in objectclasses)

    @staticmethod
    def has_all_attributes(
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> bool:
        """Check if entry has ALL specified attributes.

        Args:
            entry: Entry to check
            attributes: List of attribute names to check

        Returns:
            True if entry has all specified attributes

        """
        if not attributes:
            return True

        if not entry.attributes:
            return False

        # Case-insensitive attribute check
        entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
        return all(attr.lower() in entry_attrs_lower for attr in attributes)

    @staticmethod
    def has_any_attributes(
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> bool:
        """Check if entry has ANY of the specified attributes.

        Args:
            entry: Entry to check
            attributes: List of attribute names to check

        Returns:
            True if entry has at least one of the specified attributes

        """
        if not attributes:
            return False

        if not entry.attributes:
            return False

        # Case-insensitive attribute check
        entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
        return any(attr.lower() in entry_attrs_lower for attr in attributes)

    @staticmethod
    def remove_attributes(
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextLdifModels.Entry:
        """Remove specified attributes from entry.

        Args:
            entry: Entry to modify
            attributes: List of attribute names to remove (case-insensitive)

        Returns:
            New entry with specified attributes removed

        """
        if not attributes:
            return entry

        # Entry with no attributes - return as-is
        if entry.attributes is None:
            return entry

        # Case-insensitive removal
        attrs_to_remove = {attr.lower() for attr in attributes}

        filtered = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove
        }

        # Create new entry with filtered attributes using LdifAttributes
        if entry.dn is None:
            return entry
        result = FlextLdifModels.Entry.create(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=filtered),
        )
        if result.is_failure:
            return entry
        # Entry.create returns Entry - convert domain to public if needed
        entry_unwrapped = result.unwrap()
        if isinstance(entry_unwrapped, FlextLdifModelsDomains.Entry) and not isinstance(
            entry_unwrapped,
            FlextLdifModels.Entry,
        ):
            return FlextLdifModels.Entry.model_validate(entry_unwrapped.model_dump())
        if isinstance(entry_unwrapped, FlextLdifModels.Entry):
            return entry_unwrapped
        # Fallback: convert via model_validate
        return FlextLdifModels.Entry.model_validate(entry_unwrapped.model_dump())

    @staticmethod
    def analyze_differences(
        entry_attrs: Mapping[str, FlextTypes.GeneralValueType],
        converted_attrs: FlextLdifTypes.CommonDict.AttributeDict,
        original_dn: str,
        cleaned_dn: str,
        normalize_attr_fn: Callable[[str], str] | None = None,
    ) -> tuple[
        dict[str, FlextTypes.MetadataAttributeValue],
        dict[str, dict[str, FlextTypes.MetadataAttributeValue]],
        dict[str, FlextTypes.MetadataAttributeValue],
        dict[str, str],
    ]:
        """Analyze DN and attribute differences for round-trip support (DRY utility).

        Extracted from server quirks for reuse across RFC, OID, OUD, etc.

        Args:
            entry_attrs: Original raw attributes
            converted_attrs: Converted attributes
            original_dn: Original DN string
            cleaned_dn: Cleaned/normalized DN
            normalize_attr_fn: Optional function to normalize attribute names

        Returns:
            Tuple of (dn_differences, attribute_differences, original_attrs_complete, original_case)

        """
        # Default normalizer: lowercase
        normalize = normalize_attr_fn or (lambda x: x.lower())

        # Analyze DN differences
        dn_differences = FlextLdifUtilitiesMetadata.analyze_minimal_differences(
            original=original_dn,
            converted=cleaned_dn if cleaned_dn != original_dn else None,
            context="dn",
        )

        # Track original attribute case
        original_attribute_case: dict[str, str] = {}
        for attr_name in entry_attrs:
            attr_str = str(attr_name)
            canonical = normalize(attr_str)
            if canonical != attr_str:
                original_attribute_case[canonical] = attr_str

        # Analyze attribute differences
        attribute_differences: dict[
            str,
            dict[str, FlextTypes.MetadataAttributeValue],
        ] = {}
        original_attributes_complete: dict[str, FlextTypes.MetadataAttributeValue] = {}

        for attr_name, attr_values in entry_attrs.items():
            original_attr_name = str(attr_name)
            canonical_name = normalize(original_attr_name)

            # Preserve original values
            original_values = (
                list(attr_values)
                if isinstance(attr_values, (list, tuple))
                else [attr_values]
                if attr_values is not None
                else []
            )
            original_attributes_complete[original_attr_name] = original_values

            converted_values = converted_attrs.get(canonical_name, [])

            # Build string representations
            original_str = (
                f"{original_attr_name}: {', '.join(str(v) for v in original_values)}"
            )
            converted_str = (
                f"{canonical_name}: {', '.join(str(v) for v in converted_values)}"
                if converted_values
                else None
            )

            # Analyze differences
            attr_diff = FlextLdifUtilitiesMetadata.analyze_minimal_differences(
                original=original_str,
                converted=converted_str if converted_str != original_str else None,
                context="attribute",
            )
            attribute_differences[canonical_name] = attr_diff

        return (
            dn_differences,
            attribute_differences,
            original_attributes_complete,
            original_attribute_case,
        )

    @staticmethod
    def matches_server_patterns(
        entry_dn: str,
        attributes: Mapping[str, FlextTypes.GeneralValueType],
        *,
        dn_patterns: tuple[tuple[str, ...], ...] = (),
        attr_prefixes: tuple[str, ...] | frozenset[str] = (),
        attr_names: frozenset[str] | set[str] = frozenset(),
        keyword_patterns: tuple[str, ...] = (),
    ) -> bool:
        """Check if entry matches server-specific patterns.

        Generic pattern matcher for server detection. Servers provide patterns,
        this utility does the matching.

        Args:
            entry_dn: Entry DN string
            attributes: Entry attributes dict/mapping
            dn_patterns: Tuple of DN pattern tuples - entry matches if ALL patterns
                        in ANY tuple match (OR of ANDs)
            attr_prefixes: Attribute name prefixes to check
            attr_names: Set of attribute names that indicate this server
            keyword_patterns: Keywords to search in attribute names

        Returns:
            True if entry matches any pattern set

        """
        if not entry_dn or not attributes:
            return False

        # Convert to dict and normalize attribute names
        attrs = dict(attributes) if not isinstance(attributes, dict) else attributes
        attr_names_lower = {k.lower() for k in attrs}

        # Check DN patterns (OR of ANDs) - early return if match
        if dn_patterns and any(
            all(pattern in entry_dn for pattern in pattern_set)
            for pattern_set in dn_patterns
        ):
            return True

        # Check attribute prefixes - early return if match
        if attr_prefixes and any(
            attr.startswith(prefix) for attr in attrs for prefix in attr_prefixes
        ):
            return True

        # Check known attribute names - early return if match
        if attr_names and (attr_names_lower & set(attr_names)):
            return True

        # Check keyword patterns in attribute names
        if keyword_patterns:
            return any(
                keyword in attr
                for attr in attr_names_lower
                for keyword in keyword_patterns
            )

        return False

    @staticmethod
    def denormalize_attributes_batch(
        attributes: FlextLdifTypes.CommonDict.AttributeDict,
        *,
        case_mappings: dict[str, str] | None = None,
        boolean_mappings: dict[str, str] | None = None,
        attr_name_mappings: dict[str, str] | None = None,
        value_transformations: dict[str, dict[str, str]] | None = None,
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Batch denormalize attributes for output.

        Inverse of normalization - converts RFC-normalized attributes back to
        server-specific format. Consolidates denormalization patterns from
        OID and OUD servers into a single parameterized utility.

        Denormalization Steps
        =====================

        1. **Case Restoration**: Restores original attribute name case
           - Example: objectclass -> objectClass (OID format)

        2. **Boolean Conversion**: Converts TRUE/FALSE to server format
           - OID: TRUE -> 1, FALSE -> 0
           - OpenLDAP: Uses TRUE/FALSE (no change)

        3. **Name Mapping**: Restores server-specific attribute names
           - Example: cn -> commonName (if server prefers full name)

        4. **Value Transformations**: Server-specific value adjustments
           - Syntax conversions, encoding changes, etc.

        Args:
            attributes: Normalized attributes dictionary
            case_mappings: Attribute case restoration {normalized: original}
            boolean_mappings: Boolean value mappings {TRUE: "1", FALSE: "0"}
            attr_name_mappings: Attribute name mappings {rfc_name: server_name}
            value_transformations: Per-attribute value mappings

        Returns:
            Denormalized attributes dictionary for server-specific output

        Example:
            >>> normalized = {"objectclass": ["person"], "orclisvisible": ["TRUE"]}
            >>> denorm = FlextLdifUtilitiesEntry.denormalize_attributes_batch(
            ...     normalized,
            ...     case_mappings={"objectclass": "objectClass"},
            ...     boolean_mappings={"TRUE": "1", "FALSE": "0"},
            ... )
            >>> denorm
            {"objectClass": ["person"], "orclisvisible": ["1"]}

        """
        result: FlextLdifTypes.CommonDict.AttributeDict = {}

        for attr_name, values in attributes.items():
            # Step 1: Restore case
            output_name = attr_name
            if case_mappings:
                output_name = case_mappings.get(attr_name.lower(), attr_name)

            # Step 2: Apply name mapping
            if attr_name_mappings:
                output_name = attr_name_mappings.get(output_name, output_name)

            # Step 3: Transform values
            output_values: list[str] = []
            for value in values:
                output_value = value

                # Apply boolean mappings
                if boolean_mappings and value in boolean_mappings:
                    output_value = boolean_mappings[value]

                # Apply per-attribute value transformations
                if value_transformations and attr_name.lower() in value_transformations:
                    attr_transforms = value_transformations[attr_name.lower()]
                    output_value = attr_transforms.get(output_value, output_value)

                output_values.append(output_value)

            result[output_name] = output_values

        return result

    @staticmethod
    def normalize_attributes_batch(
        attributes: FlextLdifTypes.CommonDict.AttributeDict,
        *,
        case_mappings: dict[str, str] | None = None,
        boolean_mappings: dict[str, str] | None = None,
        attr_name_mappings: dict[str, str] | None = None,
        strip_operational: bool = False,
        operational_attrs: set[str] | None = None,
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Batch normalize attributes from server format to RFC format.

        Consolidates normalization patterns from OID and OUD servers into
        a single parameterized utility.

        Normalization Steps
        ===================

        1. **Case Normalization**: Normalizes attribute names to lowercase
           - objectClass -> objectclass

        2. **Boolean Normalization**: Converts server booleans to RFC format
           - OID: 1 -> TRUE, 0 -> FALSE
           - Preserves original format in metadata

        3. **Name Normalization**: Maps server names to RFC names
           - Example: commonName -> cn (if preferred)

        4. **Operational Removal**: Optionally removes operational attributes
           - createTimestamp, modifyTimestamp, etc.

        Args:
            attributes: Server-specific attributes dictionary
            case_mappings: Attribute case normalization {original: normalized}
            boolean_mappings: Boolean value mappings {"1": "TRUE", "0": "FALSE"}
            attr_name_mappings: Attribute name mappings {server_name: rfc_name}
            strip_operational: Whether to remove operational attributes
            operational_attrs: Set of operational attribute names

        Returns:
            Normalized attributes dictionary in RFC format

        """
        result: FlextLdifTypes.CommonDict.AttributeDict = {}

        operational_lower = (
            {a.lower() for a in operational_attrs} if operational_attrs else set()
        )
        for attr_name, values in attributes.items():
            # Step 1: Check if operational and should skip
            if strip_operational and attr_name.lower() in operational_lower:
                continue

            # Step 2: Normalize case
            output_name = attr_name.lower()
            if case_mappings:
                output_name = case_mappings.get(attr_name, output_name)

            # Step 3: Apply name mapping
            if attr_name_mappings:
                output_name = attr_name_mappings.get(attr_name, output_name)

            # Step 4: Transform values
            output_values: list[str] = []
            for value in values:
                output_value = value

                # Apply boolean normalization
                if boolean_mappings and value in boolean_mappings:
                    output_value = boolean_mappings[value]

                output_values.append(output_value)

            result[output_name] = output_values

        return result


__all__ = [
    "FlextLdifUtilitiesEntry",
]
