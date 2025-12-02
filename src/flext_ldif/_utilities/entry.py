"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Literal

from flext_core import FlextLogger, FlextResult, FlextRuntime
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
            for attr_name in attributes:
                # Type-safe access - get values with explicit type
                raw_values: list[str] | list[bytes] | bytes | str = attributes[
                    attr_name
                ]
                # Normalize to list[str] - handle all input types
                if FlextRuntime.is_list_like(raw_values):
                    normalized_result[attr_name] = [
                        v.decode("utf-8", errors="replace")
                        if isinstance(v, bytes)
                        else str(v)
                        for v in raw_values
                    ]
                elif isinstance(raw_values, bytes):
                    normalized_result[attr_name] = [
                        raw_values.decode("utf-8", errors="replace"),
                    ]
                else:
                    normalized_result[attr_name] = [str(raw_values)]
            return normalized_result

        result: FlextLdifTypes.CommonDict.AttributeDict = {}

        for attr_name in attributes:
            # Type-safe access - get values with explicit type
            attr_raw_values: list[str] | list[bytes] | bytes | str = attributes[
                attr_name
            ]
            # Normalize values to list[str] first - convert bytes to str immediately
            str_values: list[str]
            if FlextRuntime.is_list_like(attr_raw_values):
                # Convert bytes to str if needed
                str_values = [
                    v.decode("utf-8", errors="replace")
                    if isinstance(v, bytes)
                    else str(v)
                    for v in attr_raw_values
                ]
            # Single value - convert bytes to str if needed, then wrap in list
            elif isinstance(attr_raw_values, bytes):
                str_values = [attr_raw_values.decode("utf-8", errors="replace")]
            else:
                str_values = [str(attr_raw_values)]

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
    def is_schema_entry(
        entry: FlextLdifModelsDomains.Entry, *, strict: bool = True
    ) -> bool:
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
        entry: FlextLdifModelsDomains.Entry,
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
        entry: FlextLdifModelsDomains.Entry,
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
        entry: FlextLdifModelsDomains.Entry,
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
        entry: FlextLdifModelsDomains.Entry,
        attributes: list[str],
    ) -> FlextLdifModelsDomains.Entry:
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
            # Business Rule: LDIF attribute values are always ScalarValue or Sequence[ScalarValue]
            # (never recursive GeneralValueType with nested Mappings).
            # This method receives GeneralValueType from entry_attrs but converts to
            # MetadataAttributeValue for metadata storage (which only accepts ScalarValue).
            # Implication: Attribute values in LDIF are always primitive types, never nested structures.
            # Type conversion: GeneralValueType -> MetadataAttributeValue is safe because
            # LDIF attributes never contain nested Mappings in practice.
            # Business Rule: original_values must be list[str] for iteration in string building
            # Implication: Convert all values to list[str] format for consistent processing
            original_values_list: list[str] = []
            if isinstance(attr_values, (list, tuple)):
                # Sequence of values - convert to list[str]
                # Business Rule: LDIF attribute sequences are always Sequence[ScalarValue], never recursive
                original_values_list = [str(v) for v in attr_values if v is not None]
            elif attr_values is not None:
                # Single value - wrap in list for consistency with metadata format
                # Business Rule: Metadata stores attributes as sequences for consistency
                original_values_list = [str(attr_values)]
            # Store as MetadataAttributeValue (list[str] is compatible with Sequence[ScalarValue])
            original_values: FlextTypes.MetadataAttributeValue = original_values_list
            original_attributes_complete[original_attr_name] = original_values

            converted_values = converted_attrs.get(canonical_name, [])

            # Build string representations
            # Business Rule: original_values_list is always list[str], safe for iteration
            original_str = f"{original_attr_name}: {', '.join(original_values_list)}"
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

    # =========================================================================
    # BATCH METHODS - Power Method Support
    # =========================================================================

    @staticmethod
    def matches_criteria(
        entry: FlextLdifModelsDomains.Entry,
        *,
        objectclasses: Sequence[str] | None = None,
        objectclass_mode: Literal["any", "all"] = "any",
        required_attrs: Sequence[str] | None = None,
        any_attrs: Sequence[str] | None = None,
        dn_pattern: str | None = None,
        is_schema: bool | None = None,
    ) -> bool:
        """Check multiple entry criteria in one call.

        Replaces multiple conditional checks:
            if is_schema_entry(entry) and has_objectclass(entry, 'person'):
                if has_all_attributes(entry, ['cn', 'sn']):
                    ...

        With single call:
            if matches_criteria(
                entry,
                is_schema=True,
                objectclasses=['person'],
                required_attrs=['cn', 'sn']
            ):

        Args:
            entry: Entry to check
            objectclasses: Required objectClasses
            objectclass_mode: "any" (has any) or "all" (has all)
            required_attrs: All of these attributes must exist
            any_attrs: At least one of these attributes must exist
            dn_pattern: Regex pattern that DN must match
            is_schema: If set, entry must (True) or must not (False) be schema

        Returns:
            True if all specified criteria are met

        Examples:
            >>> FlextLdifUtilitiesEntry.matches_criteria(
            ...     entry,
            ...     is_schema=False,
            ...     objectclasses=["inetOrgPerson", "person"],
            ...     objectclass_mode="any",
            ...     required_attrs=["cn", "sn"],
            ... )
            True

        """
        # Check is_schema constraint
        if is_schema is not None:
            entry_is_schema = FlextLdifUtilitiesEntry.is_schema_entry(entry)
            if entry_is_schema != is_schema:
                return False

        # Check objectClasses
        if objectclasses:
            if objectclass_mode == "any":
                has_any = any(
                    FlextLdifUtilitiesEntry.has_objectclass(entry, oc)
                    for oc in objectclasses
                )
                if not has_any:
                    return False
            else:  # "all"
                has_all = all(
                    FlextLdifUtilitiesEntry.has_objectclass(entry, oc)
                    for oc in objectclasses
                )
                if not has_all:
                    return False

        # Check required attributes
        if required_attrs and not FlextLdifUtilitiesEntry.has_all_attributes(
            entry, list(required_attrs)
        ):
            return False

        # Check any attributes
        if any_attrs:
            if not FlextLdifUtilitiesEntry.has_any_attributes(entry, list(any_attrs)):
                return False

        # Check DN pattern
        if dn_pattern:
            dn_value = ""
            if entry.dn is not None:
                dn_value = (
                    entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
                )
            if not re.search(dn_pattern, dn_value, re.IGNORECASE):
                return False

        return True

    @staticmethod
    def transform_batch(
        entries: Sequence[FlextLdifModelsDomains.Entry],
        *,
        normalize_dns: bool = False,
        normalize_attrs: bool = False,
        attr_case: Literal["lower", "upper", "preserve"] = "lower",
        convert_booleans: tuple[str, str] | None = None,
        remove_attrs: Sequence[str] | None = None,
        fail_fast: bool = False,
    ) -> FlextResult[list[FlextLdifModelsDomains.Entry]]:
        """Transform multiple entries with common operations.

        Applies transformations in order:
        1. Normalize DNs
        2. Normalize attribute names
        3. Convert boolean values
        4. Remove specified attributes

        Args:
            entries: Entries to transform
            normalize_dns: Normalize DN format
            normalize_attrs: Normalize attribute names to specified case
            attr_case: Case for attribute normalization
            convert_booleans: Tuple of (source_format, target_format)
                              e.g., ("true/false", "TRUE/FALSE")
            remove_attrs: List of attributes to remove
            fail_fast: Stop on first error

        Returns:
            FlextResult containing list of transformed entries

        Examples:
            >>> result = FlextLdifUtilitiesEntry.transform_batch(
            ...     entries,
            ...     normalize_attrs=True,
            ...     attr_case="lower",
            ...     remove_attrs=["userPassword", "pwdHistory"],
            ... )

        """
        from flext_ldif._utilities.dn import FlextLdifUtilitiesDN

        results: list[FlextLdifModelsDomains.Entry] = []
        errors: list[str] = []

        for i, entry in enumerate(entries):
            try:
                current_entry = entry

                # Step 1: Normalize DN
                if normalize_dns and current_entry.dn is not None:
                    dn_value = (
                        current_entry.dn.value
                        if hasattr(current_entry.dn, "value")
                        else str(current_entry.dn)
                    )
                    norm_result = FlextLdifUtilitiesDN.norm(dn_value)
                    if norm_result.is_success:
                        normalized_dn = norm_result.unwrap()
                        # Create new DN object
                        # Business Rule: DistinguishedName is the correct type for DN objects per RFC 4514
                        new_dn = FlextLdifModelsDomains.DistinguishedName(
                            value=normalized_dn
                        )
                        current_entry = current_entry.model_copy(update={"dn": new_dn})

                # Step 2: Normalize attribute names
                if normalize_attrs and current_entry.attributes is not None:
                    attrs = current_entry.attributes.attributes
                    if attr_case == "lower":
                        new_attrs = {k.lower(): v for k, v in attrs.items()}
                    elif attr_case == "upper":
                        new_attrs = {k.upper(): v for k, v in attrs.items()}
                    else:
                        new_attrs = attrs
                    new_attributes = FlextLdifModelsDomains.LdifAttributes(
                        attributes=new_attrs
                    )
                    current_entry = current_entry.model_copy(
                        update={"attributes": new_attributes}
                    )

                # Step 3: Convert booleans
                # Business Rule: convert_boolean_attributes expects Mapping and set[str], not Entry
                # Extract attributes dict and boolean attribute names set for conversion
                # Common LDAP boolean attributes that may need format conversion
                if convert_booleans:
                    source_format, target_format = convert_booleans
                    if current_entry.attributes is not None:
                        attrs_dict = current_entry.attributes.attributes
                        # Common boolean attribute names in LDAP (case-insensitive matching)
                        # TODO: Should come from config or constants for server-specific boolean attrs
                        boolean_attrs = {
                            "userpassword",
                            "pwdaccountlocked",
                            "pwdlocked",
                            "accountlocked",
                            "passwordexpired",
                            "passwordneverexpires",
                        }
                        converted_attrs = (
                            FlextLdifUtilitiesEntry.convert_boolean_attributes(
                                attrs_dict,
                                boolean_attrs,
                                source_format=source_format,
                                target_format=target_format,
                            )
                        )
                        new_attributes_boolean = FlextLdifModelsDomains.LdifAttributes(
                            attributes=converted_attrs
                        )
                        current_entry = current_entry.model_copy(
                            update={"attributes": new_attributes_boolean}
                        )

                # Step 4: Remove attributes
                # Business Rule: remove_attributes accepts 'attributes' as positional arg, not 'attributes_to_remove'
                if remove_attrs:
                    current_entry = FlextLdifUtilitiesEntry.remove_attributes(
                        current_entry,
                        list(remove_attrs),
                    )

                results.append(current_entry)

            except Exception as e:
                if fail_fast:
                    return FlextResult.fail(f"Entry {i} transform failed: {e}")
                errors.append(f"Entry {i}: {e}")

        if errors:
            return FlextResult.fail(f"Transform errors: {'; '.join(errors)}")

        return FlextResult.ok(results)

    @staticmethod
    def filter_batch(
        entries: Sequence[FlextLdifModelsDomains.Entry],
        *,
        objectclasses: Sequence[str] | None = None,
        objectclass_mode: Literal["any", "all"] = "any",
        required_attrs: Sequence[str] | None = None,
        dn_pattern: str | None = None,
        is_schema: bool | None = None,
        exclude_schema: bool = False,
    ) -> FlextResult[list[FlextLdifModelsDomains.Entry]]:
        """Filter entries based on criteria.

        Args:
            entries: Entries to filter
            objectclasses: Filter by objectClass
            objectclass_mode: "any" or "all"
            required_attrs: Only include entries with all these attrs
            dn_pattern: Only include entries matching DN pattern
            is_schema: Only include schema (True) or non-schema (False) entries
            exclude_schema: Convenience flag to exclude schema entries

        Returns:
            FlextResult containing filtered entries

        Examples:
            >>> result = FlextLdifUtilitiesEntry.filter_batch(
            ...     entries,
            ...     objectclasses=["inetOrgPerson"],
            ...     exclude_schema=True,
            ... )

        """
        # Handle exclude_schema as is_schema=False
        effective_is_schema = is_schema
        if exclude_schema and is_schema is None:
            effective_is_schema = False

        results: list[FlextLdifModelsDomains.Entry] = [
            entry
            for entry in entries
            if FlextLdifUtilitiesEntry.matches_criteria(
                entry,
                objectclasses=objectclasses,
                objectclass_mode=objectclass_mode,
                required_attrs=required_attrs,
                dn_pattern=dn_pattern,
                is_schema=effective_is_schema,
            )
        ]

        return FlextResult.ok(results)


__all__ = [
    "FlextLdifUtilitiesEntry",
]
