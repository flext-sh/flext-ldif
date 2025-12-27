"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Literal

from flext_core import FlextLogger, FlextResult, FlextTypes, r

from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.models import m
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifUtilitiesEntry:
    """Entry transformation utilities - pure helper functions.

    Common entry transformations extracted from server quirks.
    Servers can use these for consistent attribute handling.
    """

    # Minimum length for base64 pattern matching (use constant from c.Ldif.Format.Rfc directly in methods)
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
    ) -> t.Ldif.NormalizedAttributesDict:
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
            normalized_result: t.Ldif.NormalizedAttributesDict = {}
            for attr_name in attributes:
                # Type-safe access - get values with explicit type
                raw_values: list[str] | list[bytes] | bytes | str = attributes[
                    attr_name
                ]
                # Normalize to list[str] - handle all input types
                if isinstance(raw_values, (list, tuple)):
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

        result: dict[str, list[str]] = {}

        for attr_name in attributes:
            # Type-safe access - get values with explicit type
            attr_raw_values: list[str] | list[bytes] | bytes | str = attributes[
                attr_name
            ]
            # Normalize values to list[str] first - convert bytes to str immediately
            str_values: list[str]
            if isinstance(attr_raw_values, (list, tuple)):
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
        attributes: t.Ldif.AttributesDict,
        case_map: dict[str, str],
    ) -> t.Ldif.AttributesDict:
        """Normalize attribute names using case mapping.

        Args:
            attributes: Entry attributes dict
            case_map: Dict mapping lowercase names → proper case

        Returns:
            New attributes dict with normalized attribute names

        """
        if not attributes or not case_map:
            return attributes

        def get_normalized_name(attr_name: str) -> str:
            """Get normalized attribute name."""
            return case_map.get(attr_name.lower(), attr_name)

        # Create normalized attributes dict
        result: t.Ldif.AttributesDict = {}
        for attr_name, values in attributes.items():
            normalized_name = get_normalized_name(attr_name)
            result[normalized_name] = values
        return result

    @staticmethod
    def is_schema_entry(entry: m.Ldif.Entry, *, strict: bool = True) -> bool:
        """Check if entry is a REAL schema entry with schema definitions.

        CRITICAL: This method detects ONLY real LDAP schema entries that
        contain attributetypes or objectclasses definitions. Entries with
        "cn=schema" in DN but NO schema attributes (like ODIP config
        entries) are NOT schema in strict mode.

        Args:
            entry: Entry to check (m.Ldif.Entry)
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
        entry: m.Ldif.Entry,
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
        entry: m.Ldif.Entry,
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
        entry: m.Ldif.Entry,
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
        entry: m.Ldif.Entry,
        attributes: list[str],
    ) -> m.Ldif.Entry:
        """Remove specified attributes from entry.

        Args:
            entry: Entry to modify
            attributes: List of attribute names to remove (case-insensitive)

        Returns:
            New entry with specified attributes removed

        """
        if not attributes or entry.attributes is None or entry.dn is None:
            return entry

        attrs_to_remove = {attr.lower() for attr in attributes}
        # Direct iteration instead of u.Collection.filter
        filtered: dict[str, list[str]] = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove
        }

        return m.Ldif.Entry.create(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=filtered),
        ).unwrap_or(entry)

    @staticmethod
    def analyze_differences(
        entry_attrs: Mapping[str, FlextTypes.GeneralValueType],
        converted_attrs: t.Ldif.AttributesDict,
        original_dn: str,
        cleaned_dn: str,
        normalize_attr_fn: Callable[[str], str] | None = None,
    ) -> tuple[
        dict[str, t.MetadataAttributeValue],
        dict[str, dict[str, t.MetadataAttributeValue]],
        dict[str, t.MetadataAttributeValue],
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
        def extract_case_mapping(attr_name: str) -> tuple[str, str] | None:
            """Extract case mapping if different."""
            attr_str = str(attr_name)
            canonical = normalize(attr_str)
            return (canonical, attr_str) if canonical != attr_str else None

        # Direct iteration instead of u.Collection.process
        # Extract case mappings from attribute names
        original_attribute_case: dict[str, str] = {}
        for attr_name in entry_attrs:
            try:
                result = extract_case_mapping(attr_name)
                if result is not None:
                    key, value = result
                    original_attribute_case[key] = value
            except (ValueError, TypeError, AttributeError):
                # Skip attributes that fail case mapping extraction due to data issues
                continue

        # Analyze attribute differences
        attribute_differences: dict[
            str,
            dict[str, t.MetadataAttributeValue],
        ] = {}
        original_attributes_complete: dict[str, t.MetadataAttributeValue] = {}

        for attr_name, attr_values in entry_attrs.items():
            original_attr_name = str(attr_name)
            canonical_name = normalize(original_attr_name)

            # Preserve original values
            # Business Rule: LDIF attribute values are always ScalarValue or Sequence[ScalarValue]
            # (never recursive t.GeneralValueType with nested Mappings).
            # This method receives t.GeneralValueType from entry_attrs but converts to
            # MetadataAttributeValue for metadata storage (which only accepts ScalarValue).
            # Implication: Attribute values in LDIF are always primitive types, never nested structures.
            # Type conversion: t.GeneralValueType -> MetadataAttributeValue is safe because
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
            # Store in original_attributes_complete dict
            # Use t.MetadataAttributeValue annotation on the assignment target
            typed_list: t.MetadataAttributeValue = list(original_values_list)
            original_attributes_complete[original_attr_name] = typed_list

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
        config: FlextLdifModelsSettings.ServerPatternsConfig,
    ) -> bool:
        """Check if entry matches server-specific patterns.

        Generic pattern matcher for server detection. Servers provide patterns,
        this utility does the matching.

        Args:
            entry_dn: Entry DN string
            attributes: Entry attributes dict/mapping
            config: ServerPatternsConfig with all pattern matching parameters

        Returns:
            True if entry matches any pattern set

        Example:
            config = FlextLdifModelsSettings.ServerPatternsConfig(
                dn_patterns=(("ou=users",), ("cn=REDACTED_LDAP_BIND_PASSWORD",)),
                attr_prefixes=("orcl", "oracle"),
                attr_names={"orclaci", "orclentrylevelaci"},
                keyword_patterns=("orcl", "oracle"),
            )
            matches = FlextLdifUtilitiesEntry.matches_server_patterns(
                entry_dn, attributes, config
            )

        """
        if not entry_dn or not attributes:
            return False

        # Convert to dict and normalize attribute names
        attrs = dict(attributes) if not isinstance(attributes, dict) else attributes
        attr_names_lower = {k.lower() for k in attrs}

        # Check DN patterns (OR of ANDs) - early return if match
        if config.dn_patterns and any(
            all(pattern in entry_dn for pattern in pattern_set)
            for pattern_set in config.dn_patterns
        ):
            return True

        # Check attribute prefixes - early return if match
        if config.attr_prefixes and any(
            attr.startswith(prefix) for attr in attrs for prefix in config.attr_prefixes
        ):
            return True

        # Check known attribute names - early return if match
        if config.attr_names and (attr_names_lower & set(config.attr_names)):
            return True

        # Check keyword patterns in attribute names
        if config.keyword_patterns:
            return any(
                keyword in attr
                for attr in attr_names_lower
                for keyword in config.keyword_patterns
            )

        return False

    @staticmethod
    def denormalize_attributes_batch(
        attributes: t.Ldif.AttributesDict,
        *,
        case_mappings: dict[str, str] | None = None,
        boolean_mappings: dict[str, str] | None = None,
        attr_name_mappings: dict[str, str] | None = None,
        value_transformations: dict[str, dict[str, str]] | None = None,
    ) -> t.Ldif.NormalizedAttributesDict:
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

        def transform_value(attr_name: str, value: str) -> str:
            """Transform single value for attribute."""
            output_value = value
            # Apply boolean mappings
            if boolean_mappings and value in boolean_mappings:
                output_value = boolean_mappings[value]
            # Apply per-attribute value transformations
            if value_transformations and attr_name.lower() in value_transformations:
                attr_transforms = value_transformations[attr_name.lower()]
                output_value = attr_transforms.get(output_value, output_value)
            return output_value

        def get_output_name(attr_name: str) -> str:
            """Get output attribute name after case and name mappings."""
            output_name = attr_name
            # Step 1: Restore case
            if case_mappings:
                output_name = case_mappings.get(attr_name.lower(), attr_name)
            # Step 2: Apply name mapping
            if attr_name_mappings:
                output_name = attr_name_mappings.get(output_name, output_name)
            return output_name

        result: dict[str, list[str]] = {}
        for attr_name, values in attributes.items():
            output_name = get_output_name(attr_name)
            # Transform values - ensure they are strings first
            output_values: list[str] = []
            for value in values:
                if isinstance(value, str):
                    transformed = transform_value(attr_name, value)
                    output_values.append(transformed)
                else:
                    # Skip non-string values or convert as needed
                    output_values.append(str(value))
            result[output_name] = output_values
        return result

    @staticmethod
    def normalize_attributes_batch(
        attributes: t.Ldif.AttributesDict,
        *,
        config: FlextLdifModelsSettings.AttributeNormalizeConfig | None = None,
        **kwargs: object,
    ) -> t.Ldif.AttributesDict:
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
            config: AttributeNormalizeConfig with all normalization parameters
            **kwargs: Optional parameters for AttributeNormalizeConfig (case_mappings, boolean_mappings,
                attr_name_mappings, strip_operational, operational_attrs) - used only if config is None

        Returns:
            Normalized attributes dictionary in RFC format

        """
        # Use provided config or build from kwargs
        if config is None:
            # Use model_validate which accepts dict[str, t.GeneralValueType] and validates at runtime
            config = FlextLdifModelsSettings.AttributeNormalizeConfig.model_validate(
                kwargs,
            )

        result: dict[str, list[str | bytes]] = {}

        operational_lower = (
            {a.lower() for a in config.operational_attrs}
            if config.operational_attrs
            else set()
        )
        for attr_name, values in attributes.items():
            # Step 1: Check if operational and should skip
            if config.strip_operational and attr_name.lower() in operational_lower:
                continue

            # Step 2: Normalize case
            output_name = attr_name.lower()
            if config.case_mappings:
                output_name = config.case_mappings.get(attr_name, output_name)

            # Step 3: Apply name mapping
            if config.attr_name_mappings:
                output_name = config.attr_name_mappings.get(attr_name, output_name)

            # Step 4: Transform values
            def normalize_value(value: str) -> str:
                """Normalize single value."""
                if config.boolean_mappings and value in config.boolean_mappings:
                    return config.boolean_mappings[value]
                return value

            # Apply normalization to each value
            output_values: list[str | bytes] = []
            for value in values:
                if isinstance(value, str):
                    output_values.append(normalize_value(value))
                else:
                    output_values.append(str(value))

            result[output_name] = output_values

        return result

    # =========================================================================
    # BATCH METHODS - Power Method Support
    # =========================================================================

    @staticmethod
    def _check_schema_criteria(entry: m.Ldif.Entry, *, is_schema: bool) -> bool:
        """Check schema criteria."""
        return FlextLdifUtilitiesEntry.is_schema_entry(entry) == is_schema

    @staticmethod
    def _check_objectclass_criteria(
        entry: m.Ldif.Entry,
        objectclasses: Sequence[str],
        mode: Literal["any", "all"],
    ) -> bool:
        """Check objectClass criteria."""
        # Direct iteration instead of u.Collection.filter
        matching_ocs: list[str] = [
            oc
            for oc in objectclasses
            if FlextLdifUtilitiesEntry.has_objectclass(entry, oc)
        ]
        return (
            bool(matching_ocs)
            if mode == "any"
            else len(matching_ocs) == len(objectclasses)
        )

    @staticmethod
    def _check_dn_pattern(entry: m.Ldif.Entry, pattern: str) -> bool:
        """Check DN pattern match."""
        dn_value = (
            entry.dn.value
            if entry.dn and hasattr(entry.dn, "value")
            else str(entry.dn)
            if entry.dn
            else ""
        )
        return bool(re.search(pattern, dn_value, re.IGNORECASE))

    @staticmethod
    def matches_criteria(
        entry: m.Ldif.Entry,
        config: FlextLdifModelsSettings.EntryCriteriaConfig | None = None,
        **kwargs: object,
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
            config: EntryCriteriaConfig with all criteria parameters
            **kwargs: Optional parameters for EntryCriteriaConfig (objectclasses, objectclass_mode,
                required_attrs, any_attrs, dn_pattern, is_schema) - used only if config is None

        Returns:
            True if all specified criteria are met

        Examples:
            >>> config = FlextLdifModelsSettings.EntryCriteriaConfig(
            ...     is_schema=False,
            ...     objectclasses=["inetOrgPerson", "person"],
            ...     objectclass_mode="any",
            ...     required_attrs=["cn", "sn"],
            ... )
            >>> FlextLdifUtilitiesEntry.matches_criteria(entry, config=config)
            True

        """
        # Use provided config or build from kwargs
        if config is None:
            # Use model_validate which accepts dict[str, t.GeneralValueType] and validates at runtime
            config = FlextLdifModelsSettings.EntryCriteriaConfig.model_validate(kwargs)

        checks: list[bool] = []

        if config.is_schema is not None:
            checks.append(
                FlextLdifUtilitiesEntry._check_schema_criteria(
                    entry,
                    is_schema=config.is_schema,
                ),
            )

        if config.objectclasses:
            checks.append(
                FlextLdifUtilitiesEntry._check_objectclass_criteria(
                    entry,
                    config.objectclasses,
                    config.objectclass_mode,
                ),
            )

        if config.required_attrs:
            checks.append(
                FlextLdifUtilitiesEntry.has_all_attributes(
                    entry,
                    list(config.required_attrs),
                ),
            )

        if config.any_attrs:
            checks.append(
                FlextLdifUtilitiesEntry.has_any_attributes(
                    entry,
                    list(config.any_attrs),
                ),
            )

        if config.dn_pattern:
            checks.append(
                FlextLdifUtilitiesEntry._check_dn_pattern(entry, config.dn_pattern),
            )

        return all(checks)

    @staticmethod
    def transform_batch(
        entries: Sequence[m.Ldif.Entry],
        config: FlextLdifModelsSettings.EntryTransformConfig | None = None,
        **kwargs: object,
    ) -> FlextResult[list[m.Ldif.Entry]]:
        """Transform multiple entries with common operations.

        Applies transformations in order:
        1. Normalize DNs
        2. Normalize attribute names
        3. Convert boolean values
        4. Remove specified attributes

        Args:
            entries: Entries to transform
            config: EntryTransformConfig with all transformation parameters
            **kwargs: Optional parameters for EntryTransformConfig (normalize_dns, normalize_attrs,
                attr_case, convert_booleans, remove_attrs, fail_fast) - used only if config is None

        Returns:
            FlextResult containing list of transformed entries

        Examples:
            >>> config = FlextLdifModelsSettings.EntryTransformConfig(
            ...     normalize_attrs=True,
            ...     attr_case="lower",
            ...     remove_attrs=["userPassword", "pwdHistory"],
            ... )
            >>> result = FlextLdifUtilitiesEntry.transform_batch(entries, config=config)

        """
        # Use provided config or build from kwargs
        if config is None:
            # Use model_validate which accepts dict[str, t.GeneralValueType] and validates at runtime
            config = FlextLdifModelsSettings.EntryTransformConfig.model_validate(kwargs)

        def transform_entry(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry:
            """Transform single entry with all operations."""
            current = entry
            if config.normalize_dns and current.dn:
                dn_value = (
                    current.dn.value
                    if hasattr(current.dn, "value")
                    else str(current.dn)
                )
                norm_result = FlextLdifUtilitiesDN.norm(dn_value)
                if norm_result.is_success:
                    # Use dict[str, t.GeneralValueType] for model_copy update (Pydantic accepts object)
                    # m.Ldif.DN is compatible via inheritance
                    dn_update: dict[str, t.GeneralValueType] = {
                        "dn": m.Ldif.DN(value=norm_result.value),
                    }
                    current = current.model_copy(update=dn_update)
            if config.normalize_attrs and current.attributes:
                attrs = current.attributes.attributes
                new_attrs = (
                    {k.lower(): v for k, v in attrs.items()}
                    if config.attr_case == "lower"
                    else {k.upper(): v for k, v in attrs.items()}
                    if config.attr_case == "upper"
                    else attrs
                )
                # Use dict[str, t.GeneralValueType] for model_copy update (Pydantic accepts object)
                # m.Ldif.Attributes. is compatible via inheritance
                attrs_update: dict[str, t.GeneralValueType] = {
                    "attributes": m.Ldif.Attributes(attributes=new_attrs),
                }
                current = current.model_copy(update=attrs_update)
            if config.convert_booleans and current.attributes:
                source_format, target_format = config.convert_booleans
                boolean_attrs = {
                    "userpassword",
                    "pwdaccountlocked",
                    "pwdlocked",
                    "accountlocked",
                    "passwordexpired",
                    "passwordneverexpires",
                }
                converted = FlextLdifUtilitiesEntry.convert_boolean_attributes(
                    current.attributes.attributes,
                    boolean_attrs,
                    source_format=source_format,
                    target_format=target_format,
                )
                # Use dict[str, t.GeneralValueType] for model_copy update (Pydantic accepts object)
                # m.Ldif.Attributes. is compatible via inheritance
                converted_attrs_update: dict[str, t.GeneralValueType] = {
                    "attributes": m.Ldif.Attributes(attributes=converted),
                }
                current = current.model_copy(update=converted_attrs_update)
            if config.remove_attrs:
                current = FlextLdifUtilitiesEntry.remove_attributes(
                    current,
                    list(config.remove_attrs),
                )
            return current

        # Direct iteration instead of u.Collection.batch
        transformed_list: list[m.Ldif.Entry] = []
        errors: list[tuple[int, str]] = []
        for i, entry in enumerate(entries):
            try:
                result = transform_entry(entry)
                if isinstance(result, m.Ldif.Entry):
                    transformed_list.append(result)
            except Exception as exc:
                if config.fail_fast:
                    return r[list[m.Ldif.Entry]].fail(
                        f"Transform failed at entry {i}: {exc}",
                    )
                errors.append((i, f"Transform failed at entry {i}: {exc}"))

        if errors and config.fail_fast:
            error_msg = errors[0][1]
            return r[list[m.Ldif.Entry]].fail(error_msg)

        return r[list[m.Ldif.Entry]].ok(transformed_list)

    @staticmethod
    def filter_batch(
        entries: Sequence[m.Ldif.Entry],
        config: FlextLdifModelsSettings.EntryFilterConfig | None = None,
        **kwargs: object,
    ) -> FlextResult[list[m.Ldif.Entry]]:
        """Filter entries based on criteria.

        Args:
            entries: Entries to filter
            config: EntryFilterConfig with all filter parameters
            **kwargs: Optional parameters for EntryFilterConfig (objectclasses, objectclass_mode,
                required_attrs, dn_pattern, is_schema, exclude_schema) - used only if config is None

        Returns:
            FlextResult containing filtered entries

        Example:
            >>> config = FlextLdifModelsSettings.EntryFilterConfig(
            ...     objectclasses=["inetOrgPerson"],
            ...     exclude_schema=True,
            ... )
            >>> result = FlextLdifUtilitiesEntry.filter_batch(entries, config=config)

        """
        # Use provided config or build from kwargs
        if config is None:
            # Handle exclude_schema as is_schema=False
            effective_is_schema = kwargs.get("is_schema")
            exclude_schema = kwargs.get("exclude_schema", False)
            if exclude_schema and effective_is_schema is None:
                effective_is_schema = False
            kwargs["is_schema"] = effective_is_schema
            # Use model_validate which accepts dict[str, t.GeneralValueType] and validates at runtime
            config = FlextLdifModelsSettings.EntryFilterConfig.model_validate(kwargs)

        # Direct iteration instead of u.Collection.filter
        filtered: list[m.Ldif.Entry] = [
            entry
            for entry in entries
            if FlextLdifUtilitiesEntry.matches_criteria(
                entry,
                config=FlextLdifModelsSettings.EntryCriteriaConfig(
                    objectclasses=config.objectclasses,
                    objectclass_mode=config.objectclass_mode,
                    required_attrs=config.required_attrs,
                    dn_pattern=config.dn_pattern,
                    is_schema=config.is_schema if not config.exclude_schema else False,
                ),
            )
        ]

        return r[list[m.Ldif.Entry]].ok(filtered)


__all__ = [
    "FlextLdifUtilitiesEntry",
]
