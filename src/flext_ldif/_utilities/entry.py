"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import re
from typing import cast

from flext_core import FlextLogger, FlextRuntime

from flext_ldif.models import FlextLdifModels

logger = FlextLogger(__name__)


class FlextLdifUtilitiesEntry:
    """Entry transformation utilities - pure helper functions.

    Common entry transformations extracted from server quirks.
    Servers can use these for consistent attribute handling.
    """

    # Minimum length for base64 pattern matching
    _MIN_BASE64_LENGTH: int = 8

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
        attributes: dict[str, list[str] | list[bytes] | bytes | str],
        boolean_attr_names: set[str],
        *,
        source_format: str = "0/1",
        target_format: str = "TRUE/FALSE",
    ) -> dict[str, list[str]]:
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
            normalized_result: dict[str, list[str]] = {}
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
                        values.decode("utf-8", errors="replace")
                    ]
                else:
                    normalized_result[attr_name] = [str(values)]
            return normalized_result

        result: dict[str, list[str]] = {}

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
        attributes: dict[str, list[str]],
        case_map: dict[str, str],
    ) -> dict[str, list[str]]:
        """Normalize attribute names using case mapping.

        Args:
            attributes: Entry attributes dict
            case_map: Dict mapping lowercase names → proper case

        Returns:
            New attributes dict with normalized attribute names

        """
        if not attributes or not case_map:
            return attributes

        result: dict[str, list[str]] = {}

        for attr_name, values in attributes.items():
            # Check if this attribute needs case normalization
            normalized_name = case_map.get(attr_name.lower(), attr_name)
            result[normalized_name] = values

        return result

    @staticmethod
    def detect_base64_attributes(
        attributes: dict[str, list[str]],
    ) -> set[str]:
        """Detect which attributes contain base64-encoded values.

        Args:
            attributes: Entry attributes dict

        Returns:
            Set of attribute names that contain base64 data

        """
        if not attributes:
            return set()

        base64_attrs: set[str] = set()

        for attr_name, values in attributes.items():
            for value in values:
                # Check for base64 markers or non-UTF8 patterns
                # Note: value is guaranteed to be str from type annotation
                try:
                    value.encode("utf-8").decode("utf-8")
                except (UnicodeDecodeError, AttributeError):
                    base64_attrs.add(attr_name)
                    break

                # Check for common base64 patterns
                if (
                    re.match(r"^[A-Za-z0-9+/]*={0,2}$", value)
                    and len(value) > FlextLdifUtilitiesEntry._MIN_BASE64_LENGTH
                ):
                    # Looks like base64
                    try:
                        base64.b64decode(value, validate=True)
                        base64_attrs.add(attr_name)
                        break
                    except Exception as e:
                        logger.debug(
                            "Base64 validation failed",
                            attribute_name=attr_name,
                            error=str(e),
                        )

        return base64_attrs

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
    def filter_operational_attrs(
        entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry:
        """Remove operational attributes from entry.

        Operational attributes are LDAP-managed attributes like:
        - createTimestamp, modifyTimestamp
        - creatorsName, modifiersName
        - entryUUID, entryDN
        - structuralObjectClass, etc.

        Args:
            entry: Entry to filter

        Returns:
            New entry with operational attributes removed

        """
        # Entry with no attributes - return as-is
        if entry.attributes is None:
            return entry

        # Common operational attributes (case-insensitive)
        operational_attrs = {
            "createtimestamp",
            "modifytimestamp",
            "creatorsname",
            "modifiersname",
            "entryuuid",
            "entrydn",
            "structuralobjectclass",
            "hassubordinates",
            "subschemasubentry",
            "numsubordinates",
        }

        # Filter attributes
        filtered = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in operational_attrs
        }

        # Create new entry with filtered attributes
        if entry.dn is None:
            return entry
        result = FlextLdifModels.Entry.create(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=filtered),
        )
        if result.is_failure:
            return entry
        # Entry.create returns FlextResult[FlextLdifModels.Entry]
        return cast("FlextLdifModels.Entry", result.unwrap())

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
        # Entry.create returns FlextResult[FlextLdifModels.Entry]
        return cast("FlextLdifModels.Entry", result.unwrap())


__all__ = [
    "FlextLdifUtilitiesEntry",
]
