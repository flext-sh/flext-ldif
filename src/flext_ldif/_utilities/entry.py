"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import logging
import re

from flext_ldif.models import FlextLdifModels

logger = logging.getLogger(__name__)


class FlextLdifUtilitiesEntry:
    """Entry transformation utilities - pure helper functions.

    Common entry transformations extracted from server quirks.
    Servers can use these for consistent attribute handling.
    """

    # Minimum length for base64 pattern matching
    _MIN_BASE64_LENGTH: int = 8

    @staticmethod
    def convert_boolean_attributes(
        attributes: dict[str, list[str]],
        boolean_attr_names: set[str],
        *,
        source_format: str = "0/1",
        target_format: str = "TRUE/FALSE",
    ) -> dict[str, list[str]]:
        """Convert boolean attribute values between formats.

        Args:
            attributes: Entry attributes {attr_name: [values]}
            boolean_attr_names: Set of attribute names (lowercase) to convert
            source_format: Input format ("0/1" or "TRUE/FALSE")
            target_format: Output format ("0/1" or "TRUE/FALSE")

        Returns:
            New attributes dict with converted boolean values

        """
        if not attributes or not boolean_attr_names:
            return attributes

        result = dict(attributes)

        for attr_name, values in result.items():
            if attr_name.lower() in boolean_attr_names:
                converted = []

                for value in values:
                    if source_format == "0/1" and target_format == "TRUE/FALSE":
                        converted.append("TRUE" if value == "1" else "FALSE")
                    elif source_format == "TRUE/FALSE" and target_format == "0/1":
                        converted.append("1" if value.upper() == "TRUE" else "0")
                    else:
                        converted.append(value)

                result[attr_name] = converted

        return result

    @staticmethod
    def validate_telephone_numbers(
        telephone_values: list[str],
    ) -> list[str]:
        """Validate telephone numbers - must contain at least one digit.

        Args:
            telephone_values: List of telephone number values

        Returns:
            Filtered list containing only valid telephone numbers

        """
        if not telephone_values:
            return []

        # Telephone numbers must contain at least one digit
        return [
            value for value in telephone_values if any(char.isdigit() for char in value)
        ]

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
                if not isinstance(value, str):
                    continue

                # Check for base64 markers or non-UTF8 patterns
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
                            "Base64 validation failed for %s: %s",
                            attr_name,
                            e,
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
        return FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=filtered,
        )

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

        # Case-insensitive removal
        attrs_to_remove = {attr.lower() for attr in attributes}

        filtered = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove
        }

        # Create new entry with filtered attributes using LdifAttributes
        return FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=filtered),
        )


__all__ = [
    "FlextLdifUtilitiesEntry",
]
