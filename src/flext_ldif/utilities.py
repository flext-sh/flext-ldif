"""FLEXT LDIF Utilities - Utility functions and classes for LDIF operations.

SOURCE OF TRUTH: Uses flext-core exclusively for generic operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextLogger, FlextResult, FlextUtilities

from flext_ldif.models import FlextLDIFModels

# Constants to avoid magic numbers and booleans
MIN_BASE_DN_COMPONENTS = 2
ENTRY_IS_COMPLETE = True

if TYPE_CHECKING:
    from pathlib import Path

# Type aliases for test compatibility
AttributeDict = dict[str, list[str]]
LDIFAttributeDict = dict[str, list[str]]


class FlextLDIFUtilities:
    """LDIF-specific utilities extending flext-core FlextUtilities.

    Provides LDIF domain-specific utility functions while leveraging
    flext-core SOURCE OF TRUTH for common operations.
    """

    def __init__(self) -> None:
        """Initialize LDIF utilities with dependency on flext-core."""
        self._core_utilities = FlextUtilities()
        self._logger = FlextLogger(__name__)

    @property
    def core(self) -> FlextUtilities:
        """Access flext-core utilities directly."""
        return self._core_utilities

    def validate_ldif_file_extension(self, file_path: str | Path) -> FlextResult[bool]:
        """Validate if file has proper LDIF extension.

        Args:
            file_path: Path to validate

        Returns:
            FlextResult indicating if file has valid LDIF extension

        """
        try:
            # Use flext-core file utilities
            path_str = str(file_path)
            valid_extensions = [".ldif", ".ldap", ".ldi"]

            has_valid_extension = any(
                path_str.lower().endswith(ext) for ext in valid_extensions
            )

            return FlextResult[bool].ok(has_valid_extension)
        except Exception as e:
            return FlextResult[bool].fail(f"Extension validation failed: {e}")

    def normalize_dn_format(self, dn: str) -> FlextResult[str]:
        """Normalize DN format according to LDAP standards.

        Args:
            dn: Distinguished Name to normalize

        Returns:
            FlextResult containing normalized DN

        """
        try:
            if not dn or not isinstance(dn, str) or not dn.strip():
                return FlextResult[str].fail("DN must be a non-empty string")

            # Basic DN normalization
            # Remove extra spaces, normalize case for RDN types
            components = []
            for raw_component in dn.split(","):
                component = raw_component.strip()
                if "=" in component:
                    key, value = component.split("=", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    components.append(f"{key}={value}")
                else:
                    components.append(component)

            normalized_dn = ",".join(components)
            return FlextResult[str].ok(normalized_dn)
        except Exception as e:
            return FlextResult[str].fail(f"DN normalization failed: {e}")

    def extract_base_dn(self, dn: str) -> FlextResult[str]:
        """Extract base DN from a complete DN.

        Args:
            dn: Complete Distinguished Name

        Returns:
            FlextResult containing base DN

        """
        try:
            if not dn:
                return FlextResult[str].fail("DN cannot be empty")

            # Split by comma and take the last two components as base DN
            components = [comp.strip() for comp in dn.split(",")]
            if len(components) >= MIN_BASE_DN_COMPONENTS:
                base_dn = ",".join(components[-2:])
                return FlextResult[str].ok(base_dn)

            # If less than 2 components, return the DN itself
            return FlextResult[str].ok(dn)
        except Exception as e:
            return FlextResult[str].fail(f"Base DN extraction failed: {e}")

    def validate_ldif_entry_completeness(
        self, entry: FlextLDIFModels.Entry
    ) -> FlextResult[bool]:
        """Validate if LDIF entry has all required components.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult indicating if entry is complete

        """
        try:
            # Check for required DN
            if not entry.dn or not entry.dn.value:
                return FlextResult[bool].fail("Entry missing required DN")

            # Check for attributes
            if not entry.attributes:
                return FlextResult[bool].fail("Entry missing attributes")

            # Check for objectClass
            object_classes = entry.get_attribute("objectClass")
            if not object_classes:
                return FlextResult[bool].fail("Entry missing objectClass attribute")

            return FlextResult[bool].ok(ENTRY_IS_COMPLETE)
        except Exception as e:
            return FlextResult[bool].fail(f"Entry completeness validation failed: {e}")

    def convert_entry_to_dict(
        self, entry: FlextLDIFModels.Entry
    ) -> FlextResult[dict[str, object]]:
        """Convert LDIF entry to dictionary format.

        Args:
            entry: LDIF entry to convert

        Returns:
            FlextResult containing entry as dictionary

        """
        try:
            entry_dict: dict[str, object] = {
                "dn": entry.dn.value,
                "attributes": dict(entry.attributes) if entry.attributes else {},
            }

            return FlextResult[dict[str, object]].ok(entry_dict)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Entry conversion failed: {e}")

    def calculate_entry_size(self, entry: FlextLDIFModels.Entry) -> FlextResult[int]:
        """Calculate approximate size of LDIF entry in bytes.

        Args:
            entry: LDIF entry to measure

        Returns:
            FlextResult containing entry size in bytes

        """
        try:
            total_size = 0

            # Add DN size
            total_size += len(entry.dn.value.encode("utf-8"))

            # Add attributes size
            if entry.attributes and hasattr(entry.attributes, "data"):
                for attr_name, attr_values in entry.attributes.data.items():
                    total_size += len(attr_name.encode("utf-8"))
                    # attr_values is always a list (StringList = list[str])
                    for value in attr_values:
                        total_size += len(str(value).encode("utf-8"))

            return FlextResult[int].ok(total_size)
        except Exception as e:
            return FlextResult[int].fail(f"Entry size calculation failed: {e}")

    def merge_ldif_entries(
        self, entry1: FlextLDIFModels.Entry, entry2: FlextLDIFModels.Entry
    ) -> FlextResult[FlextLDIFModels.Entry]:
        """Merge two LDIF entries with same DN.

        Args:
            entry1: First entry
            entry2: Second entry to merge into first

        Returns:
            FlextResult containing merged entry

        """
        try:
            if entry1.dn.value != entry2.dn.value:
                return FlextResult[FlextLDIFModels.Entry].fail(
                    "Cannot merge entries with different DNs"
                )

            # Create merged attributes dictionary
            merged_attributes = (
                dict(entry1.attributes.data)
                if entry1.attributes and hasattr(entry1.attributes, "data")
                else {}
            )

            if entry2.attributes and hasattr(entry2.attributes, "data"):
                for attr_name, attr_values in entry2.attributes.data.items():
                    if attr_name in merged_attributes:
                        # Merge values if attribute exists
                        existing_values = merged_attributes[attr_name]
                        # Both values are StringList (list[str]), so always merge lists
                        # Combine lists and remove duplicates
                        combined_values = list(set(existing_values + attr_values))
                        merged_attributes[attr_name] = combined_values
                    else:
                        # Add new attribute
                        merged_attributes[attr_name] = attr_values

            # Create merged entry
            merged_entry_data: dict[str, object] = {
                "dn": entry1.dn.value,
                "attributes": merged_attributes,
            }

            merged_entry = FlextLDIFModels.Factory.create_entry(merged_entry_data)
            return FlextResult[FlextLDIFModels.Entry].ok(merged_entry)
        except Exception as e:
            return FlextResult[FlextLDIFModels.Entry].fail(f"Entry merge failed: {e}")

    def get_utility_info(self) -> dict[str, object]:
        """Get LDIF utilities information.

        Returns:
            Dictionary containing utility information

        """
        return {
            "service": "FlextLDIFUtilities",
            "capabilities": [
                "ldif_file_validation",
                "dn_normalization",
                "entry_validation",
                "entry_conversion",
                "entry_merging",
            ],
            "flext_core_integration": True,
        }


__all__ = ["FlextLDIFUtilities"]
