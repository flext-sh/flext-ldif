"""FLEXT LDIF Utilities - Utility functions and classes for LDIF operations.

SOURCE OF TRUTH: Uses flext-core exclusively for generic operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextLogger, FlextResult, FlextUtilities
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

# Direct flext-core usage without aliases

if TYPE_CHECKING:
    from pathlib import Path


class FlextLdifUtilities:
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
        """Validate if file has proper LDIF extension using centralized FlextModels.

        Args:
            file_path: Path to validate

        Returns:
            FlextResult indicating if file has valid LDIF extension

        """
        try:
            # Use centralized FlextLdifModels.LdifFilePath for validation
            FlextLdifModels.LdifFilePath(path=str(file_path))
            # If validation passes, file has valid extension
            return FlextResult[bool].ok(data=True)
        except Exception:
            # If validation fails, file doesn't have valid extension or other error
            return FlextResult[bool].ok(data=False)

    def normalize_dn_format(self, dn: str) -> FlextResult[str]:
        """Normalize DN format according to LDAP standards.

        Args:
            dn: Distinguished Name to normalize

        Returns:
            FlextResult containing normalized DN

        """
        try:
            # First normalize the DN format
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

            # Then validate the normalized DN using domain model
            dn_model = FlextLdifModels.DistinguishedName(value=normalized_dn)
            validation_result = dn_model.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[str].fail(
                    validation_result.error or "Invalid DN format"
                )

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
            # Use existing FlextLdifModels.DistinguishedName validation
            dn_model = FlextLdifModels.DistinguishedName(value=dn)
            validation_result = dn_model.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[str].fail(
                    validation_result.error or "Invalid DN format"
                )

            # Split by comma and take the last two components as base DN
            components = [comp.strip() for comp in dn.split(",")]
            if len(components) >= FlextLdifConstants.MIN_BASE_DN_COMPONENTS:
                base_dn = ",".join(components[-2:])
                return FlextResult[str].ok(base_dn)

            # If less than 2 components, return the DN itself
            return FlextResult[str].ok(dn)
        except Exception as e:
            return FlextResult[str].fail(f"Base DN extraction failed: {e}")

    def validate_ldif_entry_completeness(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Validate if LDIF entry has all required components using FlextModels.

        Args:
            entry: LDIF entry to validate

        Returns:
            FlextResult indicating if entry is complete

        """
        try:
            # Use centralized FlextLdifModels.Entry validation directly
            validation_result = entry.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[bool].fail(
                    validation_result.error or "Entry validation failed"
                )

            return FlextResult[bool].ok(FlextLdifConstants.ENTRY_IS_COMPLETE)
        except Exception as e:
            return FlextResult[bool].fail(f"Entry completeness validation failed: {e}")

    def convert_entry_to_dict(
        self, entry: FlextLdifModels.Entry
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

    def calculate_entry_size(self, entry: FlextLdifModels.Entry) -> FlextResult[int]:
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
        self, entry1: FlextLdifModels.Entry, entry2: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Merge two LDIF entries with same DN.

        Args:
            entry1: First entry
            entry2: Second entry to merge into first

        Returns:
            FlextResult containing merged entry

        """
        try:
            if entry1.dn.value != entry2.dn.value:
                return FlextResult[FlextLdifModels.Entry].fail(
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

            # Create merged entry using new factory method
            merged_entry_data: dict[str, object] = {
                "dn": entry1.dn.value,
                "attributes": merged_attributes,
            }

            merged_entry = FlextLdifModels.create_entry(merged_entry_data)
            return FlextResult[FlextLdifModels.Entry].ok(merged_entry)
        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(f"Entry merge failed: {e}")

    def get_utility_info(self) -> dict[str, object]:
        """Get LDIF utilities information.

        Returns:
            Dictionary containing utility information

        """
        return {
            "service": "FlextLdifUtilities",
            "capabilities": [
                "ldif_file_validation",
                "dn_normalization",
                "entry_validation",
                "entry_conversion",
                "entry_merging",
            ],
            "flext_core_integration": True,
        }


__all__ = ["FlextLdifUtilities"]
