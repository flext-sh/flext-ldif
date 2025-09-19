"""FLEXT LDIF Utilities - LDIF-specific utility functions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextLogger, FlextResult, FlextUtilities
from flext_ldif.models import FlextLdifModels


class FlextLdifUtilities:
    """LDIF-specific utilities extending flext-core FlextUtilities.

    Provides LDIF domain-specific utility functions while leveraging
    flext-core SOURCE OF TRUTH for common operations.
    """

    def __init__(self) -> None:
        """Initialize LDIF utilities."""
        self._logger = FlextLogger(__name__)
        self._core_utilities = FlextUtilities()

    @property
    def core(self) -> FlextUtilities:
        """Access flext-core utilities directly."""
        return self._core_utilities

    def validate_ldif_file_path(self, file_path: str | Path) -> FlextResult[Path]:
        """Validate LDIF file path using flext-core patterns.

        Args:
            file_path: Path to validate

        Returns:
            FlextResult containing validated Path object

        """
        path_obj = Path(file_path)

        # Use flext-core validation for file existence
        if not path_obj.exists():
            return FlextResult[Path].fail(f"File does not exist: {path_obj}")

        if not path_obj.is_file():
            return FlextResult[Path].fail(f"Path is not a file: {path_obj}")

        # Use centralized validation model
        validated_path = FlextLdifModels.LdifFilePath(path=str(path_obj))
        return FlextResult[Path].ok(Path(validated_path.path))

    def validate_ldif_file_extension(self, file_path: str | Path) -> FlextResult[bool]:
        """Validate if file has proper LDIF extension using centralized FlextModels.

        Args:
            file_path: Path to validate

        Returns:
            FlextResult indicating if file has valid LDIF extension

        """
        # Handle path conversion exceptions
        try:
            path_str = str(file_path).lower()
        except Exception as e:
            return FlextResult[bool].fail(f"Extension validation failed: {e}")

        valid_extensions = [".ldif", ".ldap", ".ldi"]
        has_valid_extension = any(path_str.endswith(ext) for ext in valid_extensions)

        if has_valid_extension:
            # Double-check with the centralized validation model
            try:
                FlextLdifModels.LdifFilePath(path=str(file_path))
                return FlextResult[bool].ok(data=True)
            except Exception:
                # If validation fails for other reasons, still return False
                return FlextResult[bool].ok(data=False)
        else:
            return FlextResult[bool].ok(data=False)

    def validate_ldif_content(self, content: str) -> FlextResult[str]:
        """Validate LDIF content using flext-core patterns.

        Args:
            content: LDIF content to validate

        Returns:
            FlextResult containing validated content

        """
        try:
            # Use flext-core validation for non-empty string
            if not FlextUtilities.Validation.is_non_empty_string(content):
                return FlextResult[str].fail("Content cannot be empty")

            # Use centralized validation model
            validated_content = FlextLdifModels.LdifContent(content=content)
            return FlextResult[str].ok(validated_content.content)

        except Exception as e:
            return FlextResult[str].fail(f"Content validation failed: {e}")

    def validate_dn_format(self, dn: str) -> FlextResult[str]:
        """Validate DN format using flext-core patterns.

        Args:
            dn: DN string to validate

        Returns:
            FlextResult containing validated DN

        """
        try:
            # Use centralized validation model
            validated_dn = FlextLdifModels.DistinguishedName(value=dn)
            return FlextResult[str].ok(validated_dn.value)

        except Exception as e:
            return FlextResult[str].fail(f"DN validation failed: {e}")

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
                    validation_result.error or "Invalid DN format",
                )

            return FlextResult[str].ok(normalized_dn)
        except Exception as e:
            return FlextResult[str].fail(f"DN normalization failed: {e}")

    def validate_attribute_name(self, attr_name: str) -> FlextResult[str]:
        """Validate attribute name using flext-core patterns.

        Args:
            attr_name: Attribute name to validate

        Returns:
            FlextResult containing validated attribute name

        """
        try:
            # Use centralized validation model
            validated_attr = FlextLdifModels.LdifAttributeName(name=attr_name)
            return FlextResult[str].ok(validated_attr.name)

        except Exception as e:
            return FlextResult[str].fail(f"Attribute name validation failed: {e}")

    def normalize_ldif_content(self, content: str) -> FlextResult[str]:
        """Normalize LDIF content using flext-core patterns.

        Args:
            content: Raw LDIF content

        Returns:
            FlextResult containing normalized content

        """
        try:
            # Use flext-core string utilities
            normalized = content.strip()

            # Ensure proper line endings
            lines = normalized.split("\n")
            normalized_lines = [line.rstrip() for line in lines]

            # Join with proper newlines and ensure ending newline
            result = "\n".join(normalized_lines)
            if result and not result.endswith("\n"):
                result += "\n"

            return FlextResult[str].ok(result)

        except Exception as e:
            return FlextResult[str].fail(f"Content normalization failed: {e}")

    def extract_dn_from_content(self, content: str) -> FlextResult[str]:
        """Extract DN from LDIF content using flext-core patterns.

        Args:
            content: LDIF content to parse

        Returns:
            FlextResult containing extracted DN

        """
        try:
            # Use flext-core validation first
            validation_result = self.validate_ldif_content(content)
            if validation_result.is_failure:
                error_msg = validation_result.error or "Content validation failed"
                return FlextResult[str].fail(error_msg)

            validated_content = validation_result.unwrap()

            # Find first non-empty line and extract DN
            for line in validated_content.split("\n"):
                stripped_line = line.strip()
                if stripped_line and stripped_line.startswith("dn:"):
                    dn_value = stripped_line[3:].strip()
                    if dn_value:
                        return FlextResult[str].ok(dn_value)

            return FlextResult[str].fail("No DN found in content")

        except Exception as e:
            return FlextResult[str].fail(f"DN extraction failed: {e}")

    def count_entries_in_content(self, content: str) -> FlextResult[int]:
        """Count entries in LDIF content using flext-core patterns.

        Args:
            content: LDIF content to analyze

        Returns:
            FlextResult containing entry count

        """
        try:
            # Use flext-core validation first
            validation_result = self.validate_ldif_content(content)
            if validation_result.is_failure:
                error_msg = validation_result.error or "Content validation failed"
                return FlextResult[int].fail(error_msg)

            validated_content = validation_result.unwrap()

            # Count DN lines (each represents an entry)
            dn_count = 0
            for line in validated_content.split("\n"):
                stripped_line = line.strip()
                if stripped_line.startswith("dn:"):
                    dn_count += 1

            return FlextResult[int].ok(dn_count)

        except Exception as e:
            return FlextResult[int].fail(f"Entry counting failed: {e}")

    def get_file_size_mb(self, file_path: str | Path) -> FlextResult[float]:
        """Get file size in MB using flext-core patterns.

        Args:
            file_path: Path to file

        Returns:
            FlextResult containing file size in MB

        """
        try:
            path_obj = Path(file_path)

            if not path_obj.exists():
                return FlextResult[float].fail(f"File does not exist: {path_obj}")

            size_bytes = path_obj.stat().st_size
            size_mb = size_bytes / (1024 * 1024)

            return FlextResult[float].ok(size_mb)

        except Exception as e:
            return FlextResult[float].fail(f"File size calculation failed: {e}")

    def is_file_too_large(
        self, file_path: str | Path, max_size_mb: int,
    ) -> FlextResult[bool]:
        """Check if file exceeds size limit using flext-core patterns.

        Args:
            file_path: Path to file
            max_size_mb: Maximum size in MB

        Returns:
            FlextResult containing True if file is too large

        """
        try:
            size_result = self.get_file_size_mb(file_path)
            if size_result.is_failure:
                error_msg = size_result.error or "File size calculation failed"
                return FlextResult[bool].fail(error_msg)

            file_size_mb = size_result.unwrap()
            is_too_large = file_size_mb > max_size_mb

            return FlextResult[bool].ok(is_too_large)

        except Exception as e:
            return FlextResult[bool].fail(f"File size check failed: {e}")

    def create_entry_summary(
        self, entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Create entry summary using flext-core patterns.

        Args:
            entry: LDIF entry to summarize

        Returns:
            FlextResult containing entry summary

        """
        try:
            summary = {
                "dn": entry.dn.value,
                "rdn": entry.get_rdn(),
                "parent_dn": entry.get_parent_dn() or "N/A",
                "depth": str(entry.get_dn_depth()),
                "attribute_count": str(len(entry.attributes.data)),
                "total_values": str(entry.attributes.get_total_values()),
                "object_classes": ", ".join(entry.get_object_classes()),
                "is_person": str(entry.is_person_entry()),
                "is_group": str(entry.is_group_entry()),
                "is_organizational_unit": str(entry.is_organizational_unit()),
            }

            return FlextResult[dict[str, str]].ok(summary)

        except Exception as e:
            return FlextResult[dict[str, str]].fail(
                f"Entry summary creation failed: {e}",
            )

    def convert_entry_to_dict(
        self, entry: FlextLdifModels.Entry,
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
                "attributes": dict(entry.attributes.data) if entry.attributes else {},
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
                    validation_result.error or "Invalid DN format",
                )

            # Split by comma and take the last two components as base DN
            components = [comp.strip() for comp in dn.split(",")]
            min_base_dn_components = 2
            if len(components) >= min_base_dn_components:
                base_dn = ",".join(components[-2:])
                return FlextResult[str].ok(base_dn)

            # If less than 2 components, return the DN itself
            return FlextResult[str].ok(dn)
        except Exception as e:
            return FlextResult[str].fail(f"Base DN extraction failed: {e}")

    def validate_ldif_entry_completeness(
        self, entry: FlextLdifModels.Entry,
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
                    validation_result.error or "Entry validation failed",
                )

            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return FlextResult[bool].fail(f"Entry completeness validation failed: {e}")

    def merge_ldif_entries(
        self, entry1: FlextLdifModels.Entry, entry2: FlextLdifModels.Entry,
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
                    "Cannot merge entries with different DNs",
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

    @staticmethod
    def is_ldif_entry_dict(obj: object) -> bool:
        """Type guard for LDIF entry dictionary."""
        return (
            isinstance(obj, dict)
            and "dn" in obj
            and isinstance(obj["dn"], str)
            and "attributes" in obj
            and isinstance(obj["attributes"], dict)
        )

    @staticmethod
    def is_ldif_attribute_dict(obj: object) -> bool:
        """Type guard for LDIF attribute dictionary."""
        return isinstance(obj, dict) and all(
            isinstance(key, str)
            and isinstance(value, list)
            and all(isinstance(item, str) for item in value)
            for key, value in obj.items()
        )

    @staticmethod
    def is_ldif_statistics(obj: object) -> bool:
        """Type guard for LDIF statistics."""
        return isinstance(obj, dict) and all(
            isinstance(key, str) and isinstance(value, (int, float, str, list))
            for key, value in obj.items()
        )

    @staticmethod
    def is_distinguished_name(obj: object) -> bool:
        """Type guard for distinguished name string."""
        return isinstance(obj, str) and len(obj.strip()) > 0 and "=" in obj

    @staticmethod
    def is_ldif_content(obj: object) -> bool:
        """Type guard for LDIF content string."""
        return (
            isinstance(obj, str)
            and len(obj.strip()) > 0
            and obj.strip().startswith("dn:")
        )


__all__ = ["FlextLdifUtilities"]
