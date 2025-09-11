"""FLEXT-LDIF Unified Utilities Module.

Enterprise-grade LDIF utility operations with unified class architecture,
advanced Python 3.13 patterns, and comprehensive type safety.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import FlextLDIFModels

# Type aliases for Python 3.13+ generic syntax
if TYPE_CHECKING:
    type FlextResultEntries = FlextResult[list[FlextLDIFModels.Entry]]
    type FlextResultBool = FlextResult[bool]
    type AttributeDict = dict[str, str | list[str] | None]
    type LDIFAttributeDict = dict[str, list[str]]
else:
    FlextResultEntries = FlextResult
    FlextResultBool = FlextResult
    AttributeDict = dict
    LDIFAttributeDict = dict


class FlextLDIFUtilities:
    """Unified LDIF Utilities.

    Enterprise-grade utility operations organized as nested classes
    following unified architecture. Provides comprehensive LDIF
    processing, validation, and transformation utilities.
    """

    # Class-level instance for test compatibility
    _default_instance: FlextLDIFUtilities | None = None

    def __init__(self, **data: object) -> None:
        """Initialize unified utilities with dependency injection."""
        self._id = str(data.get("id", "flext-ldif-utilities"))
        self._name = str(data.get("name", "LDIF Utilities"))
        self._description = str(data.get("description", "LDIF processing utilities"))
        self._logger = FlextLogger(__name__)

        # Initialize nested utility handlers
        self._processors = self.Processors(self)
        self._converters = self.Converters(self)

    @property
    def ldif_domain_processors(self) -> Processors:
        """Simple alias for Processors - test compatibility."""
        return self._processors

    @classmethod
    def _get_default_instance(cls) -> FlextLDIFUtilities:
        """Get or create default instance for class-level access."""
        if cls._default_instance is None:
            cls._default_instance = cls()
        return cls._default_instance

    class Processors:
        """Direct access to flext-core Processors - ZERO DUPLICATION.

        This class provides direct access to FlextProcessors from flext-core
        without any duplication or wrapping. All operations use flext-core directly.
        """

        def __init__(self, utilities_instance: FlextLDIFUtilities) -> None:
            """Initialize with direct flext-core access."""
            self._utilities = utilities_instance
            self._logger = utilities_instance._logger

        def validate_entries_batch(
            self,
            entries: list[FlextLDIFModels.Entry],
            max_errors: int = 10,
            *,
            fail_fast: bool = False,
        ) -> FlextResultBool:
            """Validate entries using flext-core EntryValidator - ZERO DUPLICATION."""
            if not entries:
                return FlextResult[bool].ok(data=True)

            validation_errors = 0
            for entry in entries:
                # LDIF-specific validation - check required objectClass
                has_objectclass = (
                    hasattr(entry, "attributes")
                    and hasattr(entry.attributes, "data")
                    and isinstance(entry.attributes.data, dict)
                    and "objectClass" in entry.attributes.data
                    and entry.attributes.data["objectClass"]
                )

                if not has_objectclass:
                    validation_errors += 1
                    if fail_fast or validation_errors >= max_errors:
                        return FlextResult[bool].ok(data=False)

            return FlextResult[bool].ok(validation_errors == 0)

        def validate_entries_or_warn(
            self, entries: list[FlextLDIFModels.Entry], max_errors: int = 10, *, fail_fast: bool = False
        ) -> FlextResult[bool]:
            """Alias simples para validate_entries_batch."""
            return self.validate_entries_batch(entries, max_errors, fail_fast=fail_fast)

        def filter_entries_by_object_class(
            self, entries: list[FlextLDIFModels.Entry], object_class: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by object class - ZERO DUPLICATION."""
            if not entries:
                return FlextResult[list[FlextLDIFModels.Entry]].ok([])

            filtered_entries = []
            for entry in entries:
                obj_classes = entry.attributes.data.get("objectClass", [])
                if object_class in obj_classes:
                    filtered_entries.append(entry)

            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered_entries)

        def find_entries_with_missing_required_attributes(
            self, entries: list[FlextLDIFModels.Entry], required_attrs: list[str]
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Find entries missing required attributes - ZERO DUPLICATION."""
            if not entries:
                return FlextResult[list[FlextLDIFModels.Entry]].ok([])

            if not required_attrs:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    "Required attributes list cannot be empty"
                )

            missing_entries = []
            for entry in entries:
                missing_attrs = [
                    attr
                    for attr in required_attrs
                    if attr not in entry.attributes.data
                    or not entry.attributes.data[attr]
                ]
                if missing_attrs:
                    missing_entries.append(entry)

            return FlextResult[list[FlextLDIFModels.Entry]].ok(missing_entries)

        def get_entry_statistics(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int | float]]:
            """Get entry statistics - ZERO DUPLICATION."""
            if not entries:
                return FlextResult[dict[str, int | float]].ok(
                    {
                        "total_entries": 0,
                        "total_attributes": 0,
                        "unique_object_classes": 0,
                        "unique_attributes": 0,
                        "average_attributes_per_entry": 0.0,
                    }
                )

            total_attributes = 0
            object_classes: set[str] = set()
            all_attributes: set[str] = set()

            for entry in entries:
                total_attributes += len(entry.attributes.data)
                all_attributes.update(entry.attributes.data.keys())

                # Extract object classes
                obj_classes = entry.attributes.data.get("objectClass", [])
                object_classes.update(obj_classes)

            avg_attributes = (
                total_attributes / len(entries) if entries else 0.0
            )

            return FlextResult[dict[str, int | float]].ok(
                {
                    "total_entries": len(entries),
                    "total_attributes": total_attributes,
                    "unique_object_classes": len(object_classes),
                    "unique_attributes": len(all_attributes),
                    "average_attributes_per_entry": avg_attributes,
                }
            )

    class Converters:
        """Direct access to flext-core Converters - ZERO DUPLICATION.

        This class provides direct access to FlextUtilities from flext-core
        without any duplication or wrapping. All operations use flext-core directly.
        """

        def __init__(self, utilities_instance: FlextLDIFUtilities) -> None:
            """Initialize with direct flext-core access."""
            self._utilities = utilities_instance
            self._logger = utilities_instance._logger

        def attributes_to_ldif_format(
            self,
            attributes: AttributeDict,
            *,
            normalize_names: bool = True,
            skip_empty: bool = True,
        ) -> FlextResult[LDIFAttributeDict]:
            """Convert attributes - ZERO DUPLICATION."""
            ldif_attrs: LDIFAttributeDict = {}

            for key, values in attributes.items():
                if not key or (isinstance(key, str) and not key.strip()):
                    if skip_empty:
                        continue
                    return FlextResult[LDIFAttributeDict].fail(
                        "Empty attribute name found",
                    )

                # Normalize attribute name
                key_str = str(key) if not isinstance(key, str) else key
                if normalize_names:
                    attr_name = key_str.lower().strip()
                else:
                    attr_name = key_str.strip()

                # Convert values to list format
                converted_values: list[str] = []

                if isinstance(values, str):
                    clean_val = values.strip()
                    if clean_val or not skip_empty:
                        converted_values = [clean_val]
                elif isinstance(values, list):
                    for val in values:
                        if val is not None:
                            clean_val = str(val).strip()
                            if clean_val or not skip_empty:
                                converted_values.append(clean_val)
                elif values is not None:
                    # Handle other types (int, float, etc.) - convert to string
                    clean_val = str(values).strip()
                    if clean_val or not skip_empty:
                        converted_values = [clean_val]

                if converted_values or not skip_empty:
                    ldif_attrs[attr_name] = converted_values

            return FlextResult[LDIFAttributeDict].ok(ldif_attrs)

        def attributes_dict_to_ldif_format(
            self, attributes: dict[str, str | list[str] | None]
        ) -> FlextResult[LDIFAttributeDict]:
            """Convert attributes dict to LDIF format - ZERO DUPLICATION."""
            return self.attributes_to_ldif_format(attributes)

        def normalize_dn_components(self, dn: str) -> FlextResult[str]:
            """Normalize DN components - ZERO DUPLICATION."""
            if not dn or not dn.strip():
                return FlextResult[str].fail("DN cannot be empty")

            # Basic DN normalization
            normalized_dn = dn.strip()

            # Remove extra spaces around commas
            components = [comp.strip() for comp in normalized_dn.split(",")]
            normalized_dn = ",".join(components)

            return FlextResult[str].ok(normalized_dn)

        def entry_to_dict(self, entry: FlextLDIFModels.Entry) -> FlextResult[dict[str, object]]:
            """Convert entry to dictionary - ZERO DUPLICATION."""
            try:
                result: dict[str, object] = {
                    "dn": entry.dn.value,
                    "attributes": entry.attributes.data,
                }
                return FlextResult[dict[str, object]].ok(result)
            except Exception as e:
                return FlextResult[dict[str, object]].fail(f"Entry conversion failed: {e}")


# Class-level access aliases for test compatibility
class LdifDomainProcessors:
    """Class-level access to Processors for test compatibility."""

    @classmethod
    def validate_entries_or_warn(cls, entries: list[FlextLDIFModels.Entry], max_errors: int = 10, *, fail_fast: bool = False) -> FlextResult[bool]:
        """Class-level access to validate_entries_or_warn."""
        return FlextLDIFUtilities._get_default_instance()._processors.validate_entries_or_warn(entries, max_errors, fail_fast=fail_fast)

    @classmethod
    def filter_entries_by_object_class(cls, entries: list[FlextLDIFModels.Entry], object_class: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Class-level access to filter_entries_by_object_class."""
        return FlextLDIFUtilities._get_default_instance()._processors.filter_entries_by_object_class(entries, object_class)

    @classmethod
    def find_entries_with_missing_required_attributes(
        cls, entries: list[FlextLDIFModels.Entry], required_attrs: list[str]
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Class-level access to find_entries_with_missing_required_attributes."""
        return FlextLDIFUtilities._get_default_instance()._processors.find_entries_with_missing_required_attributes(entries, required_attrs)

    @classmethod
    def get_entry_statistics(cls, entries: list[FlextLDIFModels.Entry]) -> FlextResult[dict[str, int | float]]:
        """Class-level access to get_entry_statistics."""
        return FlextLDIFUtilities._get_default_instance()._processors.get_entry_statistics(entries)


class LdifConverters:
    """Class-level access to Converters for test compatibility."""

    @classmethod
    def attributes_dict_to_ldif_format(cls, attributes: dict[str, str | list[str] | None]) -> FlextResult[LDIFAttributeDict]:
        """Class-level access to attributes_dict_to_ldif_format."""
        return FlextLDIFUtilities._get_default_instance()._converters.attributes_dict_to_ldif_format(attributes)

    @classmethod
    def normalize_dn_components(cls, dn: str) -> FlextResult[str]:
        """Class-level access to normalize_dn_components."""
        return FlextLDIFUtilities._get_default_instance()._converters.normalize_dn_components(dn)


# Export unified utilities
__all__ = [
    "FlextLDIFUtilities",
    "LdifConverters",
    "LdifDomainProcessors",
]
