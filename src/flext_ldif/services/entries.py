"""Entries Service - Direct Entry Operations with flext-core APIs.

This service provides direct entry operations using flext-core and flext-ldif APIs:
- Direct use of FlextLdifModels.Entry for entry operations
- Direct use of FlextLdifUtilities for DN and attribute operations
- No unnecessary validation wrappers or conversions
- Railway-oriented error handling with FlextResult

Single Responsibility: Provide entry operations using direct APIs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifEntries(FlextLdifServiceBase[list[FlextLdifModels.Entry]]):
    """Direct entry operations service using flext-core APIs.

    This service provides minimal, direct entry operations by delegating
    to FlextLdifModels.Entry and FlextLdifUtilities for all logic.
    No unnecessary abstraction layers or validation wrappers.
    """

    def __init__(
        self,
        entries: list[FlextLdifModels.Entry] | None = None,
        operation: str | None = None,
        attributes_to_remove: list[str] | None = None,
    ) -> None:
        """Initialize entries service.

        Args:
            entries: List of entries to operate on
            operation: Operation to perform (for execute method)
            attributes_to_remove: List of attribute names to remove (for remove_attributes operation)

        """
        super().__init__()
        self._entries = entries or []
        self._operation = operation
        self._attributes_to_remove = attributes_to_remove or []

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute the configured operation on entries.

        Returns:
            FlextResult containing processed entries

        """
        if not self._operation:
            return FlextResult.fail("No operation specified")

        if self._operation == "remove_operational_attributes":
            return self.remove_operational_attributes_batch(self._entries)
        if self._operation == "remove_attributes":
            if not self._attributes_to_remove:
                return FlextResult.fail(
                    "No attributes_to_remove specified for remove_attributes operation",
                )
            return self.remove_attributes_batch(self._entries, self._attributes_to_remove)
        return FlextResult.fail(f"Unknown operation: {self._operation}")

    def remove_operational_attributes_batch(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove operational attributes from all entries."""
        result = []
        for entry in entries:
            processed = self.remove_operational_attributes(entry)
            if processed.is_failure:
                return FlextResult.fail(f"Failed to process entry: {processed.error}")
            result.append(processed.value)
        return FlextResult.ok(result)

    def remove_attributes_batch(
        self,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove specified attributes from all entries."""
        result = []
        for entry in entries:
            processed = self.remove_attributes(entry, attributes)
            if processed.is_failure:
                return FlextResult.fail(f"Failed to process entry: {processed.error}")
            result.append(processed.value)
        return FlextResult.ok(result)

    def get_entry_dn(
        self,
        entry: FlextLdifModels.Entry
        | dict[str, str | list[str]]
        | FlextLdifProtocols.Models.EntryWithDnProtocol,
    ) -> FlextResult[str]:
        """Extract DN from entry.

        Args:
            entry: Entry model, dict, or object implementing
                EntryWithDnProtocol to extract DN from

        Returns:
            FlextResult containing DN as string

        """
        if isinstance(entry, dict):
            dn_val = entry.get("dn")
            if not dn_val:
                return FlextResult.fail("Dict entry missing 'dn' key")
            return FlextResult.ok(str(dn_val))

        # Check if it's an EntryWithDnProtocol (has dn attribute)
        if hasattr(entry, "dn"):
            dn_val_raw = entry.dn
            # Handle None DN
            if dn_val_raw is None:
                return FlextResult.fail("Entry missing DN (dn is None)")
            # Check if dn_val has .value attribute (DN model with value field)
            if hasattr(dn_val_raw, "value") and not isinstance(dn_val_raw, str):
                # dn_val_raw.value can be str | list[str] | None
                dn_value_raw = getattr(dn_val_raw, "value", None)
                if dn_value_raw is None:
                    return FlextResult.fail("DN value is None")
                # Convert to string for return
                if isinstance(dn_value_raw, str):
                    return FlextResult.ok(dn_value_raw)
                if isinstance(dn_value_raw, list):
                    # For list, join or use first element (depends on DN structure)
                    return FlextResult.ok(str(dn_value_raw[0]) if dn_value_raw else "")
                return FlextResult.fail("DN value has unexpected type")
            # Direct string DN
            if isinstance(dn_val_raw, str):
                return FlextResult.ok(dn_val_raw)
            # Try to convert to string, handle exceptions
            try:
                return FlextResult.ok(str(dn_val_raw))
            except (ValueError, TypeError) as e:
                return FlextResult.fail(f"Failed to extract DN: {e}")

        return FlextResult.fail(
            "Entry does not implement EntryWithDnProtocol or Entry protocol",
        )

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, list[str]]]:
        """Extract attributes from entry.

        Args:
            entry: Entry to extract attributes from

        Returns:
            FlextResult containing attribute dictionary

        """
        # Check if entry has attributes attribute (handle exceptions)
        try:
            if not hasattr(entry, "attributes"):
                return FlextResult.fail("Entry missing attributes attribute")
            # Verify attributes exists - None means failure
            if entry.attributes is None:
                return FlextResult.fail("Entry has no attributes (attributes is None)")
            # Verify attributes is LdifAttributes instance
            if not entry.attributes:
                return FlextResult.ok({})
            # Check if attributes is LdifAttributes (has .attributes attribute)
            if not hasattr(entry.attributes, "attributes"):
                # If it's a dict-like object, try to use it directly
                if isinstance(entry.attributes, dict):
                    return FlextResult.ok(dict(entry.attributes))
                return FlextResult.fail(
                    f"Unknown attributes container type: {type(entry.attributes)}",
                )
            if not entry.attributes.attributes:
                return FlextResult.ok({})

            # Return attributes directly from entry
            return FlextResult.ok(dict(entry.attributes.attributes))
        except (AttributeError, ValueError) as e:
            return FlextResult.fail(f"Failed to extract attributes: {e}")

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[list[str]]:
        """Extract objectClass values from entry.

        Args:
            entry: Entry to extract objectClasses from

        Returns:
            FlextResult containing list of objectClass values

        """
        # First get attributes - if this fails, return failure
        attributes_result = self.get_entry_attributes(entry)
        if attributes_result.is_failure:
            return FlextResult.fail(
                f"Failed to get entry attributes: {attributes_result.error}"
            )

        attributes = attributes_result.unwrap()
        if not attributes:
            return FlextResult.ok([])

        # Case-insensitive search for objectClass attribute
        objectclasses: list[str] | str | None = None
        for key, value in attributes.items():
            if key.lower() == "objectclass":
                objectclasses = value
                break

        if objectclasses is None:
            return FlextResult.fail("Entry is missing objectClass attribute")

        if isinstance(objectclasses, str):
            return FlextResult.ok([objectclasses])
        return FlextResult.ok(list(objectclasses))

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create a new entry.

        Args:
            dn: Distinguished Name for the entry
            attributes: Attribute dictionary
            objectclasses: Optional objectClass values

        Returns:
            FlextResult containing new Entry

        """
        # Validate DN using FlextLdifUtilities.DN
        if not FlextLdifUtilities.DN.validate(dn):
            return FlextResult.fail(f"Invalid DN: {dn}")

        # Prepare attributes
        final_attrs = dict(attributes)
        if objectclasses:
            final_attrs["objectClass"] = objectclasses

        # Use FlextLdifModels.Entry.create directly
        return FlextLdifModels.Entry.create(dn=dn, attributes=final_attrs)

    def remove_attributes(
        self,
        entry: FlextLdifModels.Entry,
        attributes_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes from entry.

        Args:
            entry: Entry to modify
            attributes_to_remove: List of attribute names to remove

        Returns:
            FlextResult containing modified entry

        """
        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult.ok(entry)

        # Normalize attribute names to lowercase for case-insensitive comparison
        attrs_to_remove_lower = {attr.lower() for attr in attributes_to_remove}

        # Create new attributes dict without the specified attributes (case-insensitive)
        new_attrs = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove_lower
        }

        # Create new entry with modified attributes
        modified_entry = FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return FlextResult.ok(modified_entry)

    def remove_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
        objectclasses_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specific objectClass values from entry.

        Args:
            entry: Entry to modify
            objectclasses_to_remove: List of objectClass values to remove

        Returns:
            FlextResult containing modified entry

        """
        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult.ok(entry)

        # Get current objectClass values
        objectclasses_result = self.get_entry_objectclasses(entry)
        if objectclasses_result.is_failure:
            return FlextResult.ok(entry)  # No objectClass attribute, nothing to remove

        current_ocs = objectclasses_result.unwrap()
        if not current_ocs:
            return FlextResult.ok(entry)  # Empty objectClass list, nothing to remove

        # Normalize objectClass names to lowercase for case-insensitive comparison
        ocs_to_remove_lower = {oc.lower() for oc in objectclasses_to_remove}

        # Filter out objectClasses to remove (case-insensitive)
        new_ocs = [
            oc for oc in current_ocs if oc.lower() not in ocs_to_remove_lower
        ]

        # If all objectClasses were removed, return error
        if not new_ocs:
            return FlextResult.fail(
                "Cannot remove all objectClass values from entry"
            )

        # Create new attributes dict with updated objectClass
        new_attrs = dict(entry.attributes.attributes)
        new_attrs["objectClass"] = new_ocs

        # Create new entry with modified attributes
        modified_entry = FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=new_attrs),
            metadata=entry.metadata,
        )
        return FlextResult.ok(modified_entry)

    def get_attribute_values(
        self,
        attribute: list[str] | str,
    ) -> FlextResult[list[str]]:
        """Extract values from attribute.

        Args:
            attribute: Attribute value(s) to extract

        Returns:
            FlextResult containing list of string values

        """
        if isinstance(attribute, str):
            return FlextResult.ok([attribute])
        if isinstance(attribute, list):
            return FlextResult.ok(attribute)
        # Check if it's a protocol with values attribute (not a list)
        if hasattr(attribute, "values") and not isinstance(attribute, (list, tuple)):
            values = getattr(attribute, "values", None)
            if isinstance(values, str):
                return FlextResult.ok([values])
            if isinstance(values, (list, tuple)):
                return FlextResult.ok(list(values))
        # Try to iterate if it's iterable
        try:
            return FlextResult.ok(list(attribute))
        except TypeError:
            # Not iterable - return error for unsupported type
            return FlextResult.fail(
                f"Unsupported attribute type: {type(attribute).__name__}"
            )

    def get_entry_attribute(
        self,
        entry: FlextLdifModels.Entry,
        attribute_name: str,
    ) -> FlextResult[list[str]]:
        """Get a specific attribute from entry.

        Args:
            entry: Entry to extract attribute from
            attribute_name: Name of attribute to get

        Returns:
            FlextResult containing attribute values as list

        """
        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult.fail(f"Attribute '{attribute_name}' not found")

        value = entry.attributes.attributes.get(attribute_name)
        if value is None:
            return FlextResult.fail(f"Attribute '{attribute_name}' not found")

        if isinstance(value, str):
            return FlextResult.ok([value])
        return FlextResult.ok(list(value))

    def normalize_attribute_value(
        self,
        value: str | list[str] | None,
    ) -> FlextResult[str]:
        """Normalize attribute value to single string.

        Args:
            value: Value to normalize (string, list, or None)

        Returns:
            FlextResult containing normalized string value

        """
        if value is None:
            return FlextResult.fail("Cannot normalize None value")
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return FlextResult.fail("Cannot normalize empty string")
            return FlextResult.ok(stripped)
        if isinstance(value, list):
            if len(value) == 0:
                return FlextResult.fail("Cannot normalize empty list")
            first = value[0]
            if isinstance(first, str):
                stripped = first.strip()
                if not stripped:
                    return FlextResult.fail("Cannot normalize empty string")
                return FlextResult.ok(stripped)
            return FlextResult.ok(str(first))
        return FlextResult.fail(f"Cannot normalize value of type {type(value)}")

    def get_normalized_attribute(
        self,
        entry: FlextLdifModels.Entry,
        attribute_name: str,
    ) -> FlextResult[str]:
        """Get normalized (single string) value for attribute.

        Args:
            entry: Entry to extract attribute from
            attribute_name: Name of attribute to get

        Returns:
            FlextResult containing normalized string value

        """
        result = self.get_entry_attribute(entry, attribute_name)
        if result.is_failure:
            return FlextResult.fail(f"Attribute '{attribute_name}' not found")

        values = result.unwrap()
        return self.normalize_attribute_value(values)

    def remove_operational_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove operational attributes from entry.

        Operational attributes typically include:
        - createTimestamp
        - modifyTimestamp
        - creatorsName
        - modifiersName
        - entryUUID
        - etc.

        Args:
            entry: Entry to modify

        Returns:
            FlextResult containing modified entry

        """
        operational_attrs = {
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
            "entryUUID",
            "entryDN",
            "subschemaSubentry",
            "hasSubordinates",
            "numSubordinates",
            "structuralObjectClass",
            "governingStructureRule",
            "entryCSN",
            "contextCSN",
        }

        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult.ok(entry)

        # Create normalized set for case-insensitive comparison
        operational_attrs_lower = {attr.lower() for attr in operational_attrs}

        # Create new attributes dict without operational attributes (case-insensitive)
        new_attrs = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in operational_attrs_lower
        }

        # Create new entry with modified attributes
        modified_entry = FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return FlextResult.ok(modified_entry)


__all__ = ["FlextLdifEntries"]
