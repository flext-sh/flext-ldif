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

from typing import cast

from flext_core import r
from flext_core.utilities import FlextUtilities

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.utilities import FlextLdifUtilities

# Aliases for simplified usage - after all imports
u = FlextUtilities  # Utilities


class FlextLdifEntries(FlextLdifServiceBase[list[FlextLdifModels.Entry]]):
    """Direct entry operations service using flext-core APIs.

    Business Rule: Entries service provides fluent builder pattern for entry operations.
    All operations delegate directly to FlextLdifModels.Entry and FlextLdifUtilities,
    ensuring consistent behavior across the codebase. Operations are immutable - each
    operation returns new entry instances.

    Implication: Service supports method chaining for fluent API usage. Operations like
    remove_operational_attributes, normalize_dns, etc. maintain RFC compliance while
    enabling server-specific transformations via utilities.

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

    @classmethod
    def builder(cls) -> FlextLdifEntries:
        """Create fluent builder instance.

        Returns:
            Service instance for method chaining

        Example:
            result = (
                FlextLdifEntries.builder()
                .with_entries([entry])
                .with_operation("remove_operational_attributes")
                .build()
            )

        """
        return cls()

    def with_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextLdifEntries:
        """Set entries for builder.

        Args:
            entries: List of entries to operate on

        Returns:
            Self for method chaining

        """
        object.__setattr__(self, "_entries", entries)  # noqa: PLC2801
        return self

    def with_operation(
        self,
        operation: str,
    ) -> FlextLdifEntries:
        """Set operation for builder.

        Args:
            operation: Operation to perform

        Returns:
            Self for method chaining

        """
        object.__setattr__(self, "_operation", operation)  # noqa: PLC2801
        return self

    def with_attributes_to_remove(
        self,
        attributes_to_remove: list[str],
    ) -> FlextLdifEntries:
        """Set attributes to remove for builder.

        Args:
            attributes_to_remove: List of attribute names to remove

        Returns:
            Self for method chaining

        """
        object.__setattr__(self, "_attributes_to_remove", attributes_to_remove)  # noqa: PLC2801
        return self

    def build(self) -> list[FlextLdifModels.Entry]:
        """Build and execute the configured operation.

        Returns:
            List of processed entries

        """
        result = self.execute()
        if result.is_failure:
            error_msg = f"Build failed: {result.error}"
            raise RuntimeError(error_msg)
        return result.unwrap()

    def execute(self) -> r[list[FlextLdifModels.Entry]]:
        """Execute the configured operation on entries.

        Business Rule: Execute method routes to appropriate batch operation based on
        configured operation name. Supported operations: "remove_operational_attributes",
        "remove_attributes". Missing operation or invalid configuration results in
        fail-fast error responses.

        Implication: This method enables fluent builder pattern execution. Operations
        are applied to all entries in batch, with fail-fast behavior if any entry
        processing fails.

        Returns:
            FlextResult containing processed entries (immutable - new instances)

        """
        if not self._operation:
            return r.fail("No operation specified")

        if self._operation == "remove_operational_attributes":
            return self.remove_operational_attributes_batch(self._entries)
        if self._operation == "remove_attributes":
            if not self._attributes_to_remove:
                return r.fail(
                    "No attributes_to_remove specified for remove_attributes operation",
                )
            return self.remove_attributes_batch(
                self._entries, self._attributes_to_remove
            )
        return r.fail(f"Unknown operation: {self._operation}")

    def remove_operational_attributes_batch(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> r[list[FlextLdifModels.Entry]]:
        """Remove operational attributes from all entries.

        Business Rule: Batch operation removes operational attributes (RFC 4512) from
        all entries using FlextLdifUtilities.Entry.remove_operational_attributes().
        Operations are immutable - returns new entry instances. Fail-fast behavior:
        if any entry processing fails, entire batch fails.

        Implication: Operational attributes removal maintains RFC compliance while
        cleaning entries for migration or export. Batch processing ensures consistent
        behavior across all entries.

        Args:
            entries: List of entries to process

        Returns:
            FlextResult containing processed entries (operational attributes removed)

        """
        batch_result = u.process(
            entries,
            self.remove_operational_attributes,
            on_error="fail",
        )
        if batch_result.is_failure:
            return r.fail(batch_result.error or "Batch processing failed")
        results = cast("list[FlextLdifModels.Entry]", batch_result.value["results"])
        return r.ok(results)

    def remove_attributes_batch(
        self,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
    ) -> r[list[FlextLdifModels.Entry]]:
        """Remove specified attributes from all entries.

        Business Rule: Batch operation removes specified attributes from all entries.
        Operations are immutable - returns new entry instances. Fail-fast behavior:
        if any entry processing fails, entire batch fails. Empty attribute list results
        in entries returned unchanged.

        Implication: Attribute removal enables selective filtering of entries for
        migration or export. Batch processing ensures consistent behavior across
        all entries.

        Args:
            entries: List of entries to process
            attributes: List of attribute names to remove

        Returns:
            FlextResult containing processed entries (specified attributes removed)

        """
        batch_result = u.process(
            entries,
            lambda entry: self.remove_attributes(entry, attributes),
            on_error="fail",
        )
        if batch_result.is_failure:
            return r.fail(batch_result.error or "Batch processing failed")
        results = cast("list[FlextLdifModels.Entry]", batch_result.value["results"])
        return r.ok(results)

    @staticmethod
    def _extract_dn_from_dict(entry: dict[str, str | list[str]]) -> r[str]:
        """Extract DN from dict entry."""
        dn_value = u.take(entry, "dn")
        if dn_value is None:
            return r.fail("Dict entry missing 'dn' key")
        return r.ok(str(dn_value))

    @staticmethod
    def _extract_dn_from_value(
        dn_value_raw: str | list[str] | None,
    ) -> r[str]:
        """Extract DN string from value (str, list, or None)."""
        return FlextLdifUtilities.match(
            dn_value_raw,
            (type(None), lambda _: r.fail("DN value is None")),
            (str, lambda s: r.ok(s)),
            (list, lambda l: r.ok(str(u.first(l, default="")))),
            default=r.fail("DN value has unexpected type"),
        )

    @staticmethod
    def _extract_dn_from_object(dn_val_raw: object) -> r[str]:
        """Extract DN from object with dn attribute."""
        if dn_val_raw is None:
            return r.fail("Entry missing DN (dn is None)")
        if hasattr(dn_val_raw, "value") and not isinstance(dn_val_raw, str):
            dn_value_raw = u.get(dn_val_raw, "value")
            return FlextLdifEntries._extract_dn_from_value(dn_value_raw)
        if isinstance(dn_val_raw, str):
            return r.ok(dn_val_raw)
        result = u.try_(
            lambda: str(dn_val_raw),
            default=None,
            catch=(ValueError, TypeError),
        )
        if result is not None:
            return r.ok(result)
        return r.fail(f"Failed to extract DN: {type(dn_val_raw)}")

    def get_entry_dn(
        self,
        entry: FlextLdifModels.Entry
        | dict[str, str | list[str]]
        | FlextLdifProtocols.Models.EntryWithDnProtocol,
    ) -> r[str]:
        """Extract DN from entry.

        Business Rule: DN extraction supports multiple entry formats (Entry model, dict,
        EntryWithDnProtocol). Handles DN models with .value attribute and direct string
        DNs. Missing or None DNs result in fail-fast error responses.

        Implication: This method provides flexible DN extraction for various entry formats,
        enabling compatibility with different data sources. DN normalization follows
        RFC 4514 specification.

        Args:
            entry: Entry model, dict, or object implementing EntryWithDnProtocol

        Returns:
            FlextResult containing DN as string (RFC 4514 format)

        """
        if isinstance(entry, dict):
            return FlextLdifEntries._extract_dn_from_dict(entry)
        if hasattr(entry, "dn"):
            return FlextLdifEntries._extract_dn_from_object(entry.dn)
        return r.fail(
            "Entry does not implement EntryWithDnProtocol or Entry protocol",
        )

    @staticmethod
    def _extract_attrs_from_container(
        attrs: object,
    ) -> r[dict[str, list[str]]]:
        """Extract attributes from container object."""
        if hasattr(attrs, "attributes"):
            attrs_dict = attrs.attributes
            return r.ok(dict(attrs_dict) if attrs_dict else {})
        if isinstance(attrs, dict):
            return r.ok(dict(attrs))
        return r.fail(
            f"Unknown attributes container type: {type(attrs)}",
        )

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> r[dict[str, list[str]]]:
        """Extract attributes from entry.

        Business Rule: Attribute extraction handles multiple entry formats per EntryProtocol:
        - LdifAttributes model (has .attributes attribute containing dict[str, list[str]])
        - dict-like objects (used directly)
        - Protocol-compliant objects (structural typing)

        Returns dict[str, list[str]] format for compatibility with legacy code and RFC 2849.
        Missing or None attributes result in fail-fast error responses. Empty attributes
        return empty dict (valid per RFC 2849 § 2.1).

        Implication: This method provides consistent attribute extraction format across
        the codebase. Attribute values are always returned as lists, even for single-value
        attributes. Exception handling ensures robust error reporting for malformed entries.

        Args:
            entry: Entry to extract attributes from (EntryProtocol-compliant)

        Returns:
            FlextResult containing attribute dictionary (dict[str, list[str]])

        """
        # Business Rule: Handle exceptions during attribute extraction
        # EntryProtocol allows various attribute formats, so we need robust extraction
        # Implication: ValueError and AttributeError are caught and converted to FlextResult failures
        try:
            if not hasattr(entry, "attributes"):
                return r.fail("Entry missing attributes attribute")
            attrs = entry.attributes
            if attrs is None:
                return r.fail("Entry has no attributes (attributes is None)")
            if not attrs:
                return r.ok({})
            return FlextLdifEntries._extract_attrs_from_container(attrs)
        except (AttributeError, ValueError) as e:
            # Business Rule: Convert exceptions to FlextResult failures
            # This ensures railway-oriented error handling throughout the codebase
            return r.fail(f"Failed to extract attributes: {e}")

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
    ) -> r[list[str]]:
        """Extract objectClass values from entry.

        Business Rule: objectClass extraction uses case-insensitive attribute matching
        per RFC 4512 § 2.4. objectClass is mandatory per RFC 4511 § 4.1.3, but this
        method handles missing objectClass gracefully by returning failure (not empty list).

        Implication: Case-insensitive matching ensures compatibility with various LDAP
        server implementations that may use different case conventions. Single string
        values are normalized to list format for consistency.

        Args:
            entry: Entry to extract objectClasses from (EntryProtocol-compliant)

        Returns:
            FlextResult containing list of objectClass values (normalized to lowercase
            if case-insensitive matching was used)

        """
        # Business Rule: Delegate to get_entry_attributes for attribute extraction
        # This ensures consistent error handling and attribute format normalization
        # Implication: If attribute extraction fails, objectClass extraction also fails
        attributes_result = self.get_entry_attributes(entry)
        if attributes_result.is_failure:
            return r.fail(
                f"Failed to get entry attributes: {attributes_result.error}"
            )

        attributes = attributes_result.unwrap()
        if not attributes:
            return r.ok([])

        # Business Rule: Case-insensitive search for objectClass attribute per RFC 4512
        # LDAP attribute names are case-insensitive, so we match "objectclass" regardless of case
        # Implication: This handles entries with "objectClass", "objectclass", "OBJECTCLASS", etc.
        objectclasses = u.maybe(
            u.find(
                attributes.items(),
                predicate=lambda kv: u.normalize(kv[0], case="lower") == "objectclass",
            ),
            mapper=lambda kv: kv[1] if kv else None,
        )

        if objectclasses is None:
            return r.fail("Entry is missing objectClass attribute")

        # Business Rule: Normalize single string values to list format
        # This ensures consistent return type (always list[str]) regardless of input format
        # Implication: Single-value objectClass attributes are wrapped in list for consistency
        return FlextLdifUtilities.match(
            objectclasses,
            (str, lambda s: r.ok([s])),
            (list, lambda l: r.ok(list(l))),
            default=r.fail(f"Invalid objectclasses type: {type(objectclasses)}"),
        )

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> r[FlextLdifModels.Entry]:
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
            return r.fail(f"Invalid DN: {dn}")

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
    ) -> r[FlextLdifModels.Entry]:
        """Remove attributes from entry.

        Args:
            entry: Entry to modify
            attributes_to_remove: List of attribute names to remove

        Returns:
            FlextResult containing modified entry

        """
        if not entry.attributes or not entry.attributes.attributes:
            return r.ok(entry)

        # Normalize attribute names to lowercase for case-insensitive comparison
        attrs_to_remove_lower = {attr.lower() for attr in attributes_to_remove}

        # Create new attributes dict without the specified attributes (case-insensitive)
        new_attrs = u.where(
            entry.attributes.attributes,
            predicate=lambda k, v: u.not_(u.in_(k.lower(), attrs_to_remove_lower)),
        )

        # Create new entry with modified attributes
        modified_entry = FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return r.ok(modified_entry)

    def remove_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
        objectclasses_to_remove: list[str],
    ) -> r[FlextLdifModels.Entry]:
        """Remove specific objectClass values from entry.

        Args:
            entry: Entry to modify
            objectclasses_to_remove: List of objectClass values to remove

        Returns:
            FlextResult containing modified entry

        """
        if not entry.attributes or not entry.attributes.attributes:
            return r.ok(entry)

        # Get current objectClass values
        objectclasses_result = self.get_entry_objectclasses(entry)
        if objectclasses_result.is_failure:
            return r.ok(entry)  # No objectClass attribute, nothing to remove

        current_ocs = objectclasses_result.unwrap()
        if not current_ocs:
            return r.ok(entry)  # Empty objectClass list, nothing to remove

        # Normalize objectClass names to lowercase for case-insensitive comparison
        ocs_to_remove_lower = {oc.lower() for oc in objectclasses_to_remove}

        # Filter out objectClasses to remove (case-insensitive)
        new_ocs = u.filter(
            current_ocs,
            predicate=lambda oc: u.not_(u.in_(oc.lower(), ocs_to_remove_lower)),
        )

        # If all objectClasses were removed, return error
        if not new_ocs:
            return r.fail("Cannot remove all objectClass values from entry")

        # Create new attributes dict with updated objectClass
        new_attrs = dict(entry.attributes.attributes)
        new_attrs["objectClass"] = new_ocs

        # Create new entry with modified attributes
        modified_entry = FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=new_attrs),
            metadata=entry.metadata,
        )
        return r.ok(modified_entry)

    def get_attribute_values(
        self,
        attribute: list[str] | str,
    ) -> r[list[str]]:
        """Extract values from attribute.

        Args:
            attribute: Attribute value(s) to extract

        Returns:
            FlextResult containing list of string values

        """
        if isinstance(attribute, str):
            return r.ok([attribute])
        if isinstance(attribute, list):
            return r.ok(attribute)
        # Check if it's a protocol with values attribute (not a list)
        if hasattr(attribute, "values") and not isinstance(attribute, (list, tuple)):
            values = getattr(attribute, "values", None)
            if isinstance(values, str):
                return r.ok([values])
            if isinstance(values, (list, tuple)):
                return r.ok(list(values))
        # Try to iterate if it's iterable
        try:
            return r.ok(list(attribute))
        except TypeError:
            # Not iterable - return error for unsupported type
            return r.fail(
                f"Unsupported attribute type: {type(attribute).__name__}"
            )

    def get_entry_attribute(
        self,
        entry: FlextLdifModels.Entry,
        attribute_name: str,
    ) -> r[list[str]]:
        """Get a specific attribute from entry.

        Args:
            entry: Entry to extract attribute from
            attribute_name: Name of attribute to get

        Returns:
            FlextResult containing attribute values as list

        """
        if not entry.attributes or not entry.attributes.attributes:
            return r.fail(f"Attribute '{attribute_name}' not found")

        value = u.take(entry.attributes.attributes, attribute_name)
        if value is None:
            return r.fail(f"Attribute '{attribute_name}' not found")

        return FlextLdifUtilities.match(
            value,
            (str, lambda s: r.ok([s])),
            default=lambda v: r.ok(list(v)),
        )

    @staticmethod
    def _normalize_string_value(value: str) -> r[str]:
        """Normalize string value."""
        stripped = value.strip()
        if not stripped:
            return r.fail("Cannot normalize empty string")
        return r.ok(stripped)

    @staticmethod
    def _normalize_list_value(value: list[str]) -> r[str]:
        """Normalize list value to single string."""
        if u.empty(value):
            return r.fail("Cannot normalize empty list")
        first = u.first(value)
        return FlextLdifUtilities.match(
            first,
            (str, FlextLdifEntries._normalize_string_value),
            default=lambda f: r.ok(str(f)) if f is not None else r.fail("Cannot normalize empty list"),
        )

    def normalize_attribute_value(
        self,
        value: str | list[str] | None,
    ) -> r[str]:
        """Normalize attribute value to single string.

        Args:
            value: Value to normalize (string, list, or None)

        Returns:
            FlextResult containing normalized string value

        """
        if value is None:
            return r.fail("Cannot normalize None value")
        return FlextLdifUtilities.match(
            value,
            (str, FlextLdifEntries._normalize_string_value),
            (list, FlextLdifEntries._normalize_list_value),
            default=r.fail(f"Cannot normalize value of type {type(value)}"),
        )

    def get_normalized_attribute(
        self,
        entry: FlextLdifModels.Entry,
        attribute_name: str,
    ) -> r[str]:
        """Get normalized (single string) value for attribute.

        Args:
            entry: Entry to extract attribute from
            attribute_name: Name of attribute to get

        Returns:
            FlextResult containing normalized string value

        """
        result = self.get_entry_attribute(entry, attribute_name)
        if result.is_failure:
            return r.fail(f"Attribute '{attribute_name}' not found")

        values = result.unwrap()
        return self.normalize_attribute_value(values)

    def remove_operational_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> r[FlextLdifModels.Entry]:
        """Remove operational attributes from entry.

        Business Rule: Operational attributes removal uses FlextLdifUtilities.Entry
        for RFC 4512 compliant detection. Operation is immutable - returns new entry
        instance with operational attributes removed. Entry metadata is preserved.

        Implication: This method enables cleaning entries for migration or export
        while maintaining RFC compliance. Operational attributes are identified per
        RFC 4512 specification.

        Args:
            entry: Entry to process

        Returns:
            FlextResult containing new entry instance (operational attributes removed)

        Note:
            Operational attributes typically include:
            - createTimestamp
            - modifyTimestamp
            - creatorsName
            - modifiersName
            - entryUUID
            - etc.

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
            return r.ok(entry)

        # Create normalized set for case-insensitive comparison
        operational_attrs_lower = {attr.lower() for attr in operational_attrs}

        # Create new attributes dict without operational attributes (case-insensitive)
        new_attrs = {
            u.where(
                entry.attributes.attributes,
                predicate=lambda k, v: u.not_(u.in_(k.lower(), operational_attrs_lower)),
            )
        }

        # Create new entry with modified attributes
        modified_entry = FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return r.ok(modified_entry)


__all__ = ["FlextLdifEntries"]
