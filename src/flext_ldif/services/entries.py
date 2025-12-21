"""Entries Service - Direct Entry Operations with flext-core APIs.

This service provides direct entry operations using flext-core and flext-ldif APIs:
- Direct use of m.Ldif.Entry for entry operations
- Direct use of u for DN and attribute operations
- No unnecessary validation wrappers or conversions
- Railway-oriented error handling with r

Single Responsibility: Provide entry operations using direct APIs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from typing import Self

from flext_core import FlextTypes, r

from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.functional import FlextFunctional
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.utilities import u


class FlextLdifEntries(FlextLdifServiceBase[list[m.Ldif.Entry]]):
    """Direct entry operations service using flext-core APIs.

    Business Rule: Entries service provides fluent builder pattern for entry operations.
    All operations delegate directly to m.Ldif.Entry and u,
    ensuring consistent behavior across the codebase. Operations are immutable - each
    operation returns new entry instances.

    Implication: Service supports method chaining for fluent API usage. Operations like
    remove_operational_attributes, normalize_dns, etc. maintain RFC compliance while
    enabling server-specific transformations via utilities.

    This service provides minimal, direct entry operations by delegating
    to m.Ldif.Entry and u for all logic.
    No unnecessary abstraction layers or validation wrappers.
    """

    def __init__(
        self,
        entries: list[m.Ldif.Entry] | None = None,
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
    def builder(cls) -> Self:
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
        entries: list[m.Ldif.Entry],
    ) -> Self:
        """Set entries for builder.

        Args:
            entries: List of entries to operate on

        Returns:
            Self for method chaining

        """
        self._entries = entries
        return self

    def with_operation(
        self,
        operation: str,
    ) -> Self:
        """Set operation for builder.

        Args:
            operation: Operation to perform

        Returns:
            Self for method chaining

        """
        self._operation = operation
        return self

    def with_attributes_to_remove(
        self,
        attributes_to_remove: list[str],
    ) -> Self:
        """Set attributes to remove for builder.

        Args:
            attributes_to_remove: List of attribute names to remove

        Returns:
            Self for method chaining

        """
        self._attributes_to_remove = attributes_to_remove
        return self

    def build(self) -> list[m.Ldif.Entry]:
        """Build and execute the configured operation.

        Returns:
            List of processed entries

        """
        result = self.execute()
        if result.is_failure:
            error_msg = f"Build failed: {result.error}"
            raise RuntimeError(error_msg)
        return result.value

    def execute(self) -> r[list[m.Ldif.Entry]]:
        """Execute the configured operation on entries.

        Business Rule: Execute method routes to appropriate batch operation based on
        configured operation name. Supported operations: "remove_operational_attributes",
        "remove_attributes". Missing operation or invalid configuration results in
        fail-fast error responses.

        Implication: This method enables fluent builder pattern execution. Operations
        are applied to all entries in batch, with fail-fast behavior if any entry
        processing fails.

        Returns:
            r containing processed entries (immutable - new instances)

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
                self._entries,
                self._attributes_to_remove,
            )
        return r.fail(f"Unknown operation: {self._operation}")

    @staticmethod
    def remove_operational_attributes_batch(
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Remove operational attributes from all entries.

        Business Rule: Batch operation removes operational attributes (RFC 4512) from
        all entries using FlextLdifUtilitiesEntry.remove_operational_attributes().
        Operations are immutable - returns new entry instances. Fail-fast behavior:
        if any entry processing fails, entire batch fails.

        Implication: Operational attributes removal maintains RFC compliance while
        cleaning entries for migration or export. Batch processing ensures consistent
        behavior across all entries.

        Args:
            entries: List of entries to process

        Returns:
            r containing processed entries (operational attributes removed)

        """

        # batch() expects Callable[[T], R | r[R]]
        # When operation returns r[R], batch extracts .value to get R
        # So R = Entry (not r[Entry]), and batch returns r[BatchResultDict] with results: list[Entry]
        def remove_op_attrs_wrapper(
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Wrapper for remove_operational_attributes."""
            return FlextLdifEntries.remove_operational_attributes(entry)

        # Type annotation helps mypy infer T = Entry, R = Entry
        # Direct iteration instead of u.Collection.batch
        operation_fn: Callable[
            [m.Ldif.Entry],
            m.Ldif.Entry | r[m.Ldif.Entry],
        ] = remove_op_attrs_wrapper
        results: list[m.Ldif.Entry] = []
        for entry in entries:
            try:
                result = operation_fn(entry)
                # Handle both direct return and FlextResult return
                if isinstance(result, r):
                    if result.is_success and isinstance(result.value, m.Ldif.Entry):
                        results.append(result.value)
                    else:
                        return r.fail(result.error or "Failed to process entry")
                elif isinstance(result, m.Ldif.Entry):
                    results.append(result)
            except Exception as exc:
                return r.fail(f"Batch processing failed: {exc}")
        return r.ok(results)

    def remove_attributes_batch(
        self,
        entries: list[m.Ldif.Entry],
        attributes: list[str],
    ) -> r[list[m.Ldif.Entry]]:
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
            r containing processed entries (specified attributes removed)

        """

        # batch() expects Callable[[T], R | r[R]]
        # When operation returns r[R], batch extracts .value to get R
        # So R = Entry (not r[Entry]), and batch returns r[BatchResultDict] with results: list[Entry]
        def remove_attrs_wrapper(
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Wrapper for remove_attributes."""
            return FlextLdifEntries.remove_attributes(entry, attributes)

        # Direct iteration instead of u.Collection.batch
        # Type annotation helps mypy infer T = Entry, R = Entry
        # When operation returns r[Entry], we extract .value, so R = Entry
        operation_fn: Callable[
            [m.Ldif.Entry],
            m.Ldif.Entry | r[m.Ldif.Entry],
        ] = remove_attrs_wrapper
        results: list[m.Ldif.Entry] = []
        for entry in entries:
            try:
                result = operation_fn(entry)
                # Handle both direct return and FlextResult return
                if isinstance(result, r):
                    if result.is_success and isinstance(result.value, m.Ldif.Entry):
                        results.append(result.value)
                    else:
                        return r.fail(result.error or "Failed to process entry")
                elif isinstance(result, m.Ldif.Entry):
                    results.append(result)
            except Exception as exc:
                return r.fail(f"Batch processing failed: {exc}")
        return r.ok(results)

    @staticmethod
    def _extract_dn_from_dict(entry: dict[str, str | list[str]]) -> r[str]:
        """Extract DN from dict entry."""
        # Type narrowing: dict entry has 'dn' key with str | list[str] value
        dn_value = entry.get("dn")
        if dn_value is None:
            return r.fail("Dict entry missing 'dn' key")
        # Type narrowing: dn_value is str | list[str] after None check
        return r.ok(str(dn_value))

    @staticmethod
    def _extract_dn_from_value(
        dn_value_raw: str | list[str] | None,
    ) -> r[str]:
        """Extract DN string from value (str, list, or None) using DSL pattern."""

        # Use named functions instead of lambdas for clarity (DSL pattern)
        def handle_none(_value: None) -> r[str]:
            """Handle None case."""
            return r.fail("DN value is None")

        def handle_str(value: str) -> r[str]:
            """Handle string case."""
            return r.ok(value)

        def handle_list(value_list: list[str]) -> r[str]:
            """Handle list case - extract first item."""
            first_dn = value_list[0] if value_list else ""
            return r.ok(str(first_dn))

        # Type narrowing: match always returns r[str] because default is not None
        match_result: r[str] = FlextFunctional.match(
            dn_value_raw,
            (type(None), handle_none),
            (str, handle_str),
            (list, handle_list),
            default=r.fail("DN value has unexpected type"),
        )
        return match_result

    @staticmethod
    def _extract_dn_from_object(dn_val_raw: object) -> r[str]:
        """Extract DN from object with dn attribute."""
        if dn_val_raw is None:
            return r.fail("Entry missing DN (dn is None)")
        if hasattr(dn_val_raw, "value") and not isinstance(dn_val_raw, str):
            # Type narrowing: object with 'value' attribute, extract it
            dn_value_raw_obj = u.mapper().get(dn_val_raw, "value")
            # Type narrowing: value attribute is str | list[str] | None
            if isinstance(dn_value_raw_obj, (str, list)):
                dn_value_extracted: str | list[str] = dn_value_raw_obj
            else:
                dn_value_extracted: str | list[str] | None = None
            return FlextLdifEntries._extract_dn_from_value(dn_value_extracted)
        if isinstance(dn_val_raw, str):
            return r.ok(dn_val_raw)
        # Use try/except instead of u.try_
        try:
            result = str(dn_val_raw)
        except (ValueError, TypeError):
            result = None
        if result is not None:
            return r.ok(result)
        return r.fail(f"Failed to extract DN: {type(dn_val_raw)}")

    @staticmethod
    def get_entry_dn(
        entry: m.Ldif.Entry | dict[str, str | list[str]] | object,
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
            r containing DN as string (RFC 4514 format)

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
        # Type narrowing: check for EntryProtocol-like object with attributes property
        if hasattr(attrs, "attributes"):
            # Type narrowing: attrs has attributes property, access it safely
            attrs_dict_raw = getattr(attrs, "attributes", None)
            if attrs_dict_raw is not None:
                # Type narrowing: ensure attrs_dict is dict-like
                attrs_dict: dict[str, list[str]] = (
                    dict(attrs_dict_raw) if isinstance(attrs_dict_raw, dict) else {}
                )
                return r.ok(attrs_dict)
            return r.ok({})
        if isinstance(attrs, dict):
            return r.ok(dict(attrs))
        return r.fail(
            f"Unknown attributes container type: {type(attrs)}",
        )

    @staticmethod
    def get_entry_attributes(
        entry: m.Ldif.Entry,
    ) -> r[dict[str, list[str]]]:
        """Extract attributes from entry.

        Business Rule: Attribute extraction handles multiple entry formats per EntryProtocol:
        - Attributes model (has .attributes attribute containing dict[str, list[str]])
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
            r containing attribute dictionary (dict[str, list[str]])

        """
        # Business Rule: Handle exceptions during attribute extraction
        # EntryProtocol allows various attribute formats, so we need robust extraction
        # Implication: ValueError and AttributeError are caught and converted to r failures
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
            # Business Rule: Convert exceptions to r failures
            # This ensures railway-oriented error handling throughout the codebase
            return r.fail(f"Failed to extract attributes: {e}")

    @staticmethod
    def get_entry_objectclasses(
        entry: m.Ldif.Entry,
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
            r containing list of objectClass values (normalized to lowercase
            if case-insensitive matching was used)

        """
        # Business Rule: Delegate to get_entry_attributes for attribute extraction
        # This ensures consistent error handling and attribute format normalization
        # Implication: If attribute extraction fails, objectClass extraction also fails
        attributes_result = FlextLdifEntries.get_entry_attributes(entry)
        if attributes_result.is_failure:
            return r.fail(f"Failed to get entry attributes: {attributes_result.error}")

        attributes = attributes_result.value
        if not attributes:
            return r.ok([])

        # Business Rule: Case-insensitive search for objectClass attribute per RFC 4512
        # LDAP attribute names are case-insensitive, so we match "objectclass" regardless of case
        # Implication: This handles entries with "objectClass", "objectclass", "OBJECTCLASS", etc.
        # Type narrowing: u.find expects predicate: Callable[[T], bool] | Callable[[str, T], bool]
        # where T = tuple[str, list[str]] for list of items
        # Direct iteration instead of u.Collection.find
        # Use str.lower() for case-insensitive comparison
        found_kv: tuple[str, str | list[str]] | None = None
        for attr_name, attr_value in attributes.items():
            if attr_name.lower() == "objectclass":
                found_kv = (attr_name, attr_value)
                break

        # Type narrowing: found_kv is tuple[str, str | list[str]] | None
        if not found_kv:
            return r.fail("Entry is missing objectClass attribute")

        # Type narrowing: found_kv[1] is str | list[str] (attribute value)
        objectclasses: str | list[str] = found_kv[1]

        # Business Rule: Normalize single string values to list format
        # This ensures consistent return type (always list[str]) regardless of input format
        # Implication: Single-value objectClass attributes are wrapped in list for consistency
        # Type narrowing: match always returns r[list[str]] because default is not None
        match_result: r[list[str]] = FlextFunctional.match(
            objectclasses,
            (str, lambda s: r.ok([s])),
            (list, lambda lst: r.ok(list(lst))),
            default=r.fail(f"Invalid objectclasses type: {type(objectclasses)}"),
        )
        return match_result

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> r[m.Ldif.Entry]:
        """Create a new entry.

        Args:
            dn: Distinguished Name for the entry
            attributes: Attribute dictionary
            objectclasses: Optional objectClass values

        Returns:
            r containing new Entry

        """
        # Validate DN using FlextLdifUtilitiesDN
        if not FlextLdifUtilitiesDN.validate(dn):
            return r.fail(f"Invalid DN: {dn}")

        # Prepare attributes
        final_attrs = dict(attributes)
        if objectclasses:
            final_attrs["objectClass"] = objectclasses

        # Use m.Ldif.Entry.create directly
        return m.Ldif.Entry.create(dn=dn, attributes=final_attrs)

    @staticmethod
    def remove_attributes(
        entry: m.Ldif.Entry,
        attributes_to_remove: list[str],
    ) -> r[m.Ldif.Entry]:
        """Remove attributes from entry.

        Args:
            entry: Entry to modify
            attributes_to_remove: List of attribute names to remove

        Returns:
            r containing modified entry

        """
        if not entry.attributes or not entry.attributes.attributes:
            return r.ok(entry)

        # Normalize attribute names to lowercase for case-insensitive comparison
        attrs_to_remove_lower = {attr.lower() for attr in attributes_to_remove}

        # Create new attributes dict without the specified attributes (case-insensitive)
        # Use dict comprehension for type safety
        new_attrs: dict[str, list[str]] = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove_lower
        }

        # Create new entry with modified attributes
        modified_entry = m.Ldif.Entry(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return r.ok(modified_entry)

    @staticmethod
    def remove_objectclasses(
        entry: m.Ldif.Entry,
        objectclasses_to_remove: list[str],
    ) -> r[m.Ldif.Entry]:
        """Remove specific objectClass values from entry.

        Args:
            entry: Entry to modify
            objectclasses_to_remove: List of objectClass values to remove

        Returns:
            r containing modified entry

        """
        if not entry.attributes or not entry.attributes.attributes:
            return r.ok(entry)

        # Get current objectClass values
        objectclasses_result = FlextLdifEntries.get_entry_objectclasses(entry)
        if objectclasses_result.is_failure:
            return r.ok(entry)  # No objectClass attribute, nothing to remove

        current_ocs = objectclasses_result.value
        if not current_ocs:
            return r.ok(entry)  # Empty objectClass list, nothing to remove

        # Normalize objectClass names to lowercase for case-insensitive comparison
        ocs_to_remove_lower = {oc.lower() for oc in objectclasses_to_remove}

        # Filter out objectClasses to remove (case-insensitive)
        # Use list comprehension for type safety
        new_ocs: list[str] = [
            oc for oc in current_ocs if oc.lower() not in ocs_to_remove_lower
        ]

        # If all objectClasses were removed, return error
        if not new_ocs:
            return r.fail("Cannot remove all objectClass values from entry")

        # Create new attributes dict with updated objectClass
        new_attrs = dict(entry.attributes.attributes)
        new_attrs["objectClass"] = new_ocs

        # Create new entry with modified attributes
        modified_entry = m.Ldif.Entry(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=new_attrs),
            metadata=entry.metadata,
        )
        return r.ok(modified_entry)

    @staticmethod
    def get_attribute_values(
        attribute: FlextTypes.GeneralValueType,
    ) -> r[list[str]]:
        """Extract values from attribute.

        Args:
            attribute: Attribute value(s) to extract (str, list[str], or object with values attr)

        Returns:
            r containing list of string values

        """
        if isinstance(attribute, str):
            return r.ok([attribute])
        if isinstance(attribute, list):
            return r.ok(attribute)
        # Check if it's a protocol with values attribute
        if hasattr(attribute, "values"):
            values = getattr(attribute, "values", None)
            if isinstance(values, str):
                return r.ok([values])
            if isinstance(values, (list, tuple)):
                return r.ok(list(values))
            return r.fail(
                f"Attribute 'values' has unsupported type: {type(values).__name__}",
            )
        # Try to iterate if it's iterable and contains strings (but not already handled above)
        if isinstance(attribute, (tuple, set, frozenset)):
            try:
                str_list = [str(item) for item in attribute]
                return r.ok(str_list)
            except (TypeError, ValueError):
                return r.fail(
                    f"Cannot convert iterable to string list: {type(attribute).__name__}",
                )
        # Not a supported type
        return r.fail(f"Unsupported attribute type: {type(attribute).__name__}")

    @staticmethod
    def get_entry_attribute(
        entry: m.Ldif.Entry,
        attribute_name: str,
    ) -> r[list[str]]:
        """Get a specific attribute from entry.

        Args:
            entry: Entry to extract attribute from
            attribute_name: Name of attribute to get

        Returns:
            r containing attribute values as list

        """
        if not entry.attributes or not entry.attributes.attributes:
            return r.fail(f"Attribute '{attribute_name}' not found")

        value_raw: object = u.mapper().get(entry.attributes.attributes, attribute_name)
        if value_raw is None:
            return r.fail(f"Attribute '{attribute_name}' not found")

        # Type narrowing: attribute values are str | list[str]
        if isinstance(value_raw, (str, list)):
            value: str | list[str] = value_raw
        else:
            # Fallback: convert to string
            value: str | list[str] = str(value_raw)

        # Type narrowing: match always returns r[list[str]] because default is not None
        match_result: r[list[str]] = FlextFunctional.match(
            value,
            (str, lambda s: r.ok([s])),
            (list, lambda v: r.ok(list(v))),
            default=r.ok([str(value)]),
        )
        return match_result

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
        if not value or (isinstance(value, (list, dict, str)) and len(value) == 0):
            return r.fail("Cannot normalize empty list")
        first = value[0]
        # Type narrowing: match always returns r[str] because default is not None
        match_result: r[str] = FlextFunctional.match(
            first,
            (str, FlextLdifEntries._normalize_string_value),
            default=lambda f: r.ok(str(f))
            if f is not None
            else r.fail("Cannot normalize empty list"),
        )
        return match_result

    @staticmethod
    def normalize_attribute_value(
        value: str | list[str] | None,
    ) -> r[str]:
        """Normalize attribute value to single string.

        Args:
            value: Value to normalize (string, list, or None)

        Returns:
            r containing normalized string value

        """
        if value is None:
            return r.fail("Cannot normalize None value")
        # Type narrowing: match always returns r[str] because default is not None
        match_result: r[str] = FlextFunctional.match(
            value,
            (str, FlextLdifEntries._normalize_string_value),
            (list, FlextLdifEntries._normalize_list_value),
            default=r.fail(f"Cannot normalize value of type {type(value)}"),
        )
        return match_result

    def get_normalized_attribute(
        self,
        entry: m.Ldif.Entry,
        attribute_name: str,
    ) -> r[str]:
        """Get normalized (single string) value for attribute.

        Args:
            entry: Entry to extract attribute from
            attribute_name: Name of attribute to get

        Returns:
            r containing normalized string value

        """
        result = self.get_entry_attribute(entry, attribute_name)
        if result.is_failure:
            return r.fail(f"Attribute '{attribute_name}' not found")

        values = result.value
        return FlextLdifEntries.normalize_attribute_value(values)

    @staticmethod
    def remove_operational_attributes(
        entry: m.Ldif.Entry,
    ) -> r[m.Ldif.Entry]:
        """Remove operational attributes from entry.

        Business Rule: Operational attributes removal uses u.Entry
        for RFC 4512 compliant detection. Operation is immutable - returns new entry
        instance with operational attributes removed. Entry metadata is preserved.

        Implication: This method enables cleaning entries for migration or export
        while maintaining RFC compliance. Operational attributes are identified per
        RFC 4512 specification.

        Args:
            entry: Entry to process

        Returns:
            r containing new entry instance (operational attributes removed)

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
        # Use dict comprehension for type safety (u.where expects dict[str, object])
        new_attrs: dict[str, list[str]] = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in operational_attrs_lower
        }

        # Create new entry with modified attributes
        modified_entry = m.Ldif.Entry(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return r.ok(modified_entry)


__all__ = ["FlextLdifEntries"]
