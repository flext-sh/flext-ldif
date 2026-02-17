"""Entries Service - Direct Entry Operations with flext-core APIs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Self

from flext_core import FlextTypes, r
from flext_core.typings import t

from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.utilities import u


class FlextLdifEntries(FlextLdifServiceBase[list[m.Ldif.Entry]]):
    """Direct entry operations service using flext-core APIs."""

    def __init__(
        self,
        entries: list[m.Ldif.Entry] | None = None,
        operation: str | None = None,
        attributes_to_remove: list[str] | None = None,
    ) -> None:
        """Initialize entries service."""
        super().__init__()
        self._entries = entries or []
        self._operation = operation
        self._attributes_to_remove = attributes_to_remove or []

    @classmethod
    def builder(cls) -> Self:
        """Create fluent builder instance."""
        return cls()

    def with_entries(
        self,
        entries: list[m.Ldif.Entry],
    ) -> Self:
        """Set entries for builder."""
        self._entries = entries
        return self

    def with_operation(
        self,
        operation: str,
    ) -> Self:
        """Set operation for builder."""
        self._operation = operation
        return self

    def with_attributes_to_remove(
        self,
        attributes_to_remove: list[str],
    ) -> Self:
        """Set attributes to remove for builder."""
        self._attributes_to_remove = attributes_to_remove
        return self

    def build(self) -> list[m.Ldif.Entry]:
        """Build and execute the configured operation."""
        result = self.execute()
        if result.is_failure:
            error_msg = f"Build failed: {result.error}"
            raise RuntimeError(error_msg)
        return result.value

    def execute(self) -> r[list[m.Ldif.Entry]]:
        """Execute the configured operation on entries."""
        if not self._operation:
            return r[list[m.Ldif.Entry]].fail("No operation specified")

        if self._operation == "remove_operational_attributes":
            return self.remove_operational_attributes_batch(self._entries)
        if self._operation == "remove_attributes":
            if not self._attributes_to_remove:
                return r[list[m.Ldif.Entry]].fail(
                    "No attributes_to_remove specified for remove_attributes operation",
                )
            return self.remove_attributes_batch(
                self._entries,
                self._attributes_to_remove,
            )
        return r[list[m.Ldif.Entry]].fail(f"Unknown operation: {self._operation}")

    @staticmethod
    def remove_operational_attributes_batch(
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Remove operational attributes from all entries."""

        def remove_op_attrs_wrapper(
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Wrapper for remove_operational_attributes."""
            return FlextLdifEntries.remove_operational_attributes(entry)

        operation_fn: Callable[
            [m.Ldif.Entry],
            m.Ldif.Entry | r[m.Ldif.Entry],
        ] = remove_op_attrs_wrapper
        results: list[m.Ldif.Entry] = []
        for entry in entries:
            try:
                result = operation_fn(entry)

                if isinstance(result, r):
                    if result.is_success and isinstance(result.value, m.Ldif.Entry):
                        results.append(result.value)
                    else:
                        return r[list[m.Ldif.Entry]].fail(
                            result.error or "Failed to process entry",
                        )
                elif isinstance(result, m.Ldif.Entry):
                    results.append(result)
            except Exception as exc:
                return r[list[m.Ldif.Entry]].fail(
                    f"Batch processing failed: {exc}",
                )
        return r[list[m.Ldif.Entry]].ok(results)

    def remove_attributes_batch(
        self,
        entries: list[m.Ldif.Entry],
        attributes: list[str],
    ) -> r[list[m.Ldif.Entry]]:
        """Remove specified attributes from all entries."""

        def remove_attrs_wrapper(
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Wrapper for remove_attributes."""
            return FlextLdifEntries.remove_attributes(entry, attributes)

        operation_fn: Callable[
            [m.Ldif.Entry],
            m.Ldif.Entry | r[m.Ldif.Entry],
        ] = remove_attrs_wrapper
        results: list[m.Ldif.Entry] = []
        for entry in entries:
            try:
                result = operation_fn(entry)

                if isinstance(result, r):
                    if result.is_success and isinstance(result.value, m.Ldif.Entry):
                        results.append(result.value)
                    else:
                        return r[list[m.Ldif.Entry]].fail(
                            result.error or "Failed to process entry",
                        )
                elif isinstance(result, m.Ldif.Entry):
                    results.append(result)
            except Exception as exc:
                return r[list[m.Ldif.Entry]].fail(
                    f"Batch processing failed: {exc}",
                )
        return r[list[m.Ldif.Entry]].ok(results)

    @staticmethod
    def _extract_dn_from_dict(entry: dict[str, str | list[str]]) -> r[str]:
        """Extract DN from dict entry."""
        dn_value = entry.get("dn")
        if dn_value is None:
            return r[str].fail("Dict entry missing 'dn' key")

        return r[str].ok(str(dn_value))

    @staticmethod
    def _extract_dn_from_value(
        dn_value_raw: str | list[str] | None,
    ) -> r[str]:
        """Extract DN string from value (str, list, or None) using DSL pattern."""

        def handle_none(_value: None) -> r[str]:
            """Handle None case."""
            return r[str].fail("DN value is None")

        def handle_str(value: str) -> r[str]:
            """Handle string case."""
            return r[str].ok(value)

        def handle_list(value_list: list[str]) -> r[str]:
            """Handle list case - extract first item."""
            first_dn = value_list[0] if value_list else ""
            return r[str].ok(str(first_dn))

        if dn_value_raw is None:
            return handle_none(None)
        if isinstance(dn_value_raw, str):
            return handle_str(dn_value_raw)
        if isinstance(dn_value_raw, list):
            return handle_list(dn_value_raw)

        return r[str].fail(f"DN value has unexpected type: {type(dn_value_raw)}")

    @staticmethod
    def _extract_dn_from_object(dn_val_raw: object) -> r[str]:
        """Extract DN from object with dn attribute."""
        if dn_val_raw is None:
            return r[str].fail("Entry missing DN (dn is None)")
        if hasattr(dn_val_raw, "value") and not isinstance(dn_val_raw, str):
            dn_value_raw_obj: object = getattr(dn_val_raw, "value", None)

            dn_value_extracted: str | list[str] | None
            if isinstance(dn_value_raw_obj, (str, list)):
                dn_value_extracted = dn_value_raw_obj
            else:
                dn_value_extracted = None
            return FlextLdifEntries._extract_dn_from_value(dn_value_extracted)
        if isinstance(dn_val_raw, str):
            return r[str].ok(dn_val_raw)

        try:
            result = str(dn_val_raw)
        except (ValueError, TypeError):
            result = None
        if result is not None:
            return r[str].ok(result)
        return r[str].fail(f"Failed to extract DN: {type(dn_val_raw)}")

    @staticmethod
    def get_entry_dn(
        entry: m.Ldif.Entry | dict[str, str | list[str]] | t.GeneralValueType,
    ) -> r[str]:
        """Extract DN from entry."""
        if isinstance(entry, dict):
            typed_entry: dict[str, str | list[str]] = {}
            for k, v in entry.items():
                if not isinstance(k, str):
                    continue
                if isinstance(v, str):
                    typed_entry[k] = v
                elif isinstance(v, list):
                    typed_entry[k] = [str(item) for item in v]
                else:
                    typed_entry[k] = str(v)
            return FlextLdifEntries._extract_dn_from_dict(typed_entry)
        if hasattr(entry, "dn"):
            dn_attr: object = getattr(entry, "dn", None)
            if dn_attr is None:
                return r[str].fail("Entry missing DN (dn is None)")

            if isinstance(dn_attr, str):
                return r[str].ok(dn_attr)
            return FlextLdifEntries._extract_dn_from_object(dn_attr)
        return r[str].fail(
            "Entry does not implement EntryWithDnProtocol or Entry protocol",
        )

    @staticmethod
    def _extract_attrs_from_container(
        attrs: t.GeneralValueType,
    ) -> r[dict[str, list[str]]]:
        """Extract attributes from container GeneralValueType."""
        if hasattr(attrs, "attributes"):
            attrs_dict_raw = getattr(attrs, "attributes", None)
            if attrs_dict_raw is not None:
                attrs_dict: dict[str, list[str]] = (
                    dict(attrs_dict_raw) if isinstance(attrs_dict_raw, dict) else {}
                )
                return r[dict[str, list[str]]].ok(attrs_dict)
            return r[dict[str, list[str]]].ok({})
        if isinstance(attrs, dict):
            converted_attrs: dict[str, list[str]] = {
                k: [str(v)] if not isinstance(v, list) else [str(vi) for vi in v]
                for k, v in attrs.items()
            }
            return r[dict[str, list[str]]].ok(converted_attrs)
        return r[dict[str, list[str]]].fail(
            f"Unknown attributes container type: {type(attrs)}",
        )

    @staticmethod
    def get_entry_attributes(
        entry: m.Ldif.Entry,
    ) -> r[dict[str, list[str]]]:
        """Extract attributes from entry."""
        try:
            if not hasattr(entry, "attributes"):
                return r[dict[str, list[str]]].fail(
                    "Entry missing attributes attribute",
                )
            attrs = entry.attributes
            if attrs is None:
                return r[dict[str, list[str]]].fail(
                    "Entry has no attributes (attributes is None)",
                )
            if not attrs:
                return r[dict[str, list[str]]].ok({})
            return FlextLdifEntries._extract_attrs_from_container(attrs)
        except (AttributeError, ValueError) as e:
            return r[dict[str, list[str]]].fail(
                f"Failed to extract attributes: {e}",
            )

    @staticmethod
    def get_entry_objectclasses(
        entry: m.Ldif.Entry,
    ) -> r[list[str]]:
        """Extract objectClass values from entry."""
        attributes_result = FlextLdifEntries.get_entry_attributes(entry)
        if attributes_result.is_failure:
            return r[list[str]].fail(
                f"Failed to get entry attributes: {attributes_result.error}",
            )

        attributes = attributes_result.value
        if not attributes:
            return r[list[str]].ok([])

        found_kv: tuple[str, str | list[str]] | None = None
        for attr_name, attr_value in attributes.items():
            if attr_name.lower() == "objectclass":
                found_kv = (attr_name, attr_value)
                break

        if not found_kv:
            return r[list[str]].fail("Entry is missing objectClass attribute")

        objectclasses: str | list[str] = found_kv[1]

        if isinstance(objectclasses, str):
            return r[list[str]].ok([objectclasses])
        if isinstance(objectclasses, list):
            return r[list[str]].ok(list(objectclasses))

        return r[list[str]].fail(f"Invalid objectclasses type: {type(objectclasses)}")

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> r[m.Ldif.Entry]:
        """Create a new entry."""
        if not FlextLdifUtilitiesDN.validate(dn):
            return r[m.Ldif.Entry].fail(f"Invalid DN: {dn}")

        final_attrs = dict(attributes)
        if objectclasses:
            final_attrs["objectClass"] = objectclasses

        return m.Ldif.Entry.create(dn=dn, attributes=final_attrs)

    @staticmethod
    def remove_attributes(
        entry: m.Ldif.Entry,
        attributes_to_remove: list[str],
    ) -> r[m.Ldif.Entry]:
        """Remove attributes from entry."""
        if not entry.attributes or not entry.attributes.attributes:
            return r[str].ok(entry)

        attrs_to_remove_lower = {attr.lower() for attr in attributes_to_remove}

        new_attrs: dict[str, list[str]] = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove_lower
        }

        modified_entry = m.Ldif.Entry(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return r[str].ok(modified_entry)

    @staticmethod
    def remove_objectclasses(
        entry: m.Ldif.Entry,
        objectclasses_to_remove: list[str],
    ) -> r[m.Ldif.Entry]:
        """Remove specific objectClass values from entry."""
        if not entry.attributes or not entry.attributes.attributes:
            return r[m.Ldif.Entry].ok(entry)

        objectclasses_result = FlextLdifEntries.get_entry_objectclasses(entry)
        if objectclasses_result.is_failure:
            return r[m.Ldif.Entry].ok(entry)

        current_ocs = objectclasses_result.value
        if not current_ocs:
            return r[m.Ldif.Entry].ok(entry)

        ocs_to_remove_lower = {oc.lower() for oc in objectclasses_to_remove}

        new_ocs: list[str] = [
            oc for oc in current_ocs if oc.lower() not in ocs_to_remove_lower
        ]

        if not new_ocs:
            return r[m.Ldif.Entry].fail(
                "Cannot remove all objectClass values from entry",
            )

        new_attrs = dict(entry.attributes.attributes)
        new_attrs["objectClass"] = new_ocs

        modified_entry = m.Ldif.Entry(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=new_attrs),
            metadata=entry.metadata,
        )
        return r[m.Ldif.Entry].ok(modified_entry)

    @staticmethod
    def get_attribute_values(
        attribute: FlextTypes.GeneralValueType,
    ) -> r[list[str]]:
        """Extract values from attribute."""
        if isinstance(attribute, str):
            return r[list[str]].ok([attribute])
        if isinstance(attribute, list):
            str_list: list[str] = [str(item) for item in attribute]
            return r[list[str]].ok(str_list)

        if hasattr(attribute, "values"):
            values = getattr(attribute, "values", None)
            if isinstance(values, str):
                return r[list[str]].ok([values])
            if isinstance(values, (list, tuple)):
                return r[list[str]].ok(list(values))
            return r[list[str]].fail(
                f"Attribute 'values' has unsupported type: {type(values).__name__}",
            )

        if isinstance(attribute, (tuple, set, frozenset)):
            try:
                str_list = [str(item) for item in attribute]
                return r[list[str]].ok(str_list)
            except (TypeError, ValueError):
                return r[list[str]].fail(
                    f"Cannot convert iterable to string list: {type(attribute).__name__}",
                )

        return r[list[str]].fail(
            f"Unsupported attribute type: {type(attribute).__name__}",
        )

    @staticmethod
    def get_entry_attribute(
        entry: m.Ldif.Entry,
        attribute_name: str,
    ) -> r[list[str]]:
        """Get a specific attribute from entry."""
        if not entry.attributes or not entry.attributes.attributes:
            return r[list[str]].fail(f"Attribute '{attribute_name}' not found")

        value_raw: t.GeneralValueType = u.mapper().get(
            entry.attributes.attributes, attribute_name
        )

        if value_raw is None or not value_raw:
            return r[list[str]].fail(f"Attribute '{attribute_name}' not found")

        if isinstance(value_raw, str):
            return r[list[str]].ok([value_raw])
        if isinstance(value_raw, list):
            str_list: list[str] = [str(item) for item in value_raw]
            return r[list[str]].ok(str_list)

        return r[list[str]].fail(f"Invalid attribute value type: {type(value_raw)}")

    @staticmethod
    def _normalize_string_value(value: str) -> r[str]:
        """Normalize string value."""
        stripped = value.strip()
        if not stripped:
            return r[str].fail("Cannot normalize empty string")
        return r[str].ok(stripped)

    @staticmethod
    def _normalize_list_value(value: list[str]) -> r[str]:
        """Normalize list value to single string."""
        if not value or (isinstance(value, (list, dict, str)) and len(value) == 0):
            return r[str].fail("Cannot normalize empty list")
        first = value[0]

        if isinstance(first, str):
            return FlextLdifEntries._normalize_string_value(first)

        return r[str].fail(f"Cannot normalize non-string first element: {type(first)}")

    @staticmethod
    def normalize_attribute_value(
        value: str | list[str] | None,
    ) -> r[str]:
        """Normalize attribute value to single string."""
        if value is None:
            return r[str].fail("Cannot normalize None value")

        if isinstance(value, str):
            return FlextLdifEntries._normalize_string_value(value)
        if isinstance(value, list):
            return FlextLdifEntries._normalize_list_value(value)

        return r[str].fail(f"Cannot normalize unsupported value type: {type(value)}")

    def get_normalized_attribute(
        self,
        entry: m.Ldif.Entry,
        attribute_name: str,
    ) -> r[str]:
        """Get normalized (single string) value for attribute."""
        return self.get_entry_attribute(entry, attribute_name).flat_map(
            FlextLdifEntries.normalize_attribute_value,
        )

    @staticmethod
    def remove_operational_attributes(
        entry: m.Ldif.Entry,
    ) -> r[m.Ldif.Entry]:
        """Remove operational attributes from entry."""
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
            return r[str].ok(entry)

        operational_attrs_lower = {attr.lower() for attr in operational_attrs}

        new_attrs: dict[str, list[str]] = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in operational_attrs_lower
        }

        modified_entry = m.Ldif.Entry(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return r[str].ok(modified_entry)


__all__ = ["FlextLdifEntries"]
