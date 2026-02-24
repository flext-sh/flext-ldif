"""Entries Service - direct typed entry operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Self

from flext_core import r

from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m


class FlextLdifEntries(FlextLdifServiceBase[list[m.Ldif.Entry]]):
    """Entry operations with strict contracts."""

    def __init__(
        self,
        entries: list[m.Ldif.Entry] | None = None,
        operation: str | None = None,
        attributes_to_remove: list[str] | None = None,
    ) -> None:
        """Initialize entry operation builder state."""
        super().__init__()
        self._entries = entries or []
        self._operation = operation
        self._attributes_to_remove = attributes_to_remove or []

    @classmethod
    def builder(cls) -> Self:
        """Create a new entries service builder."""
        return cls()

    def with_entries(self, entries: list[m.Ldif.Entry]) -> Self:
        """Set entries to process."""
        self._entries = entries
        return self

    def with_operation(self, operation: str) -> Self:
        """Set operation name for execution."""
        self._operation = operation
        return self

    def with_attributes_to_remove(self, attributes_to_remove: list[str]) -> Self:
        """Set attributes targeted by remove operation."""
        self._attributes_to_remove = attributes_to_remove
        return self

    def build(self) -> list[m.Ldif.Entry]:
        """Execute and return processed entries or raise on failure."""
        result = self.execute()
        if result.is_failure:
            msg = f"Build failed: {result.error}"
            raise RuntimeError(msg)
        return result.value

    def execute(self) -> r[list[m.Ldif.Entry]]:
        """Run configured entry operation."""
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
                self._entries, self._attributes_to_remove
            )
        return r[list[m.Ldif.Entry]].fail(f"Unknown operation: {self._operation}")

    @staticmethod
    def remove_operational_attributes_batch(
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Remove operational attributes for all entries."""
        results: list[m.Ldif.Entry] = []
        for entry in entries:
            result = FlextLdifEntries.remove_operational_attributes(entry)
            if result.is_failure:
                return r[list[m.Ldif.Entry]].fail(
                    result.error or "Failed to process entry"
                )
            results.append(result.value)
        return r[list[m.Ldif.Entry]].ok(results)

    def remove_attributes_batch(
        self,
        entries: list[m.Ldif.Entry],
        attributes: list[str],
    ) -> r[list[m.Ldif.Entry]]:
        """Remove selected attributes for all entries."""
        results: list[m.Ldif.Entry] = []
        for entry in entries:
            result = FlextLdifEntries.remove_attributes(entry, attributes)
            if result.is_failure:
                return r[list[m.Ldif.Entry]].fail(
                    result.error or "Failed to process entry"
                )
            results.append(result.value)
        return r[list[m.Ldif.Entry]].ok(results)

    @staticmethod
    def _extract_dn_from_dict(entry: Mapping[str, str | list[str]]) -> r[str]:
        dn_value = entry.get("dn")
        if dn_value is None:
            return r[str].fail("Dict entry missing 'dn' key")
        match dn_value:
            case str() as dn_text:
                return r[str].ok(dn_text)
            case list() as dn_list:
                return r[str].ok(dn_list[0] if dn_list else "")
        return r[str].fail("Invalid DN value type")

    @staticmethod
    def _extract_dn_from_object(entry: object) -> r[str]:
        dn_value = getattr(entry, "dn", None)
        if dn_value is None:
            return r[str].fail("Entry missing DN (dn is None)")

        if hasattr(dn_value, "value"):
            value_attr = getattr(dn_value, "value", None)
            if isinstance(value_attr, str):
                return r[str].ok(value_attr)

        if isinstance(dn_value, str):
            return r[str].ok(dn_value)

        if isinstance(dn_value, list):
            return r[str].ok(dn_value[0] if dn_value else "")

        return r[str].fail("Invalid DN value type")

    @staticmethod
    def get_entry_dn(entry: m.Ldif.Entry | Mapping[str, str | list[str]]) -> r[str]:
        """Read DN from model or dictionary entry."""
        if isinstance(entry, Mapping):
            return FlextLdifEntries._extract_dn_from_dict(entry)

        return FlextLdifEntries._extract_dn_from_object(entry)

    @staticmethod
    def get_entry_attributes(entry: m.Ldif.Entry) -> r[Mapping[str, list[str]]]:
        """Get entry attributes mapping."""
        if entry.attributes is None:
            return r[dict[str, list[str]]].fail("Entry has no attributes")
        return r[dict[str, list[str]]].ok(dict(entry.attributes.attributes))

    @staticmethod
    def get_entry_objectclasses(entry: m.Ldif.Entry) -> r[list[str]]:
        """Get objectClass values from entry attributes."""
        attributes_result = FlextLdifEntries.get_entry_attributes(entry)
        if attributes_result.is_failure:
            return r[list[str]].fail(
                f"Failed to get entry attributes: {attributes_result.error}",
            )
        attributes = attributes_result.value
        for attr_name, attr_values in attributes.items():
            if attr_name.lower() == "objectclass":
                return r[list[str]].ok(list(attr_values))
        return r[list[str]].fail("Entry is missing objectClass attribute")

    @staticmethod
    def create_entry(
        dn: str,
        attributes: Mapping[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> r[m.Ldif.Entry]:
        """Create a validated entry from DN and attributes."""
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
        """Remove selected attributes from a single entry."""
        if entry.attributes is None:
            return r[m.Ldif.Entry].ok(entry)
        attrs_to_remove_lower = {attr.lower() for attr in attributes_to_remove}
        new_attrs = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove_lower
        }
        modified_entry = m.Ldif.Entry(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=new_attrs),
            metadata=entry.metadata,
        )
        return r[m.Ldif.Entry].ok(modified_entry)

    @staticmethod
    def remove_objectclasses(
        entry: m.Ldif.Entry,
        objectclasses_to_remove: list[str],
    ) -> r[m.Ldif.Entry]:
        """Remove objectClass values from a single entry."""
        if entry.attributes is None:
            return r[m.Ldif.Entry].ok(entry)
        objectclasses_result = FlextLdifEntries.get_entry_objectclasses(entry)
        if objectclasses_result.is_failure:
            return r[m.Ldif.Entry].ok(entry)
        current_ocs = objectclasses_result.value
        if not current_ocs:
            return r[m.Ldif.Entry].ok(entry)
        ocs_to_remove_lower = {oc.lower() for oc in objectclasses_to_remove}
        new_ocs = [oc for oc in current_ocs if oc.lower() not in ocs_to_remove_lower]
        if not new_ocs:
            return r[m.Ldif.Entry].fail(
                "Cannot remove all objectClass values from entry"
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
        attribute: str | list[str] | tuple[str, ...] | set[str] | frozenset[str],
    ) -> r[list[str]]:
        """Normalize attribute input into a list of strings."""
        match attribute:
            case str() as value:
                return r[list[str]].ok([value])
            case list() as values:
                return r[list[str]].ok(values)
            case tuple() | set() | frozenset() as values:
                return r[list[str]].ok(list(values))
        return r[list[str]].fail("Unsupported attribute type")

    @staticmethod
    def get_entry_attribute(entry: m.Ldif.Entry, attribute_name: str) -> r[list[str]]:
        """Read one attribute from entry."""
        if entry.attributes is None:
            return r[list[str]].fail(f"Attribute '{attribute_name}' not found")
        value = entry.attributes.attributes.get(attribute_name)
        if value is None or not value:
            return r[list[str]].fail(f"Attribute '{attribute_name}' not found")
        return r[list[str]].ok(list(value))

    @staticmethod
    def _normalize_string_value(value: str) -> r[str]:
        stripped = value.strip()
        if not stripped:
            return r[str].fail("Cannot normalize empty string")
        return r[str].ok(stripped)

    @staticmethod
    def _normalize_list_value(value: list[str]) -> r[str]:
        if not value:
            return r[str].fail("Cannot normalize empty list")
        return FlextLdifEntries._normalize_string_value(value[0])

    @staticmethod
    def normalize_attribute_value(value: str | list[str] | None) -> r[str]:
        """Normalize supported attribute value shapes to one string."""
        match value:
            case None:
                return r[str].fail("Cannot normalize None value")
            case str() as value_text:
                return FlextLdifEntries._normalize_string_value(value_text)
            case list() as value_list:
                return FlextLdifEntries._normalize_list_value(value_list)
        return r[str].fail("Cannot normalize unsupported value type")

    def get_normalized_attribute(
        self, entry: m.Ldif.Entry, attribute_name: str
    ) -> r[str]:
        """Get and normalize one entry attribute."""
        return self.get_entry_attribute(entry, attribute_name).flat_map(
            FlextLdifEntries.normalize_attribute_value,
        )

    @staticmethod
    def remove_operational_attributes(entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Remove known operational attributes from one entry."""
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
        if entry.attributes is None:
            return r[m.Ldif.Entry].ok(entry)
        operational_attrs_lower = {attr.lower() for attr in operational_attrs}
        new_attrs = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in operational_attrs_lower
        }
        modified_entry = m.Ldif.Entry(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=new_attrs),
            metadata=entry.metadata,
        )
        return r[m.Ldif.Entry].ok(modified_entry)


__all__ = ["FlextLdifEntries"]
