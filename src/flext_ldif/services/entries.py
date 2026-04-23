"""Entries Service - direct typed entry operations."""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
    MutableSequence,
)
from typing import Annotated

from flext_ldif import m, r, s, t, u


class FlextLdifEntries(s):
    """Entry operations with strict contracts."""

    entries: Annotated[
        MutableSequence[m.Ldif.Entry],
        u.Field(
            default_factory=list,
            exclude=True,
            description="Entries processed when the configured operation runner is used.",
        ),
    ]
    operation: Annotated[
        str | None,
        u.Field(
            default=None,
            exclude=True,
            description="Configured entry operation executed by run_configured_operation().",
        ),
    ]
    attributes_to_remove: Annotated[
        MutableSequence[str],
        u.Field(
            default_factory=list,
            exclude=True,
            description="Attributes removed by run_configured_operation() when using remove_attributes.",
        ),
    ]

    @staticmethod
    def _extract_dn_from_dict(
        entry: t.MutableAttributeMapping,
    ) -> r[str]:
        dn_value = entry.get("dn")
        if dn_value is None:
            return r[str].fail("Dict entry missing 'dn' key")
        match dn_value:
            case str() as dn_text:
                return r[str].ok(dn_text)
            case list() as dn_list:
                return r[str].ok(dn_list[0] if dn_list else "")
            case _:
                return r[str].fail("Dict entry has unsupported 'dn' value type")

    @staticmethod
    def _extract_dn_from_object(entry: t.JsonValue | m.Ldif.Entry) -> r[str]:
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
            if dn_value and isinstance(dn_value[0], str):
                return r[str].ok(dn_value[0])
            return r[str].ok("")
        return r[str].fail("Invalid DN value type")

    @staticmethod
    def _normalize_list_value(value: MutableSequence[str]) -> r[str]:
        if not value:
            return r[str].fail("Cannot normalize empty list")
        return FlextLdifEntries._normalize_string_value(value[0])

    @staticmethod
    def _normalize_string_value(value: str) -> r[str]:
        stripped = value.strip()
        if not stripped:
            return r[str].fail("Cannot normalize empty string")
        return r[str].ok(stripped)

    @staticmethod
    def create_entry(
        dn: str,
        attributes: t.MutableAttributeMapping,
        objectclasses: MutableSequence[str] | None = None,
    ) -> r[m.Ldif.Entry]:
        """Create a validated entry from DN and attributes."""
        if not u.Ldif.validate_dn(dn):
            return r[m.Ldif.Entry].fail(f"Invalid DN: {dn}")
        final_attrs = dict(attributes)
        if objectclasses:
            final_attrs["objectClass"] = objectclasses
        return m.Ldif.Entry.create(dn=dn, attributes=final_attrs)

    @staticmethod
    def get_attribute_values(
        attribute: str
        | MutableSequence[str]
        | tuple[str, ...]
        | set[str]
        | frozenset[str],
    ) -> r[MutableSequence[str]]:
        """Normalize attribute input into a list of strings."""
        match attribute:
            case str() as value:
                return r[MutableSequence[str]].ok([value])
            case list() as values:
                return r[MutableSequence[str]].ok(values)
            case tuple() | set() | frozenset() as values:
                return r[MutableSequence[str]].ok(list(values))
            case _:
                return r[MutableSequence[str]].fail("Unsupported attribute input type")

    @staticmethod
    def get_entry_attributes(
        entry: m.Ldif.Entry,
    ) -> r[t.MutableStrSequenceMapping]:
        """Get entry attributes mapping."""
        if entry.attributes is None:
            return r[t.MutableStrSequenceMapping].fail(
                "Entry has no attributes",
            )
        attrs: t.MutableStrSequenceMapping = dict(
            entry.attributes.attributes,
        )
        return r[t.MutableStrSequenceMapping].ok(attrs)

    @staticmethod
    def get_entry_dn(
        entry: m.Ldif.Entry | t.MutableAttributeMapping,
    ) -> r[str]:
        """Read DN from model or dictionary entry."""
        if isinstance(entry, MutableMapping):
            return FlextLdifEntries._extract_dn_from_dict(entry)
        return FlextLdifEntries._extract_dn_from_object(entry)

    @staticmethod
    def get_entry_objectclasses(entry: m.Ldif.Entry) -> r[MutableSequence[str]]:
        """Get objectClass values from entry attributes."""
        attributes_result = FlextLdifEntries.get_entry_attributes(entry)
        if attributes_result.failure:
            return r[MutableSequence[str]].fail(
                f"Failed to get entry attributes: {attributes_result.error}",
            )
        attributes: t.MutableStrSequenceMapping = {
            str(attr_name): list(attr_values)
            for attr_name, attr_values in attributes_result.value.items()
        }
        for attr_name, attr_values in attributes.items():
            if attr_name.lower() == "objectclass":
                return r[MutableSequence[str]].ok(list(attr_values))
        return r[MutableSequence[str]].fail("Entry is missing objectClass attribute")

    @staticmethod
    def remove_attributes(
        entry: m.Ldif.Entry,
        attributes_to_remove: MutableSequence[str],
    ) -> r[m.Ldif.Entry]:
        """Remove selected attributes from a single entry."""
        if entry.attributes is None:
            return r[m.Ldif.Entry].ok(entry)
        attrs_to_remove_lower = {attr.lower() for attr in attributes_to_remove}
        new_attrs: t.MutableAttributeMapping = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove_lower
        }
        dn_value = entry.dn if entry.dn is not None else entry.dn_str
        return m.Ldif.Entry.create(
            dn=dn_value,
            attributes=new_attrs,
            metadata=entry.metadata,
        )

    def run_configured_operation(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Run the configured entry operation against the bound entries."""
        if not self.operation:
            return r[MutableSequence[m.Ldif.Entry]].fail("No operation specified")
        if self.operation == "remove_attributes":
            if not self.attributes_to_remove:
                return r[MutableSequence[m.Ldif.Entry]].fail(
                    "No attributes_to_remove specified for remove_attributes operation",
                )
            results: MutableSequence[m.Ldif.Entry] = []
            for entry in self.entries:
                result = self.remove_attributes(entry, self.attributes_to_remove)
                if result.success:
                    results.append(result.value)
            return r[MutableSequence[m.Ldif.Entry]].ok(results)
        return r[MutableSequence[m.Ldif.Entry]].fail(
            f"Unknown operation: {self.operation}",
        )


__all__: list[str] = ["FlextLdifEntries"]
