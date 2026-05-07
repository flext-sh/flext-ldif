"""Entries Service - direct typed entry operations."""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
)
from typing import Annotated

from flext_ldif import m, p, r, s, t, u


class FlextLdifEntries(s):
    """Entry operations with strict contracts."""

    entries: Annotated[
        t.MutableSequenceOf[m.Ldif.Entry],
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
        t.MutableSequenceOf[str],
        u.Field(
            default_factory=list,
            exclude=True,
            description="Attributes removed by run_configured_operation() when using remove_attributes.",
        ),
    ]

    @staticmethod
    def _extract_dn_from_dict(
        entry: t.MutableAttributeMapping,
    ) -> p.Result[str]:
        dn_value = entry.get("dn")
        if dn_value is None:
            return r[str].fail("Dict entry missing 'dn' key")
        extracted_dn: str | None = None
        match dn_value:
            case str() as dn_text:
                extracted_dn = dn_text
            case list() as dn_list if dn_list and isinstance(dn_list[0], str):
                extracted_dn = dn_list[0]
            case list():
                extracted_dn = ""
        if extracted_dn is not None:
            return r[str].ok(extracted_dn)
        return r[str].fail("Dict entry has unsupported 'dn' value type")

    @staticmethod
    def _extract_dn_from_object(entry: t.JsonValue | m.Ldif.Entry) -> p.Result[str]:
        dn_value = getattr(entry, "dn", None)
        if dn_value is None:
            return r[str].fail("Entry missing DN (dn is None)")
        extracted_dn: str | None = None
        match dn_value:
            case m.Ldif.DN() | str() as dn_text:
                extracted_dn = str(dn_text)
            case list() as dn_list if dn_list and isinstance(dn_list[0], str):
                extracted_dn = dn_list[0]
            case list():
                extracted_dn = ""
        if extracted_dn is not None:
            return r[str].ok(extracted_dn)
        return r[str].fail("Invalid DN value type")

    @staticmethod
    def _normalize_list_value(value: t.MutableSequenceOf[str]) -> p.Result[str]:
        if not value:
            return r[str].fail("Cannot normalize empty list")
        return FlextLdifEntries._normalize_string_value(value[0])

    @staticmethod
    def _normalize_string_value(value: str) -> p.Result[str]:
        stripped = value.strip()
        if not stripped:
            return r[str].fail("Cannot normalize empty string")
        return r[str].ok(stripped)

    @staticmethod
    def create_entry(
        dn: str,
        attributes: t.MutableAttributeMapping,
        objectclasses: t.MutableSequenceOf[str] | None = None,
    ) -> p.Result[m.Ldif.Entry]:
        """Create a validated entry from DN and attributes."""
        if not u.Ldif.validate_dn(dn):
            return r[m.Ldif.Entry].fail(f"Invalid DN: {dn}")
        final_attrs = dict(attributes)
        if objectclasses:
            final_attrs["objectClass"] = objectclasses
        return m.Ldif.Entry.create(dn=dn, attributes=final_attrs)

    @staticmethod
    def normalize_attribute_values(
        attribute: t.Ldif.UnconvertedAttributeValue
        | t.StrSequence
        | set[str]
        | frozenset[str],
    ) -> p.Result[t.MutableSequenceOf[str]]:
        """Normalize attribute input into a list of strings."""
        match attribute:
            case str() as value:
                return r[t.MutableSequenceOf[str]].ok([value])
            case list() as values:
                return r[t.MutableSequenceOf[str]].ok(values)
            case tuple() | set() | frozenset() as values:
                return r[t.MutableSequenceOf[str]].ok(list(values))
            case _:
                return r[t.MutableSequenceOf[str]].fail(
                    "Unsupported attribute input type",
                )

    @staticmethod
    def resolve_entry_attributes(
        entry: m.Ldif.Entry,
    ) -> p.Result[t.MutableStrSequenceMapping]:
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
    def resolve_entry_dn(
        entry: m.Ldif.Entry | t.MutableAttributeMapping,
    ) -> p.Result[str]:
        """Read DN from model or dictionary entry."""
        if isinstance(entry, MutableMapping):
            return FlextLdifEntries._extract_dn_from_dict(entry)
        return FlextLdifEntries._extract_dn_from_object(entry)

    @staticmethod
    def resolve_entry_objectclasses(
        entry: m.Ldif.Entry,
    ) -> p.Result[t.MutableSequenceOf[str]]:
        """Get objectClass values from entry attributes."""
        attributes_result = FlextLdifEntries.resolve_entry_attributes(entry)
        if attributes_result.failure:
            return r[t.MutableSequenceOf[str]].fail(
                f"Failed to get entry attributes: {attributes_result.error}",
            )
        attributes: t.MutableStrSequenceMapping = {
            attr_name: list(attr_values)
            for attr_name, attr_values in attributes_result.value.items()
        }
        for attr_name, attr_values in attributes.items():
            if attr_name.lower() == "objectclass":
                return r[t.MutableSequenceOf[str]].ok(list(attr_values))
        return r[t.MutableSequenceOf[str]].fail(
            "Entry is missing objectClass attribute",
        )

    @staticmethod
    def remove_attributes(
        entry: m.Ldif.Entry,
        attributes_to_remove: t.MutableSequenceOf[str],
    ) -> p.Result[m.Ldif.Entry]:
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

    def run_configured_operation(self) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Run the configured entry operation against the bound entries."""
        if not self.operation:
            return r[t.MutableSequenceOf[m.Ldif.Entry]].fail("No operation specified")
        if self.operation == "remove_attributes":
            if not self.attributes_to_remove:
                return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(
                    "No attributes_to_remove specified for remove_attributes operation",
                )
            results: t.MutableSequenceOf[m.Ldif.Entry] = []
            for entry in self.entries:
                result = self.remove_attributes(entry, self.attributes_to_remove)
                if result.success:
                    results.append(result.value)
            return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(results)
        return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(
            f"Unknown operation: {self.operation}",
        )


__all__: list[str] = ["FlextLdifEntries"]
