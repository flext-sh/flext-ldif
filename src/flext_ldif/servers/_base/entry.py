"""Base Server Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import copy
from abc import ABC, abstractmethod
from collections.abc import Mapping, MutableMapping, MutableSequence
from typing import Annotated, ClassVar, Self, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._base import (
    FlextLdifServerMethodsMixin,
    FlextLdifServersEntryWriteContext,
)


class FlextLdifServersBaseEntry(
    s[t.Ldif.EntryPayload],
    FlextLdifServerMethodsMixin,
    ABC,
):
    """Base class for entry processing servers - satisfies Entry (structural typing)."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
    server_type: Annotated[str, m.Field(description="Server type identifier")] = (
        "unknown"
    )
    priority: Annotated[
        int,
        m.Field(description="Server priority (lower number = higher priority)"),
    ] = 0
    parent_server: Annotated[
        Self | None,
        m.Field(
            exclude=True,
            repr=False,
            description="Reference to parent server instance for server-level access",
        ),
    ] = None

    def __init__(
        self,
        entry_service: p.Ldif.EntryServer | None = None,
        _parent_server: Self | None = None,
    ) -> None:
        """Initialize entry server service with optional DI service injection."""
        super().__init__()
        self._entry_service = entry_service
        if _parent_server is not None:
            object.__setattr__(self, "parent_server", _parent_server)

    auto_execute: ClassVar[bool] = False

    @staticmethod
    def _extract_write_format_options(
        metadata: m.Ldif.ServerMetadata | None,
    ) -> m.Ldif.WriteFormatOptions | None:
        if metadata is None:
            return None
        format_options_raw: t.JsonValue | None = metadata.extensions.get(
            c.Ldif.WRITE_FORMAT_OPTIONS,
        )
        if isinstance(format_options_raw, Mapping):
            try:
                normalized_payload = u.Cli.JSON_MAPPING_ADAPTER.validate_python(
                    format_options_raw,
                )
                serialized = u.Cli.json_dumps(dict(normalized_payload)).unwrap()
                validated: m.Ldif.WriteFormatOptions = (
                    m.Ldif.WriteFormatOptions.model_validate_json(serialized)
                )
            except c.EXC_VALIDATION_TYPE as exc:
                FlextLdifServersBaseEntry._module_logger.warning(
                    "Failed to validate extension write format options",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
            else:
                return validated
        return None

    @abstractmethod
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Check if this server can handle the entry."""
        del attributes, entry_dn
        msg = "Entry servers must implement can_handle"
        raise NotImplementedError(msg)

    @abstractmethod
    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if this server can handle a schema attribute."""
        del attribute
        msg = "Entry servers must implement can_handle_attribute"
        raise NotImplementedError(msg)

    @abstractmethod
    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if this server can handle a schema objectClass."""
        del objectclass
        msg = "Entry servers must implement can_handle_objectclass"
        raise NotImplementedError(msg)

    @override
    def execute(
        self,
        **kwargs: str | m.Ldif.Entry | t.MutableJsonMapping,
    ) -> p.Result[t.Ldif.EntryPayload]:
        """Execute the entry operation for parse or write input.

        Args:
            **kwargs: Either ``ldif_content`` to parse or ``entry_model`` to
                write.

        Returns:
            Result carrying the first parsed entry or the written text; an
            empty payload when no applicable input is present.

        """
        ldif_content = kwargs.get("ldif_content")
        entry_model = kwargs.get("entry_model")
        if isinstance(ldif_content, str):
            entries_result = self._parse_content(ldif_content)
            if entries_result.success:
                entries = entries_result.value
                return r[t.Ldif.EntryPayload].ok(entries[0] if entries else "")
            return r[t.Ldif.EntryPayload].ok("")
        if isinstance(entry_model, m.Ldif.Entry):
            str_result = self._write_entry(entry_model)
            return r[t.Ldif.EntryPayload].ok(str_result.map_or(""))
        return r[t.Ldif.EntryPayload].ok("")

    def parse_server(self, value: str) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse LDIF content into entry models.

        Args:
            value: Raw LDIF content text.

        Returns:
            Result carrying the parsed entries.

        """
        return self._parse_content(value)

    def parse_input(self, ldif_text: str) -> t.MutableSequenceOf[m.Ldif.Entry] | None:
        """Parse LDIF text for direct server consumers.

        Args:
            ldif_text: Raw LDIF content text.

        Returns:
            Parsed entries, or None when parsing fails.

        """
        parse_result = self.parse_server(ldif_text)
        return parse_result.unwrap()

    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: t.MutableStrSequenceMapping,
    ) -> p.Result[m.Ldif.Entry]:
        """Parse a single entry from a DN and its attributes.

        Builds a minimal LDIF record from the DN and attributes, then parses
        it through the server's content pipeline.

        Args:
            entry_dn: Distinguished name of the entry.
            entry_attrs: Attribute names mapped to their value sequences.

        Returns:
            Result carrying the parsed entry, or a failure.

        """
        attrs_dict = dict(entry_attrs)
        ldif_lines = [f"dn: {entry_dn}"]
        for attr_name, attr_values in attrs_dict.items():
            ldif_lines.extend(f"{attr_name}: {value}" for value in attr_values)
        ldif_content = "\n".join(ldif_lines) + "\n"
        return self._parse_content(ldif_content).flat_map(
            lambda entries: (
                r[m.Ldif.Entry].ok(entries[0])
                if entries
                else r[m.Ldif.Entry].fail("No entries parsed")
            ),
        )

    def write(
        self,
        entry_data: m.Ldif.Entry | t.MutableSequenceOf[m.Ldif.Entry],
        write_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Write entry models to an LDIF string.

        Args:
            entry_data: A single entry or a sequence of entries.
            write_options: Optional output formatting options.

        Returns:
            Result carrying the LDIF text, or a failure.

        """
        if isinstance(entry_data, MutableSequence):
            return self._write_entry_list(entry_data, write_options)
        return self._write_single_entry(entry_data, write_options)

    @staticmethod
    def _build_header_lines(
        write_options: m.Ldif.WriteFormatOptions | None,
        entry_count: int,
    ) -> t.MutableSequenceOf[str]:
        """Build the header lines requested by the write options.

        Args:
            write_options: Output formatting options; None emits no headers.
            entry_count: Number of entries reported in the timestamp header.

        Returns:
            Header lines in output order.

        """
        lines: t.MutableSequenceOf[str] = []
        if write_options is None:
            return lines
        if write_options.include_version_header:
            lines.append("version: 1")
        if write_options.include_timestamps:
            timestamp = u.now().isoformat()
            lines.extend((
                f"# Generated on: {timestamp}",
                f"# Total entries: {entry_count}",
            ))
        return lines

    def _convert_raw_attributes(
        self,
        entry_attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> t.MutableStrSequenceMapping:
        """Normalize raw LDIF attribute values into canonical form.

        Decodes byte values and maps attribute names to the server's canonical
        spelling, merging duplicates.

        Args:
            entry_attrs: Raw attribute names mapped to value sequences that
                may contain bytes.

        Returns:
            Canonical attribute mapping with string values.

        """
        converted_attrs: t.MutableStrSequenceMapping = {}
        for attr_name, attr_values in entry_attrs.items():
            canonical_attr_name = self._normalize_attribute_name(attr_name)
            string_values = [
                value.decode("utf-8", errors="replace")
                if isinstance(value, bytes)
                else value
                for value in attr_values
            ]
            if canonical_attr_name in converted_attrs:
                converted_attrs[canonical_attr_name].extend(string_values)
            else:
                converted_attrs[canonical_attr_name] = string_values
        return converted_attrs

    @staticmethod
    def _denormalize_entry(
        entry: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Convert an entry from RFC form to the target server's dialect.

        Args:
            entry: Entry in RFC-normalized form.

        Returns:
            The converted entry.

        """
        return entry

    @abstractmethod
    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Run hook after parsing an entry."""
        del entry
        msg = "Entry servers must implement _hook_post_parse_entry"
        raise NotImplementedError(msg)

    @abstractmethod
    def _hook_pre_write_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Run hook before writing an entry."""
        del entry
        msg = "Entry servers must implement _hook_pre_write_entry"
        raise NotImplementedError(msg)

    @staticmethod
    def _hook_validate_entry_raw(
        dn: str,
        attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> p.Result[bool]:
        """Validate a raw entry before parsing.

        Args:
            dn: Distinguished name of the raw entry.
            attrs: Raw attribute names mapped to value sequences.

        Returns:
            Result carrying True when the entry is acceptable, or a failure.

        """
        del attrs
        if not dn:
            return r[bool].fail("DN cannot be empty")
        return r[bool].ok(value=True)

    @staticmethod
    def _inject_write_format_options(
        entry: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions,
    ) -> m.Ldif.Entry:
        """Inject write format options into the entry metadata extensions.

        Args:
            entry: Entry whose metadata receives the options.
            write_options: Output formatting options to inject.

        Returns:
            A copy of the entry carrying the options.

        """
        format_options_payload = write_options.model_dump(
            mode="json",
            exclude_none=True,
        )
        existing_extensions: t.MutableJsonMapping = (
            # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: deep-copy the
            # plain mapping (was model_copy(deep=True)).
            copy.deepcopy(entry.metadata.extensions) if entry.metadata else {}
        )
        existing_extensions[c.Ldif.WRITE_FORMAT_OPTIONS] = format_options_payload
        if entry.metadata:
            updated_metadata = entry.metadata.model_copy(
                update={"extensions": existing_extensions},
            )
        else:
            updated_metadata = m.Ldif.ServerMetadata(
                server_type=c.Ldif.ServerTypes.RFC,
                extensions=existing_extensions,
            )
        copied: m.Ldif.Entry = entry.model_copy(update={"metadata": updated_metadata})
        return copied

    @abstractmethod
    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to the server's canonical form."""
        del attr_name
        msg = "Entry servers must implement _normalize_attribute_name"
        raise NotImplementedError(msg)

    @staticmethod
    def _normalize_entry(entry: m.Ldif.Entry) -> m.Ldif.Entry:
        """Normalize an entry to RFC form with metadata tracking.

        Args:
            entry: Entry in the server's own dialect.

        Returns:
            The RFC-normalized entry.

        """
        return entry

    @abstractmethod
    def _parse_content(
        self,
        ldif_content: str,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models (internal)."""
        del ldif_content
        msg = "Entry servers must implement _parse_content"
        raise NotImplementedError(msg)

    @abstractmethod
    def _parse_entry_from_lines(
        self,
        lines: t.MutableSequenceOf[str],
    ) -> p.Result[m.Ldif.Entry]:
        """Parse one unfolded LDIF record into an Entry model."""
        del lines
        msg = "Entry servers must implement _parse_entry_from_lines"
        raise NotImplementedError(msg)

    def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write an entry model to an RFC-compliant LDIF string.

        Args:
            entry_data: Entry to serialize.

        Returns:
            Result carrying the LDIF text, or a failure.

        """
        context = FlextLdifServersEntryWriteContext.build(
            entry_data,
            self.server_type,
            self._extract_write_format_options(entry_data.metadata),
        )
        restored = context.restore_original()
        if restored is not None:
            return restored
        output_lines: t.MutableSequenceOf[str] = []
        header_failure = context.emit_entry_header(output_lines)
        if header_failure is not None:
            return header_failure
        return context.emit_changetype_body(entry_data, output_lines)

    def _write_entry_list(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> p.Result[str]:
        """Write a sequence of entries to LDIF.

        Args:
            entries: Entries to serialize in order.
            write_options: Optional output formatting options.

        Returns:
            Result carrying the joined LDIF text, or a failure.

        """
        header_lines = self._build_header_lines(write_options, len(entries))

        def format_output(results: t.StrSequence) -> str:
            # RFC 2849 SEP: a blank line closes the header and every record.
            blocks = [
                *(("\n".join(header_lines) + "\n",) if header_lines else ()),
                *(record for record in results if record),
            ]
            return "".join(f"{block}\n" for block in blocks)

        def write_entry(entry: m.Ldif.Entry) -> p.Result[str]:
            return self._write_single_entry(entry, write_options)

        return r[str].traverse(entries, write_entry).map(format_output)

    def _write_single_entry(
        self,
        entry: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> p.Result[str]:
        """Write one entry to LDIF, applying the write options first.

        Args:
            entry: Entry to serialize.
            write_options: Optional output formatting options.

        Returns:
            Result carrying the LDIF text, or a failure.

        """
        if write_options is not None:
            entry = self._inject_write_format_options(entry, write_options)
        return self._write_entry(entry)


__all__: list[str] = ["FlextLdifServersBaseEntry"]
