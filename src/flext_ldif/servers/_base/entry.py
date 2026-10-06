"""Base Server Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, MutableMapping, MutableSequence
from typing import Annotated, ClassVar, Self, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._base.entry_write import FlextLdifServersEntryWriteContext
from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin


class FlextLdifServersBaseEntry(s[t.Ldif.EntryPayload], FlextLdifServerMethodsMixin):
    """Base class for entry processing servers - satisfies Entry (structural typing)."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
    server_type: Annotated[str, u.Field(description="Server type identifier")] = (
        "unknown"
    )
    priority: Annotated[
        int,
        u.Field(description="Server priority (lower number = higher priority)"),
    ] = 0
    parent_server: Annotated[
        Self | None,
        u.Field(
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
            object.__setattr__(self, "_parent_server", _parent_server)

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
                normalized_payload = t.Cli.JSON_MAPPING_ADAPTER.validate_python(
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

    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Check if this server can handle the entry."""
        msg = "Entry servers must implement can_handle"
        raise NotImplementedError(msg)

    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if this server can handle a schema attribute."""
        msg = "Entry servers must implement can_handle_attribute"
        raise NotImplementedError(msg)

    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if this server can handle a schema objectClass."""
        msg = "Entry servers must implement can_handle_objectclass"
        raise NotImplementedError(msg)

    @override
    def execute(
        self,
        **kwargs: str | m.Ldif.Entry | t.MutableJsonMapping,
    ) -> p.Result[t.Ldif.EntryPayload]:
        """Execute entry operation (parse/write).

        Returns:
            The resulting ``p.Result[t.Ldif.EntryPayload]``.
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
        """Parse LDIF content string into Entry models.

        Returns:
            The resulting ``p.Result[t.MutableSequenceOf[m.Ldif.Entry]]``.
        """
        return self._parse_content(value)

    def parse_input(self, ldif_text: str) -> t.MutableSequenceOf[m.Ldif.Entry] | None:
        """Compatibility parser entrypoint for direct server consumers.

        Returns:
            The resulting ``t.MutableSequenceOf[m.Ldif.Entry] | None``.
        """
        parse_result = self.parse_server(ldif_text)
        return parse_result.unwrap()

    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: t.MutableStrSequenceMapping,
    ) -> p.Result[m.Ldif.Entry]:
        """Parse a single entry from DN and attributes.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
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
        """Write Entry model(s) to LDIF string format.

        Returns:
            The resulting ``p.Result[str]``.
        """
        if isinstance(entry_data, MutableSequence):
            return self._write_entry_list(entry_data, write_options)
        return self._write_single_entry(entry_data, write_options)

    @staticmethod
    def _build_header_lines(
        write_options: m.Ldif.WriteFormatOptions | None,
        entry_count: int,
    ) -> t.MutableSequenceOf[str]:
        """Build header lines based on write options.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
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
        """Convert raw LDIF attributes to t.MutableStrSequenceMapping format.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
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
        target_server: str | None = None,
    ) -> m.Ldif.Entry:
        """Denormalize entry from RFC format to target server format.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        _ = target_server
        return entry

    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Run hook after parsing an entry."""
        msg = "Entry servers must implement _hook_post_parse_entry"
        raise NotImplementedError(msg)

    def _hook_pre_write_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Run hook before writing an entry."""
        msg = "Entry servers must implement _hook_pre_write_entry"
        raise NotImplementedError(msg)

    @staticmethod
    def _hook_validate_entry_raw(
        dn: str,
        attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> p.Result[bool]:
        """Validate raw entry before parsing.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        _ = attrs
        if not dn:
            return r[bool].fail("DN cannot be empty")
        return r[bool].ok(True)

    @staticmethod
    def _inject_write_format_options(
        entry: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions,
    ) -> m.Ldif.Entry:
        """Inject write format options into entry metadata extensions.

        Returns:
            The resulting ``m.Ldif.Entry``.
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

    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to the server's canonical form."""
        msg = "Entry servers must implement _normalize_attribute_name"
        raise NotImplementedError(msg)

    @staticmethod
    def _normalize_entry(entry: m.Ldif.Entry) -> m.Ldif.Entry:
        """Normalize entry to RFC format with metadata tracking.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        return entry

    def _parse_content(
        self,
        ldif_content: str,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models (internal)."""
        msg = "Entry servers must implement _parse_content"
        raise NotImplementedError(msg)

    def _parse_entry_from_lines(
        self,
        lines: t.MutableSequenceOf[str],
    ) -> p.Result[m.Ldif.Entry]:
        """Parse one unfolded LDIF record into an Entry model."""
        msg = "Entry servers must implement _parse_entry_from_lines"
        raise NotImplementedError(msg)

    def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write Entry model to RFC-compliant LDIF string (internal).

        Returns:
            The resulting ``p.Result[str]``.
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
        effective_changetype = entry_data.changetype or context.ldif_changetype
        if effective_changetype in {
            c.Ldif.ChangeType.ADD,
            c.Ldif.ChangeType.DELETE,
            c.Ldif.ChangeType.MODIFY,
            c.Ldif.ChangeType.MODDN,
            c.Ldif.ChangeType.MODRDN,
        }:
            output_lines.append(f"changetype: {effective_changetype}")
        if effective_changetype == c.Ldif.ChangeType.MODIFY:
            return context.emit_modify_entry(output_lines)
        if effective_changetype in {
            c.Ldif.ChangeType.MODDN,
            c.Ldif.ChangeType.MODRDN,
        }:
            return context.emit_modifydn_entry(output_lines)
        if effective_changetype == c.Ldif.ChangeType.DELETE:
            output_lines.append("")
            return r[str].ok("\n".join(output_lines))
        return context.emit_add_entry(output_lines)

    def _write_entry_list(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> p.Result[str]:
        """Write list of entries to LDIF.

        Returns:
            The resulting ``p.Result[str]``.
        """
        header_lines = self._build_header_lines(write_options, len(entries))

        def format_output(results: t.StrSequence) -> str:
            all_lines = [*header_lines, *results]
            ldif_output = "\n".join(all_lines) if all_lines else ""
            if header_lines and (not ldif_output.endswith("\n")):
                ldif_output += "\n"
            return ldif_output

        def write_entry(entry: m.Ldif.Entry) -> p.Result[str]:
            return self._write_single_entry(entry, write_options)

        return r[str].traverse(entries, write_entry).map(format_output)

    def _write_single_entry(
        self,
        entry: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> p.Result[str]:
        """Write single entry to LDIF.

        Returns:
            The resulting ``p.Result[str]``.
        """
        if write_options is not None:
            entry = self._inject_write_format_options(entry, write_options)
        return self._write_entry(entry)
