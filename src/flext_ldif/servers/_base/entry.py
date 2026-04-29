"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

import base64
import re
from collections.abc import (
    Mapping,
    MutableMapping,
    MutableSequence,
)
from datetime import UTC, datetime
from typing import Annotated, ClassVar, Self, override

from flext_core import s
from flext_ldif import (
    FlextLdifServerMethodsMixin,
    c,
    m,
    p,
    r,
    t,
    u,
)

logger = u.fetch_logger(__name__)


class FlextLdifServersBaseEntry(
    FlextLdifServerMethodsMixin,
    s[t.Ldif.EntryPayload],
):
    """Base class for entry processing quirks - satisfies Entry (structural typing)."""

    server_type: Annotated[
        str,
        u.Field(
            description="Server type identifier",
        ),
    ] = "unknown"
    priority: Annotated[
        int,
        u.Field(
            description="Quirk priority (lower number = higher priority)",
        ),
    ] = 0
    parent_quirk: Annotated[
        Self | None,
        u.Field(
            exclude=True,
            repr=False,
            description="Reference to parent quirk instance for server-level access",
        ),
    ] = None

    def __init__(
        self,
        entry_service: p.Ldif.EntryQuirk | None = None,
        _parent_quirk: Self | None = None,
    ) -> None:
        """Initialize entry quirk service with optional DI service injection."""
        super().__init__()
        self._entry_service = entry_service
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    auto_execute: ClassVar[bool] = False

    @staticmethod
    def _extract_write_format_options(
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> m.Ldif.WriteFormatOptions | None:
        if metadata is None:
            return None
        format_options_raw: t.JsonValue | None = metadata.extensions.get(
            c.Ldif.WRITE_FORMAT_OPTIONS,
        )
        if isinstance(format_options_raw, Mapping):
            try:
                validated: m.Ldif.WriteFormatOptions = (
                    m.Ldif.WriteFormatOptions.model_validate(
                        t.Cli.JSON_MAPPING_ADAPTER.validate_python(format_options_raw),
                    )
                )
                return validated
            except (c.ValidationError, TypeError) as exc:
                logger.warning(
                    "Failed to validate extension write format options",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
        return None

    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Check if this quirk can handle the entry."""
        _ = entry_dn
        _ = attributes
        return False

    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if this quirk can handle a schema attribute."""
        _ = attribute
        return False

    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if this quirk can handle a schema objectClass."""
        _ = objectclass
        return False

    @override
    def execute(
        self,
        **kwargs: str | m.Ldif.Entry | t.MutableJsonMapping,
    ) -> r[t.Ldif.EntryPayload]:
        """Execute entry operation (parse/write)."""
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

    def parse_quirk(self, value: str) -> r[MutableSequence[m.Ldif.Entry]]:
        """Parse LDIF content string into Entry models."""
        return self._parse_content(value)

    def parse_input(self, ldif_text: str) -> MutableSequence[m.Ldif.Entry] | None:
        """Compatibility parser entrypoint for direct quirk consumers."""
        parse_result = self.parse_quirk(ldif_text)
        if parse_result.failure:
            return None
        return parse_result.value

    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: t.MutableStrSequenceMapping,
    ) -> r[m.Ldif.Entry]:
        """Parse a single entry from DN and attributes."""
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
        entry_data: m.Ldif.Entry | MutableSequence[m.Ldif.Entry],
        write_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> r[str]:
        """Write Entry model(s) to LDIF string format."""
        if isinstance(entry_data, MutableSequence):
            return self._write_entry_list(entry_data, write_options)
        return self._write_single_entry(entry_data, write_options)

    def _build_header_lines(
        self,
        write_options: m.Ldif.WriteFormatOptions | None,
        entry_count: int,
    ) -> MutableSequence[str]:
        """Build header lines based on write options."""
        lines: MutableSequence[str] = []
        if write_options is None:
            return lines
        if write_options.include_version_header:
            lines.append("version: 1")
        if write_options.include_timestamps:
            timestamp = datetime.now(UTC).isoformat()
            lines.extend((
                f"# Generated on: {timestamp}",
                f"# Total entries: {entry_count}",
            ))
        return lines

    def _convert_raw_attributes(
        self,
        entry_attrs: MutableMapping[str, MutableSequence[str | bytes]],
    ) -> t.MutableStrSequenceMapping:
        """Convert raw LDIF attributes to t.MutableStrSequenceMapping format."""
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

    def _denormalize_entry(
        self,
        entry: m.Ldif.Entry,
        target_server: str | None = None,
    ) -> m.Ldif.Entry:
        """Denormalize entry from RFC format to target server format."""
        _ = target_server
        return entry

    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Hook called after parsing an entry."""
        return r[m.Ldif.Entry].ok(entry)

    def _hook_pre_write_entry(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Hook called before writing an entry."""
        return r[m.Ldif.Entry].ok(entry)

    def _hook_validate_entry_raw(
        self,
        dn: str,
        attrs: MutableMapping[str, MutableSequence[str | bytes]],
    ) -> r[bool]:
        """Hook to validate raw entry before parsing."""
        _ = attrs
        if not dn:
            return r[bool].fail("DN cannot be empty")
        return r[bool].ok(True)

    def _inject_write_format_options(
        self,
        entry: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions,
    ) -> m.Ldif.Entry:
        """Inject write format options into entry metadata extensions."""
        format_options_payload = write_options.model_dump(exclude_none=True)
        existing_extensions = (
            entry.metadata.extensions.model_copy(deep=True)
            if entry.metadata
            else m.Ldif.DynamicMetadata()
        )
        existing_extensions[c.Ldif.WRITE_FORMAT_OPTIONS] = format_options_payload
        if entry.metadata:
            updated_metadata = entry.metadata.model_copy(
                update={
                    "extensions": existing_extensions,
                },
            )
        else:
            updated_metadata = m.Ldif.QuirkMetadata(
                quirk_type=c.Ldif.ServerTypes.RFC,
                extensions=existing_extensions,
            )
        copied: m.Ldif.Entry = entry.model_copy(update={"metadata": updated_metadata})
        return copied

    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to RFC 2849 canonical form."""
        if not attr_name:
            return attr_name
        if attr_name.lower() == "objectclass":
            return "objectClass"
        return attr_name

    def _normalize_entry(self, entry: m.Ldif.Entry) -> m.Ldif.Entry:
        """Normalize entry to RFC format with metadata tracking."""
        return entry

    def _parse_content(self, ldif_content: str) -> r[MutableSequence[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models (internal)."""
        _ = ldif_content
        return r[MutableSequence[m.Ldif.Entry]].fail("Must be implemented by subclass")

    def _write_entry(self, entry_data: m.Ldif.Entry) -> r[str]:
        """Write Entry model to RFC-compliant LDIF string (internal)."""
        output_lines: MutableSequence[str] = []
        fold_long_lines = True
        line_width = c.Ldif.LINE_FOLD_WIDTH
        include_dn_comments = False
        normalize_attribute_names = False
        restore_original_format = False
        write_empty_values = True
        write_hidden_attributes_as_comments = False
        write_metadata_as_comments = False
        use_original_acl_format_as_name = False
        hidden_attributes: set[str] = set()
        acl_original_format: str | None = None
        extensions_data: t.Ldif.MutableMetadataMapping = {}
        if entry_data.metadata:
            metadata_extensions = entry_data.metadata.extensions
            if u.matches_type(metadata_extensions, Mapping):
                extensions_data = dict(metadata_extensions)
        hidden_raw = extensions_data.get(c.Ldif.HIDDEN_ATTRIBUTES)
        if isinstance(hidden_raw, list):
            hidden_text: MutableSequence[str] = [str(value) for value in hidden_raw]
            hidden_attributes = {attr.lower() for attr in hidden_text}
        acl_original_raw = extensions_data.get(c.Ldif.ACL_ORIGINAL_FORMAT)
        if isinstance(acl_original_raw, str):
            acl_original_format = acl_original_raw
        format_options = self._extract_write_format_options(entry_data.metadata)
        ldif_changetype: str | None = None
        ldif_modify_operation: str = "add"
        if format_options is not None:
            fold_long_lines = format_options.fold_long_lines
            line_width = format_options.line_width
            include_dn_comments = format_options.include_dn_comments
            normalize_attribute_names = format_options.normalize_attribute_names
            restore_original_format = format_options.restore_original_format
            write_empty_values = format_options.write_empty_values
            write_hidden_attributes_as_comments = (
                format_options.write_hidden_attributes_as_comments
            )
            write_metadata_as_comments = format_options.write_metadata_as_comments
            use_original_acl_format_as_name = (
                format_options.use_original_acl_format_as_name
            )
            ldif_changetype = format_options.ldif_changetype
            ldif_modify_operation = format_options.ldif_modify_operation or "add"

        effective_line_width = (
            line_width if fold_long_lines else max(line_width, 1_000_000)
        )

        def should_restore_original() -> bool:
            """Restore original LDIF only for same-server round-trips."""
            if not restore_original_format or entry_data.metadata is None:
                return False
            return (
                str(entry_data.metadata.original_server_type).lower()
                == self.server_type.lower()
            )

        def maybe_replace_acl_name(attr_name: str, value: str) -> str:
            if not use_original_acl_format_as_name:
                return value
            if attr_name.lower() != "aci" or not acl_original_format:
                return value
            safe_acl_name = acl_original_format.replace('"', "'")
            return re.sub(r'acl\\s+"[^"]*"', f'acl "{safe_acl_name}"', value, count=1)

        def emit_attribute_line(
            attr_name: str,
            value: str,
            *,
            value_origin: str | None = None,
            raw_value: str | None = None,
        ) -> str:
            effective_name = (
                attr_name.lower() if normalize_attribute_names else attr_name
            )
            effective_value = maybe_replace_acl_name(attr_name, value)
            if value_origin == c.Ldif.ValueOrigin.BASE64 and raw_value:
                return f"{effective_name}:: {raw_value}"
            if (
                value_origin
                in {
                    c.Ldif.ValueOrigin.URL,
                    c.Ldif.ValueOrigin.FILE,
                }
                and raw_value
            ):
                return f"{effective_name}:< {raw_value}"
            should_encode = effective_name.lower() in c.Ldif.BINARY_ATTRIBUTE_NAMES
            if should_encode or u.Ldif.needs_base64_encoding(effective_value):
                encoded = base64.b64encode(effective_value.encode("utf-8")).decode(
                    "ascii",
                )
                return f"{effective_name}:: {encoded}"
            return f"{effective_name}: {effective_value}"

        def emit_control_line(control: m.Ldif.Control) -> str:
            """Serialize RFC 2849 control line."""
            line = f"control: {control.control_type}"
            if control.criticality is not None:
                line += " true" if control.criticality else " false"
            if control.value is None:
                return line
            if control.value_origin == c.Ldif.ValueOrigin.BASE64:
                encoded_value = control.raw_value or control.value
                return f"{line}:: {encoded_value}"
            if control.value_origin in {
                c.Ldif.ValueOrigin.URL,
                c.Ldif.ValueOrigin.FILE,
            }:
                url_value = control.raw_value or control.value
                return f"{line}:< {url_value}"
            return f"{line}: {control.value}"

        def get_attribute_value_metadata(
            attr_name: str,
            value_index: int,
        ) -> tuple[str | None, str | None]:
            """Return preserved value origin and raw payload for an attribute value."""
            if entry_data.attributes is None:
                return (None, None)
            attribute_metadata = entry_data.attributes.attribute_metadata.get(attr_name)
            if not isinstance(attribute_metadata, Mapping):
                return (None, None)
            origins_raw = attribute_metadata.get("value_origins")
            raw_values_raw = attribute_metadata.get("raw_values")
            origin: str | None = None
            raw_value: str | None = None
            if isinstance(origins_raw, list) and value_index < len(origins_raw):
                origin = origins_raw[value_index]
            if isinstance(raw_values_raw, list) and value_index < len(raw_values_raw):
                raw_value = raw_values_raw[value_index]
            return (origin, raw_value)

        acl_attribute_names: set[str] = {
            name.lower() for name in c.Ldif.DEFAULT_ACL_ATTRIBUTES
        }

        def append_attribute_line(attr_name: str, line: str) -> None:
            if attr_name.lower() in acl_attribute_names:
                output_lines.append(line)
                return
            output_lines.extend(u.Ldif.fold_line(line, width=effective_line_width))

        if should_restore_original() and entry_data.metadata is not None:
            original_ldif_raw: object = entry_data.metadata.original_strings.get(
                "entry_original_ldif"
            )
            if not original_ldif_raw:
                return r[str].ok("")
            restored_output = str(original_ldif_raw)
            if restored_output and not restored_output.endswith("\n"):
                restored_output += "\n"
            return r[str].ok(restored_output)

        if write_metadata_as_comments and entry_data.metadata is not None:
            output_lines.append("# Entry Metadata:")
        if include_dn_comments and entry_data.dn:
            output_lines.append(f"# DN: {entry_data.dn.value}")
        if entry_data.dn:
            dn_line = f"dn: {entry_data.dn.value}"
            output_lines.extend(u.Ldif.fold_line(dn_line, width=effective_line_width))
        else:
            return r[str].fail("Entry DN is None")
        for control in entry_data.controls:
            output_lines.extend(
                u.Ldif.fold_line(
                    emit_control_line(control),
                    width=effective_line_width,
                ),
            )
        effective_changetype = entry_data.changetype or ldif_changetype
        if effective_changetype in {
            c.Ldif.LdifChangeType.ADD,
            c.Ldif.LdifChangeType.DELETE,
            c.Ldif.LdifChangeType.MODIFY,
            c.Ldif.LdifChangeType.MODDN,
            c.Ldif.LdifChangeType.MODRDN,
        }:
            output_lines.append(f"changetype: {effective_changetype}")
        if effective_changetype == c.Ldif.LdifChangeType.MODIFY:
            if entry_data.change_operations:
                for change_operation in entry_data.change_operations:
                    output_lines.append(
                        f"{change_operation.operation}: {change_operation.attribute}",
                    )
                    for value_data in change_operation.values:
                        attr_line = emit_attribute_line(
                            change_operation.attribute,
                            value_data.value,
                            value_origin=value_data.value_origin,
                            raw_value=value_data.raw_value,
                        )
                        append_attribute_line(change_operation.attribute, attr_line)
                    output_lines.append("-")
                output_lines.append("")
                return r[str].ok("\n".join(output_lines))
            modify_excluded = {"objectclass", "cn", "changetype", "dn"}
            if hasattr(entry_data, "attributes") and entry_data.attributes:
                for attr_name, values in entry_data.attributes.items():
                    if attr_name.lower() in modify_excluded:
                        continue
                    non_empty = [v for v in values if v]
                    if not non_empty:
                        continue
                    output_lines.append(f"{ldif_modify_operation}: {attr_name}")
                    for value_index, value in enumerate(non_empty):
                        value_origin, raw_value = get_attribute_value_metadata(
                            attr_name,
                            value_index,
                        )
                        attr_line = emit_attribute_line(
                            attr_name,
                            value,
                            value_origin=value_origin,
                            raw_value=raw_value,
                        )
                        append_attribute_line(attr_name, attr_line)
                    output_lines.append("-")
            output_lines.append("")
            return r[str].ok("\n".join(output_lines))
        if effective_changetype in {
            c.Ldif.LdifChangeType.MODDN,
            c.Ldif.LdifChangeType.MODRDN,
        }:
            if entry_data.newrdn:
                output_lines.extend(
                    u.Ldif.fold_line(
                        f"newrdn: {entry_data.newrdn}",
                        width=effective_line_width,
                    ),
                )
            if entry_data.deleteoldrdn is not None:
                delete_old = "1" if entry_data.deleteoldrdn else "0"
                output_lines.append(f"deleteoldrdn: {delete_old}")
            if entry_data.newsuperior:
                output_lines.extend(
                    u.Ldif.fold_line(
                        f"newsuperior: {entry_data.newsuperior}",
                        width=effective_line_width,
                    ),
                )
            output_lines.append("")
            return r[str].ok("\n".join(output_lines))
        if effective_changetype == c.Ldif.LdifChangeType.DELETE:
            output_lines.append("")
            return r[str].ok("\n".join(output_lines))
        if hasattr(entry_data, "attributes") and entry_data.attributes:
            for attr_name, values in entry_data.attributes.items():
                attr_is_hidden = attr_name.lower() in hidden_attributes
                for value_index, value in enumerate(values):
                    str_value = value
                    if not str_value and (not write_empty_values):
                        continue
                    value_origin, raw_value = get_attribute_value_metadata(
                        attr_name,
                        value_index,
                    )
                    attr_line = emit_attribute_line(
                        attr_name,
                        str_value,
                        value_origin=value_origin,
                        raw_value=raw_value,
                    )
                    if attr_is_hidden and write_hidden_attributes_as_comments:
                        attr_line = f"# {attr_line}"
                    append_attribute_line(attr_name, attr_line)
        output_lines.append("")
        ldif_content = "\n".join(output_lines)
        return r[str].ok(ldif_content)

    def _write_entry_list(
        self,
        entries: MutableSequence[m.Ldif.Entry],
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> r[str]:
        """Write list of entries to LDIF."""
        header_lines = self._build_header_lines(write_options, len(entries))

        def format_output(results: t.StrSequence) -> str:
            all_lines = [*header_lines, *results]
            ldif_output = "\n".join(all_lines) if all_lines else ""
            if header_lines and (not ldif_output.endswith("\n")):
                ldif_output += "\n"
            return ldif_output

        return r.traverse(
            entries,
            lambda e: self._write_single_entry(e, write_options),
        ).map(format_output)

    def _write_single_entry(
        self,
        entry: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> r[str]:
        """Write single entry to LDIF."""
        if write_options is not None:
            entry = self._inject_write_format_options(entry, write_options)
        return self._write_entry(entry)
