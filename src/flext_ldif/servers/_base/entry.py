"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from typing import ClassVar

from flext_core import FlextLogger, FlextResult, FlextService, u as core_u
from pydantic import Field, ValidationError

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.constants import QuirkMethodsMixin
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifServersBaseEntry(
    QuirkMethodsMixin,
    FlextService[m.Ldif.Entry | str],
):
    """Base class for entry processing quirks - satisfies EntryProtocol (structural typing)."""

    server_type: str = "unknown"
    """Server type identifier."""

    priority: int = 0
    """Quirk priority (lower number = higher priority)."""

    parent_quirk: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description=("Reference to parent quirk instance for server-level access"),
    )

    def __init__(
        self,
        entry_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize entry quirk service with optional DI service injection."""
        super().__init__(**kwargs)
        self._entry_service = entry_service

        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    auto_execute: ClassVar[bool] = False

    def _hook_validate_entry_raw(
        self,
        dn: str,
        attrs: Mapping[str, list[str | bytes]],
    ) -> FlextResult[bool]:
        """Hook to validate raw entry before parsing."""
        _ = attrs
        if not dn:
            return FlextResult.fail("DN cannot be empty")
        return FlextResult.ok(True)

    def _hook_post_parse_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook called after parsing an entry."""
        return FlextResult.ok(entry)

    def _hook_pre_write_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook called before writing an entry."""
        return FlextResult.ok(entry)

    def can_handle_attribute(
        self,
        attribute: m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if this quirk can handle a schema attribute."""
        _ = attribute
        return False

    def can_handle_objectclass(
        self,
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if this quirk can handle a schema objectClass."""
        _ = objectclass
        return False

    def can_handle(
        self,
        entry_dn: str,
        attributes: Mapping[str, list[str]],
    ) -> bool:
        """Check if this quirk can handle the entry."""
        _ = entry_dn
        _ = attributes
        return False

    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to RFC 2849 canonical form."""
        if not attr_name:
            return attr_name

        if attr_name.lower() == "objectclass":
            return "objectClass"

        return attr_name

    def _convert_raw_attributes(
        self,
        entry_attrs: Mapping[str, list[str | bytes]],
    ) -> Mapping[str, list[str]]:
        """Convert raw LDIF attributes to dict[str, list[str]] format."""
        converted_attrs: dict[str, list[str]] = {}

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

    def _parse_content(
        self,
        ldif_content: str,
    ) -> FlextResult[list[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models (internal)."""
        _ = ldif_content
        return FlextResult.fail("Must be implemented by subclass")

    def _write_entry(
        self,
        entry_data: m.Ldif.Entry,
    ) -> FlextResult[str]:
        """Write Entry model to RFC-compliant LDIF string (internal)."""
        ascii_printable_limit = 127
        output_lines: list[str] = []

        fold_long_lines = True
        line_width = c.Ldif.Format.LINE_FOLD_WIDTH
        include_dn_comments = False
        normalize_attribute_names = False
        write_empty_values = True
        write_hidden_attributes_as_comments = False
        write_metadata_as_comments = False
        use_original_acl_format_as_name = False
        hidden_attributes: set[str] = set()
        acl_original_format: str | None = None

        extensions_data: Mapping[str, object] = {}
        if entry_data.metadata:
            metadata_extensions = entry_data.metadata.extensions
            if core_u.is_type(metadata_extensions, Mapping):
                extensions_data = dict(metadata_extensions)
            elif isinstance(metadata_extensions, m.Ldif.DynamicMetadata):
                extensions_data = dict(metadata_extensions.to_dict())

        hidden_raw = extensions_data.get(c.Ldif.MetadataKeys.HIDDEN_ATTRIBUTES)
        if isinstance(hidden_raw, list):
            hidden_attributes = {
                attr.lower() for attr in hidden_raw if isinstance(attr, str)
            }

        acl_original_raw = extensions_data.get(c.Ldif.MetadataKeys.ACL_ORIGINAL_FORMAT)
        if isinstance(acl_original_raw, str):
            acl_original_format = acl_original_raw

        format_options = self._extract_write_format_options(entry_data.metadata)
        if format_options is not None:
            fold_long_lines = bool(format_options.fold_long_lines)
            line_width = int(format_options.line_width)
            include_dn_comments = bool(format_options.include_dn_comments)
            normalize_attribute_names = bool(format_options.normalize_attribute_names)
            write_empty_values = bool(format_options.write_empty_values)
            write_hidden_attributes_as_comments = bool(
                format_options.write_hidden_attributes_as_comments,
            )
            write_metadata_as_comments = bool(format_options.write_metadata_as_comments)
            use_original_acl_format_as_name = bool(
                format_options.use_original_acl_format_as_name,
            )

        def fold_line(line: str) -> list[str]:
            """Fold a line per RFC 2849 if fold_long_lines is enabled."""
            effective_width = (
                line_width if fold_long_lines else c.Ldif.Format.LINE_FOLD_WIDTH
            )
            if len(line.encode("utf-8")) <= effective_width:
                return [line]

            folded: list[str] = []
            line_bytes = line.encode("utf-8")
            pos = 0
            while pos < len(line_bytes):
                if not folded:
                    chunk_end = min(pos + effective_width, len(line_bytes))
                else:
                    chunk_end = min(pos + effective_width - 1, len(line_bytes))

                while chunk_end > pos:
                    try:
                        chunk = line_bytes[pos:chunk_end].decode("utf-8")
                        break
                    except UnicodeDecodeError:
                        chunk_end -= 1
                else:
                    chunk_end = pos + 1
                    chunk = line_bytes[pos:chunk_end].decode("utf-8", errors="replace")
                if folded:
                    folded.append(" " + chunk)
                else:
                    folded.append(chunk)
                pos = chunk_end
            return folded

        def should_base64_encode(attr_name: str, value: str) -> bool:
            if attr_name.lower() in c.Ldif.RfcBinaryAttributes.BINARY_ATTRIBUTE_NAMES:
                return True
            if not value:
                return False
            if value[0] in c.Ldif.Format.BASE64_START_CHARS:
                return True
            if value[-1] == " ":
                return True
            for char in value:
                char_ord = ord(char)
                if (
                    char_ord < c.Ldif.LdifProcessing.ASCII_SPACE_CHAR
                    or char_ord > ascii_printable_limit
                ):
                    return True
            return False

        def maybe_replace_acl_name(attr_name: str, value: str) -> str:
            if not use_original_acl_format_as_name:
                return value
            if attr_name.lower() != "aci" or not acl_original_format:
                return value
            safe_acl_name = acl_original_format.replace('"', "'")
            return re.sub(
                r'acl\s+"[^"]*"',
                f'acl "{safe_acl_name}"',
                value,
                count=1,
            )

        def emit_attribute_line(attr_name: str, value: str) -> str:
            effective_name = (
                attr_name.lower() if normalize_attribute_names else attr_name
            )
            effective_value = maybe_replace_acl_name(attr_name, value)
            if should_base64_encode(effective_name, effective_value):
                encoded = base64.b64encode(effective_value.encode("utf-8")).decode(
                    "ascii"
                )
                return f"{effective_name}:: {encoded}"
            return f"{effective_name}: {effective_value}"

        acl_attribute_names: set[str] = {
            name.lower() for name in c.Ldif.AclAttributes.DEFAULT_ACL_ATTRIBUTES
        }
        acl_attribute_names.update(
            name.lower() for name in c.Ldif.AclAttributeRegistry.RFC_FOUNDATION
        )
        for names in c.Ldif.AclAttributeRegistry.SERVER_QUIRKS.values():
            acl_attribute_names.update(name.lower() for name in names)

        def append_attribute_line(attr_name: str, line: str) -> None:
            if attr_name.lower() in acl_attribute_names:
                output_lines.append(line)
                return
            output_lines.extend(fold_line(line))

        if write_metadata_as_comments and entry_data.metadata is not None:
            output_lines.append("# Entry Metadata:")

        if include_dn_comments and entry_data.dn:
            output_lines.append(f"# DN: {entry_data.dn.value}")

        if entry_data.dn:
            dn_line = f"dn: {entry_data.dn.value}"
            output_lines.extend(fold_line(dn_line))
        else:
            return FlextResult.fail("Entry DN is None")

        if core_u.has(entry_data, "attributes") and entry_data.attributes:
            for attr_name, values in entry_data.attributes.items():
                attr_is_hidden = attr_name.lower() in hidden_attributes
                if core_u.is_type(values, list):
                    for value in values:
                        str_value = str(value)
                        if not str_value and not write_empty_values:
                            continue
                        attr_line = emit_attribute_line(attr_name, str_value)
                        if attr_is_hidden and write_hidden_attributes_as_comments:
                            attr_line = f"# {attr_line}"
                        append_attribute_line(attr_name, attr_line)
                else:
                    str_value = str(values)
                    if not str_value and not write_empty_values:
                        continue
                    attr_line = emit_attribute_line(attr_name, str_value)
                    if attr_is_hidden and write_hidden_attributes_as_comments:
                        attr_line = f"# {attr_line}"
                    append_attribute_line(attr_name, attr_line)

        output_lines.append("")

        ldif_content = "\n".join(output_lines)
        return FlextResult.ok(ldif_content)

    def parse(self, ldif_content: str) -> FlextResult[list[m.Ldif.Entry]]:
        """Parse LDIF content string into Entry models."""
        return self._parse_content(ldif_content)

    def _build_header_lines(
        self,
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
        entry_count: int,
    ) -> list[str]:
        """Build header lines based on write options."""
        lines: list[str] = []
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

    def _resolve_write_options_for_header(
        self,
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
    ) -> FlextLdifModelsSettings.WriteFormatOptions | None:
        """Resolve write options for header generation."""
        if write_options is None:
            return FlextLdifModelsSettings.WriteFormatOptions()
        return write_options

    @staticmethod
    def _extract_write_format_options(
        metadata: FlextLdifModelsDomains.QuirkMetadata | None,
    ) -> FlextLdifModelsSettings.WriteFormatOptions | None:
        if metadata is None:
            return None

        extensions_extra = getattr(metadata.extensions, "__pydantic_extra__", None)
        format_options_raw = None
        if isinstance(extensions_extra, Mapping):
            format_options_raw = extensions_extra.get("write_format_options")
        if format_options_raw is None:
            format_options_raw = metadata.extensions.get("write_format_options")
        if isinstance(format_options_raw, Mapping):
            with suppress(Exception):
                return FlextLdifModelsSettings.WriteFormatOptions.model_validate(
                    dict(format_options_raw),
                )

        if metadata.write_options is None:
            return None

        try:
            return FlextLdifModelsSettings.WriteFormatOptions.model_validate(
                metadata.write_options.model_dump(exclude_none=True),
            )
        except ValidationError as exc:
            logger.warning(
                "Failed to validate write format options",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return None

    def _convert_write_options(
        self,
        write_options: FlextLdifModelsSettings.WriteFormatOptions
        | FlextLdifModelsDomains.WriteOptions
        | Mapping[str, t.GeneralValueType],
    ) -> FlextLdifModelsDomains.WriteOptions:
        if isinstance(write_options, FlextLdifModelsDomains.WriteOptions):
            return write_options
        if isinstance(write_options, FlextLdifModelsSettings.WriteFormatOptions):
            write_options_payload = write_options.model_dump(exclude_none=True)
            return FlextLdifModelsDomains.WriteOptions.model_validate(
                {
                    "sort_entries": write_options_payload.get("sort_attributes", False),
                    "include_comments": write_options_payload.get(
                        "include_dn_comments",
                        False,
                    ),
                    "base64_encode_binary": write_options_payload.get(
                        "base64_encode_binary",
                        False,
                    ),
                },
            )
        write_options_payload = dict(write_options)
        return FlextLdifModelsDomains.WriteOptions.model_validate({
            "sort_entries": write_options_payload.get("sort_attributes", False),
            "include_comments": write_options_payload.get(
                "include_dn_comments",
                False,
            ),
            "base64_encode_binary": write_options_payload.get(
                "base64_encode_binary",
                False,
            ),
        })

    def _inject_write_options(
        self,
        entry: m.Ldif.Entry,
        write_options: FlextLdifModelsSettings.WriteFormatOptions,
    ) -> m.Ldif.Entry:
        """Inject write options into entry metadata."""
        write_options_typed = self._convert_write_options(write_options)
        format_options_payload = write_options.model_dump(exclude_none=True)

        existing_extensions = (
            entry.metadata.extensions.model_copy(deep=True)
            if entry.metadata
            else m.Ldif.DynamicMetadata()
        )
        existing_extensions["write_format_options"] = format_options_payload

        if entry.metadata:
            updated_metadata = entry.metadata.model_copy(
                update={
                    "write_options": write_options_typed,
                    "extensions": existing_extensions,
                },
            )
        else:
            updated_metadata = m.Ldif.QuirkMetadata(
                quirk_type="rfc",
                write_options=write_options_typed,
                extensions=existing_extensions,
            )
        return entry.model_copy(update={"metadata": updated_metadata})

    def write(
        self,
        entry_data: m.Ldif.Entry | list[m.Ldif.Entry],
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None = None,
    ) -> FlextResult[str]:
        """Write Entry model(s) to LDIF string format."""
        if isinstance(entry_data, list):
            return self._write_entry_list(entry_data, write_options)
        return self._write_single_entry(entry_data, write_options)

    def _write_entry_list(
        self,
        entries: list[m.Ldif.Entry],
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
    ) -> FlextResult[str]:
        """Write list of entries to LDIF."""
        opts = self._resolve_write_options_for_header(write_options)
        header_lines = self._build_header_lines(opts, len(entries))

        def format_output(results: list[str]) -> str:
            all_lines = header_lines + results
            ldif_output = "\n".join(all_lines) if all_lines else ""
            if header_lines and not ldif_output.endswith("\n"):
                ldif_output += "\n"
            return ldif_output

        return FlextResult.traverse(
            entries,
            lambda e: self._write_single_entry(e, write_options),
        ).map(format_output)

    def _write_single_entry(
        self,
        entry: m.Ldif.Entry,
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
    ) -> FlextResult[str]:
        """Write single entry to LDIF."""
        if write_options is not None:
            entry = self._inject_write_options(entry, write_options)
        return self._write_entry(entry)

    def _normalize_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Normalize entry to RFC format with metadata tracking."""
        return entry

    def _denormalize_entry(
        self,
        entry: m.Ldif.Entry,
        target_server: str | None = None,
    ) -> m.Ldif.Entry:
        """Denormalize entry from RFC format to target server format."""
        _ = target_server
        return entry

    def execute(
        self,
        **kwargs: Mapping[str, t.GeneralValueType],
    ) -> FlextResult[m.Ldif.Entry | str]:
        """Execute entry operation (parse/write)."""
        kwargs_map: Mapping[str, object] = kwargs
        ldif_content = kwargs_map.get("ldif_content")
        entry_model = kwargs_map.get("entry_model")

        if isinstance(ldif_content, str):
            entries_result = self._parse_content(ldif_content)
            if entries_result.is_success:
                entries = entries_result.value
                return FlextResult[m.Ldif.Entry | str].ok(
                    entries[0] if entries else "",
                )
            return FlextResult[m.Ldif.Entry | str].ok("")
        if isinstance(entry_model, m.Ldif.Entry):
            str_result = self._write_entry(entry_model)
            return FlextResult[m.Ldif.Entry | str].ok(
                str_result.map_or(""),
            )

        return FlextResult[m.Ldif.Entry | str].ok("")

    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: Mapping[str, list[str]],
    ) -> FlextResult[m.Ldif.Entry]:
        """Parse a single entry from DN and attributes."""
        attrs_dict = dict(entry_attrs)

        ldif_lines = [f"dn: {entry_dn}"]
        for attr_name, attr_values in attrs_dict.items():
            ldif_lines.extend(f"{attr_name}: {value}" for value in attr_values)
        ldif_content = "\n".join(ldif_lines) + "\n"

        return self._parse_content(ldif_content).flat_map(
            lambda entries: (
                FlextResult[m.Ldif.Entry].ok(entries[0])
                if entries
                else FlextResult[m.Ldif.Entry].fail("No entries parsed")
            ),
        )
