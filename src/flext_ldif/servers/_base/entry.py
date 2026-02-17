"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import ClassVar

from flext_core import FlextLogger, FlextResult, FlextService
from pydantic import Field

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
        attrs: dict[str, list[str | bytes]],
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
        attributes: dict[str, list[str]],
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
        entry_attrs: dict[str, list[str | bytes]],
    ) -> dict[str, list[str]]:
        """Convert raw LDIF attributes to dict[str, list[str]] format."""
        converted_attrs: dict[str, list[str]] = {}

        for attr_name, attr_values_raw in entry_attrs.items():
            canonical_attr_name = self._normalize_attribute_name(attr_name)

            if not isinstance(attr_values_raw, list):
                continue
            attr_values: list[str | bytes] = attr_values_raw
            string_values: list[str] = []
            if isinstance(attr_values, list):
                string_values = [
                    (
                        value.decode("utf-8", errors="replace")
                        if isinstance(value, bytes)
                        else str(value)
                    )
                    for value in attr_values
                ]
            elif isinstance(attr_values, bytes):
                string_values = [
                    attr_values.decode("utf-8", errors="replace"),
                ]
            elif isinstance(attr_values, (list, tuple)):
                string_values = [
                    (
                        value.decode("utf-8", errors="replace")
                        if isinstance(value, bytes)
                        else str(value)
                    )
                    for value in attr_values
                ]
            else:
                string_values = [str(attr_values)]

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

        if entry_data.metadata and entry_data.metadata.write_options:
            write_opts = entry_data.metadata.write_options

            if isinstance(write_opts, dict) and "write_options" in write_opts:
                nested_opts = write_opts.get("write_options")
                if hasattr(nested_opts, "fold_long_lines"):
                    fold_long_lines = bool(nested_opts.fold_long_lines)
                if hasattr(nested_opts, "line_width"):
                    line_width = int(nested_opts.line_width or line_width)
            elif hasattr(write_opts, "fold_long_lines"):
                fold_long_lines = bool(write_opts.fold_long_lines)
                if hasattr(write_opts, "line_width"):
                    line_width = int(write_opts.line_width or line_width)

        def fold_line(line: str) -> list[str]:
            """Fold a line per RFC 2849 if fold_long_lines is enabled."""
            if not fold_long_lines or len(line.encode("utf-8")) <= line_width:
                return [line]

            folded: list[str] = []
            line_bytes = line.encode("utf-8")
            pos = 0
            while pos < len(line_bytes):
                if not folded:
                    chunk_end = min(pos + line_width, len(line_bytes))
                else:
                    chunk_end = min(pos + line_width - 1, len(line_bytes))

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

        if entry_data.dn:
            dn_line = f"dn: {entry_data.dn.value}"
            output_lines.extend(fold_line(dn_line))
        else:
            return FlextResult.fail("Entry DN is None")

        if hasattr(entry_data, "attributes") and entry_data.attributes:
            for attr_name, values in entry_data.attributes.items():
                if isinstance(values, list):
                    for value in values:
                        str_value = str(value)
                        if any(ord(char) > ascii_printable_limit for char in str_value):
                            encoded = base64.b64encode(
                                str_value.encode("utf-8"),
                            ).decode("ascii")
                            attr_line = f"{attr_name}:: {encoded}"
                        else:
                            attr_line = f"{attr_name}: {str_value}"
                        output_lines.extend(fold_line(attr_line))
                else:
                    str_value = str(values)
                    attr_line = f"{attr_name}: {str_value}"
                    output_lines.extend(fold_line(attr_line))

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
            return None
        if isinstance(write_options, FlextLdifModelsSettings.WriteFormatOptions):
            return write_options
        if isinstance(write_options, FlextLdifModelsDomains.WriteOptions):
            return FlextLdifModelsSettings.WriteFormatOptions()
        return None

    def _convert_write_options(
        self,
        write_options: FlextLdifModelsSettings.WriteFormatOptions
        | FlextLdifModelsDomains.WriteOptions
        | dict[str, t.GeneralValueType],
    ) -> (
        FlextLdifModelsSettings.WriteFormatOptions | FlextLdifModelsDomains.WriteOptions
    ):
        """Convert write options to appropriate typed model."""
        if isinstance(write_options, FlextLdifModelsSettings.WriteFormatOptions):
            return write_options
        if isinstance(write_options, FlextLdifModelsDomains.WriteOptions):
            return write_options
        if isinstance(write_options, dict):
            try:
                return FlextLdifModelsSettings.WriteFormatOptions.model_validate(
                    write_options,
                )
            except Exception:
                return FlextLdifModelsDomains.WriteOptions.model_validate(write_options)
        msg = f"Expected WriteFormatOptions | WriteOptions | dict, got {type(write_options)}"
        raise TypeError(msg)

    def _inject_write_options(
        self,
        entry: m.Ldif.Entry,
        write_options: FlextLdifModelsSettings.WriteFormatOptions,
    ) -> m.Ldif.Entry:
        """Inject write options into entry metadata."""
        write_options_typed = self._convert_write_options(write_options)
        new_write_opts: dict[str, t.GeneralValueType] = (
            dict(entry.metadata.write_options)
            if entry.metadata and entry.metadata.write_options
            else {}
        )

        new_write_opts["write_options"] = write_options_typed

        if entry.metadata:
            updated_metadata = entry.metadata.model_copy(
                update={"write_options": new_write_opts},
            )
        else:
            write_opts_for_meta: FlextLdifModelsDomains.WriteOptions | None = None
            if isinstance(write_options_typed, FlextLdifModelsDomains.WriteOptions):
                write_opts_for_meta = write_options_typed
            elif isinstance(
                write_options_typed,
                FlextLdifModelsSettings.WriteFormatOptions,
            ):
                write_opts_for_meta = (
                    FlextLdifModelsDomains.WriteOptions.model_validate(
                        write_options_typed.model_dump(),
                    )
                )
            updated_metadata = m.Ldif.QuirkMetadata(
                quirk_type="rfc",
                write_options=write_opts_for_meta,
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
        **kwargs: dict[str, t.GeneralValueType],
    ) -> FlextResult[m.Ldif.Entry | str]:
        """Execute entry operation (parse/write)."""
        ldif_content = kwargs.get("ldif_content")
        entry_model = kwargs.get("entry_model")

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
        entry_attrs: dict[str, list[str]],
    ) -> FlextResult[m.Ldif.Entry]:
        """Parse a single entry from DN and attributes."""
        if isinstance(entry_attrs, Mapping):
            attrs_dict: dict[
                str,
                str | list[str] | bytes | list[bytes] | int | float | bool | None,
            ] = dict(entry_attrs)
        elif isinstance(entry_attrs, dict):
            attrs_dict = entry_attrs
        else:
            msg = f"Expected Mapping | dict, got {type(entry_attrs)}"
            raise TypeError(msg)

        ldif_lines = [f"dn: {entry_dn}"]
        for attr_name, attr_values in attrs_dict.items():
            if isinstance(attr_values, (list, tuple)):
                if not isinstance(attr_values, list):
                    msg = f"Expected list, got {type(attr_values)}"
                    raise TypeError(msg)

                ldif_lines.extend(
                    f"{attr_name}: {value.decode('utf-8') if isinstance(value, bytes) else value}"
                    for value in attr_values
                )
            else:
                value_str = (
                    attr_values.decode("utf-8")
                    if isinstance(attr_values, bytes)
                    else attr_values
                )
                ldif_lines.append(f"{attr_name}: {value_str}")
        ldif_content = "\n".join(ldif_lines) + "\n"

        return self._parse_content(ldif_content).flat_map(
            lambda entries: (
                FlextResult[m.Ldif.Entry].ok(entries[0])
                if entries
                else FlextResult[m.Ldif.Entry].fail("No entries parsed")
            ),
        )
