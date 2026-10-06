"""Base entry server — entry write context and LDIF serialization.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.entry_lines import FlextLdifServersEntryLineEmitter


class FlextLdifServersEntryWriteContext:
    """Resolved write-option context driving one Entry → LDIF serialization."""

    def __init__(
        self,
        entry_data: m.Ldif.Entry,
        server_type: str,
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> None:
        """Resolve write options, extensions, and the effective line width."""
        self._entry = entry_data
        self._server_type = server_type
        self._format_options = format_options
        fold_long_lines = True
        line_width = c.Ldif.LINE_FOLD_WIDTH
        self._include_dn_comments = False
        normalize_attribute_names = False
        self._restore_original_format = False
        self._write_empty_values = True
        self._write_hidden_attributes_as_comments = False
        self._write_metadata_as_comments = False
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
            hidden_text: t.MutableSequenceOf[str] = [str(value) for value in hidden_raw]
            hidden_attributes = {attr.lower() for attr in hidden_text}
        acl_original_raw = extensions_data.get(c.Ldif.ACL_ORIGINAL_FORMAT)
        if isinstance(acl_original_raw, str):
            acl_original_format = acl_original_raw
        ldif_changetype: str | None = None
        ldif_modify_operation: str = "add"
        if format_options is not None:
            fold_long_lines = format_options.fold_long_lines
            line_width = format_options.line_width
            self._include_dn_comments = format_options.include_dn_comments
            normalize_attribute_names = format_options.normalize_attribute_names
            self._restore_original_format = format_options.restore_original_format
            self._write_empty_values = format_options.write_empty_values
            self._write_hidden_attributes_as_comments = (
                format_options.write_hidden_attributes_as_comments
            )
            self._write_metadata_as_comments = (
                format_options.write_metadata_as_comments
            )
            use_original_acl_format_as_name = (
                format_options.use_original_acl_format_as_name
            )
            ldif_changetype = format_options.ldif_changetype
            ldif_modify_operation = format_options.ldif_modify_operation or "add"
        self._hidden_attributes = hidden_attributes
        self._ldif_changetype = ldif_changetype
        self._ldif_modify_operation = ldif_modify_operation
        effective_line_width = (
            line_width if fold_long_lines else max(line_width, 1_000_000)
        )
        self._lines = FlextLdifServersEntryLineEmitter(
            entry_data,
            normalize_attribute_names,
            use_original_acl_format_as_name,
            acl_original_format,
            effective_line_width,
        )

    @classmethod
    def build(
        cls,
        entry_data: m.Ldif.Entry,
        server_type: str,
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> FlextLdifServersEntryWriteContext:
        """Build the write context for one entry serialization pass.

        Returns:
            The resulting ``FlextLdifServersEntryWriteContext``.
        """
        return cls(entry_data, server_type, format_options)

    @property
    def ldif_changetype(self) -> str | None:
        """Configured fallback changetype for the written entry."""
        return self._ldif_changetype

    def restore_original(self) -> p.Result[str] | None:
        """Restore the preserved original LDIF text on same-server round trips.

        Returns:
            The resulting ``p.Result[str] | None``.
        """
        entry = self._entry
        if not self._should_restore_original() or entry.metadata is None:
            return None
        original_strings = entry.metadata.original_strings
        original_ldif_raw = original_strings.get("entry_original_ldif", "")
        try:
            restored_output: str = t.str_adapter().validate_python(original_ldif_raw)
        except c.ValidationError as exc:
            return r[str].fail_op("restore original LDIF text", exc)
        if not restored_output:
            return r[str].ok("")
        restored_output += "\n" if not restored_output.endswith("\n") else ""
        return r[str].ok(restored_output)

    def emit_entry_header(
        self,
        output_lines: t.MutableSequenceOf[str],
    ) -> p.Result[str] | None:
        """Emit rejection/metadata comments, DN line, and controls.

        Returns:
            The resulting ``p.Result[str] | None`` — a failure when the DN is
            missing, otherwise ``None`` to continue writing.
        """
        entry = self._entry
        self._emit_rejection_comments(output_lines)
        if self._write_metadata_as_comments:
            output_lines.append("# Entry Metadata:")
        if self._include_dn_comments and entry.dn:
            output_lines.append(f"# DN: {entry.dn.value}")
        if entry.dn:
            effective_width = self._lines.effective_line_width
            dn_line = f"dn: {entry.dn.value}"
            output_lines.extend(u.Ldif.fold_line(dn_line, width=effective_width))
        else:
            return r[str].fail("Entry DN is None")
        for control in entry.controls:
            output_lines.extend(
                u.Ldif.fold_line(
                    self._lines.control_line(control),
                    width=self._lines.effective_line_width,
                ),
            )
        return None

    def emit_modify_entry(
        self,
        output_lines: t.MutableSequenceOf[str],
    ) -> p.Result[str]:
        """Emit the LDIF modify body (change operations or attribute ops).

        Returns:
            The resulting ``p.Result[str]``.
        """
        entry = self._entry
        if entry.change_operations:
            for change_operation in entry.change_operations:
                output_lines.append(
                    f"{change_operation.operation}: {change_operation.attribute}",
                )
                for value_data in change_operation.values:
                    attr_line = self._lines.emit_attribute_line(
                        change_operation.attribute,
                        value_data.value,
                        value_origin=value_data.value_origin,
                        raw_value=value_data.raw_value,
                    )
                    self._lines.append_attribute_line(
                        output_lines,
                        change_operation.attribute,
                        attr_line,
                    )
                output_lines.append("-")
            output_lines.append("")
            return r[str].ok("\n".join(output_lines))
        self._emit_modify_attribute_operations(output_lines)
        output_lines.append("")
        return r[str].ok("\n".join(output_lines))

    def emit_modifydn_entry(
        self,
        output_lines: t.MutableSequenceOf[str],
    ) -> p.Result[str]:
        """Emit the LDIF moddn/modrdn body.

        Returns:
            The resulting ``p.Result[str]``.
        """
        entry = self._entry
        if entry.newrdn:
            output_lines.extend(
                u.Ldif.fold_line(
                    f"newrdn: {entry.newrdn}",
                    width=self._lines.effective_line_width,
                ),
            )
        if entry.deleteoldrdn is not None:
            delete_old = "1" if entry.deleteoldrdn else "0"
            output_lines.append(f"deleteoldrdn: {delete_old}")
        if entry.newsuperior:
            output_lines.extend(
                u.Ldif.fold_line(
                    f"newsuperior: {entry.newsuperior}",
                    width=self._lines.effective_line_width,
                ),
            )
        output_lines.append("")
        return r[str].ok("\n".join(output_lines))

    def emit_add_entry(
        self,
        output_lines: t.MutableSequenceOf[str],
    ) -> p.Result[str]:
        """Emit the entry attribute body with hidden-attribute handling.

        Returns:
            The resulting ``p.Result[str]``.
        """
        entry = self._entry
        if hasattr(entry, "attributes") and entry.attributes:
            for attr_name, values in entry.attributes.items():
                self._emit_entry_attribute_values(
                    output_lines,
                    attr_name,
                    values,
                )
        output_lines.append("")
        return r[str].ok("\n".join(output_lines))

    def _should_restore_original(self) -> bool:
        """Restore original LDIF only for same-server round-trips.

        Returns:
            The resulting ``bool``.
        """
        entry = self._entry
        if not self._restore_original_format or entry.metadata is None:
            return False
        return (
            str(entry.metadata.original_server_type).lower()
            == self._server_type.lower()
        )

    def _emit_rejection_comments(
        self,
        output_lines: t.MutableSequenceOf[str],
    ) -> None:
        """Emit rejection reason comments when the entry was rejected."""
        entry = self._entry
        format_options = self._format_options
        if (
            format_options is None
            or not format_options.write_rejection_reasons
            or entry.metadata is None
            or entry.metadata.processing_stats is None
        ):
            return
        statistics = m.Ldif.EntryStatistics.model_validate(
            entry.metadata.processing_stats.model_dump(),
        )
        if statistics.was_rejected:
            for label, value in (
                ("Rejection category", statistics.rejection_category),
                ("Rejection reason", statistics.rejection_reason),
            ):
                if value is not None:
                    output_lines.extend(
                        f"# {label}: {line}" for line in value.splitlines()
                    )

    def _emit_modify_attribute_operations(
        self,
        output_lines: t.MutableSequenceOf[str],
    ) -> None:
        """Emit attribute-level modify operations from entry attributes."""
        entry = self._entry
        modify_excluded = {"objectclass", "cn", "changetype", "dn"}
        if hasattr(entry, "attributes") and entry.attributes:
            for attr_name, values in entry.attributes.items():
                if attr_name.lower() in modify_excluded:
                    continue
                non_empty = [v for v in values if v]
                if not non_empty:
                    continue
                output_lines.append(f"{self._ldif_modify_operation}: {attr_name}")
                for value_index, value in enumerate(non_empty):
                    value_origin, raw_value = self._lines.value_origin_and_raw(
                        attr_name,
                        value_index,
                    )
                    attr_line = self._lines.emit_attribute_line(
                        attr_name,
                        value,
                        value_origin=value_origin,
                        raw_value=raw_value,
                    )
                    self._lines.append_attribute_line(output_lines, attr_name, attr_line)
                output_lines.append("-")

    def _emit_entry_attribute_values(
        self,
        output_lines: t.MutableSequenceOf[str],
        attr_name: str,
        values: t.MutableSequenceOf[str],
    ) -> None:
        """Emit one attribute's values with hidden-attribute comment handling."""
        attr_is_hidden = attr_name.lower() in self._hidden_attributes
        for value_index, value in enumerate(values):
            str_value = value
            if not str_value and (not self._write_empty_values):
                continue
            value_origin, raw_value = self._lines.value_origin_and_raw(
                attr_name,
                value_index,
            )
            attr_line = self._lines.emit_attribute_line(
                attr_name,
                str_value,
                value_origin=value_origin,
                raw_value=raw_value,
            )
            if attr_is_hidden and self._write_hidden_attributes_as_comments:
                attr_line = f"# {attr_line}"
            self._lines.append_attribute_line(output_lines, attr_name, attr_line)


__all__: list[str] = ["FlextLdifServersEntryWriteContext"]
