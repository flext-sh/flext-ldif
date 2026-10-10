"""Base entry server — changetype body emitters for LDIF serialization.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import c, m, p, r, t, u

if TYPE_CHECKING:
    from flext_ldif.servers._base import (
        FlextLdifServersEntryLineEmitter,
        FlextLdifServersEntryWriteOptions,
    )


class FlextLdifServersEntryWriteBodyEmitter:
    """Emit changetype-specific entry bodies during LDIF serialization."""

    _entry: m.Ldif.Entry
    _lines: FlextLdifServersEntryLineEmitter
    _options: FlextLdifServersEntryWriteOptions

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
                self._emit_change_operation(output_lines, change_operation)
            output_lines.append("")
            return r[str].ok("\n".join(output_lines))
        self._emit_modify_attribute_operations(output_lines)
        output_lines.append("")
        return r[str].ok("\n".join(output_lines))

    def _emit_change_operation(
        self,
        output_lines: t.MutableSequenceOf[str],
        change_operation: m.Ldif.ChangeOperation,
    ) -> None:
        """Emit one LDIF change operation with its values."""
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

    def emit_changetype_body(
        self,
        entry_data: m.Ldif.Entry,
        output_lines: t.MutableSequenceOf[str],
    ) -> p.Result[str]:
        """Emit the changetype line and dispatch the matching entry body.

        Returns:
            The resulting ``p.Result[str]``.
        """
        effective_changetype = entry_data.changetype or self._options.ldif_changetype
        if effective_changetype in {
            c.Ldif.ChangeType.ADD,
            c.Ldif.ChangeType.DELETE,
            c.Ldif.ChangeType.MODIFY,
            c.Ldif.ChangeType.MODDN,
            c.Ldif.ChangeType.MODRDN,
        }:
            output_lines.append(f"changetype: {effective_changetype}")
        if effective_changetype == c.Ldif.ChangeType.MODIFY:
            return self.emit_modify_entry(output_lines)
        if effective_changetype in {
            c.Ldif.ChangeType.MODDN,
            c.Ldif.ChangeType.MODRDN,
        }:
            return self.emit_modifydn_entry(output_lines)
        if effective_changetype == c.Ldif.ChangeType.DELETE:
            output_lines.append("")
            return r[str].ok("\n".join(output_lines))
        return self.emit_add_entry(output_lines)

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
                self._emit_single_modify_attribute(
                    output_lines,
                    attr_name,
                    values,
                )

    def _emit_single_modify_attribute(
        self,
        output_lines: t.MutableSequenceOf[str],
        attr_name: str,
        values: t.MutableSequenceOf[str],
    ) -> None:
        """Emit one attribute's modify operation block."""
        non_empty = [v for v in values if v]
        if not non_empty:
            return
        output_lines.append(f"{self._options.ldif_modify_operation}: {attr_name}")
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
            self._lines.append_attribute_line(
                output_lines,
                attr_name,
                attr_line,
            )
        output_lines.append("-")

    def _emit_entry_attribute_values(
        self,
        output_lines: t.MutableSequenceOf[str],
        attr_name: str,
        values: t.MutableSequenceOf[str],
    ) -> None:
        """Emit one attribute's values with hidden-attribute comment handling."""
        attr_is_hidden = attr_name.lower() in self._options.hidden_attributes
        for value_index, value in enumerate(values):
            str_value = value
            if not str_value and (not self._options.write_empty_values):
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
            if attr_is_hidden and self._options.write_hidden_attributes_as_comments:
                attr_line = f"# {attr_line}"
            self._lines.append_attribute_line(output_lines, attr_name, attr_line)


__all__: list[str] = ["FlextLdifServersEntryWriteBodyEmitter"]
