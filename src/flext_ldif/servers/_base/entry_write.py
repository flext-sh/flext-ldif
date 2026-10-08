"""Base entry server — entry write context and LDIF serialization.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.entry_write_body import (
    FlextLdifServersEntryWriteBodyEmitter,
)


class FlextLdifServersEntryWriteContext(FlextLdifServersEntryWriteBodyEmitter):
    """Resolved write-option context driving one Entry → LDIF serialization."""

    def __init__(
        self,
        entry_data: m.Ldif.Entry,
        server_type: str,
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> None:
        """Resolve write options and the effective line emitter."""
        from flext_ldif.servers._base.entry_lines import (
            FlextLdifServersEntryLineEmitter,
        )
        from flext_ldif.servers._base.entry_write_options import (
            FlextLdifServersEntryWriteOptions,
        )

        self._entry = entry_data
        self._server_type = server_type
        self._format_options = format_options
        self._options = FlextLdifServersEntryWriteOptions(entry_data, format_options)
        self._lines = FlextLdifServersEntryLineEmitter(
            entry_data,
            normalize_attribute_names=self._options.normalize_attribute_names,
            use_original_acl_format_as_name=(
                self._options.use_original_acl_format_as_name
            ),
            acl_original_format=self._options.acl_original_format,
            effective_line_width=self._options.effective_line_width,
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
        return self._options.ldif_changetype

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
        if self._options.write_metadata_as_comments:
            output_lines.append("# Entry Metadata:")
        if self._options.include_dn_comments and entry.dn:
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

    def _should_restore_original(self) -> bool:
        """Restore original LDIF only for same-server round-trips.

        Returns:
            The resulting ``bool``.
        """
        entry = self._entry
        if not self._options.restore_original_format or entry.metadata is None:
            return False
        return str(entry.metadata.original_server_type).lower() == (
            self._server_type.lower()
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


__all__: list[str] = ["FlextLdifServersEntryWriteContext"]
