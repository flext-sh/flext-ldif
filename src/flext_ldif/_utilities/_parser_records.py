"""LDIF record splitting and line unfolding utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t


class FlextLdifParserRecordSplitter:
    """Split unfolded LDIF content into record blocks."""

    @staticmethod
    def unfold_lines(ldif_content: str) -> t.MutableSequenceOf[str]:
        """Unfold LDIF lines folded across multiple lines per RFC 2849 §3.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        lines: t.MutableSequenceOf[str] = []
        current_line: str | None = None
        for raw_line in ldif_content.split(c.Ldif.LINE_SEPARATOR):
            if (
                raw_line.startswith(c.Ldif.LINE_CONTINUATION_SPACE) and current_line
            ) or (raw_line.startswith("\t") and current_line):
                current_line += raw_line[1:]
                continue
            if current_line is not None:
                lines.append(current_line)
            if not raw_line:
                lines.append("")
                current_line = None
                continue
            current_line = raw_line
        if current_line is not None:
            lines.append(current_line)
        return lines

    @staticmethod
    def split_ldif_records(
        ldif_content: str,
    ) -> t.MutableSequenceOf[t.MutableSequenceOf[str]]:
        """Split unfolded LDIF content into record blocks.

        Returns:
            The resulting ``t.MutableSequenceOf[t.MutableSequenceOf[str]]``.
        """
        unfolded_lines = FlextLdifParserRecordSplitter.unfold_lines(ldif_content)
        records: t.MutableSequenceOf[t.MutableSequenceOf[str]] = []
        current_record: t.MutableSequenceOf[str] = []
        for raw_line in unfolded_lines:
            line = raw_line.rstrip("\r")
            if not current_record and line.lower().startswith("version:"):
                continue
            if not line.strip():
                if current_record:
                    records.append(current_record)
                    current_record = []
                continue
            current_record.append(line)
        if current_record:
            records.append(current_record)
        return records


__all__: list[str] = ["FlextLdifParserRecordSplitter"]
