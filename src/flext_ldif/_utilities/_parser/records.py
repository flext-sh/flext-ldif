"""LDIF record splitting and line unfolding utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence

from flext_ldif import c


class FlextLdifUtilitiesParserRecords:
    """Split unfolded LDIF content into record blocks."""

    @staticmethod
    def unfold_numbered_lines(ldif_content: str) -> MutableSequence[tuple[int, str]]:
        """Unfold LDIF lines per RFC 2849 §3, keeping each line's position.

        Returns:
            Each logical line paired with the 1-based number of the physical
            line it starts on.

        """
        lines: MutableSequence[tuple[int, str]] = []
        current: tuple[int, str] | None = None
        for number, raw_line in enumerate(
            ldif_content.split(c.Ldif.LINE_SEPARATOR),
            start=1,
        ):
            if current is not None and current[1] and raw_line[:1] in {
                c.Ldif.LINE_CONTINUATION_SPACE,
                "\t",
            }:
                current = (current[0], current[1] + raw_line[1:])
                continue
            if current is not None:
                lines.append(current)
            if not raw_line:
                lines.append((number, ""))
                current = None
                continue
            current = (number, raw_line)
        if current is not None:
            lines.append(current)
        return lines

    @staticmethod
    def unfold_lines(ldif_content: str) -> MutableSequence[str]:
        """Unfold LDIF lines folded across multiple lines per RFC 2849 §3.

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        return [
            line
            for _, line in FlextLdifUtilitiesParserRecords.unfold_numbered_lines(
                ldif_content,
            )
        ]

    @staticmethod
    def split_numbered_records(
        ldif_content: str,
    ) -> MutableSequence[MutableSequence[tuple[int, str]]]:
        """Split unfolded LDIF content into records of numbered lines.

        A ``version:`` line before a record's first data line and a block of
        comments alone are not records.

        Returns:
            Each record as its logical lines paired with their 1-based
            physical line numbers.

        """
        records: MutableSequence[MutableSequence[tuple[int, str]]] = []
        current_record: MutableSequence[tuple[int, str]] = []
        for number, raw_line in FlextLdifUtilitiesParserRecords.unfold_numbered_lines(
            ldif_content,
        ):
            line = raw_line.rstrip("\r")
            has_data = any(not text.startswith("#") for _, text in current_record)
            if not has_data and line.lower().startswith("version:"):
                continue
            if not line.strip():
                if has_data:
                    records.append(current_record)
                current_record = []
                continue
            current_record.append((number, line))
        if any(not text.startswith("#") for _, text in current_record):
            records.append(current_record)
        return records

    @staticmethod
    def split_ldif_records(
        ldif_content: str,
    ) -> MutableSequence[MutableSequence[str]]:
        """Split unfolded LDIF content into record blocks.

        Returns:
            The resulting ``MutableSequence[MutableSequence[str]]``.

        """
        return [
            [line for _, line in record]
            for record in FlextLdifUtilitiesParserRecords.split_numbered_records(
                ldif_content,
            )
        ]


__all__: list[str] = ["FlextLdifUtilitiesParserRecords"]
