"""OID entry server — original-line restoration helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import m, t
from flext_ldif.servers._oid.entry_parse import FlextLdifServersOidEntryParseMixin
from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry


class FlextLdifServersOidEntryRestoreLinesMixin(
    FlextLdifServersOidEntryParseMixin,
    FlextLdifServersRfcEntry,
):
    """OID entry original-line restoration and line conversion helpers."""

    @staticmethod
    def _convert_line_acl_to_oid(original_line: str) -> str:
        """Convert RFC ACL attribute name (aci) to OID format (orclaci).

        Returns:
            The resulting ``str``.
        """
        if ":" not in original_line:
            return original_line
        parts = original_line.split(":", 1)
        attr_lower = parts[0].strip().lower()
        if attr_lower == "aci":
            FlextLdifServersOidEntryRestoreLinesMixin._module_logger.debug(
                "Converting aci to orclaci",
                line=original_line,
            )
            value_part = parts[1]
            return f"orclaci:{value_part}"
        return original_line

    @staticmethod
    def _convert_line_boolean_to_oid(original_line: str) -> str:
        """Convert RFC boolean values in line to OID format.

        Returns:
            The resulting ``str``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        if ":" not in original_line:
            return original_line
        parts = original_line.split(":", 1)
        attr_lower = parts[0].strip().lower()
        if attr_lower not in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES:
            return original_line
        value_part = parts[1].strip() if len(parts) > 1 else ""
        if value_part == "TRUE":
            return f"{parts[0]}: {FlextLdifServersOidConstants.ONE_OID}"
        if value_part == "FALSE":
            return f"{parts[0]}: {FlextLdifServersOidConstants.ZERO_OID}"
        return original_line

    @staticmethod
    def _should_skip_original_line(
        original_line: str,
        current_attrs: set[str],
        write_options: m.Ldif.WriteFormatOptions | None,
        *,
        write_empty_values: bool,
    ) -> bool:
        """Check if original line should be skipped during restoration.

        Returns:
            The resulting ``bool``.
        """
        _ = write_empty_values
        if original_line.lower().startswith("dn:"):
            return True
        if original_line.strip().startswith("#"):
            include_comments = write_options and getattr(
                write_options,
                "write_metadata_as_comments",
                False,
            )
            if not include_comments:
                return True
        if ":" in original_line:
            attr_name_part = original_line.split(":", 1)[0].strip().lower()
            attr_name_part = attr_name_part.removesuffix(":").removeprefix("<")
            if current_attrs and attr_name_part not in current_attrs:
                return True
        return False

    def _write_original_attr_lines(
        self,
        ldif_lines: t.MutableSequenceOf[str],
        entry_data: m.Ldif.Entry,
        original_attr_lines_complete: t.MutableSequenceOf[str],
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> set[str]:
        """Write original attribute lines preserving exact formatting.

        Returns:
            The resulting ``set[str]``.
        """
        written_attrs: set[str] = set()
        current_attrs = self._get_current_attrs_with_acl_equivalence(entry_data)
        for original_line in original_attr_lines_complete:
            if self._should_skip_original_line(
                original_line,
                current_attrs,
                write_options,
                write_empty_values=True,
            ):
                continue
            if ":" in original_line:
                original_attr_name = original_line.split(":", 1)[0].strip().lower()
                written_attrs.add(original_attr_name)
                if original_attr_name == "aci":
                    written_attrs.add("orclaci")
                elif original_attr_name == "orclaci":
                    written_attrs.add("aci")
            line_to_write = self._convert_line_boolean_to_oid(original_line)
            line_to_write = self._convert_line_acl_to_oid(line_to_write)
            ldif_lines.append(line_to_write)
        FlextLdifServersOidEntryRestoreLinesMixin._module_logger.debug(
            "Restored original attribute lines from metadata",
            entry_dn=entry_data.dn.value[:50] if entry_data.dn else "",
            original_lines_count=len(original_attr_lines_complete),
            written_attrs=", ".join(sorted(written_attrs)),
        )
        return written_attrs


__all__: list[str] = ["FlextLdifServersOidEntryRestoreLinesMixin"]
