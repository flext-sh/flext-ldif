"""Oracle Internet Directory (OID) entry server — round-trip restore helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_ldif import c, m, t
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidEntryRestoreMixin(FlextLdifServersRfc.Entry):
    """OID entry round-trip restore helpers."""

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
            FlextLdifServersOidEntryRestoreMixin._module_logger.debug(
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

    def _denormalize_oid_attributes_for_output(
        self,
        attrs: t.MutableStrSequenceMapping,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> t.MutableStrSequenceMapping:
        """Denormalize RFC attributes to OID format.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
        """
        mk = c.Ldif
        original_attrs_raw = (
            metadata.extensions.get(mk.ORIGINAL_ATTRIBUTES_COMPLETE)
            if metadata and metadata.extensions
            else None
        )
        original_attrs_value: t.JsonPayload | None = original_attrs_raw
        original_attrs: t.MutableStrSequenceMapping | None = None
        if isinstance(original_attrs_value, Mapping):
            result_attrs: t.MutableStrSequenceMapping = {}
            for k, v in original_attrs_value.items():
                if isinstance(v, list):
                    result_attrs[k] = [str(item) for item in v]
                else:
                    result_attrs[k] = [str(v)]
            original_attrs = result_attrs
        denormalized: t.MutableStrSequenceMapping = {}
        for attr_name, attr_values in attrs.items():
            restored_name, restored_values = self._restore_single_attribute(
                attr_name,
                attr_values,
                original_attrs,
            )
            denormalized[restored_name] = restored_values
        return denormalized

    def restore_entry_from_metadata(self, entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore OID-specific formats from metadata (RFC → OID denormalization).

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        restored_entry = self._restore_boolean_values_to_oid(entry_data)
        metadata = restored_entry.metadata
        attributes = restored_entry.attributes
        if metadata is None or attributes is None:
            return restored_entry
        rename_map_raw = metadata.extensions.get("attribute_name_renames")
        rename_map: t.JsonPayload | None = rename_map_raw
        if not isinstance(rename_map, Mapping) or not rename_map:
            return restored_entry
        restored_attrs = dict(attributes.attributes)
        changed = False
        for current_name, original_name in rename_map.items():
            if not isinstance(original_name, str):
                continue
            current_values = restored_attrs.pop(current_name, None)
            if current_values is None or original_name in restored_attrs:
                continue
            restored_attrs[original_name] = list(current_values)
            changed = True
        if not changed:
            return restored_entry
        restored_copy: m.Ldif.Entry = restored_entry.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": restored_attrs,
                    "attribute_metadata": attributes.attribute_metadata,
                    "metadata": attributes.metadata,
                }),
            },
        )
        return restored_copy

    def _restore_single_attribute(
        self,
        attr_name: str,
        attr_values: t.MutableSequenceOf[str],
        original_attrs: t.MutableStrSequenceMapping | None,
    ) -> tuple[str, t.MutableSequenceOf[str]]:
        """Restore attribute from metadata or apply denormalization.

        Returns:
            The resulting ``tuple[str, t.MutableSequenceOf[str]]``.
        """
        if original_attrs:
            for orig_name, orig_values in original_attrs.items():
                if self._normalize_attribute_name(orig_name) == attr_name:
                    restored_values = list(orig_values)
                    return (orig_name, restored_values)
        denorm_name = (
            FlextLdifServersOidConstants.ORCLACI
            if attr_name.lower()
            == FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME.lower()
            else attr_name
        )
        return (denorm_name, attr_values)

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
        FlextLdifServersOidEntryRestoreMixin._module_logger.debug(
            "Restored original attribute lines from metadata",
            entry_dn=entry_data.dn.value[:50] if entry_data.dn else "",
            original_lines_count=len(original_attr_lines_complete),
            written_attrs=", ".join(sorted(written_attrs)),
        )
        return written_attrs


__all__: list[str] = ["FlextLdifServersOidEntryRestoreMixin"]
