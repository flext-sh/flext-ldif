"""Base entry server — resolved write options for entry serialization.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_ldif import c, m, t, u


class FlextLdifServersEntryWriteOptions:
    """Write options and metadata extensions resolved for one Entry write pass."""

    def __init__(
        self,
        entry_data: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> None:
        """Resolve write options, metadata extensions, and effective values."""
        fold_long_lines = True
        line_width = c.Ldif.LINE_FOLD_WIDTH
        self.include_dn_comments = False
        self.normalize_attribute_names = False
        self.restore_original_format = False
        self.write_empty_values = True
        self.write_hidden_attributes_as_comments = False
        self.write_metadata_as_comments = False
        self.use_original_acl_format_as_name = False
        self.acl_original_format: str | None = None
        self.ldif_changetype: str | None = None
        self.ldif_modify_operation: str = "add"
        extensions_data = self._entry_metadata_extensions(entry_data)
        self.hidden_attributes = self._resolved_hidden_attributes(extensions_data)
        self.acl_original_format = self._resolved_acl_original_format(
            extensions_data,
        )
        if format_options is not None:
            fold_long_lines = format_options.fold_long_lines
            line_width = format_options.line_width
            self.include_dn_comments = format_options.include_dn_comments
            self.normalize_attribute_names = format_options.normalize_attribute_names
            self.restore_original_format = format_options.restore_original_format
            self.write_empty_values = format_options.write_empty_values
            self.write_hidden_attributes_as_comments = (
                format_options.write_hidden_attributes_as_comments
            )
            self.write_metadata_as_comments = format_options.write_metadata_as_comments
            self.use_original_acl_format_as_name = (
                format_options.use_original_acl_format_as_name
            )
            self.ldif_changetype = format_options.ldif_changetype
            self.ldif_modify_operation = format_options.ldif_modify_operation or "add"
        self.effective_line_width = (
            line_width if fold_long_lines else max(line_width, 1_000_000)
        )

    @staticmethod
    def _entry_metadata_extensions(
        entry_data: m.Ldif.Entry,
    ) -> t.Ldif.MutableMetadataMapping:
        """Read the entry metadata extensions mapping when present.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        if not entry_data.metadata:
            return {}
        metadata_extensions = entry_data.metadata.extensions
        if u.matches_type(metadata_extensions, Mapping):
            return dict(metadata_extensions)
        return {}

    @staticmethod
    def _resolved_hidden_attributes(
        extensions_data: t.Ldif.MutableMetadataMapping,
    ) -> set[str]:
        """Resolve hidden attribute names (lower-cased) from extensions.

        Returns:
            The resulting ``set[str]``.
        """
        hidden_raw = extensions_data.get(c.Ldif.HIDDEN_ATTRIBUTES)
        if not isinstance(hidden_raw, list):
            return set()
        hidden_text: t.MutableSequenceOf[str] = [str(value) for value in hidden_raw]
        return {attr.lower() for attr in hidden_text}

    @staticmethod
    def _resolved_acl_original_format(
        extensions_data: t.Ldif.MutableMetadataMapping,
    ) -> str | None:
        """Resolve the preserved original ACL format from extensions.

        Returns:
            The resulting ``str | None``.
        """
        acl_original_raw = extensions_data.get(c.Ldif.ACL_ORIGINAL_FORMAT)
        if isinstance(acl_original_raw, str):
            return acl_original_raw
        return None


__all__: list[str] = ["FlextLdifServersEntryWriteOptions"]
