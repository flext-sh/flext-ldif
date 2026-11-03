# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/_settings/migrate
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._constants import FlextLdifConstantsBaseParts
    from flext_ldif._protocols import FlextLdifProtocolsBase
    from flext_ldif._protocols._settings import FlextLdifProtocolsSettingsRules
    from flext_ldif._typings import FlextLdifTypesDomain


class FlextLdifProtocolsSettingsMigrate:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class WriteFormatOptions(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def line_width(self) -> int:
            """Structural member projected from the owning model.

            Maximum line width before folding (RFC 2849 recommends 76). Only used if
            fold_long_lines=True.
            """
            ...

        @property
        def respect_attribute_order(self) -> bool:
            """Structural member projected from the owning model.

            If True, writes attributes in the order specified in Entry.metadata.
            """
            ...

        @property
        def sort_attributes(self) -> bool:
            """Structural member projected from the owning model.

            If True, sorts attributes alphabetically. Overridden by
            respect_attribute_order.
            """
            ...

        @property
        def write_hidden_attributes_as_comments(self) -> bool:
            """Structural member projected from the owning model.

            If True, attributes marked as 'hidden' in metadata will be written as
            comments.
            """
            ...

        @property
        def write_metadata_as_comments(self) -> bool:
            """Structural member projected from the owning model.

            If True, the entry's main metadata will be written as a commented block.
            """
            ...

        @property
        def include_version_header(self) -> bool:
            """If True, includes the LDIF version header in output."""
            ...

        @property
        def include_timestamps(self) -> bool:
            """Structural member projected from the owning model.

            If True, includes timestamp comments for when entries were written.
            """
            ...

        @property
        def base64_encode_binary(self) -> bool:
            """If True, automatically base64 encodes binary attribute values."""
            ...

        @property
        def fold_long_lines(self) -> bool:
            """If True, folds lines longer than line_width according to RFC 2849."""
            ...

        @property
        def restore_original_format(self) -> bool:
            """Structural member projected from the owning model.

            If True, restores original LDIF format from metadata for perfect round-
            trip. When enabled, uses
            entry.metadata.original_strings['entry_original_ldif'] to write the
            exact original format, preserving all minimal differences (spacing,
            case, punctuation, quotes, etc.). CRITICAL for zero data loss.
            """
            ...

        @property
        def write_empty_values(self) -> bool:
            """Structural member projected from the owning model.

            If True, writes attributes with empty values. If False, omits them.
            """
            ...

        @property
        def normalize_attribute_names(self) -> bool:
            """If True, normalizes attribute names to lowercase."""
            ...

        @property
        def include_dn_comments(self) -> bool:
            """If True, includes DN explanation comments for complex entries."""
            ...

        @property
        def write_removed_attributes_as_comments(self) -> bool:
            """If True, writes removed attributes as comments in LDIF output."""
            ...

        @property
        def write_migration_header(self) -> bool:
            """Structural member projected from the owning model.

            If True, writes migration metadata header at the start of LDIF file.
            """
            ...

        @property
        def migration_header_template(self) -> str | None:
            """Structural member projected from the owning model.

            Jinja2 template string for migration header. If None, uses default
            template.
            """
            ...

        @property
        def write_rejection_reasons(self) -> bool:
            """Structural member projected from the owning model.

            If True, writes rejection reasons as comments for rejected entries.
            """
            ...

        @property
        def include_removal_statistics(self) -> bool:
            """If True, includes statistics about removed attributes in headers."""
            ...

        @property
        def ldif_changetype(self) -> str | None:
            """Structural member projected from the owning model.

            If set to 'modify', writes entries in LDIF modify format (changetype:
            modify). Otherwise uses add format.
            """
            ...

        @property
        def ldif_modify_operation(self) -> str:
            """Structural member projected from the owning model.

            LDIF modify operation: 'add' or 'replace'. Used when
            ldif_changetype='modify'. Default 'add' for schema/ACL phases.
            """
            ...

        @property
        def write_original_entry_as_comment(self) -> bool:
            """Structural member projected from the owning model.

            If True, writes original source entry as commented LDIF block before
            converted entry.
            """
            ...

        @property
        def entry_category(self) -> str | None:
            """Structural member projected from the owning model.

            Migration category (e.g., 'hierarchy', 'users', 'groups', 'acl'). Used
            for phase-specific formatting.
            """
            ...

        @property
        def acl_attribute_names(self) -> FlextLdifTypesDomain.AclAttributeNames:
            """Structural member projected from the owning model.

            Set of ACL attribute names (e.g., {'orclaci', 'orclentrylevelaci'}).
            Used to identify ACL attributes.
            """
            ...

        @property
        def comment_acl_in_non_acl_phases(self) -> bool:
            """Structural member projected from the owning model.

            If True, ACL attributes are written as comments when entry_category !=
            'acl'.
            """
            ...

        @property
        def use_rfc_attribute_order(self) -> bool:
            """Structural member projected from the owning model.

            If True, writes attributes in RFC 2849 orderClass first after DN, then
            remaining attributes alphabetically. DN is always first (handled
            automatically by writer).
            """
            ...

        @property
        def rfc_order_priority_attributes(self) -> MutableSequence[str]:
            """Structural member projected from the owning model.

            Attributes to write first after DN, in order. Default: ['objectClass'].
            Remaining attributes sorted alphabetically.
            """
            ...

        @property
        def sort_objectclass_values(self) -> bool:
            """Structural member projected from the owning model.

            If True, sorts objectClass values with 'top' first, followed by other
            objectClasses in alphabetical order. This ensures proper objectClass
            hierarchy ordering in LDIF output.
            """
            ...

        @property
        def write_transformation_comments(self) -> bool:
            """Structural member projected from the owning model.

            If True, writes transformation comments with tags before modified
            attributes. Tags: [REMOVED], [RENAMED], [TRANSFORMED]. Example: '#
            [REMOVED] oldattr: value' or '# [RENAMED] old -> new: value'.
            """
            ...

        @property
        def use_original_acl_format_as_name(self) -> bool:
            """Structural member projected from the owning model.

            If True and entry_category='acl', uses the original ACL format from
            metadata (ACL_ORIGINAL_FORMAT) as the ACI name instead of generated
            name. Control characters are sanitized (ASCII < 0x20 or > 0x7E replaced
            with spaces, double quotes removed). Useful for OID→OUD migration to
            preserve original ACL context as the new ACI name.
            """
            ...

        @property
        def include_entry_markers(self) -> bool:
            """Structural member projected from the owning model.

            If True, includes entry type markers as comments before each entry.
            Markers indicate entry category (e.g., '# === USER ENTRY ===' or '# ===
            GROUP ENTRY ==='). Useful for visual separation in large files.
            """
            ...

        @property
        def entry_marker_template(self) -> str | None:
            """Structural member projected from the owning model.

            Custom Jinja2 template for entry markers. Variables: entry_type, dn,
            entry_index. If None, uses default format '# === {entry_type} ==='.
            """
            ...

        @property
        def include_statistics_summary(self) -> bool:
            """Structural member projected from the owning model.

            If True, includes a statistics summary in the file header showing entry
            counts by category and other migration metadata.
            """
            ...

        @property
        def statistics_categories(self) -> t.MutableIntMapping:
            """Structural member projected from the owning model.

            Dictionary of category names to entry counts for statistics summary.
            Example: {'users': 150, 'groups': 25, 'acl': 42}.
            """
            ...

    @runtime_checkable
    class MigrateOptions(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def migration_config(self) -> MutableMapping[str, t.Scalar] | None:
            """Structured migration settings with 6-file output and tracking."""
            ...

        @property
        def categorization_rules(
            self,
        ) -> FlextLdifProtocolsSettingsRules.CategoryRules | None:
            """Entry categorization rules (enables categorized mode)."""
            ...

        @property
        def input_files(self) -> MutableSequence[str] | None:
            """Ordered list of LDIF files to process (categorized mode)."""
            ...

        @property
        def output_files(
            self,
        ) -> (
            MutableMapping[
                FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.Categories, str
            ]
            | None
        ):
            """Category to filename mapping (categorized mode)."""
            ...

        @property
        def schema_whitelist_rules(
            self,
        ) -> FlextLdifProtocolsSettingsRules.WhitelistRules | None:
            """Allowed schema elements whitelist (categorized mode)."""
            ...

        @property
        def input_filename(self) -> str | None:
            """Specific input file to process (simple mode only)."""
            ...

        @property
        def output_filename(self) -> str | None:
            """Output filename (simple mode, defaults to 'migrated.ldif')."""
            ...

        @property
        def forbidden_attributes(self) -> MutableSequence[str] | None:
            """Attributes to remove from entries."""
            ...

        @property
        def forbidden_objectclasses(self) -> MutableSequence[str] | None:
            """ObjectClasses to remove from entries."""
            ...

        @property
        def base_dn(self) -> str | None:
            """Base DN filter (only process entries under this DN)."""
            ...

        @property
        def sort_entries_hierarchically(self) -> bool:
            """Sort entries by DN hierarchy depth then alphabetically."""
            ...

        @property
        def format_options(self) -> FlextLdifProtocolsBase.WriteFormatOptions | None:
            """LDIF formatting applied to the migrated output."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsSettingsMigrate",
]
