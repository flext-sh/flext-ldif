"""LDIF settings mix-in: migrate.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Annotated

from flext_core import FlextUtilities as u, m
from flext_ldif import c, t
from flext_ldif._models._settings_rules import FlextLdifModelsSettingsRules as msr


class FlextLdifModelsSettingsMigrate:
    """LDIF settings mix-in: migrate."""

    class MigrateOptions(m.Value):
        """Options for FlextLdif.migrate() operation.

        Consolidates 12+ optional parameters into single typed Model.
        Reduces migrate() signature from 16 parameters to 5 parameters.

        Supports three migration modes:
        - Structured: 6-file output with full tracking (via migration_config)
        - Categorized: Custom multi-file output (via categorization_rules)
        - Simple: Single output file (default)

        Inherits from m.Value:
        - Immutable (frozen=True)
        - Validates assignment
        - Extra fields forbidden
        """

        migration_config: Annotated[
            t.MutableScalarMapping | None,
            u.Field(
                description="Structured migration settings with 6-file output and tracking"
            ),
        ] = None
        categorization_rules: Annotated[
            msr.CategoryRules | None,
            u.Field(
                description="Entry categorization rules (enables categorized mode)"
            ),
        ] = None
        input_files: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(
                description="Ordered list of LDIF files to process (categorized mode)"
            ),
        ] = None
        output_files: Annotated[
            MutableMapping[c.Ldif.Categories, str] | None,
            u.Field(description="Category to filename mapping (categorized mode)"),
        ] = None
        schema_whitelist_rules: Annotated[
            msr.WhitelistRules | None,
            u.Field(description="Allowed schema elements whitelist (categorized mode)"),
        ] = None
        input_filename: Annotated[
            str | None,
            u.Field(description="Specific input file to process (simple mode only)"),
        ] = None
        output_filename: Annotated[
            str | None,
            u.Field(
                description="Output filename (simple mode, defaults to 'migrated.ldif')"
            ),
        ] = None
        forbidden_attributes: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Attributes to remove from entries"),
        ] = None
        forbidden_objectclasses: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="ObjectClasses to remove from entries"),
        ] = None
        base_dn: Annotated[
            str | None,
            u.Field(description="Base DN filter (only process entries under this DN)"),
        ] = None
        sort_entries_hierarchically: Annotated[
            bool,
            u.Field(
                description="Sort entries by DN hierarchy depth then alphabetically"
            ),
        ] = False

    class WriteFormatOptions(m.Value):
        """Formatting options for LDIF serialization.

        .. deprecated:: 0.9.0
            Use FlextLdifSettings fields (ldif_write_*) instead.
            This class will be removed in version 1.0.0.

        **Migration Guide**:
            Replace FlextLdifModelsSettings.WriteFormatOptions with FlextLdifSettings:

            .. code-block:: python

                options = FlextLdifModelsSettings.WriteFormatOptions(
                    line_width=80, fold_long_lines=True
                )
                result = ldif.write(entries, options=options)

                # NEW (correct):
                from flext_ldif import FlextLdifSettings

                settings = FlextSettings.get_global().get_namespace(
                    "ldif", FlextLdifSettings
                )
                # Override if needed: settings.ldif_write_fold_long_lines = True
                result = ldif.write(entries)  # Uses settings.ldif_write_* fields

        **Mapping Table**:
            - line_width → settings.ldif_max_line_length
            - fold_long_lines → settings.ldif_write_fold_long_lines
            - respect_attribute_order → settings.ldif_write_respect_attribute_order
            - sort_attributes → settings.ldif_write_sort_attributes
            - (see FlextLdifSettings for complete list of ldif_write_* fields)

        Provides detailed control over the output format, including line width
        for folding, and whether to respect attribute ordering from metadata.
        """

        line_width: Annotated[
            int,
            u.Field(
                ge=10,
                le=100000,
                description="Maximum line width before folding (RFC 2849 recommends 76). Only used if fold_long_lines=True.",
            ),
        ] = c.Ldif.DEFAULT_LINE_WIDTH
        respect_attribute_order: Annotated[
            bool,
            u.Field(
                description="If True, writes attributes in the order specified in Entry.metadata."
            ),
        ] = True
        sort_attributes: Annotated[
            bool,
            u.Field(
                description="If True, sorts attributes alphabetically. Overridden by respect_attribute_order."
            ),
        ] = False
        write_hidden_attributes_as_comments: Annotated[
            bool,
            u.Field(
                description="If True, attributes marked as 'hidden' in metadata will be written as comments."
            ),
        ] = False
        write_metadata_as_comments: Annotated[
            bool,
            u.Field(
                description="If True, the entry's main metadata will be written as a commented block."
            ),
        ] = False
        include_version_header: Annotated[
            bool,
            u.Field(description="If True, includes the LDIF version header in output."),
        ] = True
        include_timestamps: Annotated[
            bool,
            u.Field(
                description="If True, includes timestamp comments for when entries were written."
            ),
        ] = False
        base64_encode_binary: Annotated[
            bool,
            u.Field(
                description="If True, automatically base64 encodes binary attribute values."
            ),
        ] = False
        fold_long_lines: Annotated[
            bool,
            u.Field(
                description="If True, folds lines longer than line_width according to RFC 2849."
            ),
        ] = True
        restore_original_format: Annotated[
            bool,
            u.Field(
                description="If True, restores original LDIF format from metadata for perfect round-trip. When enabled, uses entry.metadata.original_strings['entry_original_ldif'] to write the exact original format, preserving all minimal differences (spacing, case, punctuation, quotes, etc.). CRITICAL for zero data loss."
            ),
        ] = False
        write_empty_values: Annotated[
            bool,
            u.Field(
                description="If True, writes attributes with empty values. If False, omits them."
            ),
        ] = True
        normalize_attribute_names: Annotated[
            bool,
            u.Field(description="If True, normalizes attribute names to lowercase."),
        ] = False
        include_dn_comments: Annotated[
            bool,
            u.Field(
                description="If True, includes DN explanation comments for complex entries."
            ),
        ] = False
        write_removed_attributes_as_comments: Annotated[
            bool,
            u.Field(
                description="If True, writes removed attributes as comments in LDIF output."
            ),
        ] = False
        write_migration_header: Annotated[
            bool,
            u.Field(
                description="If True, writes migration metadata header at the start of LDIF file."
            ),
        ] = False
        migration_header_template: Annotated[
            str | None,
            u.Field(
                description="Jinja2 template string for migration header. If None, uses default template."
            ),
        ] = None
        write_rejection_reasons: Annotated[
            bool,
            u.Field(
                description="If True, writes rejection reasons as comments for rejected entries."
            ),
        ] = False
        include_removal_statistics: Annotated[
            bool,
            u.Field(
                description="If True, includes statistics about removed attributes in headers."
            ),
        ] = False
        ldif_changetype: Annotated[
            str | None,
            u.Field(
                description="If set to 'modify', writes entries in LDIF modify format (changetype: modify). Otherwise uses add format."
            ),
        ] = None
        ldif_modify_operation: Annotated[
            str,
            u.Field(
                description="LDIF modify operation: 'add' or 'replace'. Used when ldif_changetype='modify'. Default 'add' for schema/ACL phases."
            ),
        ] = "add"
        write_original_entry_as_comment: Annotated[
            bool,
            u.Field(
                description="If True, writes original source entry as commented LDIF block before converted entry."
            ),
        ] = False
        entry_category: Annotated[
            str | None,
            u.Field(
                description="Migration category (e.g., 'hierarchy', 'users', 'groups', 'acl'). Used for phase-specific formatting."
            ),
        ] = None
        acl_attribute_names: Annotated[
            frozenset[str],
            u.Field(
                description="Set of ACL attribute names (e.g., {'orclaci', 'orclentrylevelaci'}). Used to identify ACL attributes."
            ),
        ] = u.Field(default_factory=frozenset)
        comment_acl_in_non_acl_phases: Annotated[
            bool,
            u.Field(
                description="If True, ACL attributes are written as comments when entry_category != 'acl'."
            ),
        ] = True
        use_rfc_attribute_order: Annotated[
            bool,
            u.Field(
                description="If True, writes attributes in RFC 2849 orderClass first after DN, then remaining attributes alphabetically. DN is always first (handled automatically by writer)."
            ),
        ] = False
        rfc_order_priority_attributes: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Attributes to write first after DN, in order. Default: ['objectClass']. Remaining attributes sorted alphabetically."
            ),
        ] = u.Field(default_factory=lambda: ["objectClass"])
        sort_objectclass_values: Annotated[
            bool,
            u.Field(
                description="If True, sorts objectClass values with 'top' first, followed by other objectClasses in alphabetical order. This ensures proper objectClass hierarchy ordering in LDIF output."
            ),
        ] = False
        write_transformation_comments: Annotated[
            bool,
            u.Field(
                description="If True, writes transformation comments with tags before modified attributes. Tags: [REMOVED], [RENAMED], [TRANSFORMED]. Example: '# [REMOVED] oldattr: value' or '# [RENAMED] old -> new: value'."
            ),
        ] = False
        use_original_acl_format_as_name: Annotated[
            bool,
            u.Field(
                description="If True and entry_category='acl', uses the original ACL format from metadata (ACL_ORIGINAL_FORMAT) as the ACI name instead of generated name. Control characters are sanitized (ASCII < 0x20 or > 0x7E replaced with spaces, double quotes removed). Useful for OID→OUD migration to preserve original ACL context as the new ACI name."
            ),
        ] = False
        include_entry_markers: Annotated[
            bool,
            u.Field(
                description="If True, includes entry type markers as comments before each entry. Markers indicate entry category (e.g., '# === USER ENTRY ===' or '# === GROUP ENTRY ==='). Useful for visual separation in large files."
            ),
        ] = False
        entry_marker_template: Annotated[
            str | None,
            u.Field(
                description="Custom Jinja2 template for entry markers. Variables: entry_type, dn, entry_index. If None, uses default format '# === {entry_type} ==='."
            ),
        ] = None
        include_statistics_summary: Annotated[
            bool,
            u.Field(
                description="If True, includes a statistics summary in the file header showing entry counts by category and other migration metadata."
            ),
        ] = False
        statistics_categories: Annotated[
            t.MutableIntMapping,
            u.Field(
                description="Dictionary of category names to entry counts for statistics summary. Example: {'users': 150, 'groups': 25, 'acl': 42}."
            ),
        ] = u.Field(default_factory=dict)
