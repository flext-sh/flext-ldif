"""Configuration models for LDIF processing.

This module contains configuration models for LDIF processing operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
)
from typing import Annotated, Self

from flext_cli import m, u
from flext_ldif import (
    FlextLdifModelsDomainAcl as mdac,
    c,
    t,
)


class FlextLdifModelsSettings:
    class AciLineFormatConfig(m.Value):
        """Configuration for formatting a complete ACI line from components."""

        name: Annotated[str, u.Field(..., description="ACL name")]
        target_clause: Annotated[
            str,
            u.Field(..., description="Target clause (e.g., '(targetattr=\"cn\")')"),
        ]
        permissions_clause: Annotated[
            str,
            u.Field(..., description="Permissions clause (e.g., 'allow (read,write)')"),
        ]
        bind_rule: Annotated[
            str,
            u.Field(..., description="Bind rule (e.g., 'userdn=\"ldap:///self\"')"),
        ]
        aci_prefix: Annotated[str, u.Field(description="ACI attribute prefix")] = (
            "aci: "
        )
        version: Annotated[str, u.Field(description="ACI version")] = "3.0"

    class AciParserConfig(m.Value):
        """Configuration for server-specific ACI parsing."""

        server_type: Annotated[
            str,
            u.Field(..., description="Server type identifier (oid, oud, rfc, etc.)"),
        ]
        aci_prefix: Annotated[str, u.Field(description="ACI line prefix")] = "aci:"
        version_acl_pattern: Annotated[
            str,
            u.Field(
                description="Regex pattern to extract version and ACL name",
            ),
        ] = r'\(version\s+(\d+\.\d+)\s*;\s*acl\s+"([^"]+)"'
        targetattr_pattern: Annotated[
            str,
            u.Field(description="Regex pattern to extract target attributes"),
        ] = r'(\(targetattr\s*=\s*"([^"]*)")'
        default_targetattr: Annotated[
            str,
            u.Field(description="Default targetattr when none found"),
        ] = "*"
        allow_deny_pattern: Annotated[
            str,
            u.Field(description="Regex pattern to extract allow/deny permissions"),
        ] = r"(allow|deny)\s*\(([^)]*)\)"
        ops_separator: Annotated[
            str,
            u.Field(description="Separator for operations list"),
        ] = ","
        action_filter: Annotated[
            str | None,
            u.Field(description="Only include permissions for this action"),
        ] = None
        bind_patterns: Annotated[
            t.MutableStrMapping,
            u.Field(description="Mapping of bind type names to regex patterns"),
        ] = u.Field(default_factory=dict)
        permission_map: Annotated[
            t.MutableStrMapping,
            u.Field(description="Permission name normalization map"),
        ] = u.Field(default_factory=dict)
        special_subjects: Annotated[
            MutableMapping[str, tuple[str, str]],
            u.Field(description="Special subject value mappings"),
        ] = u.Field(default_factory=dict)
        extra_patterns: Annotated[
            t.MutableStrMapping,
            u.Field(description="Additional extraction patterns for extensions"),
        ] = u.Field(default_factory=dict)
        default_name: Annotated[
            str,
            u.Field(description="Default ACL name when none found"),
        ] = "unnamed-acl"

    class AclMetadataConfig(m.Value):
        """Configuration for building ACL metadata extensions."""

        line_breaks: Annotated[
            list[t.JsonValue] | None,
            u.Field(description="Line break positions"),
        ] = None
        dn_spaces: Annotated[
            str | None,
            u.Field(description="DN spacing information"),
        ] = None
        targetscope: Annotated[
            list[t.JsonValue] | None,
            u.Field(description="Target scope values"),
        ] = None
        version: Annotated[
            str | None,
            u.Field(description="ACI version string"),
        ] = None
        action_type: Annotated[
            str | None,
            u.Field(description="Action type (allow/deny)"),
        ] = None

    class DnNormalizationConfig(m.Value):
        """Configuration for DN normalization."""

        case_sensitive: Annotated[
            bool,
            u.Field(description="Whether DN comparison is case-sensitive"),
        ] = False
        remove_spaces: Annotated[
            bool,
            u.Field(description="Remove spaces around DN component separators"),
        ] = True
        case_fold: Annotated[
            str | None,
            u.Field(description="Case folding strategy for DN comparison"),
        ] = None
        space_handling: Annotated[
            str | None,
            u.Field(description="Strategy for handling spaces in DN values"),
        ] = None
        escape_handling: Annotated[
            str | None,
            u.Field(description="Strategy for handling escape sequences in DN"),
        ] = None
        validate_before: Annotated[
            bool,
            u.Field(description="Validate DN format before normalization"),
        ] = True

    class AttrNormalizationConfig(m.Value):
        """Configuration for attribute normalization."""

        lowercase_keys: Annotated[
            bool,
            u.Field(description="Convert attribute names to lowercase"),
        ] = True
        sort_values: Annotated[
            bool,
            u.Field(description="Sort attribute values alphabetically"),
        ] = True
        sort_attributes: Annotated[
            str | None,
            u.Field(description="Attribute sorting strategy"),
        ] = None
        normalize_whitespace: Annotated[
            bool,
            u.Field(description="Normalize whitespace in attribute values"),
        ] = True
        case_fold_names: Annotated[
            bool,
            u.Field(description="Case-fold attribute names for comparison"),
        ] = True
        trim_values: Annotated[
            bool,
            u.Field(description="Trim leading and trailing whitespace from values"),
        ] = True
        remove_empty: Annotated[
            bool,
            u.Field(description="Remove attributes with empty values"),
        ] = False

    class ProcessConfig(m.Value):
        """Configuration for processing operations."""

        batch_size: Annotated[
            int,
            u.Field(description="Number of entries to process per batch"),
        ] = 100
        timeout_seconds: Annotated[
            int,
            u.Field(description="Maximum processing time in seconds"),
        ] = 300
        max_retries: Annotated[
            int,
            u.Field(description="Maximum retry attempts on failure"),
        ] = 3
        source_server: Annotated[
            str | None,
            u.Field(description="Source LDAP server type identifier"),
        ] = None
        target_server: Annotated[
            str | None,
            u.Field(description="Target LDAP server type identifier"),
        ] = None
        dn_config: Annotated[
            FlextLdifModelsSettings.DnNormalizationConfig | None,
            u.Field(description="DN normalization configuration"),
        ] = None
        attr_config: Annotated[
            FlextLdifModelsSettings.AttrNormalizationConfig | None,
            u.Field(description="Attribute normalization configuration"),
        ] = None

        @classmethod
        def servers(
            cls,
            *,
            source_server: str | c.Ldif.ServerTypes | None,
            target_server: str | c.Ldif.ServerTypes | None,
        ) -> Self:
            """Build processing config keeping model defaults untouched."""
            return cls(
                source_server=(
                    source_server.value
                    if isinstance(source_server, c.Ldif.ServerTypes)
                    else source_server
                ),
                target_server=(
                    target_server.value
                    if isinstance(target_server, c.Ldif.ServerTypes)
                    else target_server
                ),
            )

    class TransformConfig(m.Value):
        """Configuration for transformation operations."""

        fail_fast: Annotated[
            bool,
            u.Field(description="Stop on first transformation error"),
        ] = False
        preserve_order: Annotated[
            bool,
            u.Field(description="Preserve original entry ordering"),
        ] = True
        track_changes: Annotated[
            bool,
            u.Field(description="Track attribute-level changes for audit"),
        ] = False
        normalize_dns: Annotated[
            bool,
            u.Field(description="Normalize DNs during transformation"),
        ] = False
        normalize_attrs: Annotated[
            bool,
            u.Field(description="Normalize attributes during transformation"),
        ] = False
        process_config: Annotated[
            FlextLdifModelsSettings.ProcessConfig | None,
            u.Field(description="Processing configuration for batch operations"),
        ] = None

        @classmethod
        def servers(
            cls,
            *,
            source_server: str | c.Ldif.ServerTypes | None,
            target_server: str | c.Ldif.ServerTypes | None,
        ) -> Self:
            """Build transform config for server-to-server conversion only."""
            return cls(
                normalize_dns=True,
                normalize_attrs=True,
                process_config=FlextLdifModelsSettings.ProcessConfig.servers(
                    source_server=source_server,
                    target_server=target_server,
                ),
            )

    class ServerPatternsConfig(m.Value):
        """Configuration for server pattern matching."""

        dn_patterns: Annotated[
            tuple[tuple[str, ...], ...],
            u.Field(
                description="Tuple of DN pattern tuples - entry matches if ALL patterns in ANY tuple match",
            ),
        ] = ()
        attr_prefixes: Annotated[
            tuple[str, ...] | frozenset[str],
            u.Field(description="Attribute name prefixes to check"),
        ] = ()
        attr_names: Annotated[
            frozenset[str] | set[str],
            u.Field(
                description="Set of attribute names that indicate this server",
            ),
        ]
        keyword_patterns: Annotated[
            tuple[str, ...],
            u.Field(description="Keywords to search in attribute names"),
        ] = ()

    class EntryCriteriaConfig(m.Value):
        """Configuration for entry criteria matching.

        Consolidates parameters for matches_criteria utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            settings = FlextLdifModelsSettings.EntryCriteriaConfig(
                objectclasses=["inetOrgPerson", "person"],
                objectclass_mode="any",
                required_attrs=["cn", "sn"],
            )
            matches = FlextLdifUtilities.Entry.matches_criteria(entry, settings)

        """

        objectclasses: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Required objectClasses"),
        ] = None
        objectclass_mode: Annotated[
            c.Ldif.EntryCriteriaMode,
            u.Field(description='"any" (has any) or "all" (has all)'),
        ] = c.Ldif.EntryCriteriaMode.ANY
        required_attrs: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="All of these attributes must exist"),
        ] = None
        any_attrs: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(
                description="At least one of these attributes must exist",
            ),
        ] = None
        dn_pattern: Annotated[
            str | None,
            u.Field(description="Regex pattern that DN must match"),
        ] = None
        is_schema: Annotated[
            bool | None,
            u.Field(
                description="If set, entry must (True) or must not (False) be schema",
            ),
        ] = None

    class EntryParseMetadataConfig(m.Value):
        """Configuration for building entry parse metadata.

        Consolidates parameters for build_entry_parse_metadata utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            settings = FlextLdifModelsSettings.EntryParseMetadataConfig(
                server_type="oid",
                original_entry_dn="cn=test,dc=example",
                cleaned_dn="cn=test,dc=example",
                original_dn_line="dn: cn=test,dc=example",
            )
            metadata = FlextLdifUtilities.Metadata.build_entry_parse_metadata(settings)

        """

        server_type: Annotated[
            c.Ldif.ServerTypes,
            u.Field(
                ...,
                description="Server type performing the parse (oid, oud, rfc, etc.)",
            ),
        ]
        original_entry_dn: Annotated[
            str,
            u.Field(..., description="Original DN as parsed from LDIF"),
        ]
        cleaned_dn: Annotated[str, u.Field(..., description="Cleaned/normalized DN")]
        original_dn_line: Annotated[
            str | None,
            u.Field(
                description="Original DN line from LDIF (with folding if present)",
            ),
        ] = None
        original_attr_lines: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Original attribute lines from LDIF"),
        ] = None
        dn_was_base64: Annotated[
            bool,
            u.Field(description="Whether DN was base64 encoded"),
        ] = False
        original_attribute_case: Annotated[
            t.MutableStrMapping | None,
            u.Field(
                description="Mapping of attribute names to original case",
            ),
        ] = None

    class CategoryRules(m.Value):
        """Rules for entry categorization.

        Contains DN patterns and objectClass lists for each category.
        Replaces dict[str, t.JsonValue] with type-safe Pydantic model.
        """

        user_dn_patterns: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                default_factory=list,
                description="DN patterns for user entries (e.g., '*,ou=users,*')",
            ),
        ]
        group_dn_patterns: Annotated[
            t.MutableSequenceOf[str],
            u.Field(default_factory=list, description="DN patterns for group entries"),
        ]
        hierarchy_dn_patterns: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                default_factory=list,
                description="DN patterns for organizational hierarchy",
            ),
        ]
        schema_dn_patterns: Annotated[
            t.MutableSequenceOf[str],
            u.Field(default_factory=list, description="DN patterns for schema entries"),
        ]
        user_objectclasses: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                default_factory=list,
                description="ObjectClasses identifying user entries",
            ),
        ]
        group_objectclasses: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                default_factory=list,
                description="ObjectClasses identifying group entries",
            ),
        ]
        hierarchy_objectclasses: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                default_factory=list,
                description="ObjectClasses identifying organizational units",
            ),
        ]
        acl_attributes: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                default_factory=list,
                description="Attribute names containing ACL information",
            ),
        ]

    class LogContextExtras(m.Value):
        """Extra context fields for structured event logging."""

        user_id: Annotated[str | None, u.Field(description="User identifier")] = None
        session_id: Annotated[
            str | None,
            u.Field(description="Session identifier"),
        ] = None
        request_id: Annotated[
            str | None,
            u.Field(description="Request identifier"),
        ] = None
        component: Annotated[
            str | None,
            u.Field(description="Component name"),
        ] = None
        correlation_id: Annotated[
            str | None,
            u.Field(description="Correlation identifier"),
        ] = None
        trace_id: Annotated[str | None, u.Field(description="Trace identifier")] = None

    class WhitelistRules(m.Value):
        """Whitelist rules for entry validation.

        Defines blocked objectClasses and validation rules.
        Replaces dict[str, t.JsonValue] with type-safe Pydantic model.
        """

        blocked_objectclasses: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="ObjectClasses that should be blocked/rejected",
            ),
        ]
        allowed_objectclasses: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="ObjectClasses that are explicitly allowed",
            ),
        ]
        required_attributes: Annotated[
            t.MutableSequenceOf[str],
            u.Field(description="Attributes that must be present"),
        ]
        blocked_attributes: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Attributes that should be blocked",
            ),
        ]
        allowed_attribute_oids: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="OID patterns for allowed schema attributes",
            ),
        ]
        allowed_objectclass_oids: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="OID patterns for allowed objectClasses",
            ),
        ]
        allowed_matchingrule_oids: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="OID patterns for allowed matchingRules",
            ),
        ]
        allowed_matchingruleuse_oids: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="OID patterns for allowed matchingRuleUse definitions",
            ),
        ]
        allowed_ldapsyntax_oids: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="OID patterns for allowed ldapSyntaxes definitions",
            ),
        ]

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
                description="Structured migration settings with 6-file output and tracking",
            ),
        ] = None
        categorization_rules: Annotated[
            FlextLdifModelsSettings.CategoryRules | None,
            u.Field(
                description="Entry categorization rules (enables categorized mode)",
            ),
        ] = None
        input_files: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(
                description="Ordered list of LDIF files to process (categorized mode)",
            ),
        ] = None
        output_files: Annotated[
            MutableMapping[c.Ldif.Categories, str] | None,
            u.Field(
                description="Category to filename mapping (categorized mode)",
            ),
        ] = None
        schema_whitelist_rules: Annotated[
            FlextLdifModelsSettings.WhitelistRules | None,
            u.Field(
                description="Allowed schema elements whitelist (categorized mode)",
            ),
        ] = None
        input_filename: Annotated[
            str | None,
            u.Field(
                description="Specific input file to process (simple mode only)",
            ),
        ] = None
        output_filename: Annotated[
            str | None,
            u.Field(
                description="Output filename (simple mode, defaults to 'migrated.ldif')",
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
            u.Field(
                description="Base DN filter (only process entries under this DN)",
            ),
        ] = None
        sort_entries_hierarchically: Annotated[
            bool,
            u.Field(
                description="Sort entries by DN hierarchy depth then alphabetically",
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
                description="If True, writes attributes in the order specified in Entry.metadata.",
            ),
        ] = True
        sort_attributes: Annotated[
            bool,
            u.Field(
                description="If True, sorts attributes alphabetically. Overridden by respect_attribute_order.",
            ),
        ] = False
        write_hidden_attributes_as_comments: Annotated[
            bool,
            u.Field(
                description="If True, attributes marked as 'hidden' in metadata will be written as comments.",
            ),
        ] = False
        write_metadata_as_comments: Annotated[
            bool,
            u.Field(
                description="If True, the entry's main metadata will be written as a commented block.",
            ),
        ] = False
        include_version_header: Annotated[
            bool,
            u.Field(
                description="If True, includes the LDIF version header in output.",
            ),
        ] = True
        include_timestamps: Annotated[
            bool,
            u.Field(
                description="If True, includes timestamp comments for when entries were written.",
            ),
        ] = False
        base64_encode_binary: Annotated[
            bool,
            u.Field(
                description="If True, automatically base64 encodes binary attribute values.",
            ),
        ] = False
        fold_long_lines: Annotated[
            bool,
            u.Field(
                description="If True, folds lines longer than line_width according to RFC 2849.",
            ),
        ] = True
        restore_original_format: Annotated[
            bool,
            u.Field(
                description="If True, restores original LDIF format from metadata for perfect round-trip. When enabled, uses entry.metadata.original_strings['entry_original_ldif'] to write the exact original format, preserving all minimal differences (spacing, case, punctuation, quotes, etc.). CRITICAL for zero data loss.",
            ),
        ] = False
        write_empty_values: Annotated[
            bool,
            u.Field(
                description="If True, writes attributes with empty values. If False, omits them.",
            ),
        ] = True
        normalize_attribute_names: Annotated[
            bool,
            u.Field(
                description="If True, normalizes attribute names to lowercase.",
            ),
        ] = False
        include_dn_comments: Annotated[
            bool,
            u.Field(
                description="If True, includes DN explanation comments for complex entries.",
            ),
        ] = False
        write_removed_attributes_as_comments: Annotated[
            bool,
            u.Field(
                description="If True, writes removed attributes as comments in LDIF output.",
            ),
        ] = False
        write_migration_header: Annotated[
            bool,
            u.Field(
                description="If True, writes migration metadata header at the start of LDIF file.",
            ),
        ] = False
        migration_header_template: Annotated[
            str | None,
            u.Field(
                description="Jinja2 template string for migration header. If None, uses default template.",
            ),
        ] = None
        write_rejection_reasons: Annotated[
            bool,
            u.Field(
                description="If True, writes rejection reasons as comments for rejected entries.",
            ),
        ] = False
        include_removal_statistics: Annotated[
            bool,
            u.Field(
                description="If True, includes statistics about removed attributes in headers.",
            ),
        ] = False
        ldif_changetype: Annotated[
            str | None,
            u.Field(
                description="If set to 'modify', writes entries in LDIF modify format (changetype: modify). Otherwise uses add format.",
            ),
        ] = None
        ldif_modify_operation: Annotated[
            str,
            u.Field(
                description="LDIF modify operation: 'add' or 'replace'. Used when ldif_changetype='modify'. Default 'add' for schema/ACL phases.",
            ),
        ] = "add"
        write_original_entry_as_comment: Annotated[
            bool,
            u.Field(
                description="If True, writes original source entry as commented LDIF block before converted entry.",
            ),
        ] = False
        entry_category: Annotated[
            str | None,
            u.Field(
                description="Migration category (e.g., 'hierarchy', 'users', 'groups', 'acl'). Used for phase-specific formatting.",
            ),
        ] = None
        acl_attribute_names: Annotated[
            frozenset[str],
            u.Field(
                description="Set of ACL attribute names (e.g., {'orclaci', 'orclentrylevelaci'}). Used to identify ACL attributes.",
            ),
        ] = u.Field(default_factory=frozenset)
        comment_acl_in_non_acl_phases: Annotated[
            bool,
            u.Field(
                description="If True, ACL attributes are written as comments when entry_category != 'acl'.",
            ),
        ] = True
        use_rfc_attribute_order: Annotated[
            bool,
            u.Field(
                description="If True, writes attributes in RFC 2849 orderClass first after DN, then remaining attributes alphabetically. DN is always first (handled automatically by writer).",
            ),
        ] = False
        rfc_order_priority_attributes: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Attributes to write first after DN, in order. Default: ['objectClass']. Remaining attributes sorted alphabetically.",
            ),
        ] = u.Field(default_factory=lambda: ["objectClass"])
        sort_objectclass_values: Annotated[
            bool,
            u.Field(
                description="If True, sorts objectClass values with 'top' first, followed by other objectClasses in alphabetical order. This ensures proper objectClass hierarchy ordering in LDIF output.",
            ),
        ] = False
        write_transformation_comments: Annotated[
            bool,
            u.Field(
                description="If True, writes transformation comments with tags before modified attributes. Tags: [REMOVED], [RENAMED], [TRANSFORMED]. Example: '# [REMOVED] oldattr: value' or '# [RENAMED] old -> new: value'.",
            ),
        ] = False
        use_original_acl_format_as_name: Annotated[
            bool,
            u.Field(
                description="If True and entry_category='acl', uses the original ACL format from metadata (ACL_ORIGINAL_FORMAT) as the ACI name instead of generated name. Control characters are sanitized (ASCII < 0x20 or > 0x7E replaced with spaces, double quotes removed). Useful for OID→OUD migration to preserve original ACL context as the new ACI name.",
            ),
        ] = False
        include_entry_markers: Annotated[
            bool,
            u.Field(
                description="If True, includes entry type markers as comments before each entry. Markers indicate entry category (e.g., '# === USER ENTRY ===' or '# === GROUP ENTRY ==='). Useful for visual separation in large files.",
            ),
        ] = False
        entry_marker_template: Annotated[
            str | None,
            u.Field(
                description="Custom Jinja2 template for entry markers. Variables: entry_type, dn, entry_index. If None, uses default format '# === {entry_type} ==='.",
            ),
        ] = None
        include_statistics_summary: Annotated[
            bool,
            u.Field(
                description="If True, includes a statistics summary in the file header showing entry counts by category and other migration metadata.",
            ),
        ] = False
        statistics_categories: Annotated[
            t.MutableIntMapping,
            u.Field(
                description="Dictionary of category names to entry counts for statistics summary. Example: {'users': 150, 'groups': 25, 'acl': 42}.",
            ),
        ] = u.Field(default_factory=dict)

    class RdnProcessingConfig(m.ArbitraryTypesModel):
        """Mutable state for RDN character-by-character parsing."""

        current_attr: Annotated[str, u.Field(description="Current attribute name")] = ""
        current_val: Annotated[str, u.Field(description="Current value")] = ""
        in_value: Annotated[
            bool,
            u.Field(description="Whether parser is inside the value portion"),
        ] = False
        pairs: Annotated[
            t.MutableSequenceOf[tuple[str, str]],
            u.Field(description="Accumulated (attr, value) pairs"),
        ] = u.Field(default_factory=lambda: list[tuple[str, str]]())

    class PermissionMappingConfig(m.Value):
        """Configuration for permission mapping during ACL conversion.

        Consolidates parameters for
        FlextLdifConversion._apply_permission_mapping method.
        Reduces function signature from 6 parameters to 1 model.

        """

        original_acl: Annotated[
            mdac.Acl,
            u.Field(
                description="Original ACL model",
            ),
        ]
        converted_acl: Annotated[
            mdac.Acl,
            u.Field(
                description="Converted ACL model (modified in-place)",
            ),
        ]
        orig_perms_dict: Annotated[
            t.MutableBoolMapping,
            u.Field(..., description="Original permissions dict"),
        ]
        source_server_type: Annotated[
            str | None,
            u.Field(description="Source server type"),
        ] = None
        target_server_type: Annotated[
            str | None,
            u.Field(description="Target server type"),
        ] = None
        converted_has_permissions: Annotated[
            bool,
            u.Field(description="Whether converted ACL has permissions"),
        ] = False

    class ServerValidationRules(m.Value):
        """Server-specific validation rules for LDIF entries."""

        requires_binary_option: Annotated[
            bool,
            u.Field(
                description="Whether server requires ;binary option for non-ASCII values",
            ),
        ] = False
        requires_naming_attr: Annotated[
            bool,
            u.Field(description="Whether server requires naming attribute in entry"),
        ] = False
        requires_objectclass: Annotated[
            bool,
            u.Field(description="Whether server requires objectClass attribute"),
        ] = True
