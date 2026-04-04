"""Configuration models for LDIF processing.

This module contains configuration models for LDIF processing operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping, MutableSequence
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal

from pydantic import ConfigDict, Field

from flext_core import FlextModels, r
from flext_ldif import c, p, t

if TYPE_CHECKING:
    from flext_ldif import FlextLdifModelsDomains


class FlextLdifModelsSettings:
    """LDIF configuration models container class.

    This class acts as a namespace container for LDIF configuration models.
    All nested classes are accessed via FlextModels.* in the main models.py.
    """

    class AciLineFormatConfig(FlextModels.Value):
        """Configuration for formatting a complete ACI line from components."""

        name: Annotated[str, Field(..., description="ACL name")]
        target_clause: Annotated[
            str,
            Field(..., description="Target clause (e.g., '(targetattr=\"cn\")')"),
        ]
        permissions_clause: Annotated[
            str,
            Field(..., description="Permissions clause (e.g., 'allow (read,write)')"),
        ]
        bind_rule: Annotated[
            str,
            Field(..., description="Bind rule (e.g., 'userdn=\"ldap:///self\"')"),
        ]
        aci_prefix: Annotated[str, Field(description="ACI attribute prefix")] = "aci: "
        version: Annotated[str, Field(description="ACI version")] = "3.0"

    class AciParserConfig(FlextModels.Value):
        """Configuration for server-specific ACI parsing."""

        server_type: Annotated[
            str,
            Field(..., description="Server type identifier (oid, oud, rfc, etc.)"),
        ]
        aci_prefix: Annotated[str, Field(description="ACI line prefix")] = "aci:"
        version_acl_pattern: Annotated[
            str,
            Field(
                description="Regex pattern to extract version and ACL name",
            ),
        ] = r'\(version\s+(\d+\.\d+)\s*;\s*acl\s+"([^"]+)"'
        targetattr_pattern: Annotated[
            str,
            Field(description="Regex pattern to extract target attributes"),
        ] = r'(\(targetattr\s*=\s*"([^"]*)")'
        default_targetattr: Annotated[
            str,
            Field(description="Default targetattr when none found"),
        ] = "*"
        allow_deny_pattern: Annotated[
            str,
            Field(description="Regex pattern to extract allow/deny permissions"),
        ] = r"(allow|deny)\s*\(([^)]*)\)"
        ops_separator: Annotated[
            str,
            Field(description="Separator for operations list"),
        ] = ","
        action_filter: Annotated[
            str | None,
            Field(description="Only include permissions for this action"),
        ] = None
        bind_patterns: Annotated[
            t.MutableStrMapping,
            Field(description="Mapping of bind type names to regex patterns"),
        ] = Field(default_factory=dict)
        permission_map: Annotated[
            t.MutableStrMapping,
            Field(description="Permission name normalization map"),
        ] = Field(default_factory=dict)
        special_subjects: Annotated[
            MutableMapping[str, tuple[str, str]],
            Field(description="Special subject value mappings"),
        ] = Field(default_factory=dict)
        extra_patterns: Annotated[
            t.MutableStrMapping,
            Field(description="Additional extraction patterns for extensions"),
        ] = Field(default_factory=dict)
        default_name: Annotated[
            str,
            Field(description="Default ACL name when none found"),
        ] = "unnamed-acl"

    class AclMetadataConfig(FlextModels.Value):
        """Configuration for building ACL metadata extensions."""

        line_breaks: Annotated[
            MutableSequence[int] | None,
            Field(description="Line break positions"),
        ] = None
        dn_spaces: Annotated[
            str | None,
            Field(description="DN spacing information"),
        ] = None
        targetscope: Annotated[
            MutableSequence[int] | None,
            Field(description="Target scope values"),
        ] = None
        version: Annotated[
            str | None,
            Field(description="ACI version string"),
        ] = None
        action_type: Annotated[
            str | None,
            Field(description="Action type (allow/deny)"),
        ] = None

    class DnNormalizationConfig(FlextModels.Value):
        """Configuration for DN normalization."""

        case_sensitive: bool = Field(
            default=False, description="Whether DN comparison is case-sensitive"
        )
        remove_spaces: bool = Field(
            default=True, description="Remove spaces around DN component separators"
        )
        case_fold: str | None = Field(
            default=None, description="Case folding strategy for DN comparison"
        )
        space_handling: str | None = Field(
            default=None, description="Strategy for handling spaces in DN values"
        )
        escape_handling: str | None = Field(
            default=None, description="Strategy for handling escape sequences in DN"
        )
        validate_before: bool = Field(
            default=True, description="Validate DN format before normalization"
        )

    class AttrNormalizationConfig(FlextModels.Value):
        """Configuration for attribute normalization."""

        lowercase_keys: bool = Field(
            default=True, description="Convert attribute names to lowercase"
        )
        sort_values: bool = Field(
            default=True, description="Sort attribute values alphabetically"
        )
        sort_attributes: str | None = Field(
            default=None, description="Attribute sorting strategy"
        )
        normalize_whitespace: bool = Field(
            default=True, description="Normalize whitespace in attribute values"
        )
        case_fold_names: bool = Field(
            default=True, description="Case-fold attribute names for comparison"
        )
        trim_values: bool = Field(
            default=True, description="Trim leading and trailing whitespace from values"
        )
        remove_empty: bool = Field(
            default=False, description="Remove attributes with empty values"
        )

    class ProcessConfig(FlextModels.Value):
        """Configuration for processing operations."""

        batch_size: int = Field(
            default=100, description="Number of entries to process per batch"
        )
        timeout_seconds: int = Field(
            default=300, description="Maximum processing time in seconds"
        )
        max_retries: int = Field(
            default=3, description="Maximum retry attempts on failure"
        )
        source_server: str | None = Field(
            default=None, description="Source LDAP server type identifier"
        )
        target_server: str | None = Field(
            default=None, description="Target LDAP server type identifier"
        )
        dn_config: FlextLdifModelsSettings.DnNormalizationConfig | None = Field(
            default=None, description="DN normalization configuration"
        )
        attr_config: FlextLdifModelsSettings.AttrNormalizationConfig | None = Field(
            default=None, description="Attribute normalization configuration"
        )

    class TransformConfig(FlextModels.Value):
        """Configuration for transformation operations."""

        fail_fast: bool = Field(
            default=False, description="Stop on first transformation error"
        )
        preserve_order: bool = Field(
            default=True, description="Preserve original entry ordering"
        )
        track_changes: bool = Field(
            default=False, description="Track attribute-level changes for audit"
        )
        normalize_dns: bool = Field(
            default=False, description="Normalize DNs during transformation"
        )
        normalize_attrs: bool = Field(
            default=False, description="Normalize attributes during transformation"
        )
        process_config: FlextLdifModelsSettings.ProcessConfig | None = Field(
            default=None, description="Processing configuration for batch operations"
        )

    class ServerPatternsConfig(FlextModels.Value):
        """Configuration for server pattern matching."""

        dn_patterns: Annotated[
            tuple[tuple[str, ...], ...],
            Field(
                description="Tuple of DN pattern tuples - entry matches if ALL patterns in ANY tuple match",
            ),
        ] = ()
        attr_prefixes: Annotated[
            tuple[str, ...] | frozenset[str],
            Field(description="Attribute name prefixes to check"),
        ] = ()
        attr_names: Annotated[
            frozenset[str] | set[str],
            Field(
                description="Set of attribute names that indicate this server",
            ),
        ]
        keyword_patterns: Annotated[
            tuple[str, ...],
            Field(description="Keywords to search in attribute names"),
        ] = ()

    class EntryCriteriaConfig(FlextModels.Value):
        """Configuration for entry criteria matching.

        Consolidates parameters for matches_criteria utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.EntryCriteriaConfig(
                objectclasses=["inetOrgPerson", "person"],
                objectclass_mode="any",
                required_attrs=["cn", "sn"],
            )
            matches = FlextLdifUtilities.Entry.matches_criteria(entry, config)

        """

        objectclasses: Annotated[
            MutableSequence[str] | None,
            Field(description="Required objectClasses"),
        ] = None
        objectclass_mode: Annotated[
            Literal["any", "all"],
            Field(description='"any" (has any) or "all" (has all)'),
        ] = "any"
        required_attrs: Annotated[
            MutableSequence[str] | None,
            Field(description="All of these attributes must exist"),
        ] = None
        any_attrs: Annotated[
            MutableSequence[str] | None,
            Field(
                description="At least one of these attributes must exist",
            ),
        ] = None
        dn_pattern: Annotated[
            str | None,
            Field(description="Regex pattern that DN must match"),
        ] = None
        is_schema: Annotated[
            bool | None,
            Field(
                description="If set, entry must (True) or must not (False) be schema",
            ),
        ] = None

    class EntryParseMetadataConfig(FlextModels.Value):
        """Configuration for building entry parse metadata.

        Consolidates parameters for build_entry_parse_metadata utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.EntryParseMetadataConfig(
                quirk_type="oid",
                original_entry_dn="cn=test,dc=example",
                cleaned_dn="cn=test,dc=example",
                original_dn_line="dn: cn=test,dc=example",
            )
            metadata = FlextLdifUtilities.Metadata.build_entry_parse_metadata(config)

        """

        quirk_type: Annotated[
            c.Ldif.ServerTypeLiteral,
            Field(
                ...,
                description="Server type performing the parse (oid, oud, rfc, etc.)",
            ),
        ]
        original_entry_dn: Annotated[
            str,
            Field(..., description="Original DN as parsed from LDIF"),
        ]
        cleaned_dn: Annotated[str, Field(..., description="Cleaned/normalized DN")]
        original_dn_line: Annotated[
            str | None,
            Field(
                description="Original DN line from LDIF (with folding if present)",
            ),
        ] = None
        original_attr_lines: Annotated[
            MutableSequence[str] | None,
            Field(description="Original attribute lines from LDIF"),
        ] = None
        dn_was_base64: Annotated[
            bool,
            Field(description="Whether DN was base64 encoded"),
        ] = False
        original_attribute_case: Annotated[
            t.MutableStrMapping | None,
            Field(
                description="Mapping of attribute names to original case",
            ),
        ] = None

    class EntryTransformConfig(FlextModels.Value):
        """Configuration for batch entry transformation operations."""

        normalize_dns: Annotated[
            bool,
            Field(description="Normalize DNs per RFC 4514"),
        ] = False
        normalize_attrs: Annotated[
            bool,
            Field(description="Normalize attribute names"),
        ] = False
        attr_case: Annotated[
            str,
            Field(description="Attribute name case: 'lower', 'upper', or 'original'"),
        ] = "lower"
        convert_booleans: Annotated[
            tuple[str, str] | None,
            Field(
                description="Boolean conversion as (source_format, target_format), e.g. ('0/1', 'TRUE/FALSE')",
            ),
        ] = None
        remove_attrs: Annotated[
            MutableSequence[str] | None,
            Field(description="Attributes to remove from entries"),
        ] = None
        fail_fast: Annotated[
            bool,
            Field(description="Stop on first transform error"),
        ] = False

    class CategoryRules(FlextModels.Rules):
        """Rules for entry categorization.

        Contains DN patterns and objectClass lists for each category.
        Replaces dict[str, t.NormalizedValue] with type-safe Pydantic model.
        """

        user_dn_patterns: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="DN patterns for user entries (e.g., '*,ou=users,*')",
            ),
        ]
        group_dn_patterns: Annotated[
            MutableSequence[str],
            Field(default_factory=list, description="DN patterns for group entries"),
        ]
        hierarchy_dn_patterns: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="DN patterns for organizational hierarchy",
            ),
        ]
        schema_dn_patterns: Annotated[
            MutableSequence[str],
            Field(default_factory=list, description="DN patterns for schema entries"),
        ]
        user_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="ObjectClasses identifying user entries",
            ),
        ]
        group_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="ObjectClasses identifying group entries",
            ),
        ]
        hierarchy_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="ObjectClasses identifying organizational units",
            ),
        ]
        acl_attributes: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="Attribute names containing ACL information",
            ),
        ]

    class LogContextExtras(FlextModels.Value):
        """Extra context fields for structured event logging."""

        user_id: Annotated[str | None, Field(description="User identifier")] = None
        session_id: Annotated[
            str | None,
            Field(description="Session identifier"),
        ] = None
        request_id: Annotated[
            str | None,
            Field(description="Request identifier"),
        ] = None
        component: Annotated[
            str | None,
            Field(description="Component name"),
        ] = None
        correlation_id: Annotated[
            str | None,
            Field(description="Correlation identifier"),
        ] = None
        trace_id: Annotated[str | None, Field(description="Trace identifier")] = None

    class MigrateOptions(FlextModels.Value):
        """Options for FlextLdif.migrate() operation.

        Consolidates 12+ optional parameters into single typed Model.
        Reduces migrate() signature from 16 parameters to 5 parameters.

        Supports three migration modes:
        - Structured: 6-file output with full tracking (via migration_config)
        - Categorized: Custom multi-file output (via categorization_rules)
        - Simple: Single output file (default)

        Inherits from FlextModels.Value:
        - Immutable (frozen=True)
        - Validates assignment
        - Extra fields forbidden
        """

        migration_config: Annotated[
            t.MutableScalarMapping | None,
            Field(
                description="Structured migration config with 6-file output and tracking",
            ),
        ] = None
        categorization_rules: FlextLdifModelsSettings.CategoryRules | None = Field(
            default=None,
            description="Entry categorization rules (enables categorized mode)",
        )
        input_files: Annotated[
            MutableSequence[str] | None,
            Field(
                description="Ordered list of LDIF files to process (categorized mode)",
            ),
        ] = None
        output_files: Annotated[
            MutableMapping[c.Ldif.Categories, str] | None,
            Field(
                description="Category to filename mapping (categorized mode)",
            ),
        ] = None
        schema_whitelist_rules: FlextLdifModelsSettings.WhitelistRules | None = Field(
            default=None,
            description="Allowed schema elements whitelist (categorized mode)",
        )
        input_filename: Annotated[
            str | None,
            Field(
                description="Specific input file to process (simple mode only)",
            ),
        ] = None
        output_filename: Annotated[
            str | None,
            Field(
                description="Output filename (simple mode, defaults to 'migrated.ldif')",
            ),
        ] = None
        forbidden_attributes: Annotated[
            MutableSequence[str] | None,
            Field(description="Attributes to remove from entries"),
        ] = None
        forbidden_objectclasses: Annotated[
            MutableSequence[str] | None,
            Field(description="ObjectClasses to remove from entries"),
        ] = None
        base_dn: Annotated[
            str | None,
            Field(
                description="Base DN filter (only process entries under this DN)",
            ),
        ] = None
        sort_entries_hierarchically: Annotated[
            bool,
            Field(
                description="Sort entries by DN hierarchy depth then alphabetically",
            ),
        ] = False

    class WhitelistRules(FlextModels.Rules):
        """Whitelist rules for entry validation.

        Defines blocked objectClasses and validation rules.
        Replaces dict[str, t.NormalizedValue] with type-safe Pydantic model.
        """

        blocked_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                description="ObjectClasses that should be blocked/rejected",
            ),
        ]
        allowed_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                description="ObjectClasses that are explicitly allowed",
            ),
        ]
        required_attributes: Annotated[
            MutableSequence[str],
            Field(description="Attributes that must be present"),
        ]
        blocked_attributes: Annotated[
            MutableSequence[str],
            Field(
                description="Attributes that should be blocked",
            ),
        ]
        allowed_attribute_oids: Annotated[
            MutableSequence[str],
            Field(
                description="OID patterns for allowed schema attributes",
            ),
        ]
        allowed_objectclass_oids: Annotated[
            MutableSequence[str],
            Field(
                description="OID patterns for allowed objectClasses",
            ),
        ]
        allowed_matchingrule_oids: Annotated[
            MutableSequence[str],
            Field(
                description="OID patterns for allowed matchingRules",
            ),
        ]
        allowed_matchingruleuse_oids: Annotated[
            MutableSequence[str],
            Field(
                description="OID patterns for allowed matchingRuleUse definitions",
            ),
        ]
        allowed_ldapsyntax_oids: Annotated[
            MutableSequence[str],
            Field(
                description="OID patterns for allowed ldapSyntaxes definitions",
            ),
        ]

    class WriteFormatOptions(FlextModels.Value):
        """Formatting options for LDIF serialization.

        .. deprecated:: 0.9.0
            Use FlextLdifSettings fields (ldif_write_*) instead.
            This class will be removed in version 1.0.0.

        **Migration Guide**:
            Replace WriteFormatOptions with FlextLdifSettings:

            .. code-block:: python

                options = WriteFormatOptions(line_width=80, fold_long_lines=True)
                result = ldif.write(entries, options=options)

                # NEW (correct):
                from flext_ldif import FlextLdifSettings

                config = FlextSettings.get_global().get_namespace(
                    "ldif", FlextLdifSettings
                )
                # Override if needed: config.ldif_write_fold_long_lines = True
                result = ldif.write(entries)  # Uses config.ldif_write_* fields

        **Mapping Table**:
            - line_width → config.ldif_max_line_length
            - fold_long_lines → config.ldif_write_fold_long_lines
            - respect_attribute_order → config.ldif_write_respect_attribute_order
            - sort_attributes → config.ldif_write_sort_attributes
            - (see FlextLdifSettings for complete list of ldif_write_* fields)

        Provides detailed control over the output format, including line width
        for folding, and whether to respect attribute ordering from metadata.
        """

        line_width: Annotated[
            int,
            Field(
                ge=10,
                le=100000,
                description="Maximum line width before folding (RFC 2849 recommends 76). Only used if fold_long_lines=True.",
            ),
        ] = c.Ldif.DEFAULT_LINE_WIDTH
        respect_attribute_order: Annotated[
            bool,
            Field(
                description="If True, writes attributes in the order specified in Entry.metadata.",
            ),
        ] = True
        sort_attributes: Annotated[
            bool,
            Field(
                description="If True, sorts attributes alphabetically. Overridden by respect_attribute_order.",
            ),
        ] = False
        write_hidden_attributes_as_comments: Annotated[
            bool,
            Field(
                description="If True, attributes marked as 'hidden' in metadata will be written as comments.",
            ),
        ] = False
        write_metadata_as_comments: Annotated[
            bool,
            Field(
                description="If True, the entry's main metadata will be written as a commented block.",
            ),
        ] = False
        include_version_header: Annotated[
            bool,
            Field(
                description="If True, includes the LDIF version header in output.",
            ),
        ] = True
        include_timestamps: Annotated[
            bool,
            Field(
                description="If True, includes timestamp comments for when entries were written.",
            ),
        ] = False
        base64_encode_binary: Annotated[
            bool,
            Field(
                description="If True, automatically base64 encodes binary attribute values.",
            ),
        ] = False
        fold_long_lines: Annotated[
            bool,
            Field(
                description="If True, folds lines longer than line_width according to RFC 2849.",
            ),
        ] = True
        restore_original_format: Annotated[
            bool,
            Field(
                description="If True, restores original LDIF format from metadata for perfect round-trip. When enabled, uses entry.metadata.original_strings['entry_original_ldif'] to write the exact original format, preserving all minimal differences (spacing, case, punctuation, quotes, etc.). CRITICAL for zero data loss.",
            ),
        ] = False
        write_empty_values: Annotated[
            bool,
            Field(
                description="If True, writes attributes with empty values. If False, omits them.",
            ),
        ] = True
        normalize_attribute_names: Annotated[
            bool,
            Field(
                description="If True, normalizes attribute names to lowercase.",
            ),
        ] = False
        include_dn_comments: Annotated[
            bool,
            Field(
                description="If True, includes DN explanation comments for complex entries.",
            ),
        ] = False
        write_removed_attributes_as_comments: Annotated[
            bool,
            Field(
                description="If True, writes removed attributes as comments in LDIF output.",
            ),
        ] = False
        write_migration_header: Annotated[
            bool,
            Field(
                description="If True, writes migration metadata header at the start of LDIF file.",
            ),
        ] = False
        migration_header_template: Annotated[
            str | None,
            Field(
                description="Jinja2 template string for migration header. If None, uses default template.",
            ),
        ] = None
        write_rejection_reasons: Annotated[
            bool,
            Field(
                description="If True, writes rejection reasons as comments for rejected entries.",
            ),
        ] = False
        include_removal_statistics: Annotated[
            bool,
            Field(
                description="If True, includes statistics about removed attributes in headers.",
            ),
        ] = False
        ldif_changetype: Annotated[
            str | None,
            Field(
                description="If set to 'modify', writes entries in LDIF modify format (changetype: modify). Otherwise uses add format.",
            ),
        ] = None
        ldif_modify_operation: Annotated[
            str,
            Field(
                description="LDIF modify operation: 'add' or 'replace'. Used when ldif_changetype='modify'. Default 'add' for schema/ACL phases.",
            ),
        ] = "add"
        write_original_entry_as_comment: Annotated[
            bool,
            Field(
                description="If True, writes original source entry as commented LDIF block before converted entry.",
            ),
        ] = False
        entry_category: Annotated[
            str | None,
            Field(
                description="Migration category (e.g., 'hierarchy', 'users', 'groups', 'acl'). Used for phase-specific formatting.",
            ),
        ] = None
        acl_attribute_names: Annotated[
            frozenset[str],
            Field(
                description="Set of ACL attribute names (e.g., {'orclaci', 'orclentrylevelaci'}). Used to identify ACL attributes.",
            ),
        ] = Field(default_factory=frozenset)
        comment_acl_in_non_acl_phases: Annotated[
            bool,
            Field(
                description="If True, ACL attributes are written as comments when entry_category != 'acl'.",
            ),
        ] = True
        use_rfc_attribute_order: Annotated[
            bool,
            Field(
                description="If True, writes attributes in RFC 2849 order: objectClass first after DN, then remaining attributes alphabetically. DN is always first (handled automatically by writer).",
            ),
        ] = False
        rfc_order_priority_attributes: Annotated[
            MutableSequence[str],
            Field(
                description="Attributes to write first after DN, in order. Default: ['objectClass']. Remaining attributes sorted alphabetically.",
            ),
        ] = Field(default_factory=lambda: ["objectClass"])
        sort_objectclass_values: Annotated[
            bool,
            Field(
                description="If True, sorts objectClass values with 'top' first, followed by other objectClasses in alphabetical order. This ensures proper objectClass hierarchy ordering in LDIF output.",
            ),
        ] = False
        write_transformation_comments: Annotated[
            bool,
            Field(
                description="If True, writes transformation comments with tags before modified attributes. Tags: [REMOVED], [RENAMED], [TRANSFORMED]. Example: '# [REMOVED] oldattr: value' or '# [RENAMED] old -> new: value'.",
            ),
        ] = False
        use_original_acl_format_as_name: Annotated[
            bool,
            Field(
                description="If True and entry_category='acl', uses the original ACL format from metadata (ACL_ORIGINAL_FORMAT) as the ACI name instead of generated name. Control characters are sanitized (ASCII < 0x20 or > 0x7E replaced with spaces, double quotes removed). Useful for OID→OUD migration to preserve original ACL context as the new ACI name.",
            ),
        ] = False
        include_entry_markers: Annotated[
            bool,
            Field(
                description="If True, includes entry type markers as comments before each entry. Markers indicate entry category (e.g., '# === USER ENTRY ===' or '# === GROUP ENTRY ==='). Useful for visual separation in large files.",
            ),
        ] = False
        entry_marker_template: Annotated[
            str | None,
            Field(
                description="Custom Jinja2 template for entry markers. Variables: entry_type, dn, entry_index. If None, uses default format '# === {entry_type} ==='.",
            ),
        ] = None
        include_statistics_summary: Annotated[
            bool,
            Field(
                description="If True, includes a statistics summary in the file header showing entry counts by category and other migration metadata.",
            ),
        ] = False
        statistics_categories: Annotated[
            t.MutableIntMapping,
            Field(
                description="Dictionary of category names to entry counts for statistics summary. Example: {'users': 150, 'groups': 25, 'acl': 42}.",
            ),
        ] = Field(default_factory=dict)

    class WriteOutputOptions(FlextModels.ArbitraryTypesModel):
        """Output visibility options for attributes based on their marker status.

        This class controls how attributes are rendered in LDIF output based on
        their status in entry metadata. It works in conjunction with
        AttributeMarkerStatus to implement proper SRP architecture:

        **SRP Architecture**:
            - filters.py: MARKS attributes with AttributeMarkerStatus (never removes)
            - entry.py: REMOVES attributes based on markers
            - writer.py: Uses WriteOutputOptions to determine output visibility

        **Output Modes**:
            - "show": Write attribute normally
            - "hide": Don't write attribute at all
            - "comment": Write attribute as a comment (# attr: value)

        Example:
            .. code-block:: python

                options = WriteOutputOptions(
                    show_operational_attributes="hide",
                    show_removed_attributes="comment",
                    show_filtered_attributes="hide",
                )
                result = ldif.write(entries, output_options=options)

        """

        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
        show_operational_attributes: Annotated[
            str,
            Field(
                description="How to handle operational attributes in output. Options: 'show' (write normally), 'hide' (don't write), 'comment' (write as LDIF comment)."
            ),
        ] = "hide"
        show_removed_attributes: Annotated[
            str,
            Field(
                description="How to handle removed attributes in output. Default 'comment' writes removed attrs as '# [REMOVED] attr: value'."
            ),
        ] = "comment"
        show_filtered_attributes: Annotated[
            str,
            Field(
                description="How to handle filtered attributes in output. Default 'hide' completely omits filtered attributes."
            ),
        ] = "hide"
        show_hidden_attributes: Annotated[
            str,
            Field(
                description="How to handle explicitly hidden attributes in output. Default 'hide' completely omits hidden attributes."
            ),
        ] = "hide"
        show_renamed_original: Annotated[
            str,
            Field(
                description="How to handle original names of renamed attributes. Default 'comment' writes '# [RENAMED] old -> new: value'."
            ),
        ] = "comment"

    class EntryWriteConfig(FlextModels.Value):
        """Configuration for entry writing.

        Consolidates parameters for Entry.write method.
        Reduces function signature from 7 parameters to 1 model.

        """

        entry: FlextLdifModelsDomains.Entry = Field(
            ..., description="Entry model to write"
        )
        server_type: Annotated[str, Field(..., description="Server type identifier")]
        write_attributes_hook: Callable[
            [FlextLdifModelsDomains.Entry, MutableSequence[str]], None
        ] = Field(
            ...,
            description="Core attributes writing",
        )
        write_comments_hook: (
            Callable[[FlextLdifModelsDomains.Entry, MutableSequence[str]], None] | None
        ) = Field(
            default=None,
            description="Optional comments writing",
        )
        transform_entry_hook: (
            Callable[[FlextLdifModelsDomains.Entry], FlextLdifModelsDomains.Entry]
            | None
        ) = Field(
            default=None,
            description="Optional entry transformation",
        )
        write_dn_hook: Callable[[str, MutableSequence[str]], None] | None = Field(
            default=None,
            description="Optional DN writing",
        )
        include_comments: bool = Field(
            default=True,
            description="Include metadata comments",
        )

    class BatchWriteConfig(FlextModels.Value):
        """Configuration for batch entry writing.

        Consolidates parameters for Batch.write method.
        Reduces function signature from 6 parameters to 1 model.

        """

        entries: MutableSequence[FlextLdifModelsDomains.Entry] = Field(
            ...,
            description="List of entries to write",
        )
        server_type: Annotated[str, Field(..., description="Server type identifier")]
        write_entry_hook: Callable[[FlextLdifModelsDomains.Entry], r[str]] = Field(
            ...,
            description="Entry writing logic",
        )
        write_header_hook: Annotated[
            Callable[[], str] | None,
            Field(description="Optional header writing"),
        ] = None
        include_header: Annotated[
            bool,
            Field(description="Include LDIF header"),
        ] = True
        entry_separator: Annotated[
            str,
            Field(description="Separator between entries"),
        ] = "\n"

    class SortConfig(FlextModels.Value):
        """Configuration for entry sorting.

        Consolidates parameters for FlextLdifSorting.sort method.
        Reduces function signature from 9 parameters to 1 model.

        """

        entries: MutableSequence[FlextLdifModelsDomains.Entry] = Field(
            ...,
            description="List of entries to sort",
        )
        target: str = Field(
            default="entries", description="Sort target (entries, attributes, acl)"
        )
        by: str = Field(default="hierarchy", description="Sort strategy")
        traversal: str = Field(default="depth-first", description="Traversal order")
        predicate: Callable[[FlextLdifModelsDomains.Entry], str | t.Numeric] | None = (
            Field(
                default=None,
                description="Custom predicate function",
            )
        )
        sort_attributes: bool = Field(
            default=False, description="Sort attributes within entries"
        )
        attribute_order: MutableSequence[str] | None = Field(
            default=None, description="Custom attribute order"
        )
        sort_acl: bool = Field(default=False, description="Sort ACL attributes")
        acl_attributes: MutableSequence[str] | None = Field(
            default=None, description="ACL attributes to sort"
        )

    class RdnProcessingConfig(FlextModels.ArbitraryTypesModel):
        """Mutable state for RDN character-by-character parsing."""

        current_attr: Annotated[str, Field(description="Current attribute name")] = ""
        current_val: Annotated[str, Field(description="Current value")] = ""
        in_value: Annotated[
            bool,
            Field(description="Whether parser is inside the value portion"),
        ] = False
        pairs: Annotated[
            MutableSequence[tuple[str, str]],
            Field(description="Accumulated (attr, value) pairs"),
        ] = Field(default_factory=lambda: list[tuple[str, str]]())

    class SchemaAttributeConversionPipelineConfig(FlextModels.Value):
        """Config for schema attribute conversion pipeline (discriminated union)."""

        source_schema: Annotated[
            p.Ldif.SchemaQuirk,
            Field(..., description="Source schema quirk"),
        ]
        target_schema: Annotated[
            p.Ldif.SchemaQuirk,
            Field(..., description="Target schema quirk"),
        ]
        item_type: Annotated[
            Literal["attribute"],
            Field(description="Discriminator"),
        ] = "attribute"
        item: FlextLdifModelsDomains.SchemaAttribute = Field(
            ...,
            description="Schema attribute to convert",
        )
        item_name: Annotated[
            str,
            Field(description="Item name for errors"),
        ] = "attribute"

    class SchemaObjectClassConversionPipelineConfig(FlextModels.Value):
        """Config for schema objectclass conversion pipeline (discriminated union)."""

        source_schema: Annotated[
            p.Ldif.SchemaQuirk,
            Field(..., description="Source schema quirk"),
        ]
        target_schema: Annotated[
            p.Ldif.SchemaQuirk,
            Field(..., description="Target schema quirk"),
        ]
        item_type: Annotated[
            Literal["objectclass"],
            Field(description="Discriminator"),
        ] = "objectclass"
        item: FlextLdifModelsDomains.SchemaObjectClass = Field(
            ...,
            description="Schema objectclass to convert",
        )
        item_name: Annotated[
            str,
            Field(description="Item name for errors"),
        ] = "objectclass"

    class PermissionMappingConfig(FlextModels.Value):
        """Configuration for permission mapping during ACL conversion.

        Consolidates parameters for
        FlextLdifConversion._apply_permission_mapping method.
        Reduces function signature from 6 parameters to 1 model.

        """

        original_acl: FlextLdifModelsDomains.Acl = Field(
            ...,
            description="Original ACL model",
        )
        converted_acl: FlextLdifModelsDomains.Acl = Field(
            ...,
            description="Converted ACL model (modified in-place)",
        )
        orig_perms_dict: Annotated[
            t.MutableBoolMapping,
            Field(..., description="Original permissions dict"),
        ]
        source_server_type: Annotated[
            str | None,
            Field(description="Source server type"),
        ] = None
        target_server_type: Annotated[
            str | None,
            Field(description="Target server type"),
        ] = None
        converted_has_permissions: Annotated[
            bool,
            Field(description="Whether converted ACL has permissions"),
        ] = False

    class ServerValidationRules(FlextModels.Value):
        """Server-specific validation rules for LDIF entries."""

        requires_binary_option: Annotated[
            bool,
            Field(
                description="Whether server requires ;binary option for non-ASCII values"
            ),
        ] = False
        requires_naming_attr: Annotated[
            bool,
            Field(description="Whether server requires naming attribute in entry"),
        ] = False
        requires_objectclass: Annotated[
            bool,
            Field(description="Whether server requires objectClass attribute"),
        ] = True
