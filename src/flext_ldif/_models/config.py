"""Configuration models for LDIF processing.

This module contains configuration models for LDIF processing operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextModels
from pydantic import ConfigDict, Field

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants


class FlextLdifModelsConfig:
    """LDIF configuration models container class.

    This class acts as a namespace container for LDIF configuration models.
    All nested classes are accessed via FlextLdifModels.* in the main models.py.
    """

    # Configuration classes will be added here

    class AclMetadataConfig(FlextModels.Value):
        """Configuration for ACL metadata extensions.

        Consolidates parameters for build_metadata_extensions utility function.
        Reduces function signature from 6 parameters to 1 model.

        Example:
            config = FlextLdifModels.AclMetadataConfig(
                line_breaks=[10, 20],
                dn_spaces=True,
                targetscope="subtree",
                version="3.0",
            )
            extensions = FlextLdifUtilities.ACL.build_metadata_extensions(config)

        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        line_breaks: list[int] | None = Field(
            default=None,
            description="List of line break positions in ACL",
        )
        dn_spaces: bool = Field(
            default=False,
            description="Whether DN contains spaces after commas",
        )
        targetscope: str | None = Field(
            default=None,
            description="Target scope value (subtree, base, one)",
        )
        version: str | None = Field(
            default=None,
            description="ACL version string",
        )
        default_version: str = Field(
            default="3.0",
            description="Default version to compare against",
        )
        action_type: str | None = Field(
            default="allow",
            description="ACL action type (allow or deny) - for OUD deny rules support",
        )

    class LogContextExtras(FlextModels.Value):
        """Additional context fields for logging events.

        Replaces **extra_context: object pattern with typed Model.
        Eliminates use of object and Any types in logging functions.

        Example:
            extras = FlextLdifModels.LogContextExtras(
                user_id="admin",
                session_id="abc123",
                request_id="req-456",
            )
            event = FlextLdifUtilities.Events.log_and_emit_dn_event(
                logger=logger,
                config=dn_config,
                extras=extras,
            )

        """

        model_config = ConfigDict(
            extra="allow",  # Allow arbitrary context fields
            validate_assignment=True,
        )

        # Common context fields (all optional)
        user_id: str | None = Field(
            default=None,
            description="User identifier for audit trail",
        )
        session_id: str | None = Field(
            default=None,
            description="Session identifier for correlation",
        )
        request_id: str | None = Field(
            default=None,
            description="Request identifier for tracing",
        )
        component: str | None = Field(
            default=None,
            description="Component name for context",
        )
        correlation_id: str | None = Field(
            default=None,
            description="Correlation ID for tracking related operations across services",
        )
        trace_id: str | None = Field(
            default=None,
            description="Trace ID for distributed tracing and debugging",
        )
        # Note: extra="allow" permits additional custom fields without declaring them

    class MigrateOptions(FlextModels.Value):
        """Options for FlextLdif.migrate() operation.

        Consolidates 12+ optional parameters into single typed Model.
        Reduces migrate() signature from 16 parameters to 5 parameters.

        Supports three migration modes:
        - Structured: 6-file output with full tracking (via migration_config)
        - Categorized: Custom multi-file output (via categorization_rules)
        - Simple: Single output file (default)

        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        # Structured migration (preferred for production)
        migration_config: dict[str, object] | None = Field(
            default=None,
            description="Structured migration config with 6-file output and tracking",
        )
        write_options: dict[str, object] | None = Field(
            default=None,
            description="Write format options (line folding, removed attrs as comments)",
        )

        # Categorized mode parameters (legacy)
        categorization_rules: dict[str, list[str]] | None = Field(
            default=None,
            description="Entry categorization rules (enables categorized mode)",
        )
        input_files: list[str] | None = Field(
            default=None,
            description="Ordered list of LDIF files to process (categorized mode)",
        )
        output_files: dict[str, str] | None = Field(
            default=None,
            description="Category to filename mapping (categorized mode)",
        )
        schema_whitelist_rules: dict[str, list[str]] | None = Field(
            default=None,
            description="Allowed schema elements whitelist (categorized mode)",
        )

        # Simple mode parameters
        input_filename: str | None = Field(
            default=None,
            description="Specific input file to process (simple mode only)",
        )
        output_filename: str | None = Field(
            default=None,
            description="Output filename (simple mode, defaults to 'migrated.ldif')",
        )

        # Common filtering parameters
        forbidden_attributes: list[str] | None = Field(
            default=None,
            description="Attributes to remove from entries",
        )
        forbidden_objectclasses: list[str] | None = Field(
            default=None,
            description="ObjectClasses to remove from entries",
        )
        base_dn: str | None = Field(
            default=None,
            description="Base DN filter (only process entries under this DN)",
        )
        sort_entries_hierarchically: bool = Field(
            default=False,
            description="Sort entries by DN hierarchy depth then alphabetically",
        )

    class FilterCriteria(FlextModels.ArbitraryTypesModel):
        """Criteria for filtering LDIF entries.

        Supports multiple filter types:
        - dn_pattern: Wildcard DN pattern matching (e.g., "*,dc=example,dc=com")
        - oid_pattern: OID pattern matching with wildcard support
        - objectclass: Filter by objectClass with optional attribute validation
        - attribute: Filter by attribute presence/absence

        Example:
            criteria = FilterCriteria(
                filter_type="dn_pattern",
                pattern="*,ou=users,dc=ctbc,dc=com",
                mode="include"
            )

        """

        filter_type: str = Field(
            ...,
            description="Type of filter (dn_pattern, oid_pattern, etc.)",
        )
        pattern: str | None = Field(
            default=None,
            description="Pattern for matching (fnmatch wildcards)",
        )
        whitelist: list[str] | None = Field(
            default=None,
            description="Whitelist of patterns to include",
        )
        blacklist: list[str] | None = Field(
            default=None,
            description="Blacklist of patterns to exclude",
        )
        required_attributes: list[str] | None = Field(
            default=None,
            description="Required attributes for objectClass",
        )
        mode: str = Field(
            default="include",
            description="Mode: 'include' keep, 'exclude' remove",
        )

    class CategoryRules(FlextModels.ArbitraryTypesModel):
        """Rules for entry categorization.

        Contains DN patterns and objectClass lists for each category.
        Replaces dict[str, Any] with type-safe Pydantic model.
        """

        user_dn_patterns: list[str] = Field(
            default_factory=list,
            description="DN patterns for user entries (e.g., '*,ou=users,*')",
        )
        group_dn_patterns: list[str] = Field(
            default_factory=list,
            description="DN patterns for group entries",
        )
        hierarchy_dn_patterns: list[str] = Field(
            default_factory=list,
            description="DN patterns for organizational hierarchy",
        )
        schema_dn_patterns: list[str] = Field(
            default_factory=list,
            description="DN patterns for schema entries",
        )
        user_objectclasses: list[str] = Field(
            default_factory=lambda: ["person", "inetOrgPerson", "orclUser"],
            description="ObjectClasses identifying user entries",
        )
        group_objectclasses: list[str] = Field(
            default_factory=lambda: ["groupOfUniqueNames", "groupOfNames", "orclGroup"],
            description="ObjectClasses identifying group entries",
        )
        hierarchy_objectclasses: list[str] = Field(
            default_factory=lambda: ["organizationalUnit", "organization"],
            description="ObjectClasses identifying organizational units",
        )
        acl_attributes: list[str] = Field(
            default_factory=lambda: ["orclaci", "orclentrylevelaci"],
            description="Attribute names containing ACL information",
        )

    class WhitelistRules(FlextModels.ArbitraryTypesModel):
        """Whitelist rules for entry validation.

        Defines blocked objectClasses and validation rules.
        Replaces dict[str, Any] with type-safe Pydantic model.
        """

        blocked_objectclasses: list[str] = Field(
            default_factory=list,
            description="ObjectClasses that should be blocked/rejected",
        )
        allowed_objectclasses: list[str] = Field(
            default_factory=list,
            description="ObjectClasses that are explicitly allowed",
        )
        required_attributes: list[str] = Field(
            default_factory=list,
            description="Attributes that must be present",
        )
        blocked_attributes: list[str] = Field(
            default_factory=list,
            description="Attributes that should be blocked",
        )
        allowed_attribute_oids: list[str] = Field(
            default_factory=list,
            description="OID patterns for allowed schema attributes",
        )
        allowed_objectclass_oids: list[str] = Field(
            default_factory=list,
            description="OID patterns for allowed objectClasses",
        )
        allowed_matchingrule_oids: list[str] = Field(
            default_factory=list,
            description="OID patterns for allowed matchingRules",
        )
        allowed_matchingruleuse_oids: list[str] = Field(
            default_factory=list,
            description="OID patterns for allowed matchingRuleUse definitions",
        )

    class WriteFormatOptions(FlextModels.Value):
        """Formatting options for LDIF serialization.

        Provides detailed control over the output format, including line width
        for folding, and whether to respect attribute ordering from metadata.
        """

        model_config = ConfigDict(frozen=True)

        line_width: int = Field(
            default=FlextLdifConstants.LdifFormatting.DEFAULT_LINE_WIDTH,
            ge=10,
            le=100000,
            description="Maximum line width before folding (RFC 2849 recommends 76). Only used if fold_long_lines=True.",
        )
        respect_attribute_order: bool = Field(
            default=True,
            description="If True, writes attributes in the order specified in Entry.metadata.",
        )
        sort_attributes: bool = Field(
            default=False,
            description="If True, sorts attributes alphabetically. Overridden by respect_attribute_order.",
        )
        write_hidden_attributes_as_comments: bool = Field(
            default=False,
            description="If True, attributes marked as 'hidden' in metadata will be written as comments.",
        )
        write_metadata_as_comments: bool = Field(
            default=False,
            description="If True, the entry's main metadata will be written as a commented block.",
        )
        include_version_header: bool = Field(
            default=True,
            description="If True, includes the LDIF version header in output.",
        )
        include_timestamps: bool = Field(
            default=False,
            description="If True, includes timestamp comments for when entries were written.",
        )
        base64_encode_binary: bool = Field(
            default=False,
            description="If True, automatically base64 encodes binary attribute values.",
        )
        fold_long_lines: bool = Field(
            default=True,
            description="If True, folds lines longer than line_width according to RFC 2849.",
        )
        write_empty_values: bool = Field(
            default=True,
            description="If True, writes attributes with empty values. If False, omits them.",
        )
        normalize_attribute_names: bool = Field(
            default=False,
            description="If True, normalizes attribute names to lowercase.",
        )
        include_dn_comments: bool = Field(
            default=False,
            description="If True, includes DN explanation comments for complex entries.",
        )
        write_removed_attributes_as_comments: bool = Field(
            default=False,
            description="If True, writes removed attributes as comments in LDIF output.",
        )
        write_migration_header: bool = Field(
            default=False,
            description="If True, writes migration metadata header at the start of LDIF file.",
        )
        migration_header_template: str | None = Field(
            default=None,
            description="Jinja2 template string for migration header. If None, uses default template.",
        )
        write_rejection_reasons: bool = Field(
            default=False,
            description="If True, writes rejection reasons as comments for rejected entries.",
        )
        write_transformation_comments: bool = Field(
            default=False,
            description="If True, writes transformation details as comments (e.g., objectClass changes).",
        )
        include_removal_statistics: bool = Field(
            default=False,
            description="If True, includes statistics about removed attributes in headers.",
        )
        ldif_changetype: str | None = Field(
            default=None,
            description="If set to 'modify', writes entries in LDIF modify add format (changetype: modify). Otherwise uses add format.",
        )
        # NEW FIELDS FOR ALGAR OUD MIGRATION - Phase-aware ACL handling and original entry commenting
        write_original_entry_as_comment: bool = Field(
            default=False,
            description="If True, writes original source entry as commented LDIF block before converted entry.",
        )
        entry_category: str | None = Field(
            default=None,
            description="Migration category (e.g., 'hierarchy', 'users', 'groups', 'acl'). Used for phase-specific formatting.",
        )
        acl_attribute_names: frozenset[str] = Field(
            default_factory=frozenset,
            description="Set of ACL attribute names (e.g., {'orclaci', 'orclentrylevelaci'}). Used to identify ACL attributes.",
        )
        comment_acl_in_non_acl_phases: bool = Field(
            default=True,
            description="If True, ACL attributes are written as comments when entry_category != 'acl'.",
        )

    class MigrationConfig(FlextModels.Value):
        """Configuration for migration pipeline from YAML or dict.

        Supports structured 6-file output (00-06) with flexible categorization,
        filtering, and removed attribute tracking.
        """

        model_config = ConfigDict(frozen=True)

        # File organization (00-06)
        output_file_mapping: dict[str, str] = Field(
            default_factory=lambda: {
                "schema": "00-schema.ldif",
                "hierarchy": "01-hierarchy.ldif",
                "users": "02-users.ldif",
                "groups": "03-groups.ldif",
                "acl": "04-acl.ldif",
                "data": "05-data.ldif",
                "rejected": "06-rejected.ldif",
            },
            description="Mapping of category names to output filenames",
        )

        # Categorization rules (for 01, 02, 03, 05)
        hierarchy_objectclasses: list[str] = Field(
            default_factory=list,
            description="ObjectClasses for hierarchy entries (01-hierarchy.ldif)",
        )
        user_objectclasses: list[str] = Field(
            default_factory=list,
            description="ObjectClasses for user entries (02-users.ldif)",
        )
        group_objectclasses: list[str] = Field(
            default_factory=list,
            description="ObjectClasses for group entries (03-groups.ldif)",
        )

        # Filtering rules
        attribute_whitelist: list[str] | None = Field(
            default=None,
            description="If provided, only these attributes are kept",
        )
        attribute_blacklist: list[str] | None = Field(
            default=None,
            description="If provided, these attributes are removed",
        )
        objectclass_whitelist: list[str] | None = Field(
            default=None,
            description="If provided, only entries with these objectClasses are kept",
        )
        objectclass_blacklist: list[str] | None = Field(
            default=None,
            description="If provided, entries with these objectClasses are removed",
        )

        # Removed attributes tracking
        track_removed_attributes: bool = Field(
            default=True,
            description="If True, tracks removed attributes in entry metadata",
        )
        write_removed_as_comments: bool = Field(
            default=True,
            description="If True, writes removed attributes as comments in LDIF",
        )

        # Header template (Jinja2)
        header_template: str | None = Field(
            default=None,
            description="Jinja2 template for file headers",
        )
        header_data: dict[str, object] = Field(
            default_factory=dict,
            description="Data to pass to header template",
        )

    class ParseFormatOptions(FlextModels.Value):
        """Formatting options for LDIF parsing."""

        model_config = ConfigDict(frozen=True)

        auto_parse_schema: bool = Field(
            default=True,
            description="If True, automatically parses schema definitions from entries.",
        )
        auto_extract_acls: bool = Field(
            default=True,
            description="If True, automatically extracts ACLs from entry attributes.",
        )
        preserve_attribute_order: bool = Field(
            default=False,
            description="If True, preserves the original attribute order from the LDIF file in Entry.metadata.",
        )
        validate_entries: bool = Field(
            default=True,
            description="If True, validates entries against LDAP schema rules.",
        )
        normalize_dns: bool = Field(
            default=True,
            description="If True, normalizes DN formatting to RFC 2253 standard.",
        )
        max_parse_errors: int = Field(
            default=100,
            ge=0,
            le=10000,
            description="Maximum number of parsing errors to collect before stopping. 0 means no limit.",
        )
        include_operational_attrs: bool = Field(
            default=False,
            description="If True, includes operational attributes in parsed entries.",
        )
        strict_schema_validation: bool = Field(
            default=False,
            description="If True, applies strict schema validation and fails on violations.",
        )

    class MigrationPipelineParams(FlextModels.Value):
        """Typed parameters for migration pipeline factory.

        Replaces dict-based parameter passing with type-safe Pydantic model.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        input_dir: str = Field(
            default=".",
            description="Input directory containing LDIF files to migrate",
        )
        output_dir: str = Field(
            default=".",
            description="Output directory for migrated LDIF files",
        )
        source_server: str = Field(
            default=FlextLdifConstants.ServerTypes.RFC,
            description="Source LDAP server type (e.g., 'oid', 'oud', 'rfc')",
        )
        target_server: str = Field(
            default=FlextLdifConstants.ServerTypes.RFC,
            description="Target LDAP server type (e.g., 'oid', 'oud', 'rfc')",
        )
        migration_config: FlextLdifModelsConfig.MigrationConfig | None = Field(
            default=None,
            description="Optional migration configuration for file organization and filtering",
        )
        enable_quirks_detection: bool = Field(
            default=True,
            description="If True, auto-detect server type from content",
        )
        enable_relaxed_parsing: bool = Field(
            default=False,
            description="If True, use lenient parsing for broken/non-compliant LDIF",
        )

    class ParserParams(FlextModels.Value):
        """Typed parameters for parser service factory.

        Provides type-safe configuration for LDIF parsing operations.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        file_path: str = Field(
            description="Path to LDIF file to parse",
        )
        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.RFC,
            description="LDAP server type to use for parsing quirks",
        )
        enable_auto_detection: bool = Field(
            default=False,
            description="If True, auto-detect server type from file content",
        )
        enable_relaxed_parsing: bool = Field(
            default=False,
            description="If True, use lenient parsing mode",
        )
        parse_schema: bool = Field(
            default=True,
            description="If True, parses schema definitions from entries",
        )
        parse_acls: bool = Field(
            default=True,
            description="If True, extracts ACLs from entry attributes",
        )
        validate_entries: bool = Field(
            default=True,
            description="If True, validates entries against schema rules",
        )

    class WriterParams(FlextModels.Value):
        """Typed parameters for writer service factory.

        Provides type-safe configuration for LDIF writing operations.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        output_path: str = Field(
            description="Path where LDIF file will be written",
        )
        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.RFC,
            description="LDAP server type to use for writing quirks",
        )
        encoding: str = Field(
            default=FlextLdifConstants.Encoding.UTF8,
            description="Character encoding for output file",
        )
        max_line_length: int = Field(
            default=FlextLdifConstants.Format.MAX_LINE_LENGTH,
            description="Maximum line length for LDIF output",
            ge=50,
            le=1000,
        )
        include_operational_attrs: bool = Field(
            default=False,
            description="If True, includes operational attributes in output",
        )
        sort_attributes: bool = Field(
            default=False,
            description="If True, sorts attributes alphabetically",
        )
        strict_rfc_compliance: bool = Field(
            default=True,
            description="If True, enforces strict RFC 2849 compliance",
        )

    class ConfigInfo(FlextModels.Value):
        """Configuration information for logging and introspection.

        Structured representation of FlextLdifConfig for reporting and diagnostics.
        """

        model_config = ConfigDict(frozen=True)

        ldif_encoding: str = Field(
            description="LDIF encoding setting",
        )
        strict_rfc_compliance: bool = Field(
            description="Whether strict RFC compliance is enabled",
        )
        ldif_chunk_size: int = Field(
            description="Chunk size for LDIF processing",
        )
        max_workers: int = Field(
            description="Maximum number of worker processes",
        )
        debug: bool = Field(
            description="Whether debug mode is enabled",
        )
        log_level: str = Field(
            description="Logging level",
        )
        quirks_detection_mode: str = Field(
            description="Server quirks detection mode (auto/manual/disabled)",
        )
        quirks_server_type: str | None = Field(
            default=None,
            description="Configured server type for quirks (None if auto-detect)",
        )
        enable_relaxed_parsing: bool = Field(
            description="Whether relaxed parsing mode is enabled",
        )

        @classmethod
        def from_config(
            cls,
            config: FlextLdifConfig,
        ) -> FlextLdifModelsConfig.ConfigInfo:
            """Create ConfigInfo from FlextLdifConfig.

            Args:
                config: FlextLdifConfig instance

            Returns:
                ConfigInfo with values extracted from config

            """
            return cls(
                ldif_encoding=config.ldif_encoding,
                strict_rfc_compliance=config.strict_rfc_compliance,
                ldif_chunk_size=config.ldif_chunk_size,
                max_workers=config.max_workers,
                debug=config.debug,
                log_level=config.log_level,
                quirks_detection_mode=config.quirks_detection_mode,
                quirks_server_type=config.quirks_server_type,
                enable_relaxed_parsing=config.enable_relaxed_parsing,
            )
