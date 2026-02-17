"""Configuration models for LDIF processing."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Literal

from flext_core import r
from flext_core._models.base import FlextModelsBase
from flext_core._models.collections import FlextModelsCollections
from flext_core._models.entity import FlextModelsEntity
from flext_core.typings import FlextTypes
from pydantic import ConfigDict, Field

from flext_ldif._models.base import FlextLdifModelsBase
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.shared import SchemaObjectClass
from flext_ldif.constants import c
from flext_ldif.protocols import FlextLdifProtocols


class DnNormalizationConfig(FlextModelsEntity.Value):
    """Configuration for DN normalization."""

    case_sensitive: bool = Field(default=False)
    remove_spaces: bool = Field(default=True)
    case_fold: str | None = Field(default=None)
    space_handling: str | None = Field(default=None)
    escape_handling: str | None = Field(default=None)
    validate_before: bool = Field(default=True)


class AttrNormalizationConfig(FlextModelsEntity.Value):
    """Configuration for attribute normalization."""

    lowercase_keys: bool = Field(default=True)
    sort_values: bool = Field(default=True)
    sort_attributes: str | None = Field(default=None)
    normalize_whitespace: bool = Field(default=True)
    case_fold_names: bool = Field(default=True)
    trim_values: bool = Field(default=True)
    remove_empty: bool = Field(default=False)


class AclConversionConfig(FlextModelsEntity.Value):
    """Configuration for ACL conversion operations."""

    convert_aci: bool = Field(default=True)
    preserve_original_aci: bool = Field(default=False)
    map_server_specific: bool = Field(default=True)


class ValidationConfig(FlextModelsEntity.Value):
    """Configuration for validation operations."""

    strict_mode: bool = Field(default=True)
    validate_schema: bool = Field(default=True)
    validate_acl: bool = Field(default=True)


class MetadataConfig(FlextModelsEntity.Value):
    """Configuration for metadata operations."""

    include_timestamps: bool = Field(default=True)
    include_processing_stats: bool = Field(default=True)
    preserve_validation: bool = Field(default=False)


class ProcessConfig(FlextModelsEntity.Value):
    """Configuration for processing operations."""

    batch_size: int = Field(default=100)
    timeout_seconds: int = Field(default=300)
    max_retries: int = Field(default=3)

    source_server: str | None = Field(default=None)
    target_server: str | None = Field(default=None)
    dn_config: DnNormalizationConfig | None = Field(default=None)
    attr_config: AttrNormalizationConfig | None = Field(default=None)
    acl_config: AclConversionConfig | None = Field(default=None)
    validation_config: ValidationConfig | None = Field(default=None)
    metadata_config: MetadataConfig | None = Field(default=None)


class TransformConfig(FlextModelsEntity.Value):
    """Configuration for transformation operations."""

    fail_fast: bool = Field(default=False)
    preserve_order: bool = Field(default=True)
    track_changes: bool = Field(default=False)
    normalize_dns: bool = Field(default=False)
    normalize_attrs: bool = Field(default=False)
    process_config: ProcessConfig | None = Field(default=None)


class FilterConfig(FlextModelsEntity.Value):
    """Configuration for filtering operations."""

    mode: str = Field(default="include")
    case_sensitive: bool = Field(default=False)
    include_metadata_matches: bool = Field(default=False)


class WriteConfig(FlextModelsEntity.Value):
    """Configuration for write operations."""

    output_format: str = Field(default="ldif")
    format: str = Field(default="ldif")
    line_width: int | None = Field(default=None)
    fold_lines: bool = Field(default=True)
    base64_attrs: list[str] | None = Field(default=None)
    sort_by: str | None = Field(default=None)
    attr_order: list[str] | None = Field(default=None)
    include_metadata: bool = Field(default=False)
    server: str | None = Field(default=None)


class FlextLdifModelsSettings:
    """LDIF configuration models container class."""

    class AclMetadataConfig(FlextModelsEntity.Value):
        """Configuration for ACL metadata extensions."""

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

    class AciParserConfig(FlextModelsEntity.Value):
        """Configuration for ACI parsing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            ...,
            description="Server type for metadata",
        )
        aci_prefix: str = Field(
            default="aci:",
            description="ACI attribute prefix",
        )
        version_acl_pattern: str = Field(
            ...,
            description="Regex pattern for version and ACL name extraction",
        )
        targetattr_pattern: str = Field(
            ...,
            description="Regex pattern for targetattr extraction",
        )
        allow_deny_pattern: str = Field(
            ...,
            description="Regex pattern for allow/deny permissions",
        )
        bind_patterns: dict[str, str] = Field(
            default_factory=dict,
            description="Mapping of bind type to regex pattern",
        )
        default_name: str = Field(
            default="ACL",
            description="Default ACL name if not found",
        )
        default_targetattr: str = Field(
            default="*",
            description="Default target attribute",
        )
        ops_separator: str = Field(
            default=",",
            description="Permissions separator",
        )
        action_filter: str = Field(
            default="allow",
            description="Action to filter (allow or deny)",
        )

        extra_patterns: dict[str, str] = Field(
            default_factory=dict,
            description="Extra regex patterns for server-specific fields",
        )

        permission_map: dict[str, str] = Field(
            default_factory=lambda: {
                "read": "read",
                "write": "write",
                "add": "add",
                "delete": "delete",
                "search": "search",
                "compare": "compare",
            },
            description="Mapping of permission name to normalized name",
        )

        special_subjects: dict[str, tuple[str, str]] = Field(
            default_factory=lambda: {
                "ldap:///self": ("self", "ldap:///self"),
                "ldap:///anyone": ("anonymous", "ldap:///anyone"),
            },
            description="Special subject DN to (type, value) mapping",
        )

    class AciWriterConfig(FlextModelsEntity.Value):
        """Configuration for ACI writing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        aci_prefix: str = Field(
            default="aci: ",
            description="Prefix for ACI line",
        )
        version: str = Field(
            default="3.0",
            description="ACI version",
        )
        allow_prefix: str = Field(
            default="allow (",
            description="Prefix for allow clause",
        )
        self_subject: str = Field(
            default="ldap:///self",
            description="Value for self subject",
        )
        anonymous_subject: str = Field(
            default="ldap:///anyone",
            description="Value for anonymous subject",
        )
        supported_permissions: frozenset[str] | None = Field(
            default=None,
            description="Optional set of supported permissions to filter",
        )
        attr_separator: str = Field(
            default=" || ",
            description="Separator for multiple attributes in targetattr",
        )
        bind_operators: dict[str, str] = Field(
            default_factory=lambda: {
                "user": "userdn",
                "group": "groupdn",
                "role": "roledn",
                "self": "userdn",
                "anonymous": "userdn",
            },
            description="Mapping of subject type to bind operator",
        )

    class AciLineFormatConfig(FlextModelsEntity.Value):
        """Configuration for formatting ACI line."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        name: str = Field(
            ...,
            description="ACL name",
        )
        target_clause: str = Field(
            ...,
            description="Target clause string",
        )
        permissions_clause: str = Field(
            ...,
            description="Permissions clause string",
        )
        bind_rule: str = Field(
            ...,
            description="Bind rule string",
        )
        version: str = Field(
            default="3.0",
            description="ACI version",
        )
        aci_prefix: str = Field(
            default="aci: ",
            description="Prefix for ACI line",
        )

    class ServerPatternsConfig(FlextModelsEntity.Value):
        """Configuration for server pattern matching."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        dn_patterns: tuple[tuple[str, ...], ...] = Field(
            default=(),
            description=(
                "Tuple of DN pattern tuples - entry matches if "
                "ALL patterns in ANY tuple match"
            ),
        )
        attr_prefixes: tuple[str, ...] | frozenset[str] = Field(
            default=(),
            description="Attribute name prefixes to check",
        )
        attr_names: frozenset[str] | set[str] = Field(
            default_factory=frozenset,
            description="Set of attribute names that indicate this server",
        )
        keyword_patterns: tuple[str, ...] = Field(
            default=(),
            description="Keywords to search in attribute names",
        )

    class AttributeDenormalizeConfig(FlextModelsEntity.Value):
        """Configuration for attribute denormalization."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        case_mappings: dict[str, str] | None = Field(
            default=None,
            description="Attribute case restoration {normalized: original}",
        )
        boolean_mappings: dict[str, str] | None = Field(
            default=None,
            description='Boolean value mappings {TRUE: "1", FALSE: "0"}',
        )
        attr_name_mappings: dict[str, str] | None = Field(
            default=None,
            description="Attribute name mappings {rfc_name: server_name}",
        )
        value_transformations: dict[str, dict[str, str]] | None = Field(
            default=None,
            description="Per-attribute value mappings",
        )

    class AttributeNormalizeConfig(FlextModelsEntity.Value):
        """Configuration for attribute normalization."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        case_mappings: dict[str, str] | None = Field(
            default=None,
            description="Attribute case normalization {original: normalized}",
        )
        boolean_mappings: dict[str, str] | None = Field(
            default=None,
            description='Boolean value mappings {"1": "TRUE", "0": "FALSE"}',
        )
        attr_name_mappings: dict[str, str] | None = Field(
            default=None,
            description="Attribute name mappings {server_name: rfc_name}",
        )
        strip_operational: bool = Field(
            default=False,
            description="Whether to remove operational attributes",
        )
        operational_attrs: set[str] | None = Field(
            default=None,
            description="Set of operational attribute names",
        )

    class EntryCriteriaConfig(FlextModelsEntity.Value):
        """Configuration for entry criteria matching."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        objectclasses: Sequence[str] | None = Field(
            default=None,
            description="Required objectClasses",
        )
        objectclass_mode: Literal["any", "all"] = Field(
            default="any",
            description='"any" (has any) or "all" (has all)',
        )
        required_attrs: Sequence[str] | None = Field(
            default=None,
            description="All of these attributes must exist",
        )
        any_attrs: Sequence[str] | None = Field(
            default=None,
            description="At least one of these attributes must exist",
        )
        dn_pattern: str | None = Field(
            default=None,
            description="Regex pattern that DN must match",
        )
        is_schema: bool | None = Field(
            default=None,
            description="If set, entry must (True) or must not (False) be schema",
        )

    class EntryTransformConfig(FlextModelsEntity.Value):
        """Configuration for entry transformation."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        normalize_dns: bool = Field(
            default=False,
            description="Normalize DN format",
        )
        normalize_attrs: bool = Field(
            default=False,
            description="Normalize attribute names to specified case",
        )
        attr_case: Literal["lower", "upper", "preserve"] = Field(
            default="lower",
            description="Case for attribute normalization",
        )
        convert_booleans: tuple[str, str] | None = Field(
            default=None,
            description=(
                "Tuple of (source_format, target_format) "
                'e.g., ("true/false", "TRUE/FALSE")'
            ),
        )
        remove_attrs: Sequence[str] | None = Field(
            default=None,
            description="List of attributes to remove",
        )
        fail_fast: bool = Field(
            default=False,
            description="Stop on first error",
        )

    class EntryFilterConfig(FlextModelsEntity.Value):
        """Configuration for entry filtering."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        objectclasses: Sequence[str] | None = Field(
            default=None,
            description="Filter by objectClass",
        )
        objectclass_mode: Literal["any", "all"] = Field(
            default="any",
            description='"any" or "all"',
        )
        required_attrs: Sequence[str] | None = Field(
            default=None,
            description="Only include entries with all these attrs",
        )
        dn_pattern: str | None = Field(
            default=None,
            description="Only include entries matching DN pattern",
        )
        is_schema: bool | None = Field(
            default=None,
            description="Only include schema (True) or non-schema (False) entries",
        )
        exclude_schema: bool = Field(
            default=False,
            description="Convenience flag to exclude schema entries",
        )

    class TransformationTrackingConfig(FlextModelsEntity.Value):
        """Configuration for transformation tracking."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        original_name: str = Field(
            ...,
            description="Original attribute name (PRESERVED EXACTLY as-is)",
        )
        target_name: str | None = Field(
            default=None,
            description="Target attribute name (None if removed)",
        )
        original_values: list[str] = Field(
            ...,
            description="Original attribute values (PRESERVED EXACTLY as-is)",
        )
        target_values: list[str] | None = Field(
            default=None,
            description="Converted values (None if removed)",
        )
        transformation_type: c.Ldif.LiteralTypes.TransformationTypeLiteral = Field(
            ...,
            description="Type: renamed/removed/modified/added/soft_deleted",
        )
        reason: str = Field(
            ...,
            description="Human-readable explanation",
        )

    class EntryParseMetadataConfig(FlextModelsEntity.Value):
        """Configuration for building entry parse metadata."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        quirk_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            ...,
            description="Server type performing the parse (oid, oud, rfc, etc.)",
        )
        original_entry_dn: str = Field(
            ...,
            description="Original DN as parsed from LDIF",
        )
        cleaned_dn: str = Field(
            ...,
            description="Cleaned/normalized DN",
        )
        original_dn_line: str | None = Field(
            default=None,
            description="Original DN line from LDIF (with folding if present)",
        )
        original_attr_lines: list[str] | None = Field(
            default=None,
            description="Original attribute lines from LDIF",
        )
        dn_was_base64: bool = Field(
            default=False,
            description="Whether DN was base64 encoded",
        )
        original_attribute_case: dict[str, str] | None = Field(
            default=None,
            description="Mapping of attribute names to original case",
        )

    class RdnProcessingConfig(FlextModelsCollections.Config):
        """Mutable configuration for RDN character processing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        current_attr: str = Field(
            default="",
            description="Current attribute name being parsed",
        )
        current_val: str = Field(
            default="",
            description="Current attribute value being parsed",
        )
        in_value: bool = Field(
            default=False,
            description="Whether currently parsing value (after '=')",
        )
        pairs: list[tuple[str, str]] = Field(
            default_factory=list,
            description="List of (attr, value) pairs parsed so far",
        )

    class MetadataTransformationConfig(FlextModelsEntity.Value):
        """Configuration for metadata transformation tracking."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        original_dn: str = Field(
            ...,
            description="Original DN before transformation",
        )
        transformed_dn: str = Field(
            ...,
            description="Transformed DN after transformation",
        )
        source_dn: str = Field(
            ...,
            description="Source base DN that was replaced",
        )
        target_dn: str = Field(
            ...,
            description="Target base DN replacement",
        )
        transformed_attr_names: list[str] = Field(
            default_factory=list,
            description="List of attribute names that were transformed",
        )
        original_attrs: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Original attributes before transformation",
        )
        transformed_attrs: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Transformed attributes after transformation",
        )

    class LogContextExtras(FlextModelsEntity.Value):
        """Additional context fields for logging events."""

        model_config = ConfigDict(
            extra="allow",
            validate_assignment=True,
        )

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
            description=(
                "Correlation ID for tracking related operations across services"
            ),
        )
        trace_id: str | None = Field(
            default=None,
            description="Trace ID for distributed tracing and debugging",
        )

    class CategoryRules(FlextModelsCollections.Rules):
        """Rules for entry categorization."""

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

    class MigrateOptions(FlextModelsEntity.Value):
        """Options for FlextLdif.migrate() operation."""

        migration_config: dict[str, str | int | bool] | None = Field(
            default=None,
            description="Structured migration config with 6-file output and tracking",
        )
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None = Field(
            default=None,
            description=(
                "Write format options (line folding, removed attrs as comments)"
            ),
        )

        categorization_rules: FlextLdifModelsSettings.CategoryRules | None = Field(
            default=None,
            description="Entry categorization rules (enables categorized mode)",
        )
        input_files: list[str] | None = Field(
            default=None,
            description="Ordered list of LDIF files to process (categorized mode)",
        )
        output_files: dict[c.Ldif.Categories, str] | None = Field(
            default=None,
            description="Category to filename mapping (categorized mode)",
        )
        schema_whitelist_rules: FlextLdifModelsSettings.WhitelistRules | None = Field(
            default=None,
            description="Allowed schema elements whitelist (categorized mode)",
        )

        input_filename: str | None = Field(
            default=None,
            description="Specific input file to process (simple mode only)",
        )
        output_filename: str | None = Field(
            default=None,
            description="Output filename (simple mode, defaults to 'migrated.ldif')",
        )

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

    class FilterCriteria(FlextModelsBase.ArbitraryTypesModel):
        """Criteria for filtering LDIF entries."""

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

    class WhitelistRules(FlextModelsCollections.Rules):
        """Whitelist rules for entry validation."""

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
        allowed_ldapsyntax_oids: list[str] = Field(
            default_factory=list,
            description="OID patterns for allowed ldapSyntaxes definitions",
        )

    class EncodingRules(FlextModelsEntity.Value):
        """Generic encoding rules - server classes provide values."""

        default_encoding: str
        allowed_encodings: list[c.Ldif.LiteralTypes.EncodingLiteral] = Field(
            default_factory=list,
        )

    class DnCaseRules(FlextModelsEntity.Value):
        """Generic DN case rules - server classes provide values."""

        preserve_case: bool
        normalize_to: str | None = Field(default=None)

    class AclFormatRules(FlextModelsEntity.Value):
        """Generic ACL format rules - server classes provide values."""

        format: str
        attribute_name: str
        requires_target: bool
        requires_subject: bool

    class ServerValidationRules(FlextModelsEntity.Value):
        """Generic server validation rules - server classes provide values."""

        requires_objectclass: bool
        requires_naming_attr: bool
        requires_binary_option: bool
        encoding_rules: FlextLdifModelsSettings.EncodingRules
        dn_case_rules: FlextLdifModelsSettings.DnCaseRules
        acl_format_rules: FlextLdifModelsSettings.AclFormatRules
        track_deletions: bool
        track_modifications: bool
        track_conversions: bool

    class WriteFormatOptions(FlextModelsBase.ArbitraryTypesModel):
        """Formatting options for LDIF serialization."""

        model_config = ConfigDict(frozen=True)

        line_width: int = Field(
            default=c.Ldif.LdifFormatting.DEFAULT_LINE_WIDTH,
            ge=10,
            le=100000,
            description=(
                "Maximum line width before folding (RFC 2849 recommends 76). "
                "Only used if fold_long_lines=True."
            ),
        )
        respect_attribute_order: bool = Field(
            default=True,
            description=(
                "If True, writes attributes in the order specified in Entry.metadata."
            ),
        )
        sort_attributes: bool = Field(
            default=False,
            description=(
                "If True, sorts attributes alphabetically. "
                "Overridden by respect_attribute_order."
            ),
        )
        write_hidden_attributes_as_comments: bool = Field(
            default=False,
            description=(
                "If True, attributes marked as 'hidden' in metadata will be "
                "written as comments."
            ),
        )
        write_metadata_as_comments: bool = Field(
            default=False,
            description=(
                "If True, the entry's main metadata will be written as a "
                "commented block."
            ),
        )
        include_version_header: bool = Field(
            default=True,
            description="If True, includes the LDIF version header in output.",
        )
        include_timestamps: bool = Field(
            default=False,
            description=(
                "If True, includes timestamp comments for when entries were written."
            ),
        )
        base64_encode_binary: bool = Field(
            default=False,
            description=(
                "If True, automatically base64 encodes binary attribute values."
            ),
        )
        fold_long_lines: bool = Field(
            default=True,
            description=(
                "If True, folds lines longer than line_width according to RFC 2849."
            ),
        )
        restore_original_format: bool = Field(
            default=False,
            description=(
                "If True, restores original LDIF format from metadata for "
                "perfect round-trip. When enabled, uses "
                "entry.metadata.original_strings['entry_original_ldif'] "
                "to write the exact original format, preserving all minimal "
                "differences (spacing, case, punctuation, quotes, etc.). "
                "CRITICAL for zero data loss."
            ),
        )
        write_empty_values: bool = Field(
            default=True,
            description=(
                "If True, writes attributes with empty values. If False, omits them."
            ),
        )
        normalize_attribute_names: bool = Field(
            default=False,
            description="If True, normalizes attribute names to lowercase.",
        )
        include_dn_comments: bool = Field(
            default=False,
            description=(
                "If True, includes DN explanation comments for complex entries."
            ),
        )
        write_removed_attributes_as_comments: bool = Field(
            default=False,
            description=(
                "If True, writes removed attributes as comments in LDIF output."
            ),
        )
        write_migration_header: bool = Field(
            default=False,
            description=(
                "If True, writes migration metadata header at the start of LDIF file."
            ),
        )
        migration_header_template: str | None = Field(
            default=None,
            description=(
                "Jinja2 template string for migration header. "
                "If None, uses default template."
            ),
        )
        write_rejection_reasons: bool = Field(
            default=False,
            description=(
                "If True, writes rejection reasons as comments for rejected entries."
            ),
        )
        include_removal_statistics: bool = Field(
            default=False,
            description=(
                "If True, includes statistics about removed attributes in headers."
            ),
        )
        ldif_changetype: str | None = Field(
            default=None,
            description=(
                "If set to 'modify', writes entries in LDIF modify format "
                "(changetype: modify). Otherwise uses add format."
            ),
        )
        ldif_modify_operation: str = Field(
            default="add",
            description=(
                "LDIF modify operation: 'add' or 'replace'. "
                "Used when ldif_changetype='modify'. "
                "Default 'add' for schema/ACL phases."
            ),
        )

        write_original_entry_as_comment: bool = Field(
            default=False,
            description=(
                "If True, writes original source entry as commented LDIF block "
                "before converted entry."
            ),
        )
        entry_category: str | None = Field(
            default=None,
            description=(
                "Migration category (e.g., 'hierarchy', 'users', 'groups', "
                "'acl'). Used for phase-specific formatting."
            ),
        )
        acl_attribute_names: frozenset[str] = Field(
            default_factory=frozenset,
            description=(
                "Set of ACL attribute names (e.g., {'orclaci', "
                "'orclentrylevelaci'}). Used to identify ACL attributes."
            ),
        )
        comment_acl_in_non_acl_phases: bool = Field(
            default=True,
            description=(
                "If True, ACL attributes are written as comments when "
                "entry_category != 'acl'."
            ),
        )
        use_rfc_attribute_order: bool = Field(
            default=False,
            description=(
                "If True, writes attributes in RFC 2849 order: "
                "objectClass first after DN, then remaining attributes alphabetically. "
                "DN is always first (handled automatically by writer)."
            ),
        )
        rfc_order_priority_attributes: list[str] = Field(
            default_factory=lambda: ["objectClass"],
            description=(
                "Attributes to write first after DN, in order. "
                "Default: ['objectClass']. Remaining attributes sorted alphabetically."
            ),
        )
        sort_objectclass_values: bool = Field(
            default=False,
            description=(
                "If True, sorts objectClass values with 'top' first, followed by "
                "other objectClasses in alphabetical order. This ensures proper "
                "objectClass hierarchy ordering in LDIF output."
            ),
        )
        write_transformation_comments: bool = Field(
            default=False,
            description=(
                "If True, writes transformation comments with tags before "
                "modified attributes. Tags: [REMOVED], [RENAMED], [TRANSFORMED]. "
                "Example: '# [REMOVED] oldattr: value' or "
                "'# [RENAMED] old -> new: value'."
            ),
        )
        use_original_acl_format_as_name: bool = Field(
            default=False,
            description=(
                "If True and entry_category='acl', uses the original ACL format "
                "from metadata (ACL_ORIGINAL_FORMAT) as the ACI name instead of "
                "generated name. "
                "Control characters are sanitized (ASCII < 0x20 or > 0x7E "
                "replaced with spaces, double quotes removed). "
                "Useful for OID→OUD migration to preserve "
                "original ACL context as the new ACI name."
            ),
        )
        include_entry_markers: bool = Field(
            default=False,
            description=(
                "If True, includes entry type markers as comments before each entry. "
                "Markers indicate entry category (e.g., '# === USER ENTRY ===' or "
                "'# === GROUP ENTRY ==='). Useful for visual separation in large files."
            ),
        )
        entry_marker_template: str | None = Field(
            default=None,
            description=(
                "Custom Jinja2 template for entry markers. Variables: entry_type, dn, "
                "entry_index. If None, uses default format '# === {entry_type} ==='."
            ),
        )
        include_statistics_summary: bool = Field(
            default=False,
            description=(
                "If True, includes a statistics summary in the file header showing "
                "entry counts by category and other migration metadata."
            ),
        )
        statistics_categories: dict[str, int] = Field(
            default_factory=dict,
            description=(
                "Dictionary of category names to entry counts for statistics summary. "
                "Example: {'users': 150, 'groups': 25, 'acl': 42}."
            ),
        )

    class WriteOutputOptions(FlextModelsBase.ArbitraryTypesModel):
        """Output visibility options for attributes based on their marker status."""

        model_config = ConfigDict(frozen=True)

        show_operational_attributes: str = Field(
            default="hide",
            description=(
                "How to handle operational attributes in output. "
                "Options: 'show' (write normally), 'hide' (don't write), "
                "'comment' (write as LDIF comment)."
            ),
        )
        show_removed_attributes: str = Field(
            default="comment",
            description=(
                "How to handle removed attributes in output. "
                "Default 'comment' writes removed attrs as '# [REMOVED] attr: value'."
            ),
        )
        show_filtered_attributes: str = Field(
            default="hide",
            description=(
                "How to handle filtered attributes in output. "
                "Default 'hide' completely omits filtered attributes."
            ),
        )
        show_hidden_attributes: str = Field(
            default="hide",
            description=(
                "How to handle explicitly hidden attributes in output. "
                "Default 'hide' completely omits hidden attributes."
            ),
        )
        show_renamed_original: str = Field(
            default="comment",
            description=(
                "How to handle original names of renamed attributes. "
                "Default 'comment' writes '# [RENAMED] old -> new: value'."
            ),
        )

    class MigrationConfig(FlextModelsEntity.Value):
        """Configuration for migration pipeline from YAML or dict."""

        model_config = ConfigDict(frozen=True)

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

        track_removed_attributes: bool = Field(
            default=True,
            description="If True, tracks removed attributes in entry metadata",
        )
        write_removed_as_comments: bool = Field(
            default=True,
            description="If True, writes removed attributes as comments in LDIF",
        )

        header_template: str | None = Field(
            default=None,
            description="Jinja2 template for file headers",
        )
        header_data: dict[str, str | int | bool] = Field(
            default_factory=dict,
            description="Data to pass to header template",
        )

    class ParseFormatOptions(FlextLdifModelsBase):
        """Formatting options for LDIF parsing (VIEW MODEL)."""

        model_config = ConfigDict(frozen=True)

        auto_parse_schema: bool = Field(
            default=True,
            description=(
                "If True, automatically parses schema definitions from entries."
            ),
        )
        auto_extract_acls: bool = Field(
            default=True,
            description="If True, automatically extracts ACLs from entry attributes.",
        )
        preserve_attribute_order: bool = Field(
            default=False,
            description=(
                "If True, preserves the original attribute order from the LDIF "
                "file in Entry.metadata."
            ),
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
            description=(
                "Maximum number of parsing errors to collect before stopping. "
                "0 means no limit."
            ),
        )
        include_operational_attrs: bool = Field(
            default=False,
            description=("If True, includes operational attributes in parsed entries."),
        )
        strict_schema_validation: bool = Field(
            default=False,
            description=(
                "If True, applies strict schema validation and fails on violations."
            ),
        )

    class MigrationPipelineParams(FlextModelsEntity.Value):
        """Typed parameters for migration pipeline factory."""

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
            default=c.Ldif.ServerTypes.RFC.value,
            description="Source LDAP server type (e.g., 'oid', 'oud', 'rfc')",
        )
        target_server: str = Field(
            default=c.Ldif.ServerTypes.RFC,
            description="Target LDAP server type (e.g., 'oid', 'oud', 'rfc')",
        )
        migration_config: FlextLdifModelsSettings.MigrationConfig | None = Field(
            default=None,
            description=(
                "Optional migration configuration for file organization and filtering"
            ),
        )
        enable_quirks_detection: bool = Field(
            default=True,
            description="If True, auto-detect server type from content",
        )
        enable_relaxed_parsing: bool = Field(
            default=False,
            description="If True, use lenient parsing for broken/non-compliant LDIF",
        )

    class ParserParams(FlextModelsEntity.Value):
        """Typed parameters for parser service factory."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        file_path: str = Field(
            description="Path to LDIF file to parse",
        )
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            default="rfc",
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

    class WriterParams(FlextModelsEntity.Value):
        """Typed parameters for writer service factory."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        output_path: str = Field(
            description="Path where LDIF file will be written",
        )
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            default="rfc",
            description="LDAP server type to use for writing quirks",
        )
        encoding: c.Ldif.LiteralTypes.EncodingLiteral = Field(
            default="utf-8",
            description="Character encoding for output file",
        )
        max_line_length: int = Field(
            default=c.Ldif.LdifFormatting.MAX_LINE_WIDTH,
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

    class ConfigInfo(FlextModelsEntity.Value):
        """Configuration information for logging and introspection."""

        model_config = ConfigDict(frozen=True)

        ldif_encoding: c.Ldif.LiteralTypes.EncodingLiteral = Field(
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
        quirks_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
            default=None,
            description="Configured server type for quirks (None if auto-detect)",
        )
        enable_relaxed_parsing: bool = Field(
            description="Whether relaxed parsing mode is enabled",
        )

    class LdifContentParseConfig(FlextModelsEntity.Value):
        """Configuration for LDIF content parsing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        ldif_content: str = Field(
            ...,
            description="Raw LDIF content string",
        )
        server_type: str = Field(
            ...,
            description="Server type identifier (e.g., 'rfc', 'oid')",
        )
        parse_entry_hook: Callable[[str, Mapping[str, list[str]]], r[object]] = Field(
            ...,
            description="Hook to parse (dn, attrs) into Entry",
        )
        transform_attrs_hook: (
            Callable[
                [str, Mapping[str, list[str]]],
                tuple[str, Mapping[str, list[str]]],
            ]
            | None
        ) = Field(
            default=None,
            description="Optional hook to transform attrs before parsing",
        )
        post_parse_hook: (
            Callable[[FlextModelsEntity.Entry], FlextModelsEntity.Entry] | None
        ) = Field(
            default=None,
            description="Optional hook to transform entry after parsing",
        )
        preserve_metadata_hook: (
            Callable[[FlextModelsEntity.Entry, str, str], None] | None
        ) = Field(
            default=None,
            description="Optional hook to preserve original LDIF",
        )
        skip_empty_entries: bool = Field(
            default=True,
            description="Skip entries with no attributes",
        )
        log_level: str = Field(
            default="debug",
            description="Logging verbosity ('debug', 'info', 'warning')",
        )
        ldif_parser: (
            Callable[[str], list[tuple[str, Mapping[str, list[str]]]]] | None
        ) = Field(
            default=None,
            description="Optional custom LDIF parser",
        )

    class EntryProcessingConfig(FlextModelsEntity.Value):
        """Configuration for entry processing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        parsed_entries: list[tuple[str, Mapping[str, list[str]]]] = Field(
            ...,
            description="List of (dn, attrs) tuples from parser",
        )
        parse_entry_hook: Callable[[str, Mapping[str, list[str]]], r[object]] = Field(
            ...,
            description="Hook to parse (dn, attrs) into Entry",
        )
        transform_attrs_hook: (
            Callable[
                [str, Mapping[str, list[str]]],
                tuple[str, Mapping[str, list[str]]],
            ]
            | None
        ) = Field(
            default=None,
            description="Optional hook to transform attrs before parsing",
        )
        post_parse_hook: (
            Callable[
                [FlextModelsEntity.Entry],
                FlextModelsEntity.Entry,
            ]
            | None
        ) = Field(
            default=None,
            description="Optional hook to transform entry after parsing",
        )
        preserve_metadata_hook: (
            Callable[[FlextModelsEntity.Entry, str, str], None] | None
        ) = Field(
            default=None,
            description="Optional hook to preserve original LDIF",
        )
        skip_empty_entries: bool = Field(
            default=True,
            description="Skip entries with no attributes",
        )

    class ObjectClassParseConfig(FlextModelsEntity.Value):
        """Configuration for objectClass definition parsing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        definition: str = Field(
            ...,
            description="Raw objectClass definition",
        )
        server_type: str = Field(
            ...,
            description="Server type identifier",
        )
        parse_core_hook: Callable[[str], r[object]] = Field(
            ...,
            description="Core parsing logic",
        )
        validate_structural_hook: Callable[[str, list[str]], bool] | None = Field(
            default=None,
            description="Optional structural validation",
        )
        transform_sup_hook: Callable[[list[str]], list[str]] | None = Field(
            default=None,
            description="Optional SUP transformation",
        )
        enrich_metadata_hook: Callable[[SchemaObjectClass], None] | None = Field(
            default=None,
            description="Optional metadata enrichment",
        )

    class EntryParseConfig(FlextModelsEntity.Value):
        """Configuration for entry parsing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        dn: str = Field(
            ...,
            description="Distinguished name",
        )
        attrs: Mapping[str, list[str]] = Field(
            ...,
            description="Entry attributes",
        )
        server_type: str = Field(
            ...,
            description="Server type identifier",
        )
        create_entry_hook: Callable[[str, Mapping[str, list[str]]], r[object]] = Field(
            ...,
            description="Entry creation logic",
        )
        build_metadata_hook: (
            Callable[
                [str, Mapping[str, list[str]]],
                FlextTypes.Metadata | None,
            ]
            | None
        ) = Field(
            default=None,
            description="Optional metadata building",
        )
        normalize_dn_hook: Callable[[str], str] | None = Field(
            default=None,
            description="Optional DN normalization",
        )
        transform_attrs_hook: (
            Callable[
                [str, Mapping[str, list[str]]],
                tuple[str, Mapping[str, list[str]]],
            ]
            | None
        ) = Field(
            default=None,
            description="Optional attribute transformation",
        )

    class EntryWriteConfig(FlextModelsEntity.Value):
        """Configuration for entry writing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        entry: FlextLdifModelsDomains.Entry = Field(
            ...,
            description="Entry model to write",
        )
        server_type: str = Field(
            ...,
            description="Server type identifier",
        )
        write_attributes_hook: Callable[[FlextModelsEntity.Entry, list[str]], None] = (
            Field(
                ...,
                description="Core attributes writing",
            )
        )
        write_comments_hook: (
            Callable[[FlextModelsEntity.Entry, list[str]], None] | None
        ) = Field(
            default=None,
            description="Optional comments writing",
        )
        transform_entry_hook: (
            Callable[
                [FlextLdifModelsDomains.Entry],
                FlextLdifModelsDomains.Entry,
            ]
            | None
        ) = Field(
            default=None,
            description="Optional entry transformation",
        )
        write_dn_hook: Callable[[str, list[str]], None] | None = Field(
            default=None,
            description="Optional DN writing",
        )
        include_comments: bool = Field(
            default=True,
            description="Include metadata comments",
        )

    class BatchWriteConfig(FlextModelsEntity.Value):
        """Configuration for batch entry writing."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        entries: list[FlextModelsEntity.Entry] = Field(
            ...,
            description="List of entries to write",
        )
        server_type: str = Field(
            ...,
            description="Server type identifier",
        )
        write_entry_hook: Callable[[FlextModelsEntity.Entry], r[str]] = Field(
            ...,
            description="Entry writing logic",
        )
        write_header_hook: Callable[[], str] | None = Field(
            default=None,
            description="Optional header writing",
        )
        include_header: bool = Field(
            default=True,
            description="Include LDIF header",
        )
        entry_separator: str = Field(
            default="\n",
            description="Separator between entries",
        )

    class SortConfig(FlextModelsEntity.Value):
        """Configuration for entry sorting."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        entries: list[object] = Field(
            ...,
            description="List of entries to sort",
        )
        target: str = Field(
            default="entries",
            description="Sort target (entries, attributes, acl)",
        )
        by: str = Field(
            default="hierarchy",
            description="Sort strategy",
        )
        traversal: str = Field(
            default="depth-first",
            description="Traversal order",
        )
        predicate: Callable[[object], str | int | float] | None = Field(
            default=None,
            description="Custom predicate function",
        )
        sort_attributes: bool = Field(
            default=False,
            description="Sort attributes within entries",
        )
        attribute_order: list[str] | None = Field(
            default=None,
            description="Custom attribute order",
        )
        sort_acl: bool = Field(
            default=False,
            description="Sort ACL attributes",
        )
        acl_attributes: list[str] | None = Field(
            default=None,
            description="ACL attributes to sort",
        )

    class SchemaConversionPipelineConfig(FlextModelsEntity.Value):
        """Configuration for schema conversion pipeline."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        source_schema: (
            FlextLdifProtocols.Ldif.SchemaAttributeProtocol
            | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
            | FlextLdifProtocols.Ldif.SchemaQuirkProtocol
        ) = Field(
            ...,
            description="Source schema quirk",
        )
        target_schema: (
            FlextLdifProtocols.Ldif.SchemaAttributeProtocol
            | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
            | FlextLdifProtocols.Ldif.SchemaQuirkProtocol
        ) = Field(
            ...,
            description="Target schema quirk",
        )
        write_method: Callable[..., r[str]] = Field(
            ...,
            description="Write method to call on source schema",
        )
        parse_method: Callable[..., r[object]] = Field(
            ...,
            description="Parse method to call on target schema",
        )
        item_name: str = Field(
            ...,
            description="Item name for error messages",
        )

    class PermissionMappingConfig(FlextModelsEntity.Value):
        """Configuration for permission mapping during ACL conversion."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        original_acl: FlextLdifModelsDomains.Acl = Field(
            ...,
            description="Original ACL model",
        )
        converted_acl: FlextLdifModelsDomains.Acl = Field(
            ...,
            description="Converted ACL model (modified in-place)",
        )
        orig_perms_dict: dict[str, bool] = Field(
            ...,
            description="Original permissions dict",
        )
        source_server_type: str | None = Field(
            default=None,
            description="Source server type",
        )
        target_server_type: str | None = Field(
            default=None,
            description="Target server type",
        )
        converted_has_permissions: bool = Field(
            default=False,
            description="Whether converted ACL has permissions",
        )
