"""Configuration models for LDIF processing."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Literal

from flext_core import r
from flext_core._models.base import FlextModelsBase
from flext_core._models.collections import FlextModelsCollections
from flext_core._models.entity import FlextModelsEntity
from pydantic import ConfigDict, Field

from flext_ldif._models.base import FlextLdifModelsBase
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.protocols import FlextLdifProtocols


class DnNormalizationConfig(FlextModelsEntity.Value):
    """Configuration for DN normalization."""

    case_sensitive: bool = False
    remove_spaces: bool = True
    case_fold: str | None = None
    space_handling: str | None = None
    escape_handling: str | None = None
    validate_before: bool = True


class AttrNormalizationConfig(FlextModelsEntity.Value):
    """Configuration for attribute normalization."""

    lowercase_keys: bool = True
    sort_values: bool = True
    sort_attributes: str | None = None
    normalize_whitespace: bool = True
    case_fold_names: bool = True
    trim_values: bool = True
    remove_empty: bool = False


class AclConversionConfig(FlextModelsEntity.Value):
    """Configuration for ACL conversion operations."""

    convert_aci: bool = True
    preserve_original_aci: bool = False
    map_server_specific: bool = True


class ValidationConfig(FlextModelsEntity.Value):
    """Configuration for validation operations."""

    strict_mode: bool = True
    validate_schema: bool = True
    validate_acl: bool = True


class MetadataConfig(FlextModelsEntity.Value):
    """Configuration for metadata operations."""

    include_timestamps: bool = True
    include_processing_stats: bool = True
    preserve_validation: bool = False


class ProcessConfig(FlextModelsEntity.Value):
    """Configuration for processing operations."""

    batch_size: int = 100
    timeout_seconds: int = 300
    max_retries: int = 3
    source_server: str | None = None
    target_server: str | None = None
    dn_config: DnNormalizationConfig | None = None
    attr_config: AttrNormalizationConfig | None = None
    acl_config: AclConversionConfig | None = None
    validation_config: ValidationConfig | None = None
    metadata_config: MetadataConfig | None = None


class TransformConfig(FlextModelsEntity.Value):
    """Configuration for transformation operations."""

    fail_fast: bool = False
    preserve_order: bool = True
    track_changes: bool = False
    normalize_dns: bool = False
    normalize_attrs: bool = False
    process_config: ProcessConfig | None = None


class FilterConfig(FlextModelsEntity.Value):
    """Configuration for filtering operations."""

    mode: str = "include"
    case_sensitive: bool = False
    include_metadata_matches: bool = False


class WriteConfig(FlextModelsEntity.Value):
    """Configuration for write operations."""

    output_format: str = "ldif"
    format: str = "ldif"
    line_width: int | None = None
    fold_lines: bool = True
    base64_attrs: list[str] | None = None
    sort_by: str | None = None
    attr_order: list[str] | None = None
    include_metadata: bool = False
    server: str | None = None


class FlextLdifModelsSettings:
    """LDIF configuration models container class."""

    class _StrictConfigValue(FlextModelsEntity.Value):
        model_config = ConfigDict(extra="forbid", validate_assignment=True)

    class AclMetadataConfig(_StrictConfigValue):
        """Configuration for ACL metadata extensions."""

        line_breaks: list[int] | None = None
        dn_spaces: bool = False
        targetscope: str | None = None
        version: str | None = None
        default_version: str = "3.0"
        action_type: str | None = "allow"

    class AciParserConfig(_StrictConfigValue):
        """Configuration for ACI parsing."""

        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(...)
        aci_prefix: str = "aci:"
        version_acl_pattern: str = Field(...)
        targetattr_pattern: str = Field(...)
        allow_deny_pattern: str = Field(...)
        bind_patterns: dict[str, str] = Field(default_factory=dict)
        default_name: str = "ACL"
        default_targetattr: str = "*"
        ops_separator: str = ","
        action_filter: str = "allow"
        extra_patterns: dict[str, str] = Field(default_factory=dict)
        permission_map: dict[str, str] = Field(
            default_factory=lambda: {
                "read": "read",
                "write": "write",
                "add": "add",
                "delete": "delete",
                "search": "search",
                "compare": "compare",
            }
        )
        special_subjects: dict[str, tuple[str, str]] = Field(
            default_factory=lambda: {
                "ldap:///self": ("self", "ldap:///self"),
                "ldap:///anyone": ("anonymous", "ldap:///anyone"),
            }
        )

    class AciLineFormatConfig(_StrictConfigValue):
        """Configuration for formatting ACI line."""

        name: str = Field(...)
        target_clause: str = Field(...)
        permissions_clause: str = Field(...)
        bind_rule: str = Field(...)
        version: str = "3.0"
        aci_prefix: str = "aci: "

    class ServerPatternsConfig(_StrictConfigValue):
        """Configuration for server pattern matching."""

        dn_patterns: tuple[tuple[str, ...], ...] = Field(default=())
        attr_prefixes: tuple[str, ...] | frozenset[str] = Field(default=())
        attr_names: frozenset[str] | set[str] = Field(default_factory=frozenset)
        keyword_patterns: tuple[str, ...] = Field(default=())

    class AttributeNormalizeConfig(_StrictConfigValue):
        """Configuration for attribute normalization."""

        case_mappings: dict[str, str] | None = None
        boolean_mappings: dict[str, str] | None = None
        attr_name_mappings: dict[str, str] | None = None
        strip_operational: bool = False
        operational_attrs: set[str] | None = None

    class EntryCriteriaConfig(_StrictConfigValue):
        """Configuration for entry criteria matching."""

        objectclasses: Sequence[str] | None = None
        objectclass_mode: Literal["any", "all"] = "any"
        required_attrs: Sequence[str] | None = None
        any_attrs: Sequence[str] | None = None
        dn_pattern: str | None = None
        is_schema: bool | None = None

    class EntryTransformConfig(_StrictConfigValue):
        """Configuration for entry transformation."""

        normalize_dns: bool = False
        normalize_attrs: bool = False
        attr_case: Literal["lower", "upper", "preserve"] = "lower"
        convert_booleans: tuple[str, str] | None = None
        remove_attrs: Sequence[str] | None = None
        fail_fast: bool = False

    class EntryFilterConfig(_StrictConfigValue):
        """Configuration for entry filtering."""

        objectclasses: Sequence[str] | None = None
        objectclass_mode: Literal["any", "all"] = "any"
        required_attrs: Sequence[str] | None = None
        dn_pattern: str | None = None
        is_schema: bool | None = None
        exclude_schema: bool = False

    class EntryParseMetadataConfig(_StrictConfigValue):
        """Configuration for building entry parse metadata."""

        quirk_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(...)
        original_entry_dn: str = Field(...)
        cleaned_dn: str = Field(...)
        original_dn_line: str | None = None
        original_attr_lines: list[str] | None = None
        dn_was_base64: bool = False
        original_attribute_case: dict[str, str] | None = None

    class RdnProcessingConfig(FlextModelsCollections.Config):
        """Mutable configuration for RDN character processing."""

        model_config = ConfigDict(extra="forbid", validate_assignment=True)
        current_attr: str = ""
        current_val: str = ""
        in_value: bool = False
        pairs: list[tuple[str, str]] = Field(default_factory=list)

    class MetadataTransformationConfig(_StrictConfigValue):
        """Configuration for metadata transformation tracking."""

        original_dn: str = Field(...)
        transformed_dn: str = Field(...)
        source_dn: str = Field(...)
        target_dn: str = Field(...)
        transformed_attr_names: list[str] = Field(default_factory=list)
        original_attrs: dict[str, list[str]] = Field(default_factory=dict)
        transformed_attrs: dict[str, list[str]] = Field(default_factory=dict)

    class LogContextExtras(FlextModelsEntity.Value):
        """Additional context fields for logging events."""

        model_config = ConfigDict(extra="allow", validate_assignment=True)
        user_id: str | None = None
        session_id: str | None = None
        request_id: str | None = None
        component: str | None = None
        correlation_id: str | None = None
        trace_id: str | None = None

    class CategoryRules(FlextModelsCollections.Rules):
        """Rules for entry categorization."""

        user_dn_patterns: list[str] = Field(default_factory=list)
        group_dn_patterns: list[str] = Field(default_factory=list)
        hierarchy_dn_patterns: list[str] = Field(default_factory=list)
        schema_dn_patterns: list[str] = Field(default_factory=list)
        user_objectclasses: list[str] = Field(
            default_factory=lambda: ["person", "inetOrgPerson", "orclUser"]
        )
        group_objectclasses: list[str] = Field(
            default_factory=lambda: ["groupOfUniqueNames", "groupOfNames", "orclGroup"]
        )
        hierarchy_objectclasses: list[str] = Field(
            default_factory=lambda: ["organizationalUnit", "organization"]
        )
        acl_attributes: list[str] = Field(
            default_factory=lambda: ["orclaci", "orclentrylevelaci"]
        )

    class MigrateOptions(FlextModelsEntity.Value):
        """Options for FlextLdif.migrate() operation."""

        migration_config: dict[str, str | int | bool] | None = None
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None = None
        categorization_rules: FlextLdifModelsSettings.CategoryRules | None = None
        input_files: list[str] | None = None
        output_files: dict[c.Ldif.Categories, str] | None = None
        schema_whitelist_rules: FlextLdifModelsSettings.WhitelistRules | None = None
        input_filename: str | None = None
        output_filename: str | None = None
        forbidden_attributes: list[str] | None = None
        forbidden_objectclasses: list[str] | None = None
        base_dn: str | None = None
        sort_entries_hierarchically: bool = False

    class FilterCriteria(FlextModelsBase.ArbitraryTypesModel):
        """Criteria for filtering LDIF entries."""

        filter_type: str = Field(...)
        pattern: str | None = None
        whitelist: list[str] | None = None
        blacklist: list[str] | None = None
        required_attributes: list[str] | None = None
        mode: str = "include"

    class WhitelistRules(FlextModelsCollections.Rules):
        """Whitelist rules for entry validation."""

        blocked_objectclasses: list[str] = Field(default_factory=list)
        allowed_objectclasses: list[str] = Field(default_factory=list)
        required_attributes: list[str] = Field(default_factory=list)
        blocked_attributes: list[str] = Field(default_factory=list)
        allowed_attribute_oids: list[str] = Field(default_factory=list)
        allowed_objectclass_oids: list[str] = Field(default_factory=list)
        allowed_matchingrule_oids: list[str] = Field(default_factory=list)
        allowed_matchingruleuse_oids: list[str] = Field(default_factory=list)
        allowed_ldapsyntax_oids: list[str] = Field(default_factory=list)

    class EncodingRules(FlextModelsEntity.Value):
        """Generic encoding rules - server classes provide values."""

        default_encoding: str
        allowed_encodings: list[c.Ldif.LiteralTypes.EncodingLiteral] = Field(
            default_factory=list
        )

    class DnCaseRules(FlextModelsEntity.Value):
        """Generic DN case rules - server classes provide values."""

        preserve_case: bool
        normalize_to: str | None = None

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
            default=c.Ldif.LdifFormatting.DEFAULT_LINE_WIDTH, ge=10, le=100000
        )
        respect_attribute_order: bool = True
        sort_attributes: bool = False
        write_hidden_attributes_as_comments: bool = False
        write_metadata_as_comments: bool = False
        include_version_header: bool = True
        include_timestamps: bool = False
        base64_encode_binary: bool = False
        fold_long_lines: bool = True
        restore_original_format: bool = False
        write_empty_values: bool = True
        normalize_attribute_names: bool = False
        include_dn_comments: bool = False
        write_removed_attributes_as_comments: bool = False
        write_migration_header: bool = False
        migration_header_template: str | None = None
        write_rejection_reasons: bool = False
        include_removal_statistics: bool = False
        ldif_changetype: str | None = None
        ldif_modify_operation: str = "add"
        write_original_entry_as_comment: bool = False
        entry_category: str | None = None
        acl_attribute_names: frozenset[str] = Field(default_factory=frozenset)
        comment_acl_in_non_acl_phases: bool = True
        use_rfc_attribute_order: bool = False
        rfc_order_priority_attributes: list[str] = Field(
            default_factory=lambda: ["objectClass"]
        )
        sort_objectclass_values: bool = False
        write_transformation_comments: bool = False
        use_original_acl_format_as_name: bool = False
        include_entry_markers: bool = False
        entry_marker_template: str | None = None
        include_statistics_summary: bool = False
        statistics_categories: dict[str, int] = Field(default_factory=dict)

    class WriteOutputOptions(FlextModelsBase.ArbitraryTypesModel):
        """Output visibility options for attributes based on their marker status."""

        model_config = ConfigDict(frozen=True)
        show_operational_attributes: str = "hide"
        show_removed_attributes: str = "comment"
        show_filtered_attributes: str = "hide"
        show_hidden_attributes: str = "hide"
        show_renamed_original: str = "comment"

    class ParseFormatOptions(FlextLdifModelsBase):
        """Formatting options for LDIF parsing (VIEW MODEL)."""

        model_config = ConfigDict(frozen=True)
        auto_parse_schema: bool = True
        auto_extract_acls: bool = True
        preserve_attribute_order: bool = False
        validate_entries: bool = True
        normalize_dns: bool = True
        max_parse_errors: int = Field(default=100, ge=0, le=10000)
        include_operational_attrs: bool = False
        strict_schema_validation: bool = False

    class EntryWriteConfig(_StrictConfigValue):
        """Configuration for entry writing."""

        entry: FlextLdifModelsDomains.Entry = Field(...)
        server_type: str = Field(...)
        write_attributes_hook: Callable[[FlextModelsEntity.Entry, list[str]], None] = (
            Field(...)
        )
        write_comments_hook: (
            Callable[[FlextModelsEntity.Entry, list[str]], None] | None
        ) = None
        transform_entry_hook: (
            Callable[[FlextLdifModelsDomains.Entry], FlextLdifModelsDomains.Entry]
            | None
        ) = None
        write_dn_hook: Callable[[str, list[str]], None] | None = None
        include_comments: bool = True

    class BatchWriteConfig(_StrictConfigValue):
        """Configuration for batch entry writing."""

        entries: list[FlextModelsEntity.Entry] = Field(...)
        server_type: str = Field(...)
        write_entry_hook: Callable[[FlextModelsEntity.Entry], r[str]] = Field(...)
        write_header_hook: Callable[[], str] | None = None
        include_header: bool = True
        entry_separator: str = "\n"

    class SortConfig(_StrictConfigValue):
        """Configuration for entry sorting."""

        entries: list[object] = Field(...)
        target: str = "entries"
        by: str = "hierarchy"
        traversal: str = "depth-first"
        predicate: Callable[[object], str | int | float] | None = None
        sort_attributes: bool = False
        attribute_order: list[str] | None = None
        sort_acl: bool = False
        acl_attributes: list[str] | None = None

    class SchemaConversionPipelineConfig(_StrictConfigValue):
        """Configuration for schema conversion pipeline."""

        source_schema: (
            FlextLdifProtocols.Ldif.SchemaAttributeProtocol
            | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
            | FlextLdifProtocols.Ldif.SchemaQuirkProtocol
        ) = Field(...)
        target_schema: (
            FlextLdifProtocols.Ldif.SchemaAttributeProtocol
            | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
            | FlextLdifProtocols.Ldif.SchemaQuirkProtocol
        ) = Field(...)
        write_method: Callable[..., r[str]] = Field(...)
        parse_method: Callable[
            ...,
            object,  # Relaxed from invariant Result for flexibility
        ] = Field(...)
        item_name: str = Field(...)

    class PermissionMappingConfig(_StrictConfigValue):
        """Configuration for permission mapping during ACL conversion."""

        original_acl: FlextLdifModelsDomains.Acl = Field(...)
        converted_acl: FlextLdifModelsDomains.Acl = Field(...)
        orig_perms_dict: dict[str, bool] = Field(...)
        source_server_type: str | None = None
        target_server_type: str | None = None
        converted_has_permissions: bool = False
