"""Configuration models for LDIF processing.

This module contains configuration models for LDIF processing operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping, MutableSequence
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal

from flext_core import FlextModels, r
from pydantic import ConfigDict, Field, StringConstraints

from flext_ldif import FlextLdifModelsBases, c, p, t

if TYPE_CHECKING:
    from flext_ldif import FlextLdifModelsDomains


class FlextLdifModelsSettings:
    """LDIF configuration models container class.

    This class acts as a namespace container for LDIF configuration models.
    All nested classes are accessed via FlextModels.* in the main models.py.
    """

    @staticmethod
    def _rdn_pairs_factory() -> MutableSequence[tuple[str, str]]:
        return []

    class DnNormalizationConfig(FlextModels.Value):
        """Configuration for DN normalization."""

        case_sensitive: Annotated[bool, Field()] = False
        remove_spaces: Annotated[bool, Field()] = True
        case_fold: Annotated[str | None, Field()] = None
        space_handling: Annotated[str | None, Field()] = None
        escape_handling: Annotated[str | None, Field()] = None
        validate_before: Annotated[bool, Field()] = True

    class AttrNormalizationConfig(FlextModels.Value):
        """Configuration for attribute normalization."""

        lowercase_keys: Annotated[bool, Field()] = True
        sort_values: Annotated[bool, Field()] = True
        sort_attributes: Annotated[str | None, Field()] = None
        normalize_whitespace: Annotated[bool, Field()] = True
        case_fold_names: Annotated[bool, Field()] = True
        trim_values: Annotated[bool, Field()] = True
        remove_empty: Annotated[bool, Field()] = False

    class AclConversionConfig(FlextModels.Value):
        """Configuration for ACL conversion operations."""

        convert_aci: Annotated[bool, Field()] = True
        preserve_original_aci: Annotated[bool, Field()] = False
        map_server_specific: Annotated[bool, Field()] = True

    class ValidationConfig(FlextModels.Value):
        """Configuration for validation operations."""

        strict_mode: Annotated[bool, Field()] = True
        validate_schema: Annotated[bool, Field()] = True
        validate_acl: Annotated[bool, Field()] = True

    class MetadataConfig(FlextModels.Value):
        """Configuration for metadata operations."""

        include_timestamps: Annotated[bool, Field()] = True
        include_processing_stats: Annotated[bool, Field()] = True
        preserve_validation: Annotated[bool, Field()] = False

    class ProcessConfig(FlextModels.Value):
        """Configuration for processing operations."""

        batch_size: Annotated[int, Field()] = 100
        timeout_seconds: Annotated[int, Field()] = 300
        max_retries: Annotated[int, Field()] = 3
        source_server: Annotated[str | None, Field()] = None
        target_server: Annotated[str | None, Field()] = None
        dn_config: Annotated[
            FlextLdifModelsSettings.DnNormalizationConfig | None,
            Field(),
        ] = None
        attr_config: Annotated[
            FlextLdifModelsSettings.AttrNormalizationConfig | None,
            Field(),
        ] = None
        acl_config: Annotated[
            FlextLdifModelsSettings.AclConversionConfig | None,
            Field(),
        ] = None
        validation_config: Annotated[
            FlextLdifModelsSettings.ValidationConfig | None,
            Field(),
        ] = None
        metadata_config: Annotated[
            FlextLdifModelsSettings.MetadataConfig | None,
            Field(),
        ] = None

    class TransformConfig(FlextModels.Value):
        """Configuration for transformation operations."""

        fail_fast: Annotated[bool, Field()] = False
        preserve_order: Annotated[bool, Field()] = True
        track_changes: Annotated[bool, Field()] = False
        normalize_dns: Annotated[bool, Field()] = False
        normalize_attrs: Annotated[bool, Field()] = False
        process_config: Annotated[
            FlextLdifModelsSettings.ProcessConfig | None,
            Field(),
        ] = None

    class FilterConfig(FlextModels.Value):
        """Configuration for filtering operations."""

        mode: Annotated[str, Field()] = "include"
        case_sensitive: Annotated[bool, Field()] = False
        include_metadata_matches: Annotated[bool, Field()] = False

    class WriteConfig(FlextModels.Value):
        """Configuration for write operations."""

        output_format: Annotated[str, Field()] = "ldif"
        format: Annotated[str, Field()] = "ldif"
        line_width: Annotated[int | None, Field()] = None
        fold_lines: Annotated[bool, Field()] = True
        base64_attrs: Annotated[MutableSequence[str] | None, Field()] = None
        sort_by: Annotated[str | None, Field()] = None
        attr_order: Annotated[MutableSequence[str] | None, Field()] = None
        include_metadata: Annotated[bool, Field()] = False
        server: Annotated[str | None, Field()] = None

    class MetadataPreserveConfig:
        """Configuration for metadata preservation."""

        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=False)
        original: Annotated[bool, Field()] = False
        tracking: Annotated[bool, Field()] = False
        validation: Annotated[bool, Field()] = False

    class LoadConfig:
        """LDIF file loading configuration."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=False,
            validate_assignment=True,
        )
        file_path: Annotated[str, Field()] = ""
        encoding: Annotated[str, Field()] = "utf-8"
        ignore_errors: Annotated[bool, Field()] = False
        skip_comments: Annotated[bool, Field()] = False

    class SchemaParseConfig:
        """Schema parsing configuration."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=False,
            validate_assignment=True,
        )
        parse_attributes: Annotated[bool, Field()] = True
        parse_objectclasses: Annotated[bool, Field()] = True
        parse_matching_rules: Annotated[bool, Field()] = False
        parse_syntaxes: Annotated[bool, Field()] = False

    class ValidationRuleSet:
        """Validation rule set configuration."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=False,
            validate_assignment=True,
        )
        name: Annotated[str, Field()] = "default"
        strict_mode: Annotated[bool, Field()] = False
        allow_undefined_attrs: Annotated[bool, Field()] = True
        allow_undefined_ocs: Annotated[bool, Field()] = True

    class AclMetadataConfig(FlextModels.Value):
        """Configuration for ACL metadata extensions.

        Consolidates parameters for build_metadata_extensions utility function.
        Reduces function signature from 6 parameters to 1 model.

        Example:
            config = FlextModels.AclMetadataConfig(
                line_breaks=[10, 20],
                dn_spaces=True,
                targetscope="subtree",
                version="3.0",
            )
            extensions = FlextLdifUtilities.ACL.build_metadata_extensions(config)

        """

        line_breaks: Annotated[
            MutableSequence[int] | None,
            Field(description="List of line break positions in ACL"),
        ] = None
        dn_spaces: Annotated[
            bool,
            Field(description="Whether DN contains spaces after commas"),
        ] = False
        targetscope: Annotated[
            str | None,
            Field(description="Target scope value (subtree, base, one)"),
        ] = None
        version: Annotated[
            str | None,
            Field(description="ACL version string"),
        ] = None
        default_version: Annotated[
            str,
            Field(description="Default version to compare against"),
        ] = "3.0"
        action_type: Annotated[
            str | None,
            Field(
                description="ACL action type (allow or deny) - for OUD deny rules support",
            ),
        ] = "allow"

    class AciParserConfig(FlextModels.Value):
        """Configuration for ACI parsing.

        Consolidates all parser parameters to enable generic utility methods.
        Each server (OUD, OID, RFC) provides its Constants-based config.

        Example:
            parser_config = FlextModels.AciParserConfig(
                server_type="oud",
                aci_prefix="aci:",
                version_acl_pattern=Constants.ACL_VERSION_ACL_PATTERN,
                ...
            )
            result = FlextLdifUtilities.ACL.parse_aci(acl_line, parser_config)

        """

        server_type: Annotated[
            c.Ldif.ServerTypeLiteral,
            Field(..., description="Server type for metadata"),
        ]
        aci_prefix: Annotated[
            str,
            Field(description="ACI attribute prefix"),
        ] = "aci:"
        version_acl_pattern: Annotated[
            str,
            Field(..., description="Regex pattern for version and ACL name extraction"),
        ]
        targetattr_pattern: Annotated[
            str,
            Field(..., description="Regex pattern for targetattr extraction"),
        ]
        allow_deny_pattern: Annotated[
            str,
            Field(..., description="Regex pattern for allow/deny permissions"),
        ]
        bind_patterns: Annotated[
            MutableMapping[str, str],
            Field(
                description="Mapping of bind type to regex pattern",
            ),
        ]
        default_name: Annotated[
            str,
            Field(description="Default ACL name if not found"),
        ] = "ACL"
        default_targetattr: Annotated[
            str,
            Field(description="Default target attribute"),
        ] = "*"
        ops_separator: Annotated[
            str,
            Field(description="Permissions separator"),
        ] = ","
        action_filter: Annotated[
            str,
            Field(description="Action to filter (allow or deny)"),
        ] = "allow"
        extra_patterns: Annotated[
            MutableMapping[str, str],
            Field(
                description="Extra regex patterns for server-specific fields",
            ),
        ]
        permission_map: Annotated[
            MutableMapping[str, str],
            Field(
                description="Mapping of permission name to normalized name",
            ),
        ]
        special_subjects: Annotated[
            MutableMapping[str, tuple[str, str]],
            Field(
                description="Special subject DN to (type, value) mapping",
            ),
        ]

    class AciWriterConfig(FlextModels.Value):
        """Configuration for ACI writing.

        Consolidates all writer parameters to enable generic utility methods.
        Each server (OUD, OID, RFC) provides its Constants-based config.

        Example:
            writer_config = FlextModels.AciWriterConfig(
                aci_prefix="aci:",
                version="3.0",
                ...
            )
            result = FlextLdifUtilities.ACL.write_aci(acl, writer_config)

        """

        aci_prefix: Annotated[
            str,
            Field(description="Prefix for ACI line"),
        ] = "aci: "
        version: Annotated[str, Field(description="ACI version")] = "3.0"
        allow_prefix: Annotated[
            str,
            Field(description="Prefix for allow clause"),
        ] = "allow ("
        self_subject: Annotated[
            str,
            Field(description="Value for self subject"),
        ] = "ldap:///self"
        anonymous_subject: Annotated[
            str,
            Field(description="Value for anonymous subject"),
        ] = "ldap:///anyone"
        supported_permissions: Annotated[
            frozenset[str] | None,
            Field(
                description="Optional set of supported permissions to filter",
            ),
        ] = None
        attr_separator: Annotated[
            str,
            Field(
                description="Separator for multiple attributes in targetattr",
            ),
        ] = " || "
        bind_operators: Annotated[
            MutableMapping[str, str],
            Field(
                description="Mapping of subject type to bind operator",
            ),
        ]

    class AciLineFormatConfig(FlextModels.Value):
        r"""Configuration for formatting ACI line.

        Consolidates parameters for format_aci_line utility function.
        Reduces function signature from 6 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.AciLineFormatConfig(
                name="test-acl",
                target_clause="(targetattr=\\"cn\\")",
                permissions_clause="allow (read,write)",
                bind_rule="userdn=\\"ldap:///self\\"",
            )
            aci_line = FlextLdifUtilities.ACL.format_aci_line(config)

        """

        name: Annotated[str, Field(..., description="ACL name")]
        target_clause: Annotated[str, Field(..., description="Target clause string")]
        permissions_clause: Annotated[
            str,
            Field(..., description="Permissions clause string"),
        ]
        bind_rule: Annotated[str, Field(..., description="Bind rule string")]
        version: Annotated[str, Field(description="ACI version")] = "3.0"
        aci_prefix: Annotated[
            str,
            Field(description="Prefix for ACI line"),
        ] = "aci: "

    class ServerPatternsConfig(FlextModels.Value):
        """Configuration for server pattern matching.

        Consolidates parameters for matches_server_patterns utility function.
        Reduces function signature from 6 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.ServerPatternsConfig(
                dn_patterns=(("ou=users",), ("cn=REDACTED_LDAP_BIND_PASSWORD",)),
                attr_prefixes=("orcl", "oracle"),
                attr_names={"orclaci", "orclentrylevelaci"},
                keyword_patterns=("orcl", "oracle"),
            )
            matches = FlextLdifUtilitiesEntry.matches_entry_server_patterns(
                entry_dn, attributes, config
            )

        """

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

    class AttributeDenormalizeConfig(FlextModels.Value):
        """Configuration for attribute denormalization.

        Consolidates parameters for denormalize_attributes_batch utility function.
        Reduces function signature from 6 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.AttributeDenormalizeConfig(
                case_mappings={"objectclass": "objectClass"},
                boolean_mappings={"TRUE": "1", "FALSE": "0"},
            )
            denorm = FlextLdifUtilities.Entry.denormalize_attributes_batch(
                attributes, config
            )

        """

        case_mappings: Annotated[
            MutableMapping[str, str] | None,
            Field(
                description="Attribute case restoration {normalized: original}",
            ),
        ] = None
        boolean_mappings: Annotated[
            MutableMapping[str, str] | None,
            Field(
                description='Boolean value mappings {TRUE: "1", FALSE: "0"}',
            ),
        ] = None
        attr_name_mappings: Annotated[
            MutableMapping[str, str] | None,
            Field(
                description="Attribute name mappings {rfc_name: server_name}",
            ),
        ] = None
        value_transformations: Annotated[
            MutableMapping[str, MutableMapping[str, str]] | None,
            Field(description="Per-attribute value mappings"),
        ] = None

    class AttributeNormalizeConfig(FlextModels.Value):
        """Configuration for attribute normalization.

        Consolidates parameters for normalize_attributes_batch utility function.
        Reduces function signature from 6 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.AttributeNormalizeConfig(
                case_mappings={"objectClass": "objectclass"},
                boolean_mappings={"1": "TRUE", "0": "FALSE"},
                strip_operational=True,
            )
            norm = FlextLdifUtilities.Entry.normalize_attributes_batch(
                attributes, config
            )

        """

        case_mappings: Annotated[
            MutableMapping[str, str] | None,
            Field(
                description="Attribute case normalization {original: normalized}",
            ),
        ] = None
        boolean_mappings: Annotated[
            MutableMapping[str, str] | None,
            Field(
                description='Boolean value mappings {"1": "TRUE", "0": "FALSE"}',
            ),
        ] = None
        attr_name_mappings: Annotated[
            MutableMapping[str, str] | None,
            Field(
                description="Attribute name mappings {server_name: rfc_name}",
            ),
        ] = None
        strip_operational: Annotated[
            bool,
            Field(
                description="Whether to remove operational attributes",
            ),
        ] = False
        operational_attrs: Annotated[
            set[str] | None,
            Field(description="Set of operational attribute names"),
        ] = None

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

    class EntryTransformConfig(FlextModels.Value):
        """Configuration for entry transformation.

        Consolidates parameters for transform_batch utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.EntryTransformConfig(
                normalize_dns=True,
                normalize_attrs=True,
                attr_case="lower",
                remove_attrs=["userPassword"],
            )
            result = FlextLdifUtilities.Entry.transform_batch(entries, config)

        """

        normalize_dns: Annotated[
            bool,
            Field(description="Normalize DN format"),
        ] = False
        normalize_attrs: Annotated[
            bool,
            Field(
                description="Normalize attribute names to specified case",
            ),
        ] = False
        attr_case: Annotated[
            Literal["lower", "upper", "preserve"],
            Field(description="Case for attribute normalization"),
        ] = "lower"
        convert_booleans: Annotated[
            tuple[str, str] | None,
            Field(
                description='Tuple of (source_format, target_format) e.g., ("true/false", "TRUE/FALSE")',
            ),
        ] = None
        remove_attrs: Annotated[
            MutableSequence[str] | None,
            Field(description="List of attributes to remove"),
        ] = None
        fail_fast: Annotated[
            bool,
            Field(description="Stop on first error"),
        ] = False

    class FlextLdifUtilitiesFiltersConfig(FlextModels.Value):
        """Configuration for entry filtering.

        Consolidates parameters for filter_batch utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.FlextLdifUtilitiesFiltersConfig(
                objectclasses=["inetOrgPerson"],
                exclude_schema=True,
            )
            result = FlextLdifUtilities.Entry.filter_batch(entries, config)

        """

        objectclasses: Annotated[
            MutableSequence[str] | None,
            Field(description="Filter by objectClass"),
        ] = None
        objectclass_mode: Annotated[
            Literal["any", "all"],
            Field(description='"any" or "all"'),
        ] = "any"
        required_attrs: Annotated[
            MutableSequence[str] | None,
            Field(
                description="Only include entries with all these attrs",
            ),
        ] = None
        dn_pattern: Annotated[
            str | None,
            Field(description="Only include entries matching DN pattern"),
        ] = None
        is_schema: Annotated[
            bool | None,
            Field(
                description="Only include schema (True) or non-schema (False) entries",
            ),
        ] = None
        exclude_schema: Annotated[
            bool,
            Field(
                description="Convenience flag to exclude schema entries",
            ),
        ] = False

    class TransformationTrackingConfig(FlextModels.Value):
        """Configuration for transformation tracking.

        Consolidates parameters for track_transformation utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            config = FlextLdifModelsSettings.TransformationTrackingConfig(
                original_name="orcldasisenabled",
                target_name="orcldasisenabled",
                original_values=["1"],
                target_values=["TRUE"],
                transformation_type="modified",
                reason="OID boolean '1' -> RFC 'TRUE'",
            )
            FlextLdifUtilities.Metadata.track_transformation(metadata, config)

        """

        original_name: Annotated[
            str,
            Field(..., description="Original attribute name (PRESERVED EXACTLY as-is)"),
        ]
        target_name: Annotated[
            str | None,
            Field(description="Target attribute name (None if removed)"),
        ] = None
        original_values: Annotated[
            MutableSequence[str],
            Field(
                ...,
                description="Original attribute values (PRESERVED EXACTLY as-is)",
            ),
        ]
        target_values: Annotated[
            MutableSequence[str] | None,
            Field(description="Converted values (None if removed)"),
        ] = None
        transformation_type: Annotated[
            c.Ldif.TransformationTypeLiteral,
            Field(..., description="Type: renamed/removed/modified/added/soft_deleted"),
        ]
        reason: Annotated[str, Field(..., description="Human-readable explanation")]

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
            MutableMapping[str, str] | None,
            Field(
                description="Mapping of attribute names to original case",
            ),
        ] = None

    class RdnProcessingConfig:
        """Mutable configuration for RDN character processing.

        Consolidates parameters for _process_rdn_char and _advance_rdn_position.
        Reduces function signature from 7 parameters to 1 model.

        Note: This inherits from ConfigMap (mutable) instead of Value (frozen)
        because the parsing logic mutates state during RDN processing.
        """

        current_attr: Annotated[
            str,
            Field(description="Current attribute name being parsed"),
        ] = ""
        current_val: Annotated[
            str,
            Field(description="Current attribute value being parsed"),
        ] = ""
        in_value: Annotated[
            bool,
            Field(
                description="Whether currently parsing value (after '=')",
            ),
        ] = False
        pairs: Annotated[
            MutableSequence[tuple[str, str]],
            Field(
                description="List of (attr, value) pairs parsed so far",
            ),
        ]

    class MetadataTransformationConfig(FlextModels.Value):
        """Configuration for metadata transformation tracking.

        Consolidates parameters for _update_metadata_for_transformation.
        Reduces function signature from 8 parameters to 1 model.

        """

        original_dn: Annotated[
            str,
            Field(..., description="Original DN before transformation"),
        ]
        transformed_dn: Annotated[
            str,
            Field(..., description="Transformed DN after transformation"),
        ]
        source_dn: Annotated[
            str,
            Field(..., description="Source base DN that was replaced"),
        ]
        target_dn: Annotated[str, Field(..., description="Target base DN replacement")]
        transformed_attr_names: Annotated[
            MutableSequence[str],
            Field(
                description="List of attribute names that were transformed",
            ),
        ]
        original_attrs: Annotated[
            MutableMapping[str, MutableSequence[str]],
            Field(
                description="Original attributes before transformation",
            ),
        ]
        transformed_attrs: Annotated[
            MutableMapping[str, MutableSequence[str]],
            Field(
                description="Transformed attributes after transformation",
            ),
        ]

    class LogContextExtras(FlextModels.Value):
        """Additional context fields for logging events.

        Replaces **extra_context: t.Scalar pattern with typed Model.
            Eliminates use of t.NormalizedValue and wildcard types in logging functions.

        Example:
            extras = FlextModels.LogContextExtras(
                user_id="REDACTED_LDAP_BIND_PASSWORD",
                session_id="abc123",
                request_id="req-456",
            )
            event = FlextLdifUtilities.Events.log_and_emit_dn_event(
                logger=logger,
                config=dn_config,
                extras=extras,
            )

        """

        model_config: ClassVar[ConfigDict] = ConfigDict(
            extra="allow",
            validate_assignment=True,
        )
        user_id: Annotated[
            str | None,
            Field(description="User identifier for audit trail"),
        ] = None
        session_id: Annotated[
            str | None,
            Field(description="Session identifier for correlation"),
        ] = None
        request_id: Annotated[
            str | None,
            Field(description="Request identifier for tracing"),
        ] = None
        component: Annotated[
            str | None,
            Field(description="Component name for context"),
        ] = None
        correlation_id: Annotated[
            str | None,
            Field(
                description="Correlation ID for tracking related operations across services",
            ),
        ] = None
        trace_id: Annotated[
            str | None,
            Field(
                description="Trace ID for distributed tracing and debugging",
            ),
        ] = None

    class CategoryRules(FlextModels.Rules):
        """Rules for entry categorization.

        Contains DN patterns and objectClass lists for each category.
        Replaces dict[str, t.NormalizedValue] with type-safe Pydantic model.
        """

        user_dn_patterns: Annotated[
            MutableSequence[str],
            Field(
                description="DN patterns for user entries (e.g., '*,ou=users,*')",
            ),
        ]
        group_dn_patterns: Annotated[
            MutableSequence[str],
            Field(description="DN patterns for group entries"),
        ]
        hierarchy_dn_patterns: Annotated[
            MutableSequence[str],
            Field(
                description="DN patterns for organizational hierarchy",
            ),
        ]
        schema_dn_patterns: Annotated[
            MutableSequence[str],
            Field(description="DN patterns for schema entries"),
        ]
        user_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                description="ObjectClasses identifying user entries",
            ),
        ]
        group_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                description="ObjectClasses identifying group entries",
            ),
        ]
        hierarchy_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                description="ObjectClasses identifying organizational units",
            ),
        ]
        acl_attributes: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names containing ACL information",
            ),
        ]

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
            MutableMapping[str, t.Scalar] | None,
            Field(
                description="Structured migration config with 6-file output and tracking",
            ),
        ] = None
        write_options: Annotated[
            FlextLdifModelsSettings.WriteConfig | None,
            Field(description="Write options for migration"),
        ] = None
        categorization_rules: Annotated[
            FlextLdifModelsSettings.CategoryRules | None,
            Field(
                description="Entry categorization rules (enables categorized mode)",
            ),
        ] = None
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
        schema_whitelist_rules: Annotated[
            FlextLdifModelsSettings.WhitelistRules | None,
            Field(
                description="Allowed schema elements whitelist (categorized mode)",
            ),
        ] = None
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
                pattern="*,ou=users,dc=example,dc=com",
                mode="include"
            )

        """

        filter_type: Annotated[
            str,
            Field(..., description="Type of filter (dn_pattern, oid_pattern, etc.)"),
        ]
        pattern: Annotated[
            str | None,
            Field(description="Pattern for matching (fnmatch wildcards)"),
        ] = None
        whitelist: Annotated[
            MutableSequence[str] | None,
            Field(description="Whitelist of patterns to include"),
        ] = None
        blacklist: Annotated[
            MutableSequence[str] | None,
            Field(description="Blacklist of patterns to exclude"),
        ] = None
        required_attributes: Annotated[
            MutableSequence[str] | None,
            Field(description="Required attributes for objectClass"),
        ] = None
        mode: Annotated[
            str,
            Field(
                description="Mode: 'include' keep, 'exclude' remove",
            ),
        ] = "include"

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

    class EncodingRules(FlextModels.Value):
        """Generic encoding rules - server classes provide values."""

        default_encoding: Annotated[
            str,
            StringConstraints(min_length=1, max_length=50, pattern="^[A-Za-z0-9._-]+$"),
        ]
        allowed_encodings: Annotated[MutableSequence[str]]

    class DnCaseRules(FlextModels.Value):
        """Generic DN case rules - server classes provide values."""

        preserve_case: bool
        normalize_to: Annotated[Literal["lower", "upper"] | None, Field()] = None

    class AclFormatRules(FlextModels.Value):
        """Generic ACL format rules - server classes provide values."""

        format: str
        attribute_name: t.Ldif.Rfc4512Descriptor
        requires_target: bool
        requires_subject: bool

    class ServerValidationRules(FlextModels.Value):
        """Generic server validation rules - server classes provide values.

        No defaults - each server class must provide all values via Constants.
        """

        requires_objectclass: bool
        requires_naming_attr: bool
        requires_binary_option: bool
        encoding_rules: FlextLdifModelsSettings.EncodingRules
        dn_case_rules: FlextLdifModelsSettings.DnCaseRules
        acl_format_rules: FlextLdifModelsSettings.AclFormatRules
        track_deletions: bool
        track_modifications: bool
        track_conversions: bool

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
        ]
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
        ]
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
            MutableMapping[str, int],
            Field(
                description="Dictionary of category names to entry counts for statistics summary. Example: {'users': 150, 'groups': 25, 'acl': 42}.",
            ),
        ]

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
                default="hide",
                description="How to handle operational attributes in output. Options: 'show' (write normally), 'hide' (don't write), 'comment' (write as LDIF comment).",
            ),
        ]
        show_removed_attributes: Annotated[
            str,
            Field(
                default="comment",
                description="How to handle removed attributes in output. Default 'comment' writes removed attrs as '# [REMOVED] attr: value'.",
            ),
        ]
        show_filtered_attributes: Annotated[
            str,
            Field(
                default="hide",
                description="How to handle filtered attributes in output. Default 'hide' completely omits filtered attributes.",
            ),
        ]
        show_hidden_attributes: Annotated[
            str,
            Field(
                default="hide",
                description="How to handle explicitly hidden attributes in output. Default 'hide' completely omits hidden attributes.",
            ),
        ]
        show_renamed_original: Annotated[
            str,
            Field(
                default="comment",
                description="How to handle original names of renamed attributes. Default 'comment' writes '# [RENAMED] old -> new: value'.",
            ),
        ]

    class MigrationConfig(FlextModels.Value):
        """Configuration for migration pipeline from YAML or dict.

        Supports structured 6-file output (00-06) with flexible categorization,
        filtering, and removed attribute tracking.
        """

        output_file_mapping: Annotated[
            MutableMapping[str, str],
            Field(
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
            ),
        ]
        hierarchy_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="ObjectClasses for hierarchy entries (01-hierarchy.ldif)",
            ),
        ]
        user_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="ObjectClasses for user entries (02-users.ldif)",
            ),
        ]
        group_objectclasses: Annotated[
            MutableSequence[str],
            Field(
                default_factory=list,
                description="ObjectClasses for group entries (03-groups.ldif)",
            ),
        ]
        attribute_whitelist: Annotated[
            MutableSequence[str] | None,
            Field(
                default=None,
                description="If provided, only these attributes are kept",
            ),
        ]
        attribute_blacklist: Annotated[
            MutableSequence[str] | None,
            Field(
                default=None,
                description="If provided, these attributes are removed",
            ),
        ]
        objectclass_whitelist: Annotated[
            MutableSequence[str] | None,
            Field(
                default=None,
                description="If provided, only entries with these objectClasses are kept",
            ),
        ]
        objectclass_blacklist: Annotated[
            MutableSequence[str] | None,
            Field(
                default=None,
                description="If provided, entries with these objectClasses are removed",
            ),
        ]
        track_removed_attributes: Annotated[
            bool,
            Field(
                default=True,
                description="If True, tracks removed attributes in entry metadata",
            ),
        ]
        write_removed_as_comments: Annotated[
            bool,
            Field(
                default=True,
                description="If True, writes removed attributes as comments in LDIF",
            ),
        ]
        header_template: Annotated[
            str | None,
            Field(default=None, description="Jinja2 template for file headers"),
        ]
        header_data: Annotated[
            MutableMapping[str, t.Scalar],
            Field(default_factory=dict, description="Data to pass to header template"),
        ]

    class ParseFormatOptions(FlextLdifModelsBases.Base):
        """Formatting options for LDIF parsing (VIEW MODEL).

        **Architecture**: This is a Pydantic VIEW MODEL that represents
        parse format options. The SOURCE OF TRUTH is FlextLdifSettings fields
        (ldif_parse_*). Use `config.to_parse_options()` to convert config to
        this model.

        **Usage Pattern**:
            .. code-block:: python

                # Config is source of truth
                from flext_ldif import FlextLdifSettings

                config = FlextSettings.get_global().get_namespace(
                    "ldif", FlextLdifSettings
                )

                # Override specific fields if needed
                config.ldif_parse_auto_parse_schema = False
                config.ldif_parse_normalize_dns = True

                # Convert to Pydantic model for service use
                options = config.to_parse_options()

                # Pass Pydantic model (NOT dict) to services
                result = parser.parse(file_path, options=options)

        **Field Mapping** (Config → This Model):
            - ldif_parse_auto_parse_schema → auto_parse_schema
            - ldif_parse_auto_extract_acls → auto_extract_acls
            - ldif_parse_preserve_attribute_order → preserve_attribute_order
            - ldif_parse_validate_entries → validate_entries
            - ldif_parse_normalize_dns → normalize_dns
            - ldif_parse_max_parse_errors → max_parse_errors
            - ldif_parse_include_operational_attrs → include_operational_attrs
            - ldif_parse_strict_schema_validation → strict_schema_validation
        """

        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
        auto_parse_schema: Annotated[
            bool,
            Field(
                default=True,
                description="If True, automatically parses schema definitions from entries.",
            ),
        ]
        auto_extract_acls: Annotated[
            bool,
            Field(
                default=True,
                description="If True, automatically extracts ACLs from entry attributes.",
            ),
        ]
        preserve_attribute_order: Annotated[
            bool,
            Field(
                default=False,
                description="If True, preserves the original attribute order from the LDIF file in Entry.metadata.",
            ),
        ]
        validate_entries: Annotated[
            bool,
            Field(
                default=True,
                description="If True, validates entries against LDAP schema rules.",
            ),
        ]
        normalize_dns: Annotated[
            bool,
            Field(
                default=True,
                description="If True, normalizes DN formatting to RFC 2253 standard.",
            ),
        ]
        max_parse_errors: Annotated[
            int,
            Field(
                default=100,
                ge=0,
                le=10000,
                description="Maximum number of parsing errors to collect before stopping. 0 means no limit.",
            ),
        ]
        include_operational_attrs: Annotated[
            bool,
            Field(
                default=False,
                description="If True, includes operational attributes in parsed entries.",
            ),
        ]
        strict_schema_validation: Annotated[
            bool,
            Field(
                default=False,
                description="If True, applies strict schema validation and fails on violations.",
            ),
        ]

    class MigrationPipelineParams(FlextModels.Value):
        """Typed parameters for migration pipeline factory.

        Replaces dict-based parameter passing with type-safe Pydantic model.
        """

        input_dir: Annotated[
            str,
            Field(
                default=".",
                description="Input directory containing LDIF files to migrate",
            ),
        ]
        output_dir: Annotated[
            str,
            Field(default=".", description="Output directory for migrated LDIF files"),
        ]
        source_server: Annotated[
            str,
            Field(
                default=c.Ldif.ServerTypes.RFC.value,
                description="Source LDAP server type (e.g., 'oid', 'oud', 'rfc')",
            ),
        ]
        target_server: Annotated[
            str,
            Field(
                default=c.Ldif.ServerTypes.RFC,
                description="Target LDAP server type (e.g., 'oid', 'oud', 'rfc')",
            ),
        ]
        migration_config: Annotated[
            FlextLdifModelsSettings.MigrationConfig | None,
            Field(
                default=None,
                description="Optional migration configuration for file organization and filtering",
            ),
        ]
        enable_quirks_detection: Annotated[
            bool,
            Field(
                default=True,
                description="If True, auto-detect server type from content",
            ),
        ]
        enable_relaxed_parsing: Annotated[
            bool,
            Field(
                default=False,
                description="If True, use lenient parsing for broken/non-compliant LDIF",
            ),
        ]

    class ParserParams(FlextModels.Value):
        """Typed parameters for parser service factory.

        Provides type-safe configuration for LDIF parsing operations.
        """

        file_path: Annotated[str, Field(description="Path to LDIF file to parse")]
        server_type: Annotated[
            c.Ldif.ServerTypeLiteral,
            Field(
                default="rfc",
                description="LDAP server type to use for parsing quirks",
            ),
        ]
        enable_auto_detection: Annotated[
            bool,
            Field(
                default=False,
                description="If True, auto-detect server type from file content",
            ),
        ]
        enable_relaxed_parsing: Annotated[
            bool,
            Field(default=False, description="If True, use lenient parsing mode"),
        ]
        parse_schema: Annotated[
            bool,
            Field(
                default=True,
                description="If True, parses schema definitions from entries",
            ),
        ]
        parse_acls: Annotated[
            bool,
            Field(
                default=True,
                description="If True, extracts ACLs from entry attributes",
            ),
        ]
        validate_entries: Annotated[
            bool,
            Field(
                default=True,
                description="If True, validates entries against schema rules",
            ),
        ]

    class WriterParams(FlextModels.Value):
        """Typed parameters for writer service factory.

        Provides type-safe configuration for LDIF writing operations.
        """

        output_path: Annotated[
            str,
            Field(description="Path where LDIF file will be written"),
        ]
        server_type: Annotated[
            c.Ldif.ServerTypeLiteral,
            Field(
                default="rfc",
                description="LDAP server type to use for writing quirks",
            ),
        ]
        encoding: Annotated[
            c.Ldif.EncodingLiteral,
            Field(default="utf-8", description="Character encoding for output file"),
        ]
        max_line_length: Annotated[
            int,
            Field(
                default=c.Ldif.MAX_LINE_WIDTH,
                description="Maximum line length for LDIF output",
                ge=50,
                le=1000,
            ),
        ]
        include_operational_attrs: Annotated[
            bool,
            Field(
                default=False,
                description="If True, includes operational attributes in output",
            ),
        ]
        sort_attributes: Annotated[
            bool,
            Field(
                default=False,
                description="If True, sorts attributes alphabetically",
            ),
        ]
        strict_rfc_compliance: Annotated[
            bool,
            Field(
                default=True,
                description="If True, enforces strict RFC 2849 compliance",
            ),
        ]

    class ConfigInfo(FlextModels.Value):
        """Configuration information for logging and introspection.

        Structured representation of FlextLdifSettings for reporting and diagnostics.
        """

        ldif_encoding: Annotated[
            c.Ldif.EncodingLiteral,
            Field(description="LDIF encoding setting"),
        ]
        strict_rfc_compliance: Annotated[
            bool,
            Field(description="Whether strict RFC compliance is enabled"),
        ]
        ldif_chunk_size: Annotated[
            int,
            Field(description="Chunk size for LDIF processing"),
        ]
        max_workers: Annotated[
            int,
            Field(description="Maximum number of worker processes"),
        ]
        debug: Annotated[bool, Field(description="Whether debug mode is enabled")]
        log_level: Annotated[str, Field(description="Logging level")]
        quirks_detection_mode: Annotated[
            str,
            Field(description="Server quirks detection mode (auto/manual/disabled)"),
        ]
        quirks_server_type: Annotated[
            c.Ldif.ServerTypeLiteral | None,
            Field(
                default=None,
                description="Configured server type for quirks (None if auto-detect)",
            ),
        ]
        enable_relaxed_parsing: Annotated[
            bool,
            Field(description="Whether relaxed parsing mode is enabled"),
        ]

    class LdifContentParseConfig(FlextModels.Value):
        """Configuration for LDIF content parsing.

        Consolidates parameters for Content.parse method.
        Reduces function signature from 9 parameters to 1 model.

        """

        ldif_content: Annotated[str, Field(..., description="Raw LDIF content string")]
        server_type: Annotated[
            str,
            Field(..., description="Server type identifier (e.g., 'rfc', 'oid')"),
        ]
        parse_entry_hook: Annotated[
            Callable[
                [str, MutableMapping[str, MutableSequence[str]]],
                r[FlextLdifModelsDomains.Entry],
            ],
            Field(..., description="Hook to parse (dn, attrs) into Entry"),
        ]
        transform_attrs_hook: Annotated[
            Callable[
                [str, MutableMapping[str, MutableSequence[str]]],
                tuple[str, MutableMapping[str, MutableSequence[str]]],
            ]
            | None,
            Field(
                default=None,
                description="Optional hook to transform attrs before parsing",
            ),
        ]
        post_parse_hook: Annotated[
            Callable[[FlextLdifModelsDomains.Entry], FlextLdifModelsDomains.Entry]
            | None,
            Field(
                default=None,
                description="Optional hook to transform entry after parsing",
            ),
        ]
        preserve_metadata_hook: Annotated[
            Callable[[FlextLdifModelsDomains.Entry, str, str], None] | None,
            Field(default=None, description="Optional hook to preserve original LDIF"),
        ]
        skip_empty_entries: Annotated[
            bool,
            Field(default=True, description="Skip entries with no attributes"),
        ]
        log_level: Annotated[
            str,
            Field(
                default="debug",
                description="Logging verbosity ('debug', 'info', 'warning')",
            ),
        ]
        ldif_parser: Annotated[
            Callable[
                [str],
                MutableSequence[tuple[str, MutableMapping[str, MutableSequence[str]]]],
            ]
            | None,
            Field(default=None, description="Optional custom LDIF parser"),
        ]

    class EntryProcessingConfig(FlextModels.Value):
        """Configuration for entry processing.

        Consolidates parameters for Content.process_entries method.
        Reduces function signature from 7 parameters to 1 model.

        """

        parsed_entries: Annotated[
            MutableSequence[tuple[str, MutableMapping[str, MutableSequence[str]]]],
            Field(..., description="List of (dn, attrs) tuples from parser"),
        ]
        parse_entry_hook: Annotated[
            Callable[
                [str, MutableMapping[str, MutableSequence[str]]],
                r[FlextLdifModelsDomains.Entry],
            ],
            Field(..., description="Hook to parse (dn, attrs) into Entry"),
        ]
        transform_attrs_hook: Annotated[
            Callable[
                [str, MutableMapping[str, MutableSequence[str]]],
                tuple[str, MutableMapping[str, MutableSequence[str]]],
            ]
            | None,
            Field(
                default=None,
                description="Optional hook to transform attrs before parsing",
            ),
        ]
        post_parse_hook: Annotated[
            Callable[[FlextLdifModelsDomains.Entry], FlextLdifModelsDomains.Entry]
            | None,
            Field(
                default=None,
                description="Optional hook to transform entry after parsing",
            ),
        ]
        preserve_metadata_hook: Annotated[
            Callable[[FlextLdifModelsDomains.Entry, str, str], None] | None,
            Field(default=None, description="Optional hook to preserve original LDIF"),
        ]
        skip_empty_entries: Annotated[
            bool,
            Field(default=True, description="Skip entries with no attributes"),
        ]

    class ObjectClassParseConfig(FlextModels.Value):
        """Configuration for objectClass definition parsing.

        Consolidates parameters for ObjectClass.parse method.
        Reduces function signature from 6 parameters to 1 model.

        """

        definition: Annotated[str, Field(..., description="Raw objectClass definition")]
        server_type: Annotated[str, Field(..., description="Server type identifier")]
        parse_core_hook: Annotated[
            Callable[[str], r[FlextLdifModelsDomains.SchemaObjectClass]],
            Field(..., description="Core parsing logic"),
        ]
        validate_structural_hook: Annotated[
            Callable[[str, MutableSequence[str]], bool] | None,
            Field(default=None, description="Optional structural validation"),
        ]
        transform_sup_hook: Annotated[
            Callable[[MutableSequence[str]], MutableSequence[str]] | None,
            Field(default=None, description="Optional SUP transformation"),
        ]
        enrich_metadata_hook: Annotated[
            Callable[[FlextLdifModelsDomains.SchemaObjectClass], None] | None,
            Field(default=None, description="Optional metadata enrichment"),
        ]

    class EntryParseConfig(FlextModels.Value):
        """Configuration for entry parsing.

        Consolidates parameters for Entry.parse method.
        Reduces function signature from 7 parameters to 1 model.

        """

        dn: Annotated[str, Field(..., description="Distinguished name")]
        attrs: Annotated[
            MutableMapping[str, MutableSequence[str]],
            Field(..., description="Entry attributes"),
        ]
        server_type: Annotated[str, Field(..., description="Server type identifier")]
        create_entry_hook: Annotated[
            Callable[
                [str, MutableMapping[str, MutableSequence[str]]],
                r[FlextLdifModelsDomains.Entry],
            ],
            Field(..., description="Entry creation logic"),
        ]
        build_metadata_hook: Annotated[
            Callable[
                [str, MutableMapping[str, MutableSequence[str]]],
                t.MutableContainerMapping | None,
            ]
            | None,
            Field(default=None, description="Optional metadata building"),
        ]
        normalize_dn_hook: Annotated[
            Callable[[str], str] | None,
            Field(default=None, description="Optional DN normalization"),
        ]
        transform_attrs_hook: Annotated[
            Callable[
                [str, MutableMapping[str, MutableSequence[str]]],
                tuple[str, MutableMapping[str, MutableSequence[str]]],
            ]
            | None,
            Field(default=None, description="Optional attribute transformation"),
        ]

    class EntryWriteConfig(FlextModels.Value):
        """Configuration for entry writing.

        Consolidates parameters for Entry.write method.
        Reduces function signature from 7 parameters to 1 model.

        """

        entry: Annotated[
            FlextLdifModelsDomains.Entry,
            Field(..., description="Entry model to write"),
        ]
        server_type: Annotated[str, Field(..., description="Server type identifier")]
        write_attributes_hook: Annotated[
            Callable[[FlextLdifModelsDomains.Entry, MutableSequence[str]], None],
            Field(..., description="Core attributes writing"),
        ]
        write_comments_hook: Annotated[
            Callable[[FlextLdifModelsDomains.Entry, MutableSequence[str]], None] | None,
            Field(default=None, description="Optional comments writing"),
        ]
        transform_entry_hook: Annotated[
            Callable[[FlextLdifModelsDomains.Entry], FlextLdifModelsDomains.Entry]
            | None,
            Field(default=None, description="Optional entry transformation"),
        ]
        write_dn_hook: Annotated[
            Callable[[str, MutableSequence[str]], None] | None,
            Field(default=None, description="Optional DN writing"),
        ]
        include_comments: Annotated[
            bool,
            Field(default=True, description="Include metadata comments"),
        ]

    class BatchWriteConfig(FlextModels.Value):
        """Configuration for batch entry writing.

        Consolidates parameters for Batch.write method.
        Reduces function signature from 6 parameters to 1 model.

        """

        entries: Annotated[
            MutableSequence[FlextLdifModelsDomains.Entry],
            Field(..., description="List of entries to write"),
        ]
        server_type: Annotated[str, Field(..., description="Server type identifier")]
        write_entry_hook: Annotated[
            Callable[[FlextLdifModelsDomains.Entry], r[str]],
            Field(..., description="Entry writing logic"),
        ]
        write_header_hook: Annotated[
            Callable[[], str] | None,
            Field(default=None, description="Optional header writing"),
        ]
        include_header: Annotated[
            bool,
            Field(default=True, description="Include LDIF header"),
        ]
        entry_separator: Annotated[
            str,
            Field(default="\n", description="Separator between entries"),
        ]

    class SortConfig(FlextModels.Value):
        """Configuration for entry sorting.

        Consolidates parameters for FlextLdifSorting.sort method.
        Reduces function signature from 9 parameters to 1 model.

        """

        entries: Annotated[
            MutableSequence[FlextLdifModelsDomains.Entry],
            Field(..., description="List of entries to sort"),
        ]
        target: Annotated[
            str,
            Field(
                default="entries",
                description="Sort target (entries, attributes, acl)",
            ),
        ]
        by: Annotated[str, Field(default="hierarchy", description="Sort strategy")]
        traversal: Annotated[
            str,
            Field(default="depth-first", description="Traversal order"),
        ]
        predicate: Annotated[
            Callable[[FlextLdifModelsDomains.Entry], str | int | float] | None,
            Field(default=None, description="Custom predicate function"),
        ]
        sort_attributes: Annotated[
            bool,
            Field(default=False, description="Sort attributes within entries"),
        ]
        attribute_order: Annotated[
            MutableSequence[str] | None,
            Field(default=None, description="Custom attribute order"),
        ]
        sort_acl: Annotated[
            bool,
            Field(default=False, description="Sort ACL attributes"),
        ]
        acl_attributes: Annotated[
            MutableSequence[str] | None,
            Field(default=None, description="ACL attributes to sort"),
        ]

    class _SchemaConversionPipelineBaseConfig(FlextModels.Value):
        source_schema: Annotated[
            p.Ldif.SchemaQuirk,
            Field(..., description="Source schema quirk"),
        ]
        target_schema: Annotated[
            p.Ldif.SchemaQuirk,
            Field(..., description="Target schema quirk"),
        ]
        item_name: Annotated[str, Field(..., description="Item name for errors")]

    class SchemaAttributeConversionPipelineConfig(_SchemaConversionPipelineBaseConfig):
        """Config for schema attribute conversion pipeline (discriminated union)."""

        item_type: Annotated[
            Literal["attribute"],
            Field(default="attribute", description="Discriminator"),
        ]
        item: Annotated[
            FlextLdifModelsDomains.SchemaAttribute,
            Field(..., description="Schema attribute to convert"),
        ]
        item_name: Annotated[
            str,
            Field(default="attribute", description="Item name for errors"),
        ]

    class SchemaObjectClassConversionPipelineConfig(
        _SchemaConversionPipelineBaseConfig,
    ):
        """Config for schema objectclass conversion pipeline (discriminated union)."""

        item_type: Annotated[
            Literal["objectclass"],
            Field(default="objectclass", description="Discriminator"),
        ]
        item: Annotated[
            FlextLdifModelsDomains.SchemaObjectClass,
            Field(..., description="Schema objectclass to convert"),
        ]
        item_name: Annotated[
            str,
            Field(default="objectclass", description="Item name for errors"),
        ]

    class PermissionMappingConfig(FlextModels.Value):
        """Configuration for permission mapping during ACL conversion.

        Consolidates parameters for
        FlextLdifConversion._apply_permission_mapping method.
        Reduces function signature from 6 parameters to 1 model.

        """

        original_acl: Annotated[
            FlextLdifModelsDomains.Acl,
            Field(..., description="Original ACL model"),
        ]
        converted_acl: Annotated[
            FlextLdifModelsDomains.Acl,
            Field(..., description="Converted ACL model (modified in-place)"),
        ]
        orig_perms_dict: Annotated[
            MutableMapping[str, bool],
            Field(..., description="Original permissions dict"),
        ]
        source_server_type: Annotated[
            str | None,
            Field(default=None, description="Source server type"),
        ]
        target_server_type: Annotated[
            str | None,
            Field(default=None, description="Target server type"),
        ]
        converted_has_permissions: Annotated[
            bool,
            Field(default=False, description="Whether converted ACL has permissions"),
        ]
