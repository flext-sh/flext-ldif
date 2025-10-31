"""LDIF domain models and data structures.

This module defines Pydantic models for LDIF data structures including entries,
attributes, DNs, ACLs, and schema elements. Models provide validation and
type safety for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Notes:
 - Uses object type in **extensions for server-specific quirk data
 - Models follow Pydantic v2 patterns with computed fields and validators
 - All models are immutable by default (frozen=True where applicable)

"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, ClassVar, cast

from flext_core import FlextModels, FlextResult
from pydantic import ConfigDict, Field, computed_field, field_validator, model_validator

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.typings import FlextLdifTypes


# Factory functions for default_factory (defined at module level to avoid forward reference issues)
def _create_default_pipeline_statistics() -> FlextLdifModels.PipelineStatistics:
    """Create default PipelineStatistics instance.

    Uses globals() to get FlextLdifModels at runtime after class is fully defined.
    """
    flext_models = globals()["FlextLdifModels"]
    return flext_models.PipelineStatistics()


def _create_default_migration_statistics() -> FlextLdifModels.MigrationStatistics:
    """Create default MigrationStatistics instance.

    Uses globals() to get FlextLdifModels at runtime after class is fully defined.
    """
    flext_models = globals()["FlextLdifModels"]
    return flext_models.MigrationStatistics()


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Unified namespace class that aggregates all LDIF domain models.
    Provides a single access point for all LDIF models while maintaining
    modular organization.

    This class extends flext-core FlextModels and organizes LDIF-specific
    models into focused sub-modules for better maintainability.
    """

    # =========================================================================
    # PYTHON 3.13 TYPE ALIASES - Semantic type clarity for LDIF domain
    # =========================================================================
    # Semantic type aliases for better code readability and intent
    type DnString = str  # Distinguished Name as string
    type AttributeName = str  # LDAP attribute name
    type CategoryName = str  # Categorization key
    type ServerType = str  # LDAP server type identifier
    type ConversionData = str | dict[str, str] | list[str]  # Conversion data types

    # =========================================================================
    # DOMAIN MODELS - Core business entities
    # =========================================================================
    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",  # Allow dynamic fields from conversions
        )

        value: str = Field(
            ...,
            description="DN string value",
            min_length=FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS,
            max_length=FlextLdifConstants.LdifValidation.MAX_DN_LENGTH,
        )
        metadata: dict[str, object] | None = Field(
            default=None,
            description="Quirk-specific metadata for preserving original format",
        )

        # Basic DN pattern for validation (RFC 4514 simplified)
        _DN_COMPONENT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            FlextLdifConstants.LdifPatterns.DN_COMPONENT,
            re.IGNORECASE,
        )

        @field_validator("value", mode="after")
        @classmethod
        def validate_dn_rfc4514_format(cls, v: str) -> str:
            """Validate DN follows RFC 4514 format (domain validation, not Pydantic).

            Each component must match: letter[letter|digit|hyphen]*=value

            Args:
                v: DN string (guaranteed non-empty by min_length constraint)

            Returns:
                DN value if valid

            Raises:
                ValueError: If DN format is invalid

            """
            # Split by comma to get components
            components = [comp.strip() for comp in v.split(",") if comp.strip()]

            # Validate each component matches RFC 4514 format
            for comp in components:
                if not cls._DN_COMPONENT_PATTERN.match(comp):
                    msg = f"DN format invalid: component '{comp}' must match format 'attribute=value'"
                    raise ValueError(msg)

            return v

        @computed_field
        def components(self) -> list[str]:
            """Get DN components as a list."""
            return [comp.strip() for comp in self.value.split(",") if comp.strip()]

        def __str__(self) -> str:
            """Return the DN string value for proper str() conversion."""
            return self.value

    class QuirkMetadata(FlextModels.ArbitraryTypesModel):
        """Universal metadata container for quirk-specific data preservation.

        This model supports ANY quirk type and prevents data loss during RFC conversion.
        Quirks can store original format, timestamps, extensions, and custom data.

        Example:
            metadata = QuirkMetadata(
                original_format="( 2.16.840.1.113894... )",
                quirk_type="oud",
                extensions={"line_breaks": [45, 90], "dn_spaces": True}
            )

        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        original_format: str | None = Field(
            default=None,
            description="Original format before parsing (round-trip)",
        )
        quirk_type: str | None = Field(
            default=None,
            description="Quirk type that generated metadata (oud, oid, etc.)",
        )
        parsed_timestamp: str | None = Field(
            default=None,
            description="Timestamp when data was parsed (ISO 8601)",
        )
        x_origin: str | None = Field(
            default=None,
            description="X-ORIGIN metadata for schema definitions",
        )
        extensions: dict[str, object] = Field(
            default_factory=dict,
            description="Extensions (line_breaks, dn_spaces, attribute_order, unconverted_attributes)",
        )
        custom_data: dict[str, object] = Field(
            default_factory=dict,
            description="Additional custom data for future quirks",
        )
        server_type: FlextLdifModels.ServerType | None = Field(
            default=None,
            description="Detected LDAP server type for the entry/schema",
        )
        source_entry: str | None = Field(
            default=None,
            description="Original raw entry representation before parsing",
        )
        self_write_to_write: bool = Field(
            default=False,
            description="Flag indicating if self_write permission should be promoted to write",
        )
        oid_specific_rights: list[str] = Field(
            default_factory=list,
            description="List of OID-specific rights found during parsing",
        )
        removed_attributes: list[str] = Field(
            default_factory=list,
            description="Attributes removed during migration/filtering",
        )

        @classmethod
        def create_for_quirk(
            cls,
            quirk_type: str,
            original_format: str | None = None,
            extensions: dict[str, object] | None = None,
            custom_data: dict[str, object] | None = None,
            server_type: FlextLdifModels.ServerType | None = None,
            source_entry: str | None = None,
        ) -> FlextLdifModels.QuirkMetadata:
            """Create QuirkMetadata for a specific quirk type."""
            return cls(
                quirk_type=quirk_type,
                original_format=original_format,
                extensions=extensions or {},
                custom_data=custom_data or {},
                parsed_timestamp=None,  # Will be set by caller if needed
                server_type=server_type,
                source_entry=source_entry,
            )

    class AclPermissions(FlextModels.ArbitraryTypesModel):
        """ACL permissions for LDAP operations."""

        read: bool = Field(default=False, description="Read permission")
        write: bool = Field(default=False, description="Write permission")
        add: bool = Field(default=False, description="Add permission")
        delete: bool = Field(default=False, description="Delete permission")
        search: bool = Field(default=False, description="Search permission")
        compare: bool = Field(default=False, description="Compare permission")
        self_write: bool = Field(default=False, description="Self-write permission")
        proxy: bool = Field(default=False, description="Proxy permission")

        @classmethod
        def create(
            cls,
            data: FlextLdifTypes.Entry.EntryCreateData,
        ) -> FlextResult[FlextLdifModels.AclPermissions]:
            """Create an AclPermissions instance from data."""
            try:
                # Create mutable copy of data (may be Mapping from tests)
                data_mutable: dict[str, object] = dict(data)

                # Handle permissions list format from tests
                if "permissions" in data_mutable:
                    perms_list = data_mutable.get("permissions", [])
                    if isinstance(perms_list, list):
                        # Convert list of permissions to individual boolean fields
                        for perm in perms_list:
                            if isinstance(perm, str):
                                data_mutable[perm] = True
                        data_mutable.pop("permissions", None)

                return FlextResult[FlextLdifModels.AclPermissions].ok(
                    cls.model_validate(data_mutable),
                )
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[FlextLdifModels.AclPermissions].fail(
                    f"Failed to create AclPermissions: {e}",
                )

        @computed_field
        def permissions(self) -> list[str]:
            """Get permissions as a list of strings.

            Uses centralized constants from FlextLdifConstants.Acl
            to ensure consistency across all ACL operations.
            """
            perms = []
            if self.read:
                perms.append(FlextLdifConstants.Acl.READ)
            if self.write:
                perms.append(FlextLdifConstants.Acl.WRITE)
            if self.add:
                perms.append(FlextLdifConstants.Acl.ADD)
            if self.delete:
                perms.append(FlextLdifConstants.Acl.DELETE)
            if self.search:
                perms.append(FlextLdifConstants.Acl.SEARCH)
            if self.compare:
                perms.append(FlextLdifConstants.Acl.COMPARE)
            if self.self_write:
                perms.append(FlextLdifConstants.Acl.SELF_WRITE)
            if self.proxy:
                perms.append(FlextLdifConstants.Acl.PROXY)
            return perms

    class AclTarget(FlextModels.ArbitraryTypesModel):
        """ACL target specification."""

        target_dn: str = Field(..., description="Target DN pattern")
        attributes: list[str] = Field(
            default_factory=list,
            description="Target attributes",
        )

    class AclSubject(FlextModels.ArbitraryTypesModel):
        """ACL subject specification."""

        subject_type: str = Field(..., description="Subject type (user, group, etc.)")
        subject_value: str = Field(..., description="Subject value/pattern")

    class Acl(FlextModels.ArbitraryTypesModel):
        r"""Universal ACL model for all LDAP server types.

        Consolidated model replacing 7 separate ACL classes (FlextLdifModels.Acl, OpenLdapAcl,
        OpenLdap2Acl, OpenLdap1Acl, OracleOidAcl, OracleOudAcl, Ds389Acl).

        The server_type field determines the LDAP server implementation.

        Supported server types:
        - openldap: OpenLDAP olcAccess ACL (legacy catch-all)
        - openldap2: OpenLDAP 2.x modern cn=config ACL
        - openldap1: OpenLDAP 1.x legacy slapd.conf ACL
        - oid: Oracle Internet Directory (OID) orclaci ACL
        - oud: Oracle Unified Directory (OUD) orclaci ACL
        - 389ds: Red Hat 389 Directory Server ACI

        Example:
            acl = Acl(
                name="allow-read",
                target=AclTarget(target_dn="dc=example,dc=com", attributes=["cn"]),
                subject=AclSubject(subject_type="user", subject_value="cn=admin"),
                permissions=AclPermissions(read=True),
                server_type="oud",
                raw_acl="access to dn=\"dc=example,dc=com\" by users read"
            )

        """

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
        )

        name: str = Field(default="", description="ACL name")
        target: FlextLdifModels.AclTarget | None = Field(
            default=None,
            description="ACL target",
        )
        subject: FlextLdifModels.AclSubject | None = Field(
            default=None,
            description="ACL subject",
        )
        permissions: FlextLdifModels.AclPermissions | None = Field(
            default=None,
            description="ACL permissions",
        )
        server_type: FlextLdifConstants.LiteralTypes.ServerType = Field(
            default="rfc",
            description="LDAP server type (openldap, openldap2, openldap1, oid, oud, 389ds)",
        )
        raw_line: str = Field(default="", description="Original raw ACL line from LDIF")
        raw_acl: str = Field(default="", description="Original ACL string from LDIF")
        metadata: FlextLdifModels.QuirkMetadata | None = Field(
            default=None,
            description="Server-specific metadata for quirks transformation (e.g., OID→RFC conversion info)",
        )

        def get_acl_format(self) -> str:
            """Get ACL format for this server type.

            Returns the RFC or server-specific ACL format constant.
            Uses centralized mapping from FlextLdifConstants.AclFormats.SERVER_TYPE_TO_FORMAT
            to ensure consistency across all ACL operations.
            """
            return FlextLdifConstants.AclFormats.SERVER_TYPE_TO_FORMAT.get(
                self.server_type,
                FlextLdifConstants.AclFormats.ACI,
            )

        def get_acl_type(self) -> str:
            """Get ACL type identifier for this server.

            Returns ACL type string derived from server_type with '_acl' suffix.
            """
            short_form_map = {
                "oracle_oid": "oid",
                "oracle_oud": "oud",
            }
            short_server_type = short_form_map.get(self.server_type, self.server_type)
            return f"{short_server_type}_acl"

    # =========================================================================
    # DTO MODELS - Data transfer objects
    # =========================================================================
    # Note: CQRS classes (ParseLdifCommand, WriteLdifCommand, etc.) are
    # exported from flext_ldif.__init__.py to avoid circular imports.

    class LdifValidationResult(FlextModels.ArbitraryTypesModel):
        """Result of LDIF validation operations."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
        )

        is_valid: bool = Field(default=False, description="Whether validation passed")
        errors: list[str] = Field(
            default_factory=list,
            description="List of validation errors",
        )
        warnings: list[str] = Field(
            default_factory=list,
            description="List of validation warnings",
        )

        @computed_field
        def error_count(self) -> int:
            """Count of validation errors."""
            return len(self.errors)

        @computed_field
        def warning_count(self) -> int:
            """Count of validation warnings."""
            return len(self.warnings)

        @computed_field
        def total_issues(self) -> int:
            """Total issues (errors + warnings)."""
            # Explicit int cast to help type checker
            errors: int = len(self.errors)
            warnings: int = len(self.warnings)
            return errors + warnings

        @computed_field
        def validation_summary(self) -> str:
            """Get human-readable validation summary."""
            if self.is_valid:
                return f"Valid ({self.warning_count} warnings)"
            return f"Invalid ({self.error_count} errors, {self.warning_count} warnings)"

    class AnalysisResult(FlextModels.ArbitraryTypesModel):
        """Result of LDIF analytics operations."""

        total_entries: int = Field(
            default=0,
            description="Total number of entries analyzed",
        )
        object_class_distribution: FlextLdifTypes.CommonDict.DistributionDict = Field(
            default_factory=dict,
            description="Distribution of object classes",
        )
        patterns_detected: list[str] = Field(
            default_factory=list,
            description="Detected patterns in the data",
        )

        @computed_field
        def unique_object_class_count(self) -> int:
            """Count of unique object classes."""
            return len(self.object_class_distribution)

        @computed_field
        def pattern_count(self) -> int:
            """Count of detected patterns."""
            return len(self.patterns_detected)

        @computed_field
        def most_common_object_class(self) -> str | None:
            """Get the most common object class."""
            if not self.object_class_distribution:
                return None
            return max(
                self.object_class_distribution,
                key=lambda k: self.object_class_distribution.get(k, 0),
            )

        @computed_field
        def analytics_summary(self) -> str:
            """Get human-readable analytics summary."""
            return (
                f"{self.total_entries} entries analyzed, "
                f"{self.unique_object_class_count} unique object classes, "
                f"{self.pattern_count} patterns detected"
            )

    # SearchConfig deleted (0 usages) - use dict[str, object] for LDAP search config
    # DiffItem and DiffResult deleted (0 usages) - use dict[str, list[dict]] for diff operations

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

    class ExclusionInfo(FlextModels.ArbitraryTypesModel):
        """Metadata for excluded entries/schema items.

        Stored in QuirkMetadata.extensions['exclusion_info'] to track why
        an entry was excluded during filtering operations.

        Example:
            exclusion = ExclusionInfo(
                excluded=True,
                exclusion_reason="DN outside base context",
                filter_criteria=FilterCriteria(
                    filter_type="dn_pattern", pattern="*,dc=old,dc=com"
                ),
                timestamp="2025-10-09T12:34:56Z"
            )

        """

        excluded: bool = Field(
            default=False,
            description="Whether the item is excluded",
        )
        exclusion_reason: str | None = Field(
            default=None,
            description="Human-readable reason for exclusion",
        )
        filter_criteria: FlextLdifModels.FilterCriteria | None = Field(
            default=None,
            description="Filter criteria that caused the exclusion",
        )
        timestamp: str = Field(
            ...,
            description="ISO 8601 timestamp when exclusion was marked",
        )

    class CategorizedEntries(FlextModels.ArbitraryTypesModel):
        """Result of entry categorization by objectClass.

        Categorizes LDIF entries into users, groups, containers, and uncategorized
        based on configurable objectClass sets.

        Example:
            categorized = CategorizedEntries(
                users=[user_entry1, user_entry2],
                groups=[group_entry1],
                containers=[ou_entry1, ou_entry2],
                uncategorized=[],
                summary={"users": 2, "groups": 1, "containers": 2, "uncategorized": 0}
            )

        """

        users: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Entries categorized as users (inetOrgPerson, person, etc.)",
        )
        groups: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description=f"Entries categorized as groups ({FlextLdifConstants.ObjectClasses.GROUP_OF_NAMES}, etc.)",
        )
        containers: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Entries categorized as containers (organizationalUnit, etc.)",
        )
        uncategorized: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Entries that don't match any category",
        )

        @computed_field
        def summary(self) -> FlextLdifTypes.CommonDict.DistributionDict:
            """Get summary of entry counts by category."""
            return {
                "users": len(self.users),
                "groups": len(self.groups),
                "containers": len(self.containers),
                "uncategorized": len(self.uncategorized),
            }

        @computed_field
        def total_entries(self) -> int:
            """Total number of categorized entries."""
            return (
                len(self.users)
                + len(self.groups)
                + len(self.containers)
                + len(self.uncategorized)
            )

        @classmethod
        def create_empty(cls) -> FlextLdifModels.CategorizedEntries:
            """Create an empty CategorizedEntries instance."""
            return cls(
                users=[],
                groups=[],
                containers=[],
                uncategorized=[],
            )

    class SchemaDiscoveryResult(FlextModels.ArbitraryTypesModel):
        """Result of schema discovery operations."""

        attributes: FlextLdifTypes.Models.AttributesData = Field(
            default_factory=dict,
            description="Discovered attributes with their metadata",
        )
        objectclasses: FlextLdifTypes.Models.ObjectClassesData = Field(
            default_factory=dict,
            description="Discovered object classes with their metadata",
        )
        total_attributes: int = Field(
            default=0,
            description="Total number of discovered attributes",
        )
        total_objectclasses: int = Field(
            default=0,
            description="Total number of discovered object classes",
        )
        server_type: str = Field(
            default="generic",
            description="Server type for which schema was discovered",
        )
        entry_count: int = Field(
            default=0,
            description="Number of entries used for schema discovery",
        )
        server_info: object = Field(
            default=None,
            description="LDAP server information from Root DSE",
        )
        server_quirks: object = Field(
            default=None,
            description="Server-specific quirks and behaviors",
        )
        naming_contexts: list[str] = Field(
            default_factory=list,
            description="Naming contexts (suffixes) available on server",
        )
        supported_controls: list[str] = Field(
            default_factory=list,
            description="LDAP controls supported by server",
        )
        supported_extensions: list[str] = Field(
            default_factory=list,
            description="LDAP extensions supported by server",
        )

        @computed_field
        def discovery_ratio(self) -> float:
            """Calculate discovery ratio (attributes per entry)."""
            if self.entry_count == 0:
                return 0.0
            return self.total_attributes / self.entry_count

        @computed_field
        def schema_completeness(self) -> float:
            """Calculate schema completeness score (0-100).

            Based on:
            - Attribute discovery density
            - ObjectClass coverage
            - Entry sample size
            """
            if self.entry_count == 0:
                return 0.0

            # Normalize components
            attr_density = min(self.total_attributes / 50, 1.0)  # Cap at 50 attrs
            oc_coverage = min(self.total_objectclasses / 10, 1.0)  # Cap at 10 OCs
            sample_size = min(self.entry_count / 1000, 1.0)  # Cap at 1000 entries

            # Weighted average
            completeness = (
                attr_density * 0.5 + oc_coverage * 0.3 + sample_size * 0.2
            ) * 100
            return round(completeness, 2)

        @computed_field
        def discovery_summary(self) -> str:
            """Get human-readable discovery summary."""
            return (
                f"Discovered {self.total_attributes} attributes and "
                f"{self.total_objectclasses} object classes from "
                f"{self.entry_count} entries ({self.server_type})"
            )

    class SchemaAttribute(FlextModels.ArbitraryTypesModel):
        """LDAP schema attribute definition model (RFC 4512 compliant).

        Represents an LDAP attribute type definition from schema with full RFC 4512 support.
        """

        name: str = Field(..., description="Attribute name")
        oid: str = Field(..., description="Attribute OID")
        desc: str | None = Field(
            None,
            description="Attribute description (RFC 4512 DESC)",
        )
        sup: str | None = Field(
            None,
            description="Superior attribute type (RFC 4512 SUP)",
        )
        equality: str | None = Field(
            None,
            description="Equality matching rule (RFC 4512 EQUALITY)",
        )
        ordering: str | None = Field(
            None,
            description="Ordering matching rule (RFC 4512 ORDERING)",
        )
        substr: str | None = Field(
            None,
            description="Substring matching rule (RFC 4512 SUBSTR)",
        )
        syntax: str | None = Field(
            None,
            description="Attribute syntax OID (RFC 4512 SYNTAX)",
        )
        length: int | None = Field(None, description="Maximum length constraint")
        usage: str | None = Field(None, description="Attribute usage (RFC 4512 USAGE)")
        single_value: bool = Field(
            default=False,
            description="Whether attribute is single-valued (RFC 4512 SINGLE-VALUE)",
        )
        collective: bool = Field(
            default=False,
            description="Whether attribute is collective (RFC 4512 COLLECTIVE)",
        )
        no_user_modification: bool = Field(
            default=False,
            description="Whether users can modify this attribute (RFC 4512 NO-USER-MODIFICATION)",
        )
        metadata: FlextLdifModels.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata",
        )

        @computed_field
        def has_matching_rules(self) -> bool:
            """Check if attribute has any matching rules defined."""
            return bool(self.equality or self.ordering or self.substr)

        @computed_field
        def syntax_definition(self) -> FlextLdifModels.Syntax | None:
            """Resolve syntax OID to complete Syntax model using RFC 4517 validation.

            Returns:
                Resolved Syntax model with RFC 4517 compliance details, or None if:
                - syntax field is None or empty
                - syntax OID validation fails
                - syntax resolution fails

            """
            if not self.syntax:
                return None
            return FlextLdifModels.Syntax.resolve_syntax_oid(
                self.syntax,
                server_type="rfc",
            )

    class Syntax(FlextModels.ArbitraryTypesModel):
        """LDAP attribute syntax definition model (RFC 4517 compliant).

        Represents an LDAP attribute syntax OID and its validation rules per RFC 4517.
        """

        oid: str = Field(
            ...,
            description="Syntax OID (RFC 4517, format: 1.3.6.1.4.1.1466.115.121.1.X)",
        )
        name: str | None = Field(
            None,
            description="Human-readable syntax name (e.g., 'Boolean', 'Integer')",
        )
        desc: str | None = Field(
            None,
            description="Syntax description and purpose",
        )
        type_category: str = Field(
            default="string",
            description="Syntax type category: string, integer, binary, dn, time, boolean",
        )
        is_binary: bool = Field(
            default=False,
            description="Whether this syntax uses binary encoding",
        )
        max_length: int | None = Field(
            None,
            description="Maximum length in bytes (if applicable)",
        )
        case_insensitive: bool = Field(
            default=False,
            description="Whether comparisons are case-insensitive",
        )
        allows_multivalued: bool = Field(
            default=True,
            description="Whether attributes using this syntax can be multivalued",
        )
        encoding: str = Field(
            default="utf-8",
            description="Expected character encoding (utf-8, ascii, iso-8859-1, etc.)",
        )
        validation_pattern: str | None = Field(
            None,
            description="Optional regex pattern for value validation",
        )
        metadata: FlextLdifModels.QuirkMetadata | None = Field(
            default=None,
            description="Server-specific quirk metadata",
        )

        @field_validator("oid")
        @classmethod
        def validate_oid(cls, v: str) -> str:
            """Validate that OID is not empty."""
            if not v or not v.strip():
                msg = "OID cannot be empty"
                raise ValueError(msg)
            return v

        @computed_field
        def is_rfc4517_standard(self) -> bool:
            """Check if this is a standard RFC 4517 syntax OID."""
            oid_base = "1.3.6.1.4.1.1466.115.121.1"
            return self.oid.startswith(oid_base)

        @computed_field
        def syntax_oid_suffix(self) -> str | None:
            """Extract the numeric suffix from RFC 4517 OID."""
            # Compute directly instead of accessing is_rfc4517_standard property
            oid_base = "1.3.6.1.4.1.1466.115.121.1"
            is_standard = self.oid.startswith(oid_base)
            if not is_standard:
                return None
            parts = self.oid.split(".")
            return parts[-1] if parts else None

        @staticmethod
        def resolve_syntax_oid(
            oid: str, server_type: str = "rfc"
        ) -> FlextLdifModels.Syntax | None:
            """Resolve a syntax OID to a Syntax model using RFC 4517 validation.

            This method is used by both models and the syntax service to avoid circular dependencies.

            Args:
                oid: Syntax OID to resolve
                server_type: LDAP server type for quirk metadata

            Returns:
                Resolved Syntax model with RFC 4517 compliance details, or None if:
                - oid is None or empty
                - syntax OID validation fails
                - syntax resolution fails

            """
            # Handle missing syntax
            if not oid or not oid.strip():
                return None

            try:
                # Build lookup tables
                oid_to_name = FlextLdifConstants.RfcSyntaxOids.OID_TO_NAME.copy()

                # Look up name from OID
                name = oid_to_name.get(oid)
                type_category = (
                    FlextLdifConstants.RfcSyntaxOids.NAME_TO_TYPE_CATEGORY.get(
                        name, "string"
                    )
                    if name
                    else "string"
                )

                # Create metadata for server-specific handling
                metadata = (
                    FlextLdifModels.QuirkMetadata(
                        quirk_type=server_type,
                        extensions={"description": f"RFC 4517 syntax OID: {oid}"},
                    )
                    if server_type != FlextLdifConstants.ServerTypes.RFC
                    else None
                )

                # Create and validate Syntax model
                return FlextLdifModels.Syntax(
                    oid=oid,
                    name=name,
                    desc=None,
                    type_category=type_category,
                    max_length=None,
                    validation_pattern=None,
                    metadata=metadata,
                )

            except (ImportError, Exception):
                # Log and return None for any resolution errors
                # This prevents the model from being invalid due to service failures
                return None

    class SchemaObjectClass(FlextModels.ArbitraryTypesModel):
        """LDAP schema object class definition model (RFC 4512 compliant).

        Represents an LDAP object class definition from schema with full RFC 4512 support.
        """

        name: str = Field(..., description="Object class name")
        oid: str = Field(..., description="Object class OID")
        desc: str | None = Field(
            None,
            description="Object class description (RFC 4512 DESC)",
        )
        sup: str | list[str] | None = Field(
            None,
            description="Superior object class(es) (RFC 4512 SUP)",
        )
        kind: str = Field(
            default=FlextLdifConstants.Schema.STRUCTURAL,
            description="Object class kind (RFC 4512: STRUCTURAL, AUXILIARY, ABSTRACT)",
        )
        must: list[str] | None = Field(
            default=None,
            description="Required attributes (RFC 4512 MUST)",
        )
        may: list[str] | None = Field(
            default=None,
            description="Optional attributes (RFC 4512 MAY)",
        )
        metadata: FlextLdifModels.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata",
        )

        @computed_field
        def is_structural(self) -> bool:
            """Check if this is a structural object class."""
            return self.kind.upper() == FlextLdifConstants.Schema.STRUCTURAL

        @computed_field
        def is_auxiliary(self) -> bool:
            """Check if this is an auxiliary object class."""
            return self.kind.upper() == FlextLdifConstants.Schema.AUXILIARY

        @computed_field
        def is_abstract(self) -> bool:
            """Check if this is an abstract object class."""
            return self.kind.upper() == FlextLdifConstants.Schema.ABSTRACT

        @computed_field
        def total_attributes(self) -> int:
            """Total number of attributes (required + optional)."""
            must_count = len(self.must) if self.must else 0
            may_count = len(self.may) if self.may else 0
            return must_count + may_count

        @computed_field
        def attribute_summary(self) -> FlextLdifTypes.CommonDict.DistributionDict:
            """Get summary of required and optional attributes."""
            must_count = len(self.must) if self.must else 0
            may_count = len(self.may) if self.may else 0
            return {
                "required": must_count,
                "optional": may_count,
                "total": must_count + may_count,
            }

    class Entry(FlextModels.Entity):
        """LDIF entry domain model."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",  # Allow dynamic fields from conversions and transformations
        )

        dn: FlextLdifModels.DistinguishedName = Field(
            ...,
            description="Distinguished Name of the entry",
        )
        attributes: FlextLdifModels.LdifAttributes = Field(
            ...,
            description="Entry attributes container",
        )
        metadata: FlextLdifModels.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for preserving original entry format and server-specific data",
        )
        acls: list[FlextLdifModels.Acl] | None = Field(
            default=None,
            description="Access Control Lists extracted from entry attributes",
        )
        objectclasses: list[FlextLdifModels.SchemaObjectClass] | None = Field(
            default=None,
            description="ObjectClass definitions for schema validation",
        )
        attributes_schema: list[FlextLdifModels.SchemaAttribute] | None = Field(
            default=None,
            description="AttributeType definitions for schema validation",
        )
        entry_metadata: dict[str, object] | None = Field(
            default=None,
            description="Entry-level metadata (changetype, modifyTimestamp, etc.)",
        )
        validation_metadata: dict[str, object] | None = Field(
            default=None,
            description="Validation results and metadata from entry processing",
        )

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> FlextLdifModels.Entry:
            """Validate cross-field consistency in Entry model.

            Notes:
            - ObjectClass validation is optional - downstream code handles
              entries without objectClass via rejection or warnings.
            - Schema entries (dn: cn=schema) are allowed without objectClass
              as they contain schema definitions, not directory objects.

            Returns:
            Self (for method chaining)

            """
            # Allow entries without objectClass to pass through validation.
            # Downstream code (migration, quirks, etc.) will handle:
            # - Rejection of entries without required objectClass
            # - Logging of warnings for malformed entries
            # - Optional transformation or filtering based on application rules
            return self

        @computed_field
        def unconverted_attributes(self) -> dict[str, object]:
            """Get unconverted attributes from metadata extensions (read-only view)."""
            if self.metadata and "unconverted_attributes" in self.metadata.extensions:
                return cast(
                    "dict[str, object]",
                    self.metadata.extensions["unconverted_attributes"],
                )
            return {}

        @classmethod
        def create(
            cls,
            dn: str | FlextLdifModels.DistinguishedName,
            attributes: (
                FlextLdifTypes.CommonDict.AttributeDict | FlextLdifModels.LdifAttributes
            ),
            metadata: FlextLdifModels.QuirkMetadata | None = None,
            acls: list[FlextLdifModels.Acl] | None = None,
            objectclasses: list[FlextLdifModels.SchemaObjectClass] | None = None,
            attributes_schema: list[FlextLdifModels.SchemaAttribute] | None = None,
            entry_metadata: dict[str, object] | None = None,
            validation_metadata: dict[str, object] | None = None,
            server_type: FlextLdifModels.ServerType | None = None,  # New parameter
            source_entry: str | None = None,  # New parameter
            unconverted_attributes: dict[str, object] | None = None,  # New parameter
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create a new Entry instance with composition fields.

            Args:
            dn: Distinguished Name for the entry
            attributes: Entry attributes as dict[str, list[str]] or LdifAttributes
            metadata: Optional quirk metadata for preserving original format
            acls: Optional list of Access Control Lists for the entry
            objectclasses: Optional list of ObjectClass definitions for schema validation
            attributes_schema: Optional list of SchemaAttribute definitions for schema validation
            entry_metadata: Optional entry-level metadata (changetype, modifyTimestamp, etc.)
            validation_metadata: Optional validation results and metadata
            server_type: Optional server type for the entry (for quirk metadata)
            source_entry: Optional original source entry string (for quirk metadata)
            unconverted_attributes: Optional dictionary of unconverted attributes (for quirk metadata)

            Returns:
            FlextResult with Entry instance or validation error

            """
            try:
                # Convert string DN to DistinguishedName if needed
                dn_obj: FlextLdifModels.DistinguishedName
                if isinstance(dn, str):
                    # Directly instantiate DistinguishedName - Pydantic will validate
                    dn_obj = FlextLdifModels.DistinguishedName(value=dn)
                else:
                    dn_obj = dn

                # Convert dict[str, object] to LdifAttributes if needed
                attrs_obj: FlextLdifModels.LdifAttributes
                if isinstance(attributes, dict):
                    # Normalize attribute values to list[str]
                    attrs_dict: dict[str, list[str]] = {}
                    for attr_name, attr_values in attributes.items():
                        # Normalize to list if string
                        values_list: list[str] = (
                            [str(attr_values)]
                            if isinstance(attr_values, str)
                            else [str(v) for v in attr_values]
                        )
                        attrs_dict[attr_name] = values_list
                    attrs_obj = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                else:
                    attrs_obj = attributes

                # Handle metadata creation and update
                if metadata is None:
                    if server_type or source_entry or unconverted_attributes:
                        metadata = FlextLdifModels.QuirkMetadata(
                            server_type=server_type,
                            source_entry=source_entry,
                            extensions={
                                "unconverted_attributes": unconverted_attributes or {}
                            },
                        )
                elif server_type or source_entry or unconverted_attributes:
                    # Update existing metadata if new values are provided
                    metadata.server_type = server_type or metadata.server_type
                    metadata.source_entry = source_entry or metadata.source_entry
                    if unconverted_attributes:
                        if not metadata.extensions:
                            metadata.extensions = {}
                        metadata.extensions["unconverted_attributes"] = (
                            unconverted_attributes
                        )

                # Use model_validate to ensure Pydantic handles
                # default_factory fields. Entity fields have defaults.
                entry_data = {
                    FlextLdifConstants.DictKeys.DN: dn_obj,
                    FlextLdifConstants.DictKeys.ATTRIBUTES: attrs_obj,
                    "metadata": metadata,
                    "acls": acls,
                    "objectclasses": objectclasses,
                    "attributes_schema": attributes_schema,
                    "entry_metadata": entry_metadata,
                    "validation_metadata": validation_metadata,
                }
                return FlextResult[FlextLdifModels.Entry].ok(
                    cls.model_validate(entry_data),
                )
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create Entry: {e}",
                )

        @classmethod
        def from_ldap3(cls, ldap3_entry: object) -> FlextResult[FlextLdifModels.Entry]:
            """Create Entry from ldap3 Entry object.

            Args:
                ldap3_entry: ldap3 Entry object with entry_dn and entry_attributes_as_dict

            Returns:
                FlextResult with Entry instance or error

            """
            try:
                # Extract DN
                dn_str = str(getattr(ldap3_entry, "entry_dn", ""))

                # Extract attributes - ldap3 provides dict[str, list[str]]
                entry_attrs: dict[str, list[str]] = (
                    getattr(ldap3_entry, "entry_attributes_as_dict", {})
                    if hasattr(ldap3_entry, "entry_attributes_as_dict")
                    else {}
                )

                # Normalize to dict[str, list[str]] (ensure all values are lists of strings)
                attrs_dict: dict[str, list[str]] = {}
                for attr_name, attr_value_list in entry_attrs.items():
                    if isinstance(attr_value_list, list):
                        attrs_dict[attr_name] = [str(v) for v in attr_value_list]
                    elif isinstance(attr_value_list, str):
                        attrs_dict[attr_name] = [attr_value_list]
                    else:
                        attrs_dict[attr_name] = [str(attr_value_list)]

                # Use Entry.create to handle DN and attribute conversion
                from typing import cast as typing_cast

                return cls.create(
                    dn=dn_str,
                    attributes=typing_cast("dict[str, list[str] | str]", attrs_dict),
                )

            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create Entry from ldap3: {e}",
                )

        def get_attribute_values(self, attribute_name: str) -> list[str]:
            """Get all values for a specific attribute.

            LDAP attribute names are case-insensitive.

            Args:
            attribute_name: Name of the attribute to retrieve

            Returns:
            List of attribute values, empty list if attribute doesn't exist

            """
            # Case-insensitive attribute lookup (LDAP standard)
            attr_name_lower = attribute_name.lower()
            for stored_name, attr_values in self.attributes.attributes.items():
                if stored_name.lower() == attr_name_lower:
                    return attr_values
            return []

        def has_attribute(self, attribute_name: str) -> bool:
            """Check if entry has a specific attribute.

            LDAP attribute names are case-insensitive.

            Args:
            attribute_name: Name of the attribute to check

            Returns:
            True if attribute exists with at least one value, False otherwise

            """
            return len(self.get_attribute_values(attribute_name)) > 0

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specified object class.

            Args:
            object_class: Name of the object class to check

            Returns:
            True if entry has the object class, False otherwise

            """
            return object_class in self.get_attribute_values(
                FlextLdifConstants.DictKeys.OBJECTCLASS,
            )

        def get_all_attribute_names(self) -> list[str]:
            """Get list of all attribute names in the entry.

            Returns:
            List of attribute names (case as stored in entry)

            """
            return list(self.attributes.attributes.keys())

        def get_all_attributes(self) -> dict[str, list[str]]:
            """Get all attributes as dictionary.

            Returns:
            Dictionary of attribute_name -> list[str] (deep copy)

            """
            return dict(self.attributes.attributes)

        def count_attributes(self) -> int:
            """Count the number of attributes in the entry.

            Returns:
            Number of attributes (including multivalued attributes count as 1)

            """
            return len(self.attributes.attributes)

        def get_dn_components(self) -> list[str]:
            """Get DN components (RDN parts) from the entry's DN.

            Returns:
            List of DN components (e.g., ["cn=admin", "dc=example", "dc=com"])

            """
            components = self.dn.components
            return cast("list[str]", components)

        def matches_filter(
            self,
            filter_func: Callable[..., bool] | None = None,
        ) -> bool:
            """Check if entry matches a filter function.

            Convenience method for delegation to filters module.
            If no filter provided, returns True (entry matches).

            Args:
            filter_func: Optional callable that takes Entry and returns bool

            Returns:
            True if entry matches filter (or no filter provided), False otherwise

            """
            if filter_func is None:
                return True
            try:
                return filter_func(self)
            except Exception:
                return False

        def to_dict(self) -> dict[str, object]:
            """Convert Entry to dictionary representation.

            Used for serialization and data interchange.

            Returns:
            Dictionary with all entry fields

            """
            return {
                "dn": self.dn.value,
                "attributes": self.get_all_attributes(),
                "metadata": self.metadata,
                "acls": self.acls,
                "objectclasses": self.objectclasses,
                "entry_metadata": self.entry_metadata,
                "validation_metadata": self.validation_metadata,
            }

        def clone(self) -> FlextLdifModels.Entry:
            """Create an immutable copy of the entry.

            Returns:
            New Entry instance with same values (shallow copy of attributes)

            """
            return FlextLdifModels.Entry(
                dn=self.dn,
                attributes=FlextLdifModels.LdifAttributes(
                    attributes=dict(self.attributes.attributes),
                ),
                metadata=self.metadata,
                acls=list(self.acls) if self.acls else None,
                objectclasses=list(self.objectclasses) if self.objectclasses else None,
                entry_metadata=dict(self.entry_metadata)
                if self.entry_metadata
                else None,
                validation_metadata=dict(self.validation_metadata)
                if self.validation_metadata
                else None,
            )

        @computed_field
        def is_schema_entry(self) -> bool:
            """Check if entry is a schema definition entry.

            Schema entries contain objectClass definitions and are typically
            found in the schema naming context.

            Returns:
            True if entry has objectClasses, False otherwise

            """
            return bool(self.objectclasses)

        @computed_field
        def is_acl_entry(self) -> bool:
            """Check if entry has Access Control Lists.

            Returns:
            True if entry has ACLs, False otherwise

            """
            return bool(self.acls)

        @computed_field
        def has_validation_errors(self) -> bool:
            """Check if entry has validation errors.

            Returns:
            True if entry has validation errors in validation_metadata, False otherwise

            """
            if not self.validation_metadata:
                return False
            return bool(self.validation_metadata.get("errors"))

        def get_objectclass_names(self) -> list[str]:
            """Get list of objectClass attribute values from entry."""
            return self.get_attribute_values(FlextLdifConstants.DictKeys.OBJECTCLASS)

    class LdifAttributes(FlextModels.ArbitraryTypesModel):
        """LDIF attributes container - simplified dict-like interface."""

        model_config = ConfigDict(extra="allow")  # Allow dynamic attribute fields

        attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Attribute name to values list",
        )
        attribute_metadata: dict[str, dict[str, Any]] = Field(
            default_factory=dict,
            description="Metadata for each attribute, like category or hidden status.",
        )
        metadata: dict[str, object] | None = Field(
            default=None,
            description="Metadata for preserving ordering and formats",
        )

        def __len__(self) -> int:
            """Return the number of attributes."""
            return len(self.attributes)

        def __getitem__(self, key: str) -> list[str]:
            """Get attribute values by name (case-sensitive LDAP).

            Args:
                key: Attribute name

            Returns:
                List of attribute values

            Raises:
                KeyError if attribute not found

            """
            return self.attributes[key]

        def __setitem__(self, key: str, value: list[str]) -> None:
            """Set attribute values by name.

            Args:
                key: Attribute name
                value: List of values

            """
            self.attributes[key] = value

        def __contains__(self, key: str) -> bool:
            """Check if attribute exists."""
            return key in self.attributes

        def get(self, key: str, default: list[str] | None = None) -> list[str]:
            """Get attribute values with optional default.

            Args:
                key: Attribute name
                default: Default list if not found

            Returns:
                List of values or default

            """
            return self.attributes.get(key, default or [])

        def get_values(self, key: str, default: list[str] | None = None) -> list[str]:
            """Get attribute values as a list (same as get()).

            Args:
                key: Attribute name
                default: Default list if not found

            Returns:
                List of attribute values, or default if not found

            """
            return self.get(key, default)

        def has_attribute(self, key: str) -> bool:
            """Check if attribute exists.

            Args:
                key: Attribute name

            Returns:
                True if attribute exists

            """
            return key in self.attributes

        def iter_attributes(self) -> list[str]:
            """Get list of all attribute names.

            Returns:
                List of attribute names

            """
            return list(self.attributes.keys())

        def items(self) -> list[tuple[str, list[str]]]:
            """Get attribute name-values pairs.

            Returns:
                List of (name, values) tuples

            """
            return list(self.attributes.items())

        def keys(self) -> list[str]:
            """Get attribute names."""
            return list(self.attributes.keys())

        def values(self) -> list[list[str]]:
            """Get attribute values lists."""
            return list(self.attributes.values())

        def add_attribute(self, key: str, values: str | list[str]) -> None:
            """Add or update an attribute with values.

            Args:
                key: Attribute name
                values: Single value or list of values

            """
            if isinstance(values, str):
                values = [values]
            self.attributes[key] = values

        def remove_attribute(self, key: str) -> None:
            """Remove an attribute if it exists.

            Args:
                key: Attribute name

            """
            self.attributes.pop(key, None)

        def to_ldap3(
            self,
            exclude: list[str] | None = None,
        ) -> FlextLdifTypes.CommonDict.AttributeDict:
            """Convert to ldap3-compatible attributes dict.

            Args:
                exclude: List of attribute names to exclude from output

            Returns:
                Dict compatible with ldap3 library format

            """
            exclude_set = set(exclude or [])
            result: FlextLdifTypes.CommonDict.AttributeDict = {}

            for attr_name, values in self.attributes.items():
                if attr_name not in exclude_set:
                    result[attr_name] = values

            return result

        @classmethod
        def create(
            cls,
            attrs_data: dict[str, object],
        ) -> FlextResult[FlextLdifModels.LdifAttributes]:
            """Create an LdifAttributes instance from data.

            Args:
                attrs_data: Dictionary mapping attribute names to values

            Returns:
                FlextResult with LdifAttributes instance or error

            """
            try:
                # Normalize values to list[str]
                normalized_attrs: dict[str, list[str]] = {}
                for key, val in attrs_data.items():
                    if isinstance(val, list):
                        normalized_attrs[key] = [str(v) for v in val]
                    elif isinstance(val, str):
                        normalized_attrs[key] = [val]
                    else:
                        normalized_attrs[key] = [str(val)]

                return FlextResult[FlextLdifModels.LdifAttributes].ok(
                    cls(attributes=normalized_attrs),
                )
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[FlextLdifModels.LdifAttributes].fail(
                    f"Failed to create LdifAttributes: {e}",
                )

    class PipelineStatistics(FlextModels.ArbitraryTypesModel):
        """Statistics for LDIF pipeline operations.

        Tracks counts of entries processed, categorized, validated, and rejected
        during pipeline execution for monitoring and troubleshooting.

        Attributes:
        total_entries: Total entries processed
        processed_entries: Successfully processed entries
        schema_entries: Entries categorized as schema
        hierarchy_entries: Entries categorized as hierarchy
        user_entries: Entries categorized as users
        group_entries: Entries categorized as groups
        acl_entries: Entries categorized as ACLs
        rejected_entries: Entries rejected due to validation failures
        rejected_reasons: Map of rejection reason to entry count
        processing_duration: Time in seconds for processing

        """

        model_config = ConfigDict(
            arbitrary_types_allowed=True,
            validate_default=True,
        )

        total_entries: int = Field(
            default=0,
            ge=0,
            description="Total entries encountered",
        )
        processed_entries: int = Field(
            default=0,
            ge=0,
            description="Successfully processed entries",
        )
        schema_entries: int = Field(
            default=0,
            ge=0,
            description="Schema entries categorized",
        )
        hierarchy_entries: int = Field(
            default=0,
            ge=0,
            description="Hierarchy entries categorized",
        )
        user_entries: int = Field(
            default=0,
            ge=0,
            description="User entries categorized",
        )
        group_entries: int = Field(
            default=0,
            ge=0,
            description="Group entries categorized",
        )
        acl_entries: int = Field(default=0, ge=0, description="ACL entries categorized")
        rejected_entries: int = Field(default=0, ge=0, description="Entries rejected")
        rejected_reasons: dict[str, int] = Field(
            default_factory=dict,
            description="Rejection reason distribution",
        )
        processing_duration: float = Field(
            default=0.0,
            ge=0.0,
            description="Processing duration in seconds",
        )

    class PipelineExecutionResult(FlextModels.Value):
        """Result of pipeline execution containing categorized entries and statistics.

        Contains the complete result of a pipeline execution including entries
        organized by category, statistics, and output file paths. Immutable value
        object following DDD patterns.

        Attributes:
            entries_by_category: Entries organized by their categorization
            statistics: Pipeline execution statistics (always present)
            file_paths: Output file paths for each category

        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        entries_by_category: dict[str, list[FlextLdifModels.Entry]] = Field(
            default_factory=dict,
            description="Entries organized by category",
        )
        statistics: FlextLdifModels.PipelineStatistics = Field(
            default_factory=_create_default_pipeline_statistics,
            description="Pipeline execution statistics",
        )
        file_paths: dict[str, str] = Field(
            default_factory=dict,
            description="Output file paths for each category",
        )

    class SchemaBuilderResult(FlextModels.Value):
        """Result of schema builder build() operation.

        Contains attributes, object classes, server type, and metadata about the schema.

        Note: Uses builder-friendly field names (description, required_attributes)
        rather than RFC 4512 names (desc, must, may) for better API usability.

        Attributes:
            attributes: Dict of attribute name to attribute definition
            object_classes: Dict of object class name to object class definition
            server_type: Target LDAP server type identifier
            entry_count: Number of entries in the schema

        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
            str_strip_whitespace=True,
        )

        attributes: dict[str, dict[str, object]] = Field(
            default_factory=dict,
            description="Attribute definitions keyed by attribute name",
        )
        object_classes: dict[str, dict[str, object]] = Field(
            default_factory=dict,
            description="Object class definitions keyed by class name",
        )
        server_type: str = Field(
            default="generic",
            min_length=1,
            description="Target LDAP server type (generic, oid, oud, openldap, etc.)",
        )
        entry_count: int = Field(
            default=0,
            ge=0,
            description="Number of entries associated with this schema",
        )

        @computed_field
        def total_attributes(self) -> int:
            """Total number of attributes defined in schema.

            Returns:
                Count of attribute definitions

            """
            return len(self.attributes)

        @computed_field
        def total_object_classes(self) -> int:
            """Total number of object classes defined in schema.

            Returns:
                Count of object class definitions

            """
            return len(self.object_classes)

        @computed_field
        def is_empty(self) -> bool:
            """Check if schema has no attributes or object classes.

            Returns:
                True if schema is empty (no attributes and no object classes)

            """
            attrs_count: int = len(self.attributes)
            obj_classes_count: int = len(self.object_classes)
            return attrs_count == 0 and obj_classes_count == 0

        @computed_field
        def schema_dict(self) -> dict[str, object]:
            """Complete schema containing both attributes and object classes.

            Returns:
                Dict with 'attributes' and 'object_classes' keys

            """
            return {
                "attributes": self.attributes,
                "object_classes": self.object_classes,
            }

        @computed_field
        def schema_summary(self) -> dict[str, int | str]:
            """Summary of schema contents.

            Returns:
                Dict with counts of attributes, object classes, server type, and entries

            """
            # Access fields directly to avoid recursion with model_dump()
            # Cast computed fields to proper types for Pyrefly compatibility
            attrs: int = cast("int", self.total_attributes)
            ocs: int = cast("int", self.total_object_classes)
            return {
                "attributes": attrs,
                "object_classes": ocs,
                "server_type": self.server_type,
                "entry_count": self.entry_count,
            }

    class MigrationStatistics(FlextModels.Value):
        """Statistics from LDIF migration pipeline execution.

        Tracks counts of migrated schema elements and entries with computed metrics
        for success rate and completeness assessment.

        Attributes:
            total_schema_attributes: Count of schema attributes migrated
            total_schema_objectclasses: Count of schema object classes migrated
            total_entries: Count of directory entries migrated
            failed_entries: Count of entries that failed migration (default 0)

        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        total_schema_attributes: int = Field(
            default=0,
            ge=0,
            description="Number of schema attributes migrated",
        )
        total_schema_objectclasses: int = Field(
            default=0,
            ge=0,
            description="Number of schema object classes migrated",
        )
        total_entries: int = Field(
            default=0,
            ge=0,
            description="Number of directory entries migrated",
        )
        failed_entries: int = Field(
            default=0,
            ge=0,
            description="Number of entries that failed migration",
        )

        @computed_field
        def total_schema_elements(self) -> int:
            """Total count of schema elements (attributes + object classes).

            Returns:
                Sum of attributes and object classes

            """
            return self.total_schema_attributes + self.total_schema_objectclasses

        @computed_field
        def total_items(self) -> int:
            """Total count of all migrated items (schema + entries).

            Returns:
                Sum of schema elements and entries

            """
            # Cast computed field to proper type for Pyrefly compatibility
            schema_elems: int = cast("int", self.total_schema_elements)
            return schema_elems + self.total_entries

        @computed_field
        def has_schema(self) -> bool:
            """Check if any schema elements were migrated.

            Returns:
                True if attributes or object classes exist

            """
            # Cast computed field to proper type for Pyrefly compatibility
            schema_elems: int = cast("int", self.total_schema_elements)
            return schema_elems > 0

        @computed_field
        def has_entries(self) -> bool:
            """Check if any entries were migrated.

            Returns:
                True if entry count > 0

            """
            return self.total_entries > 0

        @computed_field
        def success_rate(self) -> float:
            """Calculate migration success rate as percentage.

            Returns:
                Success rate 0.0-100.0, or 100.0 if no entries to migrate

            """
            total_attempted = self.total_entries + self.failed_entries
            if total_attempted == 0:
                return 100.0
            successful = self.total_entries
            return (successful / total_attempted) * 100.0

        @computed_field
        def statistics_summary(self) -> dict[str, int | float]:
            """Comprehensive statistics summary.

            Returns:
                Dict with all counts and computed metrics

            """
            # Access fields directly to avoid recursion with model_dump()
            # Cast computed fields to proper types for Pyrefly compatibility
            schema_elems: int = cast("int", self.total_schema_elements)
            total_items: int = cast("int", self.total_items)
            success: float = cast("float", self.success_rate)
            return {
                "schema_attributes": self.total_schema_attributes,
                "schema_objectclasses": self.total_schema_objectclasses,
                "total_schema": schema_elems,
                "entries": self.total_entries,
                "failed": self.failed_entries,
                "total_items": total_items,
                "success_rate": round(success, 2),
            }

    # =========================================================================
    # RESPONSE MODELS - Composed from domain models and statistics
    # =========================================================================

    class ParseStatistics(FlextModels.Value):
        """Statistics from LDIF parsing operation (composed from PipelineStatistics pattern)."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        total_entries: int = Field(ge=0, description="Total entries parsed")
        schema_entries: int = Field(ge=0, description="Schema type entries")
        data_entries: int = Field(ge=0, description="Data entries")
        parse_errors: int = Field(ge=0, description="Parse errors encountered")
        detected_server_type: str | None = Field(
            None,
            description="Auto-detected server type from content",
        )

        @computed_field
        def success_rate(self) -> float:
            """Success rate as percentage."""
            if self.total_entries == 0:
                return 100.0
            return (
                (self.total_entries - self.parse_errors) / self.total_entries
            ) * 100.0

    class ParseResponse(FlextModels.Value):
        """Composed response from parsing operation.

        Combines Entry models with statistics from parse operation.
        Uses model composition instead of dict intermediaries.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        entries: list[FlextLdifModels.Entry] = Field(description="Parsed LDIF entries")
        statistics: FlextLdifModels.ParseStatistics = Field(
            description="Parse operation statistics"
        )
        detected_server_type: str | None = Field(None)

    class WriteStatistics(FlextModels.Value):
        """Statistics from LDIF write operation."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        entries_written: int = Field(ge=0, description="Number of entries written")
        output_file: str | None = Field(None, description="Output file path")
        file_size_bytes: int = Field(
            ge=0, default=0, description="Written file size in bytes"
        )
        encoding: str = Field(default="utf-8", description="File encoding used")

    class WriteResponse(FlextModels.Value):
        """Composed response from write operation.

        Contains written LDIF content and statistics using model composition.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        content: str | None = Field(None, description="Written LDIF content")
        statistics: FlextLdifModels.WriteStatistics = Field(
            description="Write operation statistics"
        )

    class WriteFormatOptions(FlextModels.Value):
        """Formatting options for LDIF serialization.

        Provides detailed control over the output format, including line width
        for folding, and whether to respect attribute ordering from metadata.
        """

        model_config = ConfigDict(frozen=True)

        line_width: int = Field(
            default=FlextLdifConstants.LdifFormat.DEFAULT_LINE_WIDTH,
            ge=10,
            le=100000,
            description="Maximum line width before folding (RFC 2849 recommends 76). Set high for no folding.",
        )
        disable_line_folding: bool = Field(
            default=False,
            description="If True, disables line folding completely (ignores line_width).",
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
            default=True,
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

    class AclStatistics(FlextModels.Value):
        """Statistics from ACL extraction operation."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        total_entries_processed: int = Field(ge=0, description="Total entries analyzed")
        entries_with_acls: int = Field(ge=0, description="Entries containing ACLs")
        total_acls_extracted: int = Field(
            ge=0, description="Total ACL objects extracted"
        )
        acl_attribute_name: str | None = Field(
            None,
            description="Primary ACL attribute name found",
        )

    class AclResponse(FlextModels.Value):
        """Composed response from ACL extraction.

        Combines extracted Acl models with extraction statistics.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        acls: list[FlextLdifModels.Acl] = Field(description="Extracted ACL models")
        statistics: FlextLdifModels.AclStatistics = Field(
            description="ACL extraction statistics"
        )

    class MigrationPipelineResult(FlextModels.Value):
        """Result of migration pipeline execution.

        Contains migrated schema, entries, statistics, and output file paths
        from a complete LDIF migration operation. Immutable value object following
        DDD patterns.

        Attributes:
            migrated_schema: Migrated schema data (attributes and object classes)
            entries: List of migrated directory entries as dicts
            stats: Migration statistics with computed metrics (always present)
            output_files: List of generated output file paths

        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        migrated_schema: dict[str, object] = Field(
            default_factory=dict,
            description="Migrated schema data",
        )
        entries: list[object] = Field(
            default_factory=list,
            description="List of migrated directory entries (Entry objects or dicts)",
        )
        stats: FlextLdifModels.MigrationStatistics = Field(
            default_factory=_create_default_migration_statistics,
            description="Migration statistics and metrics",
        )
        output_files: list[str] = Field(
            default_factory=list,
            description="Generated output file paths",
        )

        @computed_field
        def is_empty(self) -> bool:
            """Check if migration produced no results.

            Returns:
                True if no schema and no entries were migrated

            """
            # Compute directly instead of accessing computed field properties
            has_schema: bool = (
                self.stats.total_schema_attributes > 0
                or self.stats.total_schema_objectclasses > 0
            )
            has_entries: bool = self.stats.total_entries > 0
            return not has_schema and not has_entries

        @computed_field
        def entry_count(self) -> int:
            """Get count of migrated entries.

            Returns:
                Number of entries in entries list

            """
            return len(self.entries)

        @computed_field
        def output_file_count(self) -> int:
            """Get count of generated output files.

            Returns:
                Number of output files produced

            """
            return len(self.output_files)

        @computed_field
        def migration_summary(self) -> dict[str, object]:
            """Comprehensive migration result summary.

            Returns:
                Dict with statistics, entry count, and output file count

            """
            return {
                "statistics": self.stats.statistics_summary,
                "entry_count": self.entry_count,
                "output_files": self.output_file_count,
                "is_empty": self.is_empty,
            }

    # =========================================================================
    # CLIENT AND SERVICE RESULT MODELS
    # =========================================================================

    class ClientStatus(FlextModels.Value):
        """Client status information."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        status: str = Field(description="Client initialization status")
        services: list[str] = Field(
            default_factory=list,
            description="List of registered service names",
        )
        config: dict[str, object] = Field(
            default_factory=dict,
            description="Active configuration settings",
        )

    class ValidationResult(FlextModels.Value):
        """Entry validation result."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        is_valid: bool = Field(description="Overall validation status")
        total_entries: int = Field(
            ge=0,
            description="Total number of entries validated",
        )
        valid_entries: int = Field(ge=0, description="Number of valid entries")
        invalid_entries: int = Field(ge=0, description="Number of invalid entries")
        errors: list[str] = Field(
            default_factory=list,
            description="List of validation error messages",
        )

        @computed_field
        def success_rate(self) -> float:
            """Calculate validation success rate as percentage."""
            if self.total_entries == 0:
                return 100.0
            return (self.valid_entries / self.total_entries) * 100.0

    class MigrationEntriesResult(FlextModels.Value):
        """Result from migrating entries between servers."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        total_entries: int = Field(ge=0, description="Total number of input entries")
        migrated_entries: int = Field(
            ge=0,
            description="Number of successfully migrated entries",
        )
        from_server: str = Field(description="Source server type")
        to_server: str = Field(description="Target server type")
        success: bool = Field(description="Migration completion status")

        @computed_field
        def migration_rate(self) -> float:
            """Calculate migration success rate as percentage."""
            if self.total_entries == 0:
                return 100.0
            return (self.migrated_entries / self.total_entries) * 100.0

    class EntryAnalysisResult(FlextModels.Value):
        """Result from entry analysis operations."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        total_entries: int = Field(ge=0, description="Total number of entries analyzed")
        objectclass_distribution: dict[str, int] = Field(
            default_factory=dict,
            description="Distribution of object classes",
        )
        patterns_detected: list[str] = Field(
            default_factory=list,
            description="Detected patterns in entries",
        )

        @computed_field
        def unique_objectclasses(self) -> int:
            """Count of unique object classes."""
            return len(self.objectclass_distribution)

    class ServerDetectionResult(FlextModels.Value):
        """Result from LDAP server type detection."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        detected_server_type: str = Field(description="Detected LDAP server type")
        confidence: float = Field(
            ge=0.0,
            le=1.0,
            description="Detection confidence score",
        )
        scores: dict[str, int] = Field(
            default_factory=dict,
            description="Score for each server type",
        )
        patterns_found: list[str] = Field(
            default_factory=list,
            description="List of detected server-specific patterns",
        )
        is_confident: bool = Field(description="Whether confidence meets threshold")
        detection_error: str | None = Field(
            default=None,
            description="Error message if detection failed",
        )
        fallback_reason: str | None = Field(
            default=None,
            description="Reason for fallback to RFC mode",
        )

    class QuirkCollection(FlextModels.Value):
        """Collection of all quirks (Schema, ACL, Entry) for a single server type.

        Stores all three quirk types together for unified access and management.
        """

        model_config = ConfigDict(
            arbitrary_types_allowed=True,
            frozen=True,
            validate_default=True,
        )

        server_type: str = Field(
            description="Server type identifier (e.g., 'oid', 'oud')",
        )
        schema_quirks: list[object] = Field(
            default_factory=list,
            description="List of Schema quirk model instances",
        )
        acl_quirks: list[object] = Field(
            default_factory=list,
            description="List of ACL quirk model instances",
        )
        entrys: list[object] = Field(
            default_factory=list,
            description="List of Entry quirk model instances",
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


__all__ = ["FlextLdifModels"]
