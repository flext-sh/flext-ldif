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

import operator
import re
from collections.abc import Callable, Generator, Mapping
from typing import Any, ClassVar, Literal, cast

from flext_core import FlextLogger, FlextModels, FlextResult
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants

logger = FlextLogger(__name__)


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Unified namespace class that aggregates all LDIF domain models.
    Provides a single access point for all LDIF models while maintaining
    modular organization.

    This class extends flext-core FlextModels and organizes LDIF-specific
    models into focused sub-modules for better maintainability.
    """

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
        server_type: str | None = Field(
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
        priority: int | None = Field(
            default=None,
            description="Priority level for quirk processing",
        )
        description: str | None = Field(
            default=None,
            description="Description of the quirk metadata or processing",
        )

        @classmethod
        def create_for(
            cls,
            quirk_type: str,
            original_format: str | None = None,
            extensions: dict[str, object] | None = None,
            custom_data: dict[str, object] | None = None,
            server_type: str | None = None,
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

    class ErrorDetail(FlextModels.Value):
        """Error detail information for failed operations.

        Replaces dict[str, Any] with type-safe error tracking.
        """

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",  # Allow additional error context
        )

        item: str = Field(
            ...,
            description="Item that failed (DN, entry, attribute name, etc.)",
        )
        error: str = Field(
            ...,
            description="Error message describing the failure",
        )
        error_code: str | None = Field(
            default=None,
            description="Optional error code for categorization",
        )
        context: dict[str, object] = Field(
            default_factory=dict,
            description="Additional context information for the error",
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
            data: dict[str, object],
        ) -> FlextResult[FlextLdifModels.AclPermissions]:
            """Create an AclPermissions instance from data."""
            try:
                # Create mutable copy of data
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

            Returns the RFC baseline ACL format constant.

            NOTE: Core modules (models.py) cannot access services/* or servers/* per architecture.
            For server-specific formats, the services layer should query FlextLdifServer registry
            and pass the value when creating Acl models.
            """
            from flext_ldif.constants import FlextLdifConstants

            # Return RFC baseline ACL format
            return FlextLdifConstants.AclFormats.DEFAULT_ACL_FORMAT

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
        object_class_distribution: dict[str, int] = Field(
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

    class CategoryRules(BaseModel):
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

    class WhitelistRules(BaseModel):
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
        def summary(self) -> dict[str, int]:
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

        attributes: dict[str, dict[str, object]] = Field(
            default_factory=dict,
            description="Discovered attributes with their metadata",
        )
        objectclasses: dict[str, dict[str, object]] = Field(
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
        server_info: Any = Field(
            default=None,
            description="LDAP server information from Root DSE",
        )
        servers: Any = Field(
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
        # OUD and server-specific fields
        immutable: bool = Field(
            default=False,
            description="Whether attribute is immutable (OUD extension)",
        )
        user_modification: bool = Field(
            default=True,
            description="Whether users can modify this attribute (OUD extension)",
        )
        obsolete: bool = Field(
            default=False,
            description="Whether attribute is obsolete (OUD extension)",
        )
        x_origin: str | None = Field(
            None,
            description="Origin of attribute definition (server-specific X-ORIGIN extension)",
        )
        x_file_ref: str | None = Field(
            None,
            description="File reference for attribute definition (server-specific X-FILE-REF extension)",
        )
        x_name: str | None = Field(
            None,
            description="Extended name for attribute (server-specific X-NAME extension)",
        )
        x_alias: str | None = Field(
            None,
            description="Extended alias for attribute (server-specific X-ALIAS extension)",
        )
        x_oid: str | None = Field(
            None,
            description="Extended OID for attribute (server-specific X-OID extension)",
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
            oid: str,
            server_type: str = "rfc",
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
                        name,
                        "string",
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

            except (ImportError, Exception) as e:
                # Log and return None for any resolution errors
                # This prevents the model from being invalid due to service failures
                logger.warning(
                    "Failed to resolve syntax for field, returning None: %s",
                    e,
                    exc_info=True,
                )
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
        def attribute_summary(self) -> dict[str, int]:
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
                result = self.metadata.extensions["unconverted_attributes"]
                if isinstance(result, dict):
                    return result
            return {}

        @classmethod
        def create(
            cls,
            dn: str | FlextLdifModels.DistinguishedName,
            attributes: (dict[str, str | list[str]] | FlextLdifModels.LdifAttributes),
            metadata: FlextLdifModels.QuirkMetadata | None = None,
            acls: list[FlextLdifModels.Acl] | None = None,
            objectclasses: list[FlextLdifModels.SchemaObjectClass] | None = None,
            attributes_schema: list[FlextLdifModels.SchemaAttribute] | None = None,
            entry_metadata: dict[str, object] | None = None,
            validation_metadata: dict[str, object] | None = None,
            server_type: str | None = None,  # New parameter
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
                                "unconverted_attributes": unconverted_attributes or {},
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
        def from_ldap3(cls, ldap3_entry: Any) -> FlextResult[FlextLdifModels.Entry]:
            """Create Entry from ldap3 Entry object.

            Args:
                ldap3_entry: ldap3 Entry object with entry_dn and entry_attributes_as_dict

            Returns:
                FlextResult with Entry instance or error

            """
            try:
                # Extract DN
                dn_str = str(getattr(ldap3_entry, "entry_dn", ""))

                # Extract attributes - ldap3 provides dict with various types
                entry_attrs_raw: Any = (
                    getattr(ldap3_entry, "entry_attributes_as_dict", {})
                    if hasattr(ldap3_entry, "entry_attributes_as_dict")
                    else {}
                )

                # Normalize to dict[str, list[str]] (ensure all values are lists of strings)
                attrs_dict: dict[str, list[str]] = {}
                if isinstance(entry_attrs_raw, dict):
                    for attr_name, attr_value_list in entry_attrs_raw.items():
                        if isinstance(attr_value_list, list):
                            attrs_dict[str(attr_name)] = [
                                str(v) for v in attr_value_list
                            ]
                        elif isinstance(attr_value_list, str):
                            attrs_dict[str(attr_name)] = [attr_value_list]
                        else:
                            attrs_dict[str(attr_name)] = [str(attr_value_list)]

                # Use Entry.create to handle DN and attribute conversion
                # Cast attrs_dict to expected type for type safety
                from typing import cast

                attributes_typed = cast("dict[str, str | list[str]]", attrs_dict)
                return cls.create(
                    dn=dn_str,
                    attributes=attributes_typed,
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
            return self.dn.components()

        def matches_filter(
            self,
            filter_func: Callable[[FlextLdifModels.Entry], bool] | None = None,
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
                # filter_func expects Entry object (per signature)
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
        attribute_metadata: dict[str, dict[str, object]] = Field(
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

        def __iter__(self) -> Generator[tuple[str, Any]]:
            """Iterate over attribute items (name, values).

            Conforms to Pydantic BaseModel __iter__ contract.
            Allows: for name, values in attributes_obj: ...

            Returns:
                Generator of (attribute_name, attribute_values) tuples

            """
            yield from self.attributes.items()

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
        ) -> dict[str, str | list[str]]:
            """Convert to ldap3-compatible attributes dict.

            Args:
                exclude: List of attribute names to exclude from output

            Returns:
                Dict compatible with ldap3 library format

            """
            exclude_set = set(exclude or [])
            return {
                attr_name: values
                for attr_name, values in self.attributes.items()
                if attr_name not in exclude_set
            }

        @classmethod
        def create(
            cls,
            attrs_data: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.LdifAttributes]:
            """Create an LdifAttributes instance from data.

            Args:
                attrs_data: Mapping of attribute names to values (str, list[str], or object)

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

        def mark_as_deleted(
            self,
            attribute_name: str,
            reason: str,
            deleted_by: str,
        ) -> None:
            """Mark attribute as soft-deleted with audit trail.

            HIGH COMPLEXITY: Uses UTC timestamp, tracks deletion metadata,
            preserves original values for compliance/rollback.

            Uses existing attribute_metadata dict to track deletion.
            Attribute stays in self.attributes but is marked.

            Args:
                attribute_name: Name of attribute to mark deleted
                reason: Reason for deletion (e.g., "migration", "obsolete")
                deleted_by: Server/quirk that deleted it (e.g., "oid", "oud")

            Raises:
                ValueError: If attribute not found in attributes

            """
            from datetime import UTC, datetime

            if attribute_name not in self.attributes:
                msg = f"Attribute '{attribute_name}' not found in attributes"
                raise ValueError(msg)

            # Use existing attribute_metadata dict
            self.attribute_metadata[attribute_name] = {
                "status": "deleted",
                "deleted_at": datetime.now(UTC).isoformat(),
                "deleted_reason": reason,
                "deleted_by": deleted_by,
                "original_values": self.attributes[attribute_name].copy(),
            }

        def get_active_attributes(self) -> dict[str, list[str]]:
            """Get only active attributes (exclude deleted/hidden).

            MEDIUM COMPLEXITY: Filters attributes based on metadata status,
            handles missing metadata gracefully.

            Returns:
                Dict of attribute_name -> values for active attributes only

            """
            if not self.attribute_metadata:
                return dict(self.attributes)

            return {
                name: values
                for name, values in self.attributes.items()
                if self.attribute_metadata.get(name, {}).get("status", "active")
                not in {"deleted", "hidden"}
            }

        def get_deleted_attributes(self) -> dict[str, dict[str, object]]:
            """Get soft-deleted attributes with their metadata.

            MEDIUM COMPLEXITY: Returns deleted attributes with full audit trail
            (timestamp, reason, original values) for reconciliation.

            Returns:
                Dict of attribute_name -> metadata_dict for deleted attributes

            """
            if not self.attribute_metadata:
                return {}

            return {
                name: meta
                for name, meta in self.attribute_metadata.items()
                if meta.get("status") == "deleted"
            }

    class EntryResult(FlextModels.Value):
        """Result of LDIF processing containing categorized entries and statistics.

        This is the UNIFIED result model for all LDIF operations. Contains entries
        organized by category, comprehensive statistics, and output file paths.

        Immutable value object following DDD patterns.

        Attributes:
            entries_by_category: Entries organized by their categorization
                                (schema, hierarchy, users, groups, acl, data, rejected)
            statistics: Comprehensive execution statistics (counts, durations, reasons)
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
        statistics: FlextLdifModels.Statistics | None = Field(
            default=None,
            description="Pipeline execution statistics",
        )
        file_paths: dict[str, str] = Field(
            default_factory=dict,
            description="Output file paths for each category",
        )

        def get_all_entries(self) -> list[FlextLdifModels.Entry]:
            """Flatten all categories into single list.

            Returns:
                List of all entries from all categories combined.

            """
            all_entries: list[FlextLdifModels.Entry] = []
            for entries in self.entries_by_category.values():
                all_entries.extend(entries)
            return all_entries

        def get_category(
            self,
            category: str,
            default: list[FlextLdifModels.Entry] | None = None,
        ) -> list[FlextLdifModels.Entry]:
            """Get entries from specific category safely.

            Args:
                category: Category name to retrieve
                default: Default value if category not found

            Returns:
                List of entries in the category, or default if not found.

            """
            return self.entries_by_category.get(category, default or [])

        @classmethod
        def from_entries(
            cls,
            entries: list[FlextLdifModels.Entry],
            category: str = "all",
            statistics: FlextLdifModels.Statistics | None = None,
        ) -> FlextLdifModels.EntryResult:
            """Create EntryResult from list of entries.

            Args:
                entries: List of Entry objects
                category: Category name for the entries (default: "all")
                statistics: Optional statistics object (creates default if None)

            Returns:
                New EntryResult instance.

            """
            stats = statistics or FlextLdifModels.Statistics.for_pipeline(
                total=len(entries)
            )
            return cls(
                entries_by_category={category: entries},
                statistics=stats,
            )

        @classmethod
        def empty(cls) -> FlextLdifModels.EntryResult:
            """Create empty EntryResult.

            Returns:
                Empty EntryResult with no entries and default statistics.

            """
            return cls(
                entries_by_category={},
                statistics=FlextLdifModels.Statistics.for_pipeline(),
            )

        def merge(
            self, other: FlextLdifModels.EntryResult
        ) -> FlextLdifModels.EntryResult:
            """Merge two EntryResults.

            Combines entries from both results, with categories merged.
            If same category exists in both, entries are concatenated.
            Statistics are summed for numeric fields.

            Args:
                other: Another EntryResult to merge with this one

            Returns:
                New EntryResult with merged data.

            """
            # Merge categories - concatenate entries for duplicate categories
            merged_categories: dict[str, list[FlextLdifModels.Entry]] = {
                **self.entries_by_category
            }
            for cat, entries in other.entries_by_category.items():
                if cat in merged_categories:
                    merged_categories[cat] = list(merged_categories[cat]) + list(
                        entries
                    )
                else:
                    merged_categories[cat] = list(entries)

            # Merge statistics (sum counters)
            # Handle None statistics by creating defaults
            self_stats = self.statistics or FlextLdifModels.Statistics.for_pipeline()
            other_stats = other.statistics or FlextLdifModels.Statistics.for_pipeline()

            merged_stats = self_stats.model_copy(
                update={
                    "total_entries": self_stats.total_entries
                    + other_stats.total_entries,
                }
            )

            # Merge file paths
            merged_paths = {**self.file_paths, **other.file_paths}

            return self.__class__(
                entries_by_category=merged_categories,
                statistics=merged_stats,
                file_paths=merged_paths,
            )

        # =====================================================================
        # DOMAIN EVENT ACCESS (v1.0.0+)
        # =====================================================================

        @property
        def events(
            self,
        ) -> list[
            FlextLdifModels.ParseEvent
            | FlextLdifModels.FilterEvent
            | FlextLdifModels.CategoryEvent
            | FlextLdifModels.WriteEvent
            | FlextLdifModels.AclEvent
            | FlextLdifModels.DnEvent
            | FlextLdifModels.MigrationEvent
            | FlextLdifModels.ConversionEvent
            | FlextLdifModels.SchemaEvent
        ]:
            """Access domain events from statistics.

            Returns empty list if statistics is None or has no events.
            Provides convenient access to audit trail.

            Returns:
                List of domain events from statistics.events

            Example:
                >>> result = parser.parse(content)
                >>> for event in result.events:
                ...     print(f"{event.timestamp}: {type(event).__name__}")

            """
            return self.statistics.events if self.statistics else []

        @property
        def has_events(self) -> bool:
            """Indicates whether domain events are tracked in this result.

            Returns:
                True if events list is not empty.

            """
            return bool(self.events)

        def add_event(
            self,
            event: (
                FlextLdifModels.ParseEvent
                | FlextLdifModels.FilterEvent
                | FlextLdifModels.CategoryEvent
                | FlextLdifModels.WriteEvent
                | FlextLdifModels.AclEvent
                | FlextLdifModels.DnEvent
                | FlextLdifModels.MigrationEvent
                | FlextLdifModels.ConversionEvent
                | FlextLdifModels.SchemaEvent
            ),
        ) -> FlextLdifModels.EntryResult:
            """Add domain event to statistics (immutable operation).

            Creates new EntryResult with event added to statistics.events.
            If statistics is None, creates new Statistics with single event.

            Args:
                event: Domain event to add

            Returns:
                New EntryResult with event added

            Example:
                >>> filter_event = FlextLdifModels.FilterEvent(
                ...     event_id="evt_001",
                ...     timestamp=datetime.now(timezone.utc),
                ...     filter_operation="filter_by_dn",
                ...     entries_before=100,
                ...     entries_after=50,
                ...     filter_duration_ms=25.0,
                ... )
                >>> new_result = result.add_event(filter_event)
                >>> assert len(new_result.events) == len(result.events) + 1

            """
            if not self.statistics:
                new_stats = FlextLdifModels.Statistics(events=[event])
            else:
                new_stats = self.statistics.add_event(event)

            return self.model_copy(update={"statistics": new_stats})

        def get_events_by_type(
            self, event_type: type[FlextModels.DomainEvent]
        ) -> list[FlextModels.DomainEvent]:
            """Filter events by type.

            Args:
                event_type: Event class to filter

            Returns:
                List of events matching type

            Example:
                >>> parse_events = result.get_events_by_type(FlextLdifModels.ParseEvent)
                >>> for event in parse_events:
                ...     print(f"Parsed {event.entries_parsed} entries")

            """
            return [e for e in self.events if isinstance(e, event_type)]

    class Statistics(FlextModels.Value):
        """Unified statistics model for all LDIF operations.

        Consolidates PipelineStatistics, ParseStatistics, WriteStatistics,
        and AclStatistics into a single model following the EntryResult pattern.

        Uses helper methods to create operation-specific statistics while
        maintaining a single source of truth for all statistical data.

        Attributes:
            Core counters (all operations):
                total_entries: Total entries encountered/processed
                processed_entries: Successfully processed entries
                failed_entries: Entries that failed processing

            Category counters (pipeline operations):
                schema_entries: Schema entries categorized
                data_entries: Data entries (non-schema)
                hierarchy_entries: Hierarchy/organizational entries
                user_entries: User entries
                group_entries: Group entries
                acl_entries: ACL entries

            Schema migration counters:
                schema_attributes: Schema attributes migrated
                schema_objectclasses: Schema object classes migrated

            ACL extraction counters:
                acls_extracted: Total ACL objects extracted
                acls_failed: ACL parsing failures
                acl_attribute_name: Primary ACL attribute name

            Parsing counters:
                parse_errors: Parse errors encountered
                detected_server_type: Auto-detected LDAP server type

            Writing counters:
                entries_written: Entries successfully written
                output_file: Output file path
                file_size_bytes: Written file size
                encoding: File encoding used

            Metadata:
                processing_duration: Processing time in seconds
                rejection_reasons: Map of rejection reason to count

        Example:
            >>> # Parsing statistics
            >>> stats = Statistics.for_parsing(total=100, schema=10, data=90, errors=2)
            >>>
            >>> # Pipeline statistics
            >>> stats = Statistics.for_pipeline(
            ...     total=100, processed=98, schema=10, users=50, groups=38
            ... )
            >>>
            >>> # Merge statistics
            >>> combined = stats1.merge(stats2)

        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        # CORE COUNTERS
        total_entries: int = Field(
            default=0,
            ge=0,
            description="Total entries encountered/processed",
        )
        processed_entries: int = Field(
            default=0,
            ge=0,
            description="Successfully processed entries",
        )
        failed_entries: int = Field(
            default=0,
            ge=0,
            description="Entries that failed processing",
        )

        # CATEGORY COUNTERS
        schema_entries: int = Field(
            default=0,
            ge=0,
            description="Schema entries categorized",
        )
        data_entries: int = Field(
            default=0,
            ge=0,
            description="Data entries (non-schema)",
        )
        hierarchy_entries: int = Field(
            default=0,
            ge=0,
            description="Hierarchy/organizational entries",
        )
        user_entries: int = Field(
            default=0,
            ge=0,
            description="User entries",
        )
        group_entries: int = Field(
            default=0,
            ge=0,
            description="Group entries",
        )
        acl_entries: int = Field(
            default=0,
            ge=0,
            description="ACL entries",
        )
        rejected_entries: int = Field(
            default=0,
            ge=0,
            description="Entries rejected during processing",
        )

        # SCHEMA MIGRATION COUNTERS
        schema_attributes: int = Field(
            default=0,
            ge=0,
            description="Schema attributes migrated",
        )
        schema_objectclasses: int = Field(
            default=0,
            ge=0,
            description="Schema object classes migrated",
        )

        # ACL EXTRACTION COUNTERS
        acls_extracted: int = Field(
            default=0,
            ge=0,
            description="Total ACL objects extracted",
        )
        acls_failed: int = Field(
            default=0,
            ge=0,
            description="ACL parsing failures",
        )
        acl_attribute_name: str | None = Field(
            default=None,
            description="Primary ACL attribute name",
        )

        # PARSING COUNTERS
        parse_errors: int = Field(
            default=0,
            ge=0,
            description="Parse errors encountered",
        )
        detected_server_type: str | None = Field(
            default=None,
            description="Auto-detected LDAP server type",
        )

        # WRITING COUNTERS
        entries_written: int = Field(
            default=0,
            ge=0,
            description="Entries successfully written",
        )
        output_file: str | None = Field(
            default=None,
            description="Output file path",
        )
        file_size_bytes: int = Field(
            default=0,
            ge=0,
            description="Written file size in bytes",
        )
        encoding: str = Field(
            default="utf-8",
            description="File encoding used",
        )

        # METADATA
        processing_duration: float = Field(
            default=0.0,
            ge=0.0,
            description="Processing duration in seconds",
        )
        rejection_reasons: dict[str, int] = Field(
            default_factory=dict,
            description="Rejection reason distribution",
        )

        # DOMAIN EVENTS (v1.0.0+)
        events: list[
            FlextLdifModels.ParseEvent
            | FlextLdifModels.FilterEvent
            | FlextLdifModels.CategoryEvent
            | FlextLdifModels.WriteEvent
            | FlextLdifModels.AclEvent
            | FlextLdifModels.DnEvent
            | FlextLdifModels.MigrationEvent
            | FlextLdifModels.ConversionEvent
            | FlextLdifModels.SchemaEvent
        ] = Field(
            default_factory=list,
            description="Domain events capturing operation history (v1.0.0+)",
        )

        # COMPUTED FIELDS
        @computed_field
        def success_rate(self) -> float:
            """Calculate success rate percentage.

            Returns:
                Success rate as percentage (0.0-100.0).

            """
            if self.total_entries == 0:
                return 100.0
            return (
                (self.total_entries - self.failed_entries) / self.total_entries
            ) * 100.0

        @computed_field
        def has_schema(self) -> bool:
            """Check if schema elements exist.

            Returns:
                True if any schema attributes or objectclasses present.

            """
            return (self.schema_attributes + self.schema_objectclasses) > 0

        @computed_field
        def has_entries(self) -> bool:
            """Check if entries exist.

            Returns:
                True if total_entries > 0.

            """
            return self.total_entries > 0

        @computed_field
        def has_events(self) -> bool:
            """Check if domain events are tracked.

            Returns:
                True if events list is not empty.

            """
            return len(self.events) > 0

        @computed_field
        def event_count(self) -> int:
            """Get total number of domain events recorded.

            Returns:
                Number of events in the events list.

            """
            return len(self.events)

        @computed_field
        def event_types(self) -> list[str]:
            """Get list of unique event types in history.

            Returns:
                List of event class names (e.g., ["ParseEvent", "FilterEvent"]).

            """
            return list({type(e).__name__ for e in self.events})

        # HELPER METHODS
        @classmethod
        def for_parsing(
            cls,
            total: int,
            schema: int = 0,
            data: int = 0,
            errors: int = 0,
            detected_type: str | None = None,
        ) -> FlextLdifModels.Statistics:
            """Create statistics for parsing operations.

            Args:
                total: Total entries parsed
                schema: Schema entries count
                data: Data entries count
                errors: Parse errors encountered
                detected_type: Auto-detected server type

            Returns:
                Statistics instance for parsing.

            """
            return cls(
                total_entries=total,
                schema_entries=schema,
                data_entries=data,
                parse_errors=errors,
                detected_server_type=detected_type,
            )

        @classmethod
        def for_writing(
            cls,
            written: int,
            output_file: str | None = None,
            size: int = 0,
            encoding: str = "utf-8",
        ) -> FlextLdifModels.Statistics:
            """Create statistics for writing operations.

            Args:
                written: Number of entries written
                output_file: Output file path
                size: File size in bytes
                encoding: File encoding

            Returns:
                Statistics instance for writing.

            """
            return cls(
                entries_written=written,
                total_entries=written,
                output_file=output_file,
                file_size_bytes=size,
                encoding=encoding,
            )

        @classmethod
        def for_acl_extraction(
            cls,
            processed: int,
            extracted: int = 0,
            failed: int = 0,
            attribute_name: str | None = None,
        ) -> FlextLdifModels.Statistics:
            """Create statistics for ACL extraction operations.

            Args:
                processed: Total entries processed
                extracted: Total ACLs extracted
                failed: ACL parsing failures
                attribute_name: Primary ACL attribute name

            Returns:
                Statistics instance for ACL extraction.

            """
            return cls(
                total_entries=processed,
                acls_extracted=extracted,
                acls_failed=failed,
                acl_attribute_name=attribute_name,
            )

        @classmethod
        def for_pipeline(
            cls,
            total: int = 0,
            processed: int = 0,
            schema: int = 0,
            hierarchy: int = 0,
            users: int = 0,
            groups: int = 0,
            acls: int = 0,
            rejected: int = 0,
            duration: float = 0.0,
        ) -> FlextLdifModels.Statistics:
            """Create statistics for pipeline operations.

            Args:
                total: Total entries encountered
                processed: Successfully processed entries
                schema: Schema entries
                hierarchy: Hierarchy entries
                users: User entries
                groups: Group entries
                acls: ACL entries
                rejected: Rejected entries
                duration: Processing duration

            Returns:
                Statistics instance for pipeline.

            """
            return cls(
                total_entries=total,
                processed_entries=processed,
                schema_entries=schema,
                hierarchy_entries=hierarchy,
                user_entries=users,
                group_entries=groups,
                acl_entries=acls,
                failed_entries=rejected,
                processing_duration=duration,
            )

        @classmethod
        def empty(cls) -> FlextLdifModels.Statistics:
            """Create empty statistics.

            Returns:
                Statistics instance with all counters at zero.

            """
            return cls()

        def merge(
            self, other: FlextLdifModels.Statistics
        ) -> FlextLdifModels.Statistics:
            """Merge two Statistics instances by summing counters.

            Combines statistics from multiple operations by adding all
            numeric counters. Useful for aggregating statistics across
            pipeline stages or parallel operations.

            Args:
                other: Another Statistics instance to merge

            Returns:
                New Statistics with merged counters.

            Example:
                >>> stats1 = Statistics.for_parsing(total=50, errors=2)
                >>> stats2 = Statistics.for_parsing(total=30, errors=1)
                >>> combined = stats1.merge(stats2)
                >>> combined.total_entries  # 80
                >>> combined.parse_errors  # 3

            """
            # Merge rejection reasons dictionaries
            merged_reasons = {**self.rejection_reasons}
            for reason, count in other.rejection_reasons.items():
                merged_reasons[reason] = merged_reasons.get(reason, 0) + count

            return self.__class__(
                # Core counters
                total_entries=self.total_entries + other.total_entries,
                processed_entries=self.processed_entries + other.processed_entries,
                failed_entries=self.failed_entries + other.failed_entries,
                # Category counters
                schema_entries=self.schema_entries + other.schema_entries,
                data_entries=self.data_entries + other.data_entries,
                hierarchy_entries=self.hierarchy_entries + other.hierarchy_entries,
                user_entries=self.user_entries + other.user_entries,
                group_entries=self.group_entries + other.group_entries,
                acl_entries=self.acl_entries + other.acl_entries,
                # Schema migration counters
                schema_attributes=self.schema_attributes + other.schema_attributes,
                schema_objectclasses=self.schema_objectclasses
                + other.schema_objectclasses,
                # ACL extraction counters
                acls_extracted=self.acls_extracted + other.acls_extracted,
                acls_failed=self.acls_failed + other.acls_failed,
                acl_attribute_name=self.acl_attribute_name or other.acl_attribute_name,
                # Parsing counters
                parse_errors=self.parse_errors + other.parse_errors,
                detected_server_type=self.detected_server_type
                or other.detected_server_type,
                # Writing counters (take from other if not set in self)
                entries_written=self.entries_written + other.entries_written,
                output_file=self.output_file or other.output_file,
                file_size_bytes=self.file_size_bytes + other.file_size_bytes,
                encoding=self.encoding if self.encoding != "utf-8" else other.encoding,
                # Metadata
                processing_duration=self.processing_duration
                + other.processing_duration,
                rejection_reasons=merged_reasons,
                # Domain events (v1.0.0+)
                events=[*self.events, *other.events],
            )

        def add_event(
            self,
            event: (
                FlextLdifModels.ParseEvent
                | FlextLdifModels.FilterEvent
                | FlextLdifModels.CategoryEvent
                | FlextLdifModels.WriteEvent
                | FlextLdifModels.AclEvent
                | FlextLdifModels.DnEvent
                | FlextLdifModels.MigrationEvent
                | FlextLdifModels.ConversionEvent
                | FlextLdifModels.SchemaEvent
            ),
        ) -> FlextLdifModels.Statistics:
            """Add domain event to history (immutable operation).

            Creates new Statistics instance with event appended to events list.
            Preserves all existing statistics counters and metadata.

            Args:
                event: Domain event to add to history

            Returns:
                New Statistics instance with event added

            Example:
                >>> parse_event = FlextLdifModels.ParseEvent(
                ...     event_id="evt_001",
                ...     timestamp=datetime.now(timezone.utc),
                ...     entries_parsed=100,
                ...     parse_duration_ms=50.0,
                ...     detected_server_type="oud",
                ... )
                >>> new_stats = stats.add_event(parse_event)
                >>> assert len(new_stats.events) == len(stats.events) + 1

            """
            return self.model_copy(update={"events": [*self.events, event]})

        def get_events_by_type(
            self, event_type: type[FlextModels.DomainEvent]
        ) -> list[FlextModels.DomainEvent]:
            """Filter events by type.

            Args:
                event_type: Event class to filter (e.g., FlextLdifModels.ParseEvent)

            Returns:
                List of events matching the specified type

            Example:
                >>> parse_events = stats.get_events_by_type(FlextLdifModels.ParseEvent)
                >>> filter_events = stats.get_events_by_type(
                ...     FlextLdifModels.FilterEvent
                ... )
                >>> for event in parse_events:
                ...     print(f"Parsed {event.entries_parsed} entries")

            """
            return [e for e in self.events if isinstance(e, event_type)]

        def get_latest_event(
            self, event_type: type[FlextModels.DomainEvent] | None = None
        ) -> FlextModels.DomainEvent | None:
            """Get latest event, optionally filtered by type.

            Args:
                event_type: Optional event class to filter

            Returns:
                Latest event matching criteria, or None if no events

            Example:
                >>> # Get latest parse event
                >>> latest_parse = stats.get_latest_event(FlextLdifModels.ParseEvent)
                >>> if latest_parse:
                ...     print(f"Last parse: {latest_parse.entries_parsed} entries")
                >>>
                >>> # Get latest event of any type
                >>> latest_any = stats.get_latest_event()
                >>> if latest_any:
                ...     print(f"Last operation: {type(latest_any).__name__}")

            """
            if event_type:
                filtered = self.get_events_by_type(event_type)
                return filtered[-1] if filtered else None
            return self.events[-1] if self.events else None

    # =========================================================================
    # DOMAIN EVENTS - Event Sourcing & Audit Trail (v1.0.0+)
    # =========================================================================

    class ParseEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF parsing operation completes.

        Captures parsing operation metadata including entry counts, duration,
        server type detection, and errors for audit trails and monitoring.

        Architecture:
            - Layer: Domain (Event)
            - Pattern: Event Sourcing / Domain Event
            - Immutability: Yes (frozen=True via FlextModels.DomainEvent)
            - Base: FlextModels.DomainEvent from flext-core

        Used for:
            - Audit trails and compliance logging
            - Performance monitoring and analytics
            - Debug and troubleshooting
            - Pipeline operation tracking

        Example:
            >>> from datetime import datetime, timezone
            >>> event = FlextLdifModels.ParseEvent(
            ...     event_id="parse_20250108_001",
            ...     timestamp=datetime.now(timezone.utc),
            ...     entries_parsed=1500,
            ...     schema_entries=50,
            ...     data_entries=1450,
            ...     parse_duration_ms=234.5,
            ...     source_file="directory.ldif",
            ...     detected_server_type="oud",
            ...     quirks_applied=["oud_acl_parsing", "oud_schema_extensions"],
            ... )
            >>> print(
            ...     f"Parsed {event.entries_parsed} entries in {event.parse_duration_ms}ms"
            ... )
            Parsed 1500 entries in 234.5ms
            >>> print(f"Success rate: {event.success_rate:.2f}%")
            Success rate: 100.00%
            >>> print(f"Throughput: {event.throughput_entries_per_sec:.0f} entries/sec")
            Throughput: 6396 entries/sec

        Attributes:
            entries_parsed: Total number of entries parsed from LDIF source
            schema_entries: Number of schema definition entries
            data_entries: Number of data entries (users, groups, etc.)
            parse_duration_ms: Parse operation duration in milliseconds
            source_file: Source LDIF file path (if parsing from file)
            source_type: Type of source ("file", "string", "stream", "ldap3")
            detected_server_type: Auto-detected server type (oid, oud, openldap, etc.)
            detection_confidence: Confidence score for server detection (0.0-1.0)
            quirks_applied: Server-specific quirks applied during parsing
            errors_encountered: Non-fatal parse errors encountered
            fatal_errors: Fatal errors that halted processing

        Computed Fields:
            success_rate: Parse success rate as percentage
            throughput_entries_per_sec: Parsing throughput in entries per second
            has_errors: Indicates if any errors were encountered
            schema_to_data_ratio: Ratio of schema entries to data entries

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Core metrics
        entries_parsed: int = Field(
            ...,
            ge=0,
            description="Total number of entries parsed from LDIF source",
        )
        schema_entries: int = Field(
            default=0,
            ge=0,
            description="Number of schema definition entries (objectClass, attributeType, etc.)",
        )
        data_entries: int = Field(
            default=0,
            ge=0,
            description="Number of data entries (user, group, ou, etc.)",
        )

        # Performance
        parse_duration_ms: float = Field(
            ...,
            ge=0.0,
            description="Parse operation duration in milliseconds",
        )

        # Context
        source_file: str | None = Field(
            None,
            description="Source LDIF file path (if parsing from file)",
        )
        source_type: Literal["file", "string", "stream", "ldap3"] = Field(
            default="string",
            description="Type of source being parsed",
        )

        # Server detection
        detected_server_type: str = Field(
            default="rfc",
            description="Auto-detected LDAP server type (oid, oud, openldap, ad, etc.)",
        )
        detection_confidence: float = Field(
            default=1.0,
            ge=0.0,
            le=1.0,
            description="Confidence score for server type detection (0.0-1.0)",
        )

        # Quirks
        quirks_applied: list[str] = Field(
            default_factory=list,
            description="List of server-specific quirks applied during parsing",
        )

        # Errors
        errors_encountered: list[str] = Field(
            default_factory=list,
            description="Parse errors encountered (non-fatal)",
        )
        fatal_errors: list[str] = Field(
            default_factory=list,
            description="Fatal parse errors that halted processing",
        )

        # Computed metrics
        @computed_field
        def success_rate(self) -> float:
            """Calculate parse success rate as percentage."""
            if self.entries_parsed == 0:
                return 100.0
            total_errors = len(self.errors_encountered) + len(self.fatal_errors)
            return ((self.entries_parsed - total_errors) / self.entries_parsed) * 100.0

        @computed_field
        def throughput_entries_per_sec(self) -> float:
            """Calculate parsing throughput in entries per second."""
            if self.parse_duration_ms == 0:
                return 0.0
            return (self.entries_parsed / self.parse_duration_ms) * 1000.0

        @computed_field
        def has_errors(self) -> bool:
            """Indicates if any errors were encountered."""
            return len(self.errors_encountered) > 0 or len(self.fatal_errors) > 0

        @computed_field
        def schema_to_data_ratio(self) -> float:
            """Calculate ratio of schema entries to data entries."""
            if self.data_entries == 0:
                return float("inf") if self.schema_entries > 0 else 0.0
            return self.schema_entries / self.data_entries

    class FilterEvent(FlextModels.DomainEvent):
        """Event emitted when entry filtering operation is applied.

        Captures filtering metadata including counts, criteria, exclusions,
        and performance metrics for audit trails and pipeline monitoring.

        Architecture:
            - Layer: Domain (Event)
            - Pattern: Event Sourcing / Domain Event
            - Immutability: Yes (frozen=True)
            - Base: FlextModels.DomainEvent from flext-core

        Used for:
            - Audit trails of data transformations
            - Understanding data loss in pipeline stages
            - Debug and validation of filtering rules
            - Performance optimization of filter operations

        Example:
            >>> event = FlextLdifModels.FilterEvent(
            ...     event_id="filter_20250108_001",
            ...     timestamp=datetime.now(timezone.utc),
            ...     filter_operation="filter_by_objectclass",
            ...     entries_before=1500,
            ...     entries_after=800,
            ...     filter_criteria=[
            ...         {"field": "objectClass", "value": "inetOrgPerson"}
            ...     ],
            ...     filter_duration_ms=45.2,
            ... )
            >>> print(f"Filtered {event.entries_excluded} entries")
            Filtered 700 entries
            >>> print(f"Retention: {event.filter_efficiency:.2f}%")
            Retention: 53.33%

        Attributes:
            filter_operation: Specific filter operation name
            entries_before: Entry count before filtering
            entries_after: Entry count after filtering
            filter_criteria: Applied filter criteria (serialized)
            exclusion_reasons: Map of exclusion reason to count
            excluded_dns: DNs of excluded entries (for audit)
            filter_duration_ms: Filter operation duration in milliseconds

        Computed Fields:
            entries_excluded: Number of entries excluded by filter
            filter_efficiency: Filtering efficiency (percentage retained)
            exclusion_rate: Exclusion rate as percentage
            throughput_entries_per_sec: Filtering throughput

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Operation
        filter_operation: str = Field(
            ...,
            description="Specific filter operation name (filter_by_dn, filter_by_objectclass, etc.)",
        )

        # Counts
        entries_before: int = Field(
            ...,
            ge=0,
            description="Entry count before filtering",
        )
        entries_after: int = Field(
            ...,
            ge=0,
            description="Entry count after filtering",
        )

        # Criteria
        filter_criteria: list[dict[str, Any]] = Field(
            default_factory=list,
            description="Applied filter criteria (serialized)",
        )

        # Exclusions
        exclusion_reasons: dict[str, int] = Field(
            default_factory=dict,
            description="Map of exclusion reason to count",
        )
        excluded_dns: list[str] = Field(
            default_factory=list,
            description="DNs of excluded entries (for audit)",
        )

        # Performance
        filter_duration_ms: float = Field(
            default=0.0,
            ge=0.0,
            description="Filter operation duration in milliseconds",
        )

        # Computed metrics
        @computed_field
        def entries_excluded(self) -> int:
            """Calculate number of entries excluded by filter."""
            return self.entries_before - self.entries_after

        @computed_field
        def filter_efficiency(self) -> float:
            """Calculate filtering efficiency (percentage retained)."""
            if self.entries_before == 0:
                return 100.0
            return (self.entries_after / self.entries_before) * 100.0

        @computed_field
        def exclusion_rate(self) -> float:
            """Calculate exclusion rate as percentage."""
            return 100.0 - cast("float", self.filter_efficiency)

        @computed_field
        def throughput_entries_per_sec(self) -> float:
            """Calculate filtering throughput in entries per second."""
            if self.filter_duration_ms == 0:
                return 0.0
            return (self.entries_before / self.filter_duration_ms) * 1000.0

    class CategoryEvent(FlextModels.DomainEvent):
        """Event emitted when entry categorization operation completes.

        Captures categorization metadata including distribution, rules,
        and performance for audit trails and analytics.

        Architecture:
            - Layer: Domain (Event)
            - Pattern: Event Sourcing / Domain Event
            - Immutability: Yes (frozen=True)
            - Base: FlextModels.DomainEvent from flext-core

        Used for:
            - Audit trail of categorization logic
            - Understanding data distribution across categories
            - Validation of categorization rules
            - Performance monitoring of categorization

        Example:
            >>> event = FlextLdifModels.CategoryEvent(
            ...     event_id="cat_20250108_001",
            ...     timestamp=datetime.now(timezone.utc),
            ...     categorization_operation="categorize_by_objectclass",
            ...     entries_categorized=1500,
            ...     category_distribution={
            ...         "schema": 50,
            ...         "users": 800,
            ...         "groups": 300,
            ...         "organizational_units": 200,
            ...         "other": 150,
            ...     },
            ...     categorization_duration_ms=67.8,
            ... )
            >>> print(f"Categories: {event.category_count}")
            Categories: 5
            >>> print(f"Diversity: {event.diversity_score:.2f}")
            Diversity: 85.42

        Attributes:
            categorization_operation: Categorization operation name
            entries_categorized: Total entries categorized
            category_distribution: Map of category name to entry count
            uncategorized_count: Number of uncategorizable entries
            categorization_rules: Categorization rules applied
            categorization_duration_ms: Operation duration in milliseconds

        Computed Fields:
            category_count: Total number of distinct categories
            largest_category: Name and size of largest category
            smallest_category: Name and size of smallest category
            diversity_score: Category diversity score (0-100, Shannon entropy)
            throughput_entries_per_sec: Categorization throughput

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Operation
        categorization_operation: str = Field(
            ...,
            description="Categorization operation name (categorize_by_objectclass, etc.)",
        )

        # Counts
        entries_categorized: int = Field(
            ...,
            ge=0,
            description="Total entries categorized",
        )

        # Distribution
        category_distribution: dict[str, int] = Field(
            ...,
            description="Map of category name to entry count",
        )
        uncategorized_count: int = Field(
            default=0,
            ge=0,
            description="Number of entries that couldn't be categorized",
        )

        # Rules
        categorization_rules: list[dict[str, Any]] = Field(
            default_factory=list,
            description="Categorization rules applied (serialized)",
        )

        # Performance
        categorization_duration_ms: float = Field(
            default=0.0,
            ge=0.0,
            description="Categorization operation duration in milliseconds",
        )

        # Computed metrics
        @computed_field
        def category_count(self) -> int:
            """Total number of distinct categories."""
            return len(self.category_distribution)

        @computed_field
        def largest_category(self) -> tuple[str, int]:
            """Returns name and size of largest category."""
            if not self.category_distribution:
                return ("", 0)
            return max(self.category_distribution.items(), key=operator.itemgetter(1))

        @computed_field
        def smallest_category(self) -> tuple[str, int]:
            """Returns name and size of smallest category."""
            if not self.category_distribution:
                return ("", 0)
            return min(self.category_distribution.items(), key=operator.itemgetter(1))

        @computed_field
        def diversity_score(self) -> float:
            """Calculate category diversity score (0-100).

            Higher score = more evenly distributed across categories.
            Uses Shannon entropy normalized to 0-100 scale.

            Returns:
                Diversity score from 0.0 (all in one category) to 100.0 (perfectly distributed)

            """
            if not self.category_distribution or self.entries_categorized == 0:
                return 0.0

            import math

            total = sum(self.category_distribution.values())
            entropy = 0.0

            for count in self.category_distribution.values():
                if count > 0:
                    p = count / total
                    entropy -= p * math.log2(p)

            # Normalize to 0-100 scale
            max_entropy = math.log2(len(self.category_distribution))
            if max_entropy == 0:
                return 0.0

            return (entropy / max_entropy) * 100.0

        @computed_field
        def throughput_entries_per_sec(self) -> float:
            """Calculate categorization throughput in entries per second."""
            if self.categorization_duration_ms == 0:
                return 0.0
            return (self.entries_categorized / self.categorization_duration_ms) * 1000.0

    class WriteEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF write operation completes.

        Captures write operation metadata including counts, file paths,
        target server, and performance for audit trails.

        Architecture:
            - Layer: Domain (Event)
            - Pattern: Event Sourcing / Domain Event
            - Immutability: Yes (frozen=True)
            - Base: FlextModels.DomainEvent from flext-core

        Used for:
            - Audit trail of output files
            - Performance monitoring of write operations
            - Validation of format transformations
            - Output format and encoding tracking

        Example:
            >>> event = FlextLdifModels.WriteEvent(
            ...     event_id="write_20250108_001",
            ...     timestamp=datetime.now(timezone.utc),
            ...     entries_written=800,
            ...     write_duration_ms=123.4,
            ...     output_file="/path/to/output.ldif",
            ...     target_server_type="oud",
            ...     encoding="utf-8",
            ...     quirks_applied=["oud_acl_format", "oud_schema_syntax"],
            ...     bytes_written=1_234_567,
            ... )
            >>> print(
            ...     f"Wrote {event.entries_written} entries at {event.throughput_entries_per_sec:.0f} entries/sec"
            ... )
            Wrote 800 entries at 6483 entries/sec
            >>> print(f"Throughput: {event.throughput_mb_per_sec:.2f} MB/sec")
            Throughput: 9.53 MB/sec

        Attributes:
            entries_written: Number of entries written to output
            output_file: Output file path (if writing to file)
            output_type: Type of output target ("file", "string", "stream")
            target_server_type: Target LDAP server type
            encoding: File encoding used
            quirks_applied: Server-specific quirks applied
            transformations_applied: Transformations applied to entries
            bytes_written: Total bytes written
            lines_written: Total lines written
            write_duration_ms: Operation duration in milliseconds

        Computed Fields:
            throughput_entries_per_sec: Write throughput in entries per second
            throughput_mb_per_sec: Write throughput in MB per second
            avg_bytes_per_entry: Average bytes per entry
            compression_potential: Estimated compression potential ratio

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Counts
        entries_written: int = Field(
            ...,
            ge=0,
            description="Number of entries written to output",
        )

        # Output
        output_file: str | None = Field(
            None,
            description="Output file path (if writing to file)",
        )
        output_type: Literal["file", "string", "stream"] = Field(
            default="file",
            description="Type of output target",
        )

        # Server
        target_server_type: str = Field(
            default="rfc",
            description="Target LDAP server type (oid, oud, openldap, ad, etc.)",
        )

        # Encoding
        encoding: str = Field(
            default="utf-8",
            description="File encoding used for write operation",
        )

        # Quirks
        quirks_applied: list[str] = Field(
            default_factory=list,
            description="Server-specific quirks applied during write",
        )
        transformations_applied: list[str] = Field(
            default_factory=list,
            description="Transformations applied to entries before write",
        )

        # Size
        bytes_written: int = Field(
            default=0,
            ge=0,
            description="Total bytes written to output",
        )
        lines_written: int = Field(
            default=0,
            ge=0,
            description="Total lines written to output",
        )

        # Performance
        write_duration_ms: float = Field(
            default=0.0,
            ge=0.0,
            description="Write operation duration in milliseconds",
        )

        # Computed metrics
        @computed_field
        def throughput_entries_per_sec(self) -> float:
            """Calculate write throughput in entries per second."""
            if self.write_duration_ms == 0:
                return 0.0
            return (self.entries_written / self.write_duration_ms) * 1000.0

        @computed_field
        def throughput_mb_per_sec(self) -> float:
            """Calculate write throughput in MB per second."""
            if self.write_duration_ms == 0:
                return 0.0
            mb_written = self.bytes_written / (1024 * 1024)
            return (mb_written / self.write_duration_ms) * 1000.0

        @computed_field
        def avg_bytes_per_entry(self) -> float:
            """Calculate average bytes per entry."""
            if self.entries_written == 0:
                return 0.0
            return self.bytes_written / self.entries_written

        @computed_field
        def compression_potential(self) -> float:
            """Estimate compression potential based on avg entry size.

            Returns ratio: higher = more compressible.
            Assumes LDIF text is typically 60-70% compressible.

            Returns:
                Estimated compression ratio (e.g., 0.65 = 65% compression)

            """
            # Placeholder - can be refined with actual compression statistics
            return 0.65

    class AclEvent(FlextModels.DomainEvent):
        """Event emitted when ACL extraction/processing operation completes.

        Captures ACL operation metadata including counts, formats, errors,
        and performance for audit trails and security compliance.

        Architecture:
            - Layer: Domain (Event)
            - Pattern: Event Sourcing / Domain Event
            - Immutability: Yes (frozen=True)
            - Base: FlextModels.DomainEvent from flext-core

        Used for:
            - Audit trail of ACL operations
            - Validation of ACL parsing correctness
            - Security compliance tracking
            - Performance monitoring of ACL extraction

        Example:
            >>> event = FlextLdifModels.AclEvent(
            ...     event_id="acl_20250108_001",
            ...     timestamp=datetime.now(timezone.utc),
            ...     acl_operation="extract_acls",
            ...     entries_processed=800,
            ...     acls_extracted=250,
            ...     acls_failed=10,
            ...     server_type="oud",
            ...     acl_format="orclaci",
            ...     extraction_duration_ms=89.3,
            ... )
            >>> print(
            ...     f"Extracted {event.acls_extracted} ACLs with {event.extraction_success_rate:.2f}% success"
            ... )
            Extracted 250 ACLs with 96.15% success
            >>> print(f"Average: {event.acls_per_entry:.2f} ACLs per entry")
            Average: 0.31 ACLs per entry

        Attributes:
            acl_operation: ACL operation name (extract_acls, parse_acls, etc.)
            entries_processed: Number of entries processed for ACLs
            acls_extracted: Number of ACLs successfully extracted
            acls_failed: Number of ACLs that failed extraction/parsing
            server_type: Server type for ACL format
            acl_format: Specific ACL format (orclaci, aclentry, olcAccess, etc.)
            error_details: Detailed error information for failures
            extraction_duration_ms: Operation duration in milliseconds

        Computed Fields:
            extraction_success_rate: ACL extraction success rate percentage
            acls_per_entry: Average ACLs per entry
            throughput_acls_per_sec: ACL extraction throughput

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Operation
        acl_operation: str = Field(
            ...,
            description="ACL operation name (extract_acls, parse_acls, transform_acls, etc.)",
        )

        # Counts
        entries_processed: int = Field(
            ...,
            ge=0,
            description="Number of entries processed for ACLs",
        )
        acls_extracted: int = Field(
            default=0,
            ge=0,
            description="Number of ACLs successfully extracted",
        )
        acls_failed: int = Field(
            default=0,
            ge=0,
            description="Number of ACLs that failed extraction/parsing",
        )

        # Format
        server_type: str = Field(
            ...,
            description="Server type for ACL format (oid, oud, openldap, etc.)",
        )
        acl_format: str = Field(
            ...,
            description="Specific ACL format (orclaci, aclentry, olcAccess, etc.)",
        )

        # Errors
        error_details: list[FlextLdifModels.ErrorDetail] = Field(
            default_factory=list,
            description="Detailed error information for failed ACL extractions",
        )

        # Performance
        extraction_duration_ms: float = Field(
            default=0.0,
            ge=0.0,
            description="ACL extraction duration in milliseconds",
        )

        # Computed metrics
        @computed_field
        def extraction_success_rate(self) -> float:
            """Calculate ACL extraction success rate as percentage."""
            total_acls = self.acls_extracted + self.acls_failed
            if total_acls == 0:
                return 100.0
            return (self.acls_extracted / total_acls) * 100.0

        @computed_field
        def acls_per_entry(self) -> float:
            """Calculate average ACLs per entry."""
            if self.entries_processed == 0:
                return 0.0
            return self.acls_extracted / self.entries_processed

        @computed_field
        def throughput_acls_per_sec(self) -> float:
            """Calculate ACL extraction throughput in ACLs per second."""
            if self.extraction_duration_ms == 0:
                return 0.0
            total_acls = self.acls_extracted + self.acls_failed
            return (total_acls / self.extraction_duration_ms) * 1000.0

    class DnEvent(FlextModels.DomainEvent):
        """Event emitted when DN operation completes.

        Captures DN parsing, validation, normalization, and transformation metadata
        for audit trails, compliance tracking, and performance monitoring.

        Architecture:
            - Layer: Domain (Event)
            - Pattern: Event Sourcing / Domain Event
            - Immutability: Yes (frozen=True)
            - Base: FlextModels.DomainEvent from flext-core

        Used for:
            - Audit trail of DN operations
            - Validation of DN parsing correctness
            - DN transformation tracking
            - Performance monitoring of DN operations

        Example:
            >>> event = FlextLdifModels.DnEvent(
            ...     event_id="dn_20250108_001",
            ...     timestamp=datetime.now(timezone.utc),
            ...     dn_operation="normalize",
            ...     input_dn="CN=Admin,DC=Example,DC=Com",
            ...     output_dn="cn=admin,dc=example,dc=com",
            ...     operation_duration_ms=1.2,
            ...     validation_result=True,
            ...     parse_components=[
            ...         ("cn", "admin"),
            ...         ("dc", "example"),
            ...         ("dc", "com"),
            ...     ],
            ... )
            >>> print(f"DN normalized in {event.operation_duration_ms:.2f}ms")
            DN normalized in 1.20ms
            >>> print(f"Valid DN: {event.validation_result}")
            Valid DN: True

        Attributes:
            dn_operation: DN operation name (parse, validate, normalize, transform, etc.)
            input_dn: Input DN before operation
            output_dn: Output DN after operation (None if operation failed)
            operation_duration_ms: Operation duration in milliseconds
            validation_result: Whether DN validation succeeded (None if not validated)
            parse_components: Parsed DN components as list of (attribute, value) tuples

        Computed Fields:
            has_output: Whether operation produced valid output
            component_count: Number of DN components parsed

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Operation
        dn_operation: str = Field(
            ...,
            description="DN operation name (parse, validate, normalize, transform, etc.)",
        )

        # Input/Output
        input_dn: str = Field(
            ...,
            description="Input DN before operation",
        )
        output_dn: str | None = Field(
            default=None,
            description="Output DN after operation (None if operation failed)",
        )

        # Performance
        operation_duration_ms: float = Field(
            default=0.0,
            ge=0.0,
            description="DN operation duration in milliseconds",
        )

        # Validation
        validation_result: bool | None = Field(
            default=None,
            description="Whether DN validation succeeded (None if not validated)",
        )

        # Parsing
        parse_components: list[tuple[str, str]] | None = Field(
            default=None,
            description="Parsed DN components as list of (attribute, value) tuples",
        )

        # Computed metrics
        @computed_field
        def has_output(self) -> bool:
            """Check if operation produced valid output."""
            return self.output_dn is not None

        @computed_field
        def component_count(self) -> int:
            """Get number of DN components parsed."""
            if self.parse_components is None:
                return 0
            return len(self.parse_components)

    class MigrationEvent(FlextModels.DomainEvent):
        """Event emitted when migration operation completes.

        Captures migration pipeline metadata including source/target servers,
        entries migrated, transformation statistics, and performance metrics.

        Architecture:
            - Layer: Domain (Event)
            - Pattern: Event Sourcing / Domain Event
            - Immutability: Yes (frozen=True)
            - Base: FlextModels.DomainEvent from flext-core

        Used for:
            - Migration audit trails
            - Progress tracking and reporting
            - Performance analysis
            - Error tracking and diagnostics

        Example:
            >>> event = FlextLdifModels.MigrationEvent(
            ...     event_id="mig_20250108_001",
            ...     timestamp=datetime.now(timezone.utc),
            ...     migration_operation="full_migration",
            ...     source_server="oid",
            ...     target_server="oud",
            ...     entries_processed=1000,
            ...     entries_migrated=980,
            ...     entries_failed=20,
            ...     migration_duration_ms=5420.5,
            ...     error_details=[{"entry": "cn=test", "error": "Invalid DN"}],
            ... )
            >>> print(f"Migration success rate: {event.migration_success_rate:.2f}%")
            Migration success rate: 98.00%
            >>> print(f"Throughput: {event.throughput_entries_per_sec:.2f} entries/sec")
            Throughput: 180.72 entries/sec

        Attributes:
            migration_operation: Migration operation name (full_migration, incremental, etc.)
            source_server: Source LDAP server type
            target_server: Target LDAP server type
            entries_processed: Total entries processed
            entries_migrated: Entries successfully migrated
            entries_failed: Entries that failed migration
            migration_duration_ms: Total migration duration in milliseconds
            error_details: Detailed error information for failed entries

        Computed Fields:
            migration_success_rate: Migration success rate percentage
            throughput_entries_per_sec: Migration throughput in entries per second

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Operation
        migration_operation: str = Field(
            ...,
            description="Migration operation name (full_migration, incremental, etc.)",
        )

        # Servers
        source_server: str = Field(
            ...,
            description="Source LDAP server type (oid, oud, openldap, etc.)",
        )
        target_server: str = Field(
            ...,
            description="Target LDAP server type (oid, oud, openldap, etc.)",
        )

        # Counts
        entries_processed: int = Field(
            ...,
            ge=0,
            description="Total number of entries processed",
        )
        entries_migrated: int = Field(
            default=0,
            ge=0,
            description="Number of entries successfully migrated",
        )
        entries_failed: int = Field(
            default=0,
            ge=0,
            description="Number of entries that failed migration",
        )

        # Performance
        migration_duration_ms: float = Field(
            default=0.0,
            ge=0.0,
            description="Total migration duration in milliseconds",
        )

        # Errors
        error_details: list[FlextLdifModels.ErrorDetail] = Field(
            default_factory=list,
            description="Detailed error information for failed entries",
        )

        # Computed metrics
        @computed_field
        def migration_success_rate(self) -> float:
            """Calculate migration success rate as percentage."""
            if self.entries_processed == 0:
                return 100.0
            return (self.entries_migrated / self.entries_processed) * 100.0

        @computed_field
        def throughput_entries_per_sec(self) -> float:
            """Calculate migration throughput in entries per second."""
            if self.migration_duration_ms == 0:
                return 0.0
            return (self.entries_processed / self.migration_duration_ms) * 1000.0

    class ConversionEvent(FlextModels.DomainEvent):
        """Event emitted when format conversion operation completes.

        Captures conversion metadata including format types, items converted,
        transformation success/failure, and performance metrics.

        Architecture:
            - Layer: Domain (Event)
            - Pattern: Event Sourcing / Domain Event
            - Immutability: Yes (frozen=True)
            - Base: FlextModels.DomainEvent from flext-core

        Used for:
            - Conversion audit trails
            - Format transformation tracking
            - Quality assurance
            - Performance monitoring

        Example:
            >>> event = FlextLdifModels.ConversionEvent(
            ...     event_id="conv_20250108_001",
            ...     timestamp=datetime.now(timezone.utc),
            ...     conversion_operation="acl_transform",
            ...     source_format="orclaci",
            ...     target_format="olcAccess",
            ...     items_processed=50,
            ...     items_converted=48,
            ...     items_failed=2,
            ...     conversion_duration_ms=125.3,
            ...     error_details=[{"item": "acl1", "error": "Invalid syntax"}],
            ... )
            >>> print(f"Conversion success rate: {event.conversion_success_rate:.2f}%")
            Conversion success rate: 96.00%
            >>> print(f"Throughput: {event.throughput_items_per_sec:.2f} items/sec")
            Throughput: 399.04 items/sec

        Attributes:
            conversion_operation: Conversion operation name (acl_transform, schema_convert, etc.)
            source_format: Source format type
            target_format: Target format type
            items_processed: Total items processed
            items_converted: Items successfully converted
            items_failed: Items that failed conversion
            conversion_duration_ms: Conversion duration in milliseconds
            error_details: Detailed error information for failed conversions

        Computed Fields:
            conversion_success_rate: Conversion success rate percentage
            throughput_items_per_sec: Conversion throughput in items per second

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Operation
        conversion_operation: str = Field(
            ...,
            description="Conversion operation name (acl_transform, schema_convert, etc.)",
        )

        # Formats
        source_format: str = Field(
            ...,
            description="Source format type (orclaci, aclentry, etc.)",
        )
        target_format: str = Field(
            ...,
            description="Target format type (olcAccess, aclentry, etc.)",
        )

        # Counts
        items_processed: int = Field(
            ...,
            ge=0,
            description="Total number of items processed",
        )
        items_converted: int = Field(
            default=0,
            ge=0,
            description="Number of items successfully converted",
        )
        items_failed: int = Field(
            default=0,
            ge=0,
            description="Number of items that failed conversion",
        )

        # Performance
        conversion_duration_ms: float = Field(
            default=0.0,
            ge=0.0,
            description="Conversion duration in milliseconds",
        )

        # Errors
        error_details: list[FlextLdifModels.ErrorDetail] = Field(
            default_factory=list,
            description="Detailed error information for failed conversions",
        )

        # Computed metrics
        @computed_field
        def conversion_success_rate(self) -> float:
            """Calculate conversion success rate as percentage."""
            if self.items_processed == 0:
                return 100.0
            return (self.items_converted / self.items_processed) * 100.0

        @computed_field
        def throughput_items_per_sec(self) -> float:
            """Calculate conversion throughput in items per second."""
            if self.conversion_duration_ms == 0:
                return 0.0
            return (self.items_processed / self.conversion_duration_ms) * 1000.0

    class SchemaEvent(FlextModels.DomainEvent):
        """Event emitted when schema processing operation completes.

        Captures schema operation metadata including operation type, items processed,
        success/failure counts, and performance metrics.

        Used for tracking schema parsing, validation, and transformation operations.

        Attributes:
            schema_operation: Operation name (parse_attribute, parse_objectclass, validate, etc.)
            items_processed: Total number of schema items processed
            items_succeeded: Number of items processed successfully
            items_failed: Number of items that failed processing
            operation_duration_ms: Total operation duration in milliseconds
            server_type: LDAP server type (oid, oud, openldap, etc.)
            error_details: Detailed error information for failed items

        Computed Fields:
            schema_success_rate: Success rate as percentage (0.0-100.0)
            throughput_items_per_sec: Processing throughput in items per second

        """

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

        # Operation metadata
        schema_operation: str = Field(
            ...,
            description="Schema operation name (parse_attribute, parse_objectclass, validate, etc.)",
        )

        # Processing metrics
        items_processed: int = Field(..., ge=0, description="Total items processed")
        items_succeeded: int = Field(
            default=0, ge=0, description="Items processed successfully"
        )
        items_failed: int = Field(default=0, ge=0, description="Items that failed")

        # Performance metrics
        operation_duration_ms: float = Field(
            default=0.0, ge=0.0, description="Operation duration in milliseconds"
        )

        # Context
        server_type: str = Field(
            default="rfc", description="LDAP server type (oid, oud, openldap, etc.)"
        )

        # Errors
        error_details: list[FlextLdifModels.ErrorDetail] = Field(
            default_factory=list,
            description="Detailed error information for failed items",
        )

        # Computed metrics
        @computed_field
        def schema_success_rate(self) -> float:
            """Calculate schema processing success rate as percentage."""
            if self.items_processed == 0:
                return 100.0
            return (self.items_succeeded / self.items_processed) * 100.0

        @computed_field
        def throughput_items_per_sec(self) -> float:
            """Calculate schema processing throughput in items per second."""
            if self.operation_duration_ms == 0:
                return 0.0
            return (self.items_processed / self.operation_duration_ms) * 1000.0

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
            return {
                "attributes": self.total_attributes(),
                "object_classes": self.total_object_classes(),
                "server_type": self.server_type,
                "entry_count": self.entry_count,
            }

    # =========================================================================
    # RESPONSE MODELS - Composed from domain models and statistics
    # =========================================================================

    class ParseResponse(FlextModels.Value):
        """Composed response from parsing operation.

        Combines Entry models with statistics from parse operation.
        Uses model composition instead of dict intermediaries.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        entries: list[FlextLdifModels.Entry] = Field(description="Parsed LDIF entries")
        statistics: FlextLdifModels.Statistics = Field(
            description="Parse operation statistics",
        )
        detected_server_type: str | None = Field(None)

    class WriteResponse(FlextModels.Value):
        """Composed response from write operation.

        Contains written LDIF content and statistics using model composition.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        content: str | None = Field(None, description="Written LDIF content")
        statistics: FlextLdifModels.Statistics = Field(
            description="Write operation statistics",
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
        ldif_changetype: str | None = Field(
            default=None,
            description="If set to 'modify', writes entries in LDIF modify add format (changetype: modify). Otherwise uses add format.",
        )

    class AclResponse(FlextModels.Value):
        """Composed response from ACL extraction.

        Combines extracted Acl models with extraction statistics.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        acls: list[FlextLdifModels.Acl] = Field(description="Extracted ACL models")
        statistics: FlextLdifModels.Statistics = Field(
            description="ACL extraction statistics",
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
        stats: dict[str, int] | FlextLdifModels.Statistics = Field(
            default_factory=dict,
            description="Migration statistics and metrics (Statistics or dict)",
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
            # stats can be dict or MigrationStatistics object
            if isinstance(self.stats, dict):
                has_schema = (
                    self.stats.get("total_schema_attributes", 0) > 0
                    or self.stats.get("total_schema_objectclasses", 0) > 0
                )
                has_entries = self.stats.get("total_entries", 0) > 0
            else:
                has_schema = (
                    self.stats.schema_attributes > 0
                    or self.stats.schema_objectclasses > 0
                )
                has_entries = self.stats.total_entries > 0
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
            stats_summary = (
                self.stats.statistics_summary
                if hasattr(self.stats, "statistics_summary")
                else self.stats
            )
            return {
                "statistics": stats_summary,
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
        schemas: list[object] = Field(
            default_factory=list,
            description="List of Schema quirk model instances",
        )
        acls: list[object] = Field(
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

    # =========================================================================
    # SERVICE PARAMETER MODELS - Typed parameters for service factories
    # =========================================================================
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
        migration_config: FlextLdifModels.MigrationConfig | None = Field(
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
        def from_config(cls, config: FlextLdifConfig) -> FlextLdifModels.ConfigInfo:
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

    # ═══════════════════════════════════════════════════════════════════════
    # STATISTICS MODELS
    # ═══════════════════════════════════════════════════════════════════════

    class StatisticsResult(FlextModels.Value):
        """Statistics result from LDIF processing pipeline.

        Contains comprehensive statistics about categorized entries, rejections,
        and output files generated during migration.

        Attributes:
            total_entries: Total number of entries processed
            categorized: Count of entries per category
            rejection_rate: Percentage of entries rejected (0.0-1.0)
            rejection_count: Number of rejected entries
            rejection_reasons: List of unique rejection reasons
            written_counts: Count of entries written per category
            output_files: Mapping of categories to output file paths

        """

        total_entries: int = Field(
            description="Total number of entries processed",
        )
        categorized: dict[str, int] = Field(
            description="Count of entries per category",
        )
        rejection_rate: float = Field(
            description="Percentage of entries rejected (0.0-1.0)",
        )
        rejection_count: int = Field(
            description="Number of rejected entries",
        )
        rejection_reasons: list[str] = Field(
            description="List of unique rejection reasons",
        )
        written_counts: dict[str, int] = Field(
            description="Count of entries written per category",
        )
        output_files: dict[str, str] = Field(
            description="Mapping of categories to output file paths",
        )

    class EntriesStatistics(FlextModels.Value):
        """Statistics calculated from a list of Entry models.

        Provides distribution analysis of objectClasses and server types
        across a collection of LDIF entries.

        Attributes:
            total_entries: Total number of entries analyzed
            object_class_distribution: Count of entries per objectClass
            server_type_distribution: Count of entries per server type

        """

        total_entries: int = Field(
            description="Total number of entries analyzed",
        )
        object_class_distribution: dict[str, int] = Field(
            description="Count of entries per objectClass",
        )
        server_type_distribution: dict[str, int] = Field(
            description="Count of entries per server type",
        )

    class ServiceStatus(FlextModels.Value):
        """Generic service status model for execute() health checks.

        Base model for all service health check responses providing
        standard status information across all FLEXT LDIF services.

        Attributes:
            service: Service name identifier
            status: Operational status (e.g., "operational", "degraded")
            rfc_compliance: RFC standards implemented (e.g., "RFC 2849", "RFC 4512")

        """

        service: str = Field(
            description="Service name identifier",
        )
        status: str = Field(
            description="Operational status",
        )
        rfc_compliance: str = Field(
            description="RFC standards implemented by this service",
        )

    class SchemaServiceStatus(FlextModels.Value):
        """Schema service status with server-specific metadata.

        Extended status model for FlextLdifSchema service including
        server type configuration and available operations.

        Attributes:
            service: Service name identifier
            server_type: Server type configuration (e.g., "oud", "oid", "rfc")
            status: Operational status
            rfc_compliance: RFC 4512 compliance
            operations: List of available schema operations

        """

        service: str = Field(
            description="Service name identifier",
        )
        server_type: str = Field(
            description="Server type configuration",
        )
        status: str = Field(
            description="Operational status",
        )
        rfc_compliance: str = Field(
            description="RFC 4512 compliance",
        )
        operations: list[str] = Field(
            description="List of available schema operations",
        )

    class SyntaxServiceStatus(FlextModels.Value):
        """Syntax service status with lookup table metadata.

        Extended status model for FlextLdifSyntax service including
        counts of registered syntax OIDs and common syntaxes.

        Attributes:
            service: Service name identifier
            status: Operational status
            rfc_compliance: RFC 4517 compliance
            total_syntaxes: Total number of registered syntax OIDs
            common_syntaxes: Number of commonly used syntax OIDs

        """

        service: str = Field(
            description="Service name identifier",
        )
        status: str = Field(
            description="Operational status",
        )
        rfc_compliance: str = Field(
            description="RFC 4517 compliance",
        )
        total_syntaxes: int = Field(
            description="Total number of registered syntax OIDs",
        )
        common_syntaxes: int = Field(
            description="Number of commonly used syntax OIDs",
        )

    class SyntaxLookupResult(FlextModels.Value):
        """Result of syntax OID/name lookup operations.

        Contains results from bidirectional OID ↔ name lookups
        performed by FlextLdifSyntax builder pattern.

        Attributes:
            oid_lookup: Resolved name for OID lookup (None if not found or not requested)
            name_lookup: Resolved OID for name lookup (None if not found or not requested)

        """

        oid_lookup: str | None = Field(
            default=None,
            description="Resolved name for OID lookup",
        )
        name_lookup: str | None = Field(
            default=None,
            description="Resolved OID for name lookup",
        )

    class ValidationServiceStatus(FlextModels.Value):
        """Validation service status with validation type metadata.

        Status model for FlextLdifValidation service including
        list of supported validation types.

        Attributes:
            service: Service name identifier
            status: Operational status
            rfc_compliance: RFC 2849/4512 compliance
            validation_types: List of supported validation types

        """

        service: str = Field(
            description="Service name identifier",
        )
        status: str = Field(
            description="Operational status",
        )
        rfc_compliance: str = Field(
            description="RFC 2849/4512 compliance",
        )
        validation_types: list[str] = Field(
            description="List of supported validation types",
        )

    ParseResult = (
        list["FlextLdifModels.Entry"]
        | tuple[list["FlextLdifModels.Entry"], int, list[str]]
    )

    class ValidationBatchResult(FlextModels.Value):
        """Result of batch validation operations.

        Contains validation results for multiple attribute names
        and objectClass names validated in a single operation.

        Attributes:
            results: Mapping of validated item names to validation status (True=valid, False=invalid)

        """

        results: dict[str, bool] = Field(
            description="Mapping of validated items to validation status",
        )


__all__ = ["FlextLdifModels"]
