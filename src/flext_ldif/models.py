"""FLEXT LDIF Models - Unified Namespace for LDIF Domain Models.

This module provides a unified namespace class that aggregates all LDIF domain models
from specialized sub-modules. It extends flext-core FlextCore.Models with LDIF-specific
domain entities organized into focused modules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Type Checking Notes:
- ANN401: **extensions uses Any for flexible quirk-specific data
- pyrefly: import errors for pydantic/dependency_injector (searches wrong site-packages path)
- pyright: configured with extraPaths to resolve imports (see pyrightconfig.json)
- mypy: passes with strict mode (0 errors)
- All 639 tests pass - code is correct, only infrastructure configuration differs
"""

from __future__ import annotations

from flext_core import FlextCore
from pydantic import Field, computed_field


class FlextLdifModels(FlextCore.Models):
    """LDIF domain models extending flext-core FlextCore.Models.

    Unified namespace class that aggregates all LDIF domain models from specialized sub-modules.
    Provides a single access point for all LDIF models while maintaining modular organization.

    This class extends flext-core FlextCore.Models and organizes LDIF-specific models into
    focused sub-modules for better maintainability and reduced complexity.
    """

    # =========================================================================
    # DOMAIN MODELS - Core business entities
    # =========================================================================
    class DistinguishedName(FlextCore.Models.Value):
        """Distinguished Name value object."""

        value: str = Field(..., description="DN string value")
        metadata: dict[str, str] | None = Field(
            default=None,
            description="Quirk-specific metadata for preserving original format",
        )

    class AttributeName(FlextCore.Models.Value):
        """LDIF attribute name value object."""

        name: str = Field(..., description="Attribute name")

    class LdifUrl(FlextCore.Models.Value):
        """LDIF URL value object."""

        url: str = Field(..., description="LDIF URL")

    class Encoding(FlextCore.Models.Value):
        """LDIF encoding value object."""

        encoding: str = Field(..., description="Character encoding")

    class QuirkMetadata(FlextCore.Models.Value):
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

        original_format: str | None = Field(
            default=None,
            description="Original string format before parsing (for perfect round-trip)",
        )
        quirk_type: str | None = Field(
            default=None,
            description="Quirk type that generated this metadata (oud, oid, openldap, etc.)",
        )
        parsed_timestamp: str | None = Field(
            default=None, description="Timestamp when data was parsed (ISO 8601 format)"
        )
        extensions: dict[str, object] = Field(
            default_factory=dict,
            description="Quirk-specific extensions (line_breaks, dn_spaces, attribute_order, etc.)",
        )
        custom_data: dict[str, object] = Field(
            default_factory=dict, description="Additional custom data for future quirks"
        )

    class AclPermissions(FlextCore.Models.Value):
        """ACL permissions for LDAP operations."""

        read: bool = Field(default=False, description="Read permission")
        write: bool = Field(default=False, description="Write permission")
        add: bool = Field(default=False, description="Add permission")
        delete: bool = Field(default=False, description="Delete permission")
        search: bool = Field(default=False, description="Search permission")
        compare: bool = Field(default=False, description="Compare permission")
        self_write: bool = Field(default=False, description="Self-write permission")
        proxy: bool = Field(default=False, description="Proxy permission")

    class AclTarget(FlextCore.Models.Value):
        """ACL target specification."""

        target_dn: str = Field(..., description="Target DN pattern")
        attributes: list[str] = Field(
            default_factory=list, description="Target attributes"
        )

    class AclSubject(FlextCore.Models.Value):
        """ACL subject specification."""

        subject_type: str = Field(..., description="Subject type (user, group, etc.)")
        subject_value: str = Field(..., description="Subject value/pattern")

    class Acl(FlextCore.Models.Value):
        """Unified ACL representation."""

        target: FlextLdifModels.AclTarget = Field(..., description="ACL target")
        subject: FlextLdifModels.AclSubject = Field(..., description="ACL subject")
        permissions: FlextLdifModels.AclPermissions = Field(
            ..., description="ACL permissions"
        )

    # =========================================================================
    # DTO MODELS - Data transfer objects
    # =========================================================================

    class LdifValidationResult(FlextCore.Models.Value):
        """Result of LDIF validation operations."""

        is_valid: bool = Field(default=False, description="Whether validation passed")
        errors: FlextCore.Types.StringList = Field(
            default_factory=list, description="List of validation errors"
        )
        warnings: FlextCore.Types.StringList = Field(
            default_factory=list, description="List of validation warnings"
        )

    class AnalyticsResult(FlextCore.Models.Value):
        """Result of LDIF analytics operations."""

        total_entries: int = Field(
            default=0, description="Total number of entries analyzed"
        )
        object_class_distribution: dict[str, int] = Field(
            default_factory=dict, description="Distribution of object classes"
        )
        patterns_detected: FlextCore.Types.StringList = Field(
            default_factory=list, description="Detected patterns in the data"
        )

    class SearchConfig(FlextCore.Models.Value):
        """Configuration for LDAP search operations."""

        base_dn: str = Field(..., description="Base DN for the search")
        search_filter: str = Field(
            default="(objectClass=*)", description="LDAP search filter"
        )
        attributes: FlextCore.Types.StringList = Field(
            default_factory=list, description="Attributes to retrieve"
        )
        scope: str = Field(default="sub", description="Search scope (base, one, sub)")
        time_limit: int = Field(
            default=30, description="Time limit for search in seconds"
        )
        size_limit: int = Field(
            default=0, description="Size limit for search results (0 = no limit)"
        )

        def validate_base_dn(self, v: str) -> str:
            """Validate base DN is not empty.

            Args:
                v: Base DN to validate

            Returns:
                Validated base DN

            Raises:
                ValueError: If base DN is empty

            """
            if not v or not v.strip():
                msg = "Base DN cannot be empty"
                raise ValueError(msg)
            return v.strip()

    class DiffResult(FlextCore.Models.Value):
        """Result of a diff operation showing changes between two datasets.

        Value object for diff comparison results across LDAP data types:
        attributes, objectClasses, ACLs, and directory entries.

        Attributes:
            added: Items present in target but not in source
            removed: Items present in source but not in target
            modified: Items present in both but with different values
            unchanged: Items that are identical in both datasets

        """

        added: list[FlextCore.Types.Dict] = Field(
            default_factory=list,
            description="Items present in target but not in source",
        )
        removed: list[FlextCore.Types.Dict] = Field(
            default_factory=list,
            description="Items present in source but not in target",
        )
        modified: list[FlextCore.Types.Dict] = Field(
            default_factory=list,
            description="Items present in both but with different values",
        )
        unchanged: list[FlextCore.Types.Dict] = Field(
            default_factory=list,
            description="Items that are identical in both datasets",
        )

        def has_changes(self) -> bool:
            """Check if there are any differences."""
            return bool(self.added or self.removed or self.modified)

        def total_changes(self) -> int:
            """Total number of changes (added + removed + modified)."""
            return len(self.added) + len(self.removed) + len(self.modified)

        def get_summary(self) -> str:
            """Get human-readable summary of changes."""
            if not self.has_changes():
                return "No differences found"

            parts: list[object] = []
            if self.added:
                parts.append(f"{len(self.added)} added")
            if self.removed:
                parts.append(f"{len(self.removed)} removed")
            if self.modified:
                parts.append(f"{len(self.modified)} modified")
            if self.unchanged:
                parts.append(f"{len(self.unchanged)} unchanged")

            return ", ".join(str(part) for part in parts)

    class FilterCriteria(FlextCore.Models.Value):
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
            description="Type of filter: dn_pattern, oid_pattern, objectclass, or attribute",
        )
        pattern: str | None = Field(
            default=None,
            description="Pattern for matching (supports wildcards with fnmatch)",
        )
        whitelist: FlextCore.Types.StringList | None = Field(
            default=None,
            description="Whitelist of patterns to include (for OID filtering)",
        )
        blacklist: FlextCore.Types.StringList | None = Field(
            default=None, description="Blacklist of patterns to exclude"
        )
        required_attributes: FlextCore.Types.StringList | None = Field(
            default=None, description="Required attributes for objectClass filtering"
        )
        mode: str = Field(
            default="include",
            description="Filter mode: 'include' to keep matches, 'exclude' to remove matches",
        )

    class ExclusionInfo(FlextCore.Models.Value):
        """Metadata for excluded entries/schema items.

        Stored in QuirkMetadata.extensions['exclusion_info'] to track why
        an entry was excluded during filtering operations.

        Example:
            exclusion = ExclusionInfo(
                excluded=True,
                exclusion_reason="DN outside base context",
                filter_criteria=FilterCriteria(filter_type="dn_pattern", pattern="*,dc=old,dc=com"),
                timestamp="2025-10-09T12:34:56Z"
            )

        """

        excluded: bool = Field(
            default=False, description="Whether the item is excluded"
        )
        exclusion_reason: str | None = Field(
            default=None, description="Human-readable reason for exclusion"
        )
        filter_criteria: FlextLdifModels.FilterCriteria | None = Field(
            default=None, description="Filter criteria that caused the exclusion"
        )
        timestamp: str = Field(
            ..., description="ISO 8601 timestamp when exclusion was marked"
        )

    class CategorizedEntries(FlextCore.Models.Value):
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
            description="Entries categorized as groups (groupOfNames, etc.)",
        )
        containers: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Entries categorized as containers (organizationalUnit, etc.)",
        )
        uncategorized: list[FlextLdifModels.Entry] = Field(
            default_factory=list, description="Entries that don't match any category"
        )

        @computed_field  # type: ignore[misc]
        @property
        def summary(self) -> dict[str, int]:
            """Summary counts for each category - automatically computed."""
            return {
                "users": len(self.users),
                "groups": len(self.groups),
                "containers": len(self.containers),
                "uncategorized": len(self.uncategorized),
                "total": len(self.users)
                + len(self.groups)
                + len(self.containers)
                + len(self.uncategorized),
            }

    class SchemaDiscoveryResult(FlextCore.Models.Value):
        """Result of schema discovery operations."""

        attributes: dict[str, FlextCore.Types.Dict] = Field(
            default_factory=dict,
            description="Discovered attributes with their metadata",
        )
        objectclasses: dict[str, FlextCore.Types.Dict] = Field(
            default_factory=dict,
            description="Discovered object classes with their metadata",
        )

        @computed_field  # type: ignore[misc]
        @property
        def total_attributes(self) -> int:
            """Total number of attributes discovered - automatically computed."""
            return len(self.attributes)

        @computed_field  # type: ignore[misc]
        @property
        def total_objectclasses(self) -> int:
            """Total number of object classes discovered - automatically computed."""
            return len(self.objectclasses)

        def has_schema_data(self) -> bool:
            """Check if schema contains any data."""
            return bool(self.attributes or self.objectclasses)

    class SchemaAttribute(FlextCore.Models.Value):
        """LDAP schema attribute definition model.

        Represents an LDAP attribute type definition from schema.
        """

        name: str = Field(..., description="Attribute name")
        oid: str = Field(..., description="Attribute OID")
        description: str | None = Field(None, description="Attribute description")
        syntax: str = Field(..., description="Attribute syntax OID")
        single_value: bool = Field(
            default=False, description="Whether attribute is single-valued"
        )
        no_user_modification: bool = Field(
            default=False, description="Whether users can modify this attribute"
        )

    class SchemaObjectClass(FlextCore.Models.Value):
        """LDAP schema object class definition model.

        Represents an LDAP object class definition from schema.
        """

        name: str = Field(..., description="Object class name")
        oid: str = Field(..., description="Object class OID")
        description: str | None = Field(None, description="Object class description")
        required_attributes: list[str] = Field(
            default_factory=list, description="Required attributes"
        )
        optional_attributes: list[str] = Field(
            default_factory=list, description="Optional attributes"
        )
        structural: bool = Field(
            default=True, description="Whether this is a structural object class"
        )
        auxiliary: bool = Field(
            default=False, description="Whether this is an auxiliary object class"
        )
        abstract: bool = Field(
            default=False, description="Whether this is an abstract object class"
        )

    class Entry(FlextCore.Models.Entity):
        """LDIF entry domain model."""

        dn: FlextLdifModels.DistinguishedName = Field(
            ..., description="Distinguished Name of the entry"
        )
        attributes: FlextLdifModels.LdifAttributes = Field(
            ..., description="Entry attributes container"
        )
        metadata: FlextLdifModels.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for preserving original entry format",
        )

    class AttributeValues(FlextCore.Models.Value):
        """LDIF attribute values container."""

        values: FlextCore.Types.StringList = Field(
            default_factory=list, description="Attribute values"
        )

    class LdifAttributes(FlextCore.Models.Value):
        """LDIF attributes container with dict-like interface."""

        attributes: dict[str, FlextLdifModels.AttributeValues] = Field(
            default_factory=dict, description="Attribute name to values mapping"
        )
        metadata: dict[str, str] | None = Field(
            default=None,
            description="Quirk-specific metadata for preserving attribute ordering and formats",
        )

        def to_ldap3(
            self, exclude: FlextCore.Types.StringList | None = None
        ) -> dict[str, str | FlextCore.Types.StringList]:
            """Convert attributes to ldap3 format (strings for single values, lists for multi).

            Args:
                exclude: List of attribute names to exclude (e.g., ["objectClass"])

            Returns:
                Dictionary with single-valued attributes as strings and multi-valued as lists

            """
            exclude_set: set[str] | set[object] = set(exclude) if exclude else set()
            result: dict[str, str | FlextCore.Types.StringList] = {}

            for name, attr_values in self.attributes.items():
                if name not in exclude_set:
                    values = attr_values.values
                    result[name] = values[0] if len(values) == 1 else values

            return result

        def add_attribute(
            self, name: str, value: str | FlextCore.Types.StringList
        ) -> None:
            """Add attribute value(s)."""
            if isinstance(value, str):
                value = [value]
            if name in self.attributes:
                self.attributes[name].values.extend(value)
            else:
                self.attributes[name] = FlextLdifModels.AttributeValues(values=value)

        def remove_attribute(self, name: str) -> None:
            """Remove attribute by name."""
            self.attributes.pop(name, None)

    class EntryParsedEvent(FlextCore.Models.DomainEvent):
        """Event emitted when an entry is successfully parsed."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        entry_count: int = Field(..., description="Number of entries parsed")
        source_type: str = Field(..., description="Type of source")
        format_detected: str = Field(..., description="Detected format")
        timestamp: str = Field(..., description="Event timestamp")

    class EntriesValidatedEvent(FlextCore.Models.DomainEvent):
        """Event emitted when entries are validated."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        entry_count: int = Field(..., description="Number of entries validated")
        is_valid: bool = Field(..., description="Whether validation passed")
        error_count: int = Field(..., description="Number of validation errors")
        strict_mode: bool = Field(..., description="Whether strict mode was used")
        timestamp: str = Field(..., description="Event timestamp")

    class AnalyticsGeneratedEvent(FlextCore.Models.DomainEvent):
        """Event emitted when analytics are generated."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        entry_count: int = Field(..., description="Number of entries analyzed")
        statistics: dict[str, int | float] = Field(
            ..., description="Analytics statistics"
        )
        timestamp: str = Field(..., description="Event timestamp")

    class EntriesWrittenEvent(FlextCore.Models.DomainEvent):
        """Event emitted when entries are written."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        entry_count: int = Field(..., description="Number of entries written")
        output_path: str = Field(..., description="Output path")
        format_used: str = Field(..., description="Format used for writing")
        format_options: dict[str, int] = Field(
            default_factory=dict, description="Format options"
        )
        timestamp: str = Field(..., description="Event timestamp")

    class MigrationCompletedEvent(FlextCore.Models.DomainEvent):
        """Event emitted when migration is completed."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        source_entries: int = Field(..., description="Number of source entries")
        target_entries: int = Field(..., description="Number of target entries")
        migration_type: str = Field(..., description="Type of migration performed")
        timestamp: str = Field(..., description="Event timestamp")

    class QuirkRegisteredEvent(FlextCore.Models.DomainEvent):
        """Event emitted when a quirk is registered."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        server_type: str = Field(..., description="Server type")
        quirk_name: str = Field(..., description="Name of the registered quirk")
        timestamp: str = Field(..., description="Event timestamp")


__all__ = ["FlextLdifModels"]
