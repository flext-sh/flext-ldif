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
from typing import Annotated, ClassVar, Literal

from flext_core import FlextModels, FlextResult
from pydantic import (
    ConfigDict,
    Discriminator,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.typings import FlextLdifTypes


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Unified namespace class that aggregates all LDIF domain models.
    Provides a single access point for all LDIF models while maintaining
    modular organization.

    This class extends flext-core FlextModels and organizes LDIF-specific
    models into focused sub-modules for better maintainability.
    """

    # =========================================================================
    # LDIF VALUE OBJECTS - Domain-specific immutable values with validation
    # =========================================================================

    class ObjectClass(FlextModels.Value):
        """Immutable value object representing an LDAP object class.

        Provides type-safe object class representation with validation
        for valid LDAP object class names (lowercase, alphanumeric with hyphens).

        ARCHITECTURAL PATTERN:
        - Extends FlextModels.Value for immutability
        - Enforces object class name validation
        - Supports comparison and hashing for use in collections
        - Provides clear domain semantics vs raw strings
        """

        value: str = Field(
            min_length=1,
            pattern=r"^[a-z0-9-]+$",
            description="Object class name with validation",
            examples=["inetOrgPerson", "groupOfNames", "organizationalUnit"],
        )

        @computed_field
        def display_name(self) -> str:
            """Get human-readable display name."""
            return self.value.title()

    class AttributeName(FlextModels.Value):
        """Immutable value object representing an LDAP attribute name.

        Provides type-safe attribute name representation with validation
        for valid LDAP attribute names (lowercase, alphanumeric with hyphens).

        ARCHITECTURAL PATTERN:
        - Extends FlextModels.Value for immutability
        - Enforces attribute name validation
        - Supports comparison for attribute identification
        - Provides clear domain semantics vs raw strings
        """

        value: str = Field(
            min_length=1,
            pattern=r"^[a-z0-9_-]+$",
            description="Attribute name with validation",
            examples=["cn", "mail", "telephoneNumber", "objectClass"],
        )

        @computed_field
        def is_multivalued_hint(self) -> bool:
            """Guess if attribute might be multivalued based on name."""
            # Heuristic: plural names often indicate multivalued
            return self.value.endswith(("s", "List", "members"))

    class SearchScope(FlextModels.Value):
        """Immutable value object representing an LDAP search scope.

        Provides type-safe search scope with validation for allowed LDAP scopes.

        ARCHITECTURAL PATTERN:
        - Extends FlextModels.Value for immutability
        - Enforces search scope enum validation
        - Supports comparison for scope operations
        - Provides clear domain semantics vs raw strings
        """

        value: Literal["base", "one", "sub", "subordinate"] = Field(
            description="Search scope value with enum validation",
            examples=["base", "one", "sub", "subordinate"],
        )

        @computed_field
        def is_deep_search(self) -> bool:
            """Check if scope performs deep search (sub or subordinate)."""
            return self.value in {"sub", "subordinate"}

    class FilterValue(FlextModels.Value):
        """Immutable value object representing an LDAP search filter.

        Provides type-safe LDAP filter representation with basic validation.

        ARCHITECTURAL PATTERN:
        - Extends FlextModels.Value for immutability
        - Validates basic filter structure (parentheses matching)
        - Supports comparison for filter identification
        - Provides clear domain semantics vs raw strings
        """

        value: str = Field(
            min_length=1,
            pattern=r"^\(.*\)$",
            description="LDAP search filter with validation",
            examples=["(objectClass=person)", "(|(cn=*)(mail=*))"],
        )

        @computed_field
        def is_complex(self) -> bool:
            """Check if filter is complex (contains logical operators)."""
            return "|" in self.value or "&" in self.value or "!" in self.value

    # =========================================================================
    # DOMAIN MODELS - Core business entities
    # =========================================================================
    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
        )

        value: str = Field(
            ..., description="DN string value", min_length=1, max_length=2048
        )
        metadata: FlextLdifTypes.Models.CustomDataDict | None = Field(
            default=None,
            description="Quirk-specific metadata for preserving original format",
        )

        # Basic DN pattern for validation (RFC 4514 simplified)
        _DN_COMPONENT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^[a-zA-Z][a-zA-Z0-9-]*=.*",  # attribute=value format
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

        original_format: str | None = Field(
            default=None,
            description="Original format before parsing (round-trip)",
        )
        quirk_type: str | None = Field(
            default=None,
            description="Quirk type that generated metadata (oud, oid, etc.)",
        )
        parsed_timestamp: str | None = Field(
            default=None, description="Timestamp when data was parsed (ISO 8601)"
        )
        extensions: FlextLdifTypes.Models.CustomDataDict = Field(
            default_factory=dict,
            description="Extensions (line_breaks, dn_spaces, attribute_order)",
        )
        custom_data: FlextLdifTypes.Models.CustomDataDict = Field(
            default_factory=dict, description="Additional custom data for future quirks"
        )

        @classmethod
        def create_for_quirk(
            cls,
            quirk_type: str,
            original_format: str | None = None,
            extensions: FlextLdifTypes.Models.CustomDataDict | None = None,
            custom_data: FlextLdifTypes.Models.CustomDataDict | None = None,
        ) -> FlextLdifModels.QuirkMetadata:
            """Create QuirkMetadata for a specific quirk type."""
            return cls(
                quirk_type=quirk_type,
                original_format=original_format,
                extensions=extensions or {},
                custom_data=custom_data or {},
                parsed_timestamp=None,  # Will be set by caller if needed
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
            cls, data: FlextLdifTypes.Entry.EntryCreateData
        ) -> FlextResult[FlextLdifModels.AclPermissions]:
            """Create an AclPermissions instance from data."""
            try:
                # Create mutable copy of data (may be Mapping from tests)
                data_mutable: FlextLdifTypes.Models.CustomDataDict = dict(data)

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
                    cls.model_validate(data_mutable)
                )
            except Exception as e:  # pragma: no cover
                return FlextResult[FlextLdifModels.AclPermissions].fail(
                    f"Failed to create AclPermissions: {e}"
                )

        @computed_field
        def permissions(self) -> list[str]:
            """Get permissions as a list of strings."""
            perms = []
            if self.read:
                perms.append("read")
            if self.write:
                perms.append("write")
            if self.add:
                perms.append("add")
            if self.delete:
                perms.append("delete")
            if self.search:
                perms.append("search")
            if self.compare:
                perms.append("compare")
            if self.self_write:
                perms.append("self_write")
            if self.proxy:
                perms.append("proxy")
            return perms

    class AclTarget(FlextModels.ArbitraryTypesModel):
        """ACL target specification."""

        target_dn: str = Field(..., description="Target DN pattern")
        attributes: list[str] = Field(
            default_factory=list, description="Target attributes"
        )

    class AclSubject(FlextModels.ArbitraryTypesModel):
        """ACL subject specification."""

        subject_type: str = Field(..., description="Subject type (user, group, etc.)")
        subject_value: str = Field(..., description="Subject value/pattern")

    class AclBase(FlextModels.ArbitraryTypesModel):
        """Base class for all ACL types with common fields.

        This base class defines the shared fields for all ACL implementations.
        Server-specific subtypes extend this with Literal[...] discriminator field.

        Used as the base type in public APIs. The AclType discriminated union
        provides runtime polymorphic type routing based on server_type field.
        """

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
        )

        name: str = Field(..., description="ACL name")
        target: FlextLdifModels.AclTarget = Field(..., description="ACL target")
        subject: FlextLdifModels.AclSubject = Field(..., description="ACL subject")
        permissions: FlextLdifModels.AclPermissions = Field(
            ..., description="ACL permissions"
        )
        server_type: Literal[
            "openldap", "openldap2", "openldap1", "oracle_oid", "oracle_oud", "389ds"
        ] = Field(..., description="Server type discriminator")
        raw_acl: str = Field(default="", description="Original ACL string")

    class OpenLdapAcl(AclBase):
        """OpenLDAP olcAccess ACL (catch-all legacy)."""

    class OpenLdap2Acl(AclBase):
        """OpenLDAP 2.x modern cn=config ACL."""

    class OpenLdap1Acl(AclBase):
        """OpenLDAP 1.x legacy slapd.conf ACL."""

    class OracleOidAcl(AclBase):
        """Oracle Internet Directory (OID) orclaci ACL."""

    class OracleOudAcl(AclBase):
        """Oracle Unified Directory (OUD) orclaci ACL."""

    class Ds389Acl(AclBase):
        """Red Hat 389 Directory Server ACI."""

    # Discriminated Union: Pydantic 2 polymorphic type with automatic routing
    # The server_type field determines which ACL subtype to use
    # Direct Pydantic 2 approach - no factory class needed
    # Use this type directly with Pydantic's model_validate() for instantiation
    AclType = Annotated[
        OpenLdapAcl
        | OpenLdap2Acl
        | OpenLdap1Acl
        | OracleOidAcl
        | OracleOudAcl
        | Ds389Acl,
        Discriminator(FlextLdifConstants.DictKeys.SERVER_TYPE),
    ]

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
            default_factory=list, description="List of validation errors"
        )
        warnings: list[str] = Field(
            default_factory=list, description="List of validation warnings"
        )

    class AnalyticsResult(FlextModels.ArbitraryTypesModel):
        """Result of LDIF analytics operations."""

        total_entries: int = Field(
            default=0, description="Total number of entries analyzed"
        )
        object_class_distribution: FlextLdifTypes.CommonDict.DistributionDict = Field(
            default_factory=dict, description="Distribution of object classes"
        )
        patterns_detected: list[str] = Field(
            default_factory=list, description="Detected patterns in the data"
        )

    class SearchConfig(FlextModels.ArbitraryTypesModel):
        """Configuration for LDAP search operations."""

        base_dn: str = Field(
            ..., min_length=1, description="Base DN for the search (cannot be empty)"
        )
        search_filter: str = Field(
            default="(objectClass=*)", description="LDAP search filter"
        )
        attributes: list[str] = Field(
            default_factory=list, description="Attributes to retrieve"
        )
        scope: str = Field(default="sub", description="Search scope (base, one, sub)")
        time_limit: int = Field(
            default=30, description="Time limit for search in seconds"
        )
        size_limit: int = Field(
            default=0, description="Size limit for search results (0 = no limit)"
        )

    class DiffItem(FlextModels.ArbitraryTypesModel):
        """Individual item in a diff operation result.

        Represents a single changed item with its metadata.
        """

        key: str = Field(..., description="Item identifier/key")
        value: FlextLdifTypes.Models.ItemData = Field(
            ..., description="Item data/value"
        )
        metadata: FlextLdifTypes.Models.ItemMetadata | None = Field(
            default=None, description="Additional metadata about the change"
        )

    class DiffResult(FlextModels.ArbitraryTypesModel):
        """Result of a diff operation showing changes between two datasets.

        Value object for diff comparison results across LDAP data types:
        attributes, objectClasses, ACLs, and directory entries.

        Attributes:
        added: Items present in target but not in source
        removed: Items present in source but not in target
        modified: Items present in both but with different values
        unchanged: Items that are identical in both datasets

        """

        added: list[FlextLdifModels.DiffItem] = Field(
            default_factory=list,
            description="Items present in target but not in source",
        )
        removed: list[FlextLdifModels.DiffItem] = Field(
            default_factory=list,
            description="Items present in source but not in target",
        )
        modified: list[FlextLdifModels.DiffItem] = Field(
            default_factory=list,
            description="Items present in both but with different values",
        )
        unchanged: list[FlextLdifModels.DiffItem] = Field(
            default_factory=list,
            description="Items that are identical in both datasets",
        )

        @computed_field
        def has_changes(self) -> bool:
            """Check if there are any differences."""
            return bool(self.added or self.removed or self.modified)

        @computed_field
        def total_changes(self) -> int:
            """Total number of changes (added + removed + modified)."""
            return len(self.added) + len(self.removed) + len(self.modified)

        def summary(self) -> str:
            """Get human-readable summary of changes."""
            if not self.has_changes():
                return "No differences found"

            parts: list[str] = []
            if self.added:
                parts.append(f"{len(self.added)} added")
            if self.removed:
                parts.append(f"{len(self.removed)} removed")
            if self.modified:
                parts.append(f"{len(self.modified)} modified")
            if self.unchanged:
                parts.append(f"{len(self.unchanged)} unchanged")

            return ", ".join(parts)

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
            default=None, description="Blacklist of patterns to exclude"
        )
        required_attributes: list[str] | None = Field(
            default=None, description="Required attributes for objectClass"
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
            description="Entries categorized as groups (groupOfNames, etc.)",
        )
        containers: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Entries categorized as containers (organizationalUnit, etc.)",
        )
        uncategorized: list[FlextLdifModels.Entry] = Field(
            default_factory=list, description="Entries that don't match any category"
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

    class SchemaAttribute(FlextModels.ArbitraryTypesModel):
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
        metadata: FlextLdifModels.QuirkMetadata | None = Field(
            default=None, description="Quirk-specific metadata"
        )

    class SchemaObjectClass(FlextModels.ArbitraryTypesModel):
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
        metadata: FlextLdifModels.QuirkMetadata | None = Field(
            default=None, description="Quirk-specific metadata"
        )

        @computed_field
        def object_class_kind(self) -> str:
            """Get object class kind (structural, auxiliary, or abstract)."""
            if self.abstract:
                return "abstract"
            if self.auxiliary:
                return "auxiliary"
            return "structural"

        @computed_field
        def total_attributes(self) -> int:
            """Total number of attributes (required + optional)."""
            return len(self.required_attributes) + len(self.optional_attributes)

        @computed_field
        def attribute_summary(self) -> FlextLdifTypes.CommonDict.DistributionDict:
            """Get summary of required and optional attributes."""
            return {
                "required": len(self.required_attributes),
                "optional": len(self.optional_attributes),
                "total": len(self.required_attributes) + len(self.optional_attributes),
            }

    class Entry(FlextModels.Entity):
        """LDIF entry domain model."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
        )

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

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> FlextLdifModels.Entry:
            """Validate cross-field consistency in Entry model.

            Validates:
            - ObjectClass attribute exists (LDAP requirement)

            Returns:
            Self (for method chaining)

            Raises:
            ValueError: If validation fails

            """
            # Ensure entry has objectClass attribute (LDAP requirement)
            # Exception: schema entries (dn: cn=schema) contain schema
            # definitions, not directory objects
            if (
                not self.has_attribute("objectClass")
                and self.dn.value.lower() != "cn=schema"
            ):
                msg = f"Entry {self.dn.value} must have objectClass"
                raise ValueError(msg)

            return self

        @classmethod
        def create(
            cls,
            dn: str | FlextLdifModels.DistinguishedName,
            attributes: FlextLdifTypes.CommonDict.AttributeDict
            | FlextLdifModels.LdifAttributes,
            metadata: FlextLdifModels.QuirkMetadata | None = None,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create a new Entry instance with validation.

            Args:
            dn: Distinguished Name for the entry
            attributes: Entry attributes as dict[str, list[str]] or LdifAttributes
            metadata: Optional quirk metadata

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
                    # Build AttributeValues for each attribute
                    attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}
                    for attr_name, attr_values in attributes.items():
                        attrs_dict[attr_name] = FlextLdifModels.AttributeValues(
                            values=attr_values
                        )
                    attrs_obj = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                else:
                    attrs_obj = attributes

                # Use model_validate to ensure Pydantic handles
                # default_factory fields. Entity fields have defaults.
                entry_data = {
                    FlextLdifConstants.DictKeys.DN: dn_obj,
                    FlextLdifConstants.DictKeys.ATTRIBUTES: attrs_obj,
                    "metadata": metadata,
                }
                return FlextResult[FlextLdifModels.Entry].ok(
                    cls.model_validate(entry_data)
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create Entry: {e}"
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
                    return attr_values.values
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
                FlextLdifConstants.DictKeys.OBJECTCLASS
            )

    class AttributeValues(FlextModels.ArbitraryTypesModel):
        """LDIF attribute values container."""

        values: list[str] = Field(default_factory=list, description="Attribute values")

        @computed_field
        def single_value(self) -> str | None:
            """Get single value if there's exactly one value, None otherwise."""
            if len(self.values) == 1:
                return self.values[0]
            return None

    class LdifAttributes(FlextModels.ArbitraryTypesModel):
        """LDIF attributes container with dict-like interface."""

        attributes: dict[str, FlextLdifModels.AttributeValues] = Field(
            default_factory=dict, description="Attribute name to values"
        )
        metadata: FlextLdifTypes.Models.CustomDataDict | None = Field(
            default=None,
            description="Metadata for preserving ordering and formats",
        )

        def get(self, key: str, default: list[str] | None = None) -> list[str] | None:
            """Dict-like get method for backward compatibility."""
            if key in self.attributes:
                return self.attributes[key].values
            return default

        def get_attribute(self, key: str) -> FlextLdifModels.AttributeValues | None:
            """Get AttributeValues for a specific attribute name.

            Args:
            key: Attribute name

            Returns:
            AttributeValues object or None if not found

            """
            return self.attributes.get(key)

        def add_attribute(self, key: str, values: str | list[str]) -> None:
            """Add or update an attribute with values.

            Args:
            key: Attribute name
            values: Single value or list of values

            """
            if isinstance(values, str):
                values = [values]
            self.attributes[key] = FlextLdifModels.AttributeValues(values=values)

        def remove_attribute(self, key: str) -> None:
            """Remove an attribute if it exists.

            Args:
            key: Attribute name

            """
            self.attributes.pop(key, None)

        def to_ldap3(
            self, exclude: list[str] | None = None
        ) -> FlextLdifTypes.CommonDict.AttributeDict:
            """Convert to ldap3-compatible attributes dict.

            Args:
            exclude: List of attribute names to exclude from output

            Returns:
            Dict compatible with ldap3 library format

            """
            exclude_set = set(exclude or [])
            result: FlextLdifTypes.CommonDict.AttributeDict = {}

            for attr_name, attr_values in self.attributes.items():
                if attr_name not in exclude_set:
                    result[attr_name] = attr_values.values

            return result

        @classmethod
        def create(
            cls, attrs_data: FlextLdifTypes.Models.CustomDataDict
        ) -> FlextResult[FlextLdifModels.LdifAttributes]:
            """Create an LdifAttributes instance from data.

            Args:
            attrs_data: Dictionary mapping attribute names to values

            Returns:
            FlextResult with LdifAttributes instance or error

            """
            try:
                # Wrap attrs_data in ATTRIBUTES key for Pydantic validation
                # The model has an ATTRIBUTES field that expects this
                return FlextResult[FlextLdifModels.LdifAttributes].ok(
                    cls.model_validate({
                        FlextLdifConstants.DictKeys.ATTRIBUTES: attrs_data
                    })
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifAttributes].fail(
                    f"Failed to create LdifAttributes: {e}"
                )

    class EntryParsedEvent(FlextModels.DomainEvent):
        """Event emitted when an entry is successfully parsed."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        entry_count: int = Field(..., description="Number of entries parsed")
        source_type: str = Field(..., description="Type of source")
        format_detected: str = Field(..., description="Detected format")
        timestamp: str = Field(..., description="Event timestamp")

    class EntriesValidatedEvent(FlextModels.DomainEvent):
        """Event emitted when entries are validated."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        entry_count: int = Field(..., description="Number of entries validated")
        is_valid: bool = Field(..., description="Whether validation passed")
        error_count: int = Field(..., description="Number of validation errors")
        strict_mode: bool = Field(..., description="Whether strict mode was used")
        timestamp: str = Field(..., description="Event timestamp")

    class AnalyticsGeneratedEvent(FlextModels.DomainEvent):
        """Event emitted when analytics are generated."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        entry_count: int = Field(..., description="Number of entries analyzed")
        statistics: FlextLdifTypes.Models.CustomDataDict = Field(
            ..., description="Analytics statistics"
        )
        timestamp: str = Field(..., description="Event timestamp")

    class EntriesWrittenEvent(FlextModels.DomainEvent):
        """Event emitted when entries are written."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        entry_count: int = Field(..., description="Number of entries written")
        output_path: str = Field(..., description="Output path")
        format_used: str = Field(..., description="Format used for writing")
        format_options: FlextLdifTypes.CommonDict.DistributionDict = Field(
            default_factory=dict, description="Format options"
        )
        timestamp: str = Field(..., description="Event timestamp")

    class MigrationCompletedEvent(FlextModels.DomainEvent):
        """Event emitted when migration is completed."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        source_entries: int = Field(..., description="Number of source entries")
        target_entries: int = Field(..., description="Number of target entries")
        migration_type: str = Field(..., description="Type of migration performed")
        timestamp: str = Field(..., description="Event timestamp")

    class QuirkRegisteredEvent(FlextModels.DomainEvent):
        """Event emitted when a quirk is registered."""

        event_type: str = Field(..., description="Event type")
        aggregate_id: str = Field(..., description="Aggregate ID")
        server_type: str = Field(..., description="Server type")
        quirk_name: str = Field(..., description="Name of the registered quirk")
        timestamp: str = Field(..., description="Event timestamp")

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
            default=0, ge=0, description="Total entries encountered"
        )
        processed_entries: int = Field(
            default=0, ge=0, description="Successfully processed entries"
        )
        schema_entries: int = Field(
            default=0, ge=0, description="Schema entries categorized"
        )
        hierarchy_entries: int = Field(
            default=0, ge=0, description="Hierarchy entries categorized"
        )
        user_entries: int = Field(
            default=0, ge=0, description="User entries categorized"
        )
        group_entries: int = Field(
            default=0, ge=0, description="Group entries categorized"
        )
        acl_entries: int = Field(default=0, ge=0, description="ACL entries categorized")
        rejected_entries: int = Field(default=0, ge=0, description="Entries rejected")
        rejected_reasons: dict[str, int] = Field(
            default_factory=dict, description="Rejection reason distribution"
        )
        processing_duration: float = Field(
            default=0.0, ge=0.0, description="Processing duration in seconds"
        )

    class PipelineExecutionResult(FlextModels.ArbitraryTypesModel):
        """Result of pipeline execution containing categorized entries and statistics.

        Contains the complete result of a pipeline execution including entries
        organized by category, statistics, and output file paths.

        Attributes:
        entries_by_category: Entries organized by their categorization
        statistics: Pipeline execution statistics
        file_paths: Output file paths for each category

        """

        model_config = ConfigDict(
            arbitrary_types_allowed=True,
            validate_default=True,
        )

        entries_by_category: dict[str, list[FlextLdifModels.Entry]] = Field(
            default_factory=dict,
            description="Entries organized by category",
        )
        statistics: FlextLdifModels.PipelineStatistics = Field(
            default_factory=lambda: FlextLdifModels.PipelineStatistics(),  # noqa: PLW0108
            description="Pipeline execution statistics",
        )
        file_paths: dict[str, str] = Field(
            default_factory=dict,
            description="Output file paths for each category",
        )


__all__ = ["FlextLdifModels"]
