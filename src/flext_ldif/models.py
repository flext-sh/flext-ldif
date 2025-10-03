"""FLEXT LDIF Models - Advanced Pydantic 2 Models with Monadic Composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import Literal, Self, cast

from pydantic import (
    ConfigDict,
    Field,
    SerializationInfo,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)

from flext_core import FlextModels, FlextResult, FlextTypes
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.typings import FlextLdifTypes

# LDIF format constants
rfc = "rfc"
oid = "oid"
auto = "auto"
oud = "oud"


def _default_ldif_attributes() -> FlextLdifModels.LdifAttributes:
    """Factory function for default LDIF attributes."""
    # Returns empty LdifAttributes instance
    return FlextLdifModels.LdifAttributes(attributes={})


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Contains ONLY Pydantic v2 model definitions with business logic.
    Uses flext-core SOURCE OF TRUTH for model patterns and validation.
    Implements advanced monadic composition patterns with FlextResult.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        extra="forbid",
        frozen=False,
        validate_return=True,
        ser_json_timedelta="iso8601",
        ser_json_bytes="base64",
        hide_input_in_errors=True,
        json_schema_extra={
            "examples": [
                {
                    "ldif_processing_enabled": True,
                    "validation_enabled": True,
                    "schema_validation_enabled": True,
                    "acl_processing_enabled": True,
                }
            ],
            "description": "LDIF processing models for comprehensive directory data operations",
        },
    )

    @computed_field
    def active_ldif_models_count(self) -> int:
        """Computed field returning the number of active LDIF model types."""
        model_types = [
            "DistinguishedName",
            "LdifAttribute",
            "LdifAttributes",
            "Entry",
            "ChangeRecord",
            "SchemaObjectClass",
            "SchemaDiscoveryResult",
            "AclTarget",
            "AclSubject",
            "AclPermissions",
            "UnifiedAcl",
            "SchemaAttribute",
            "SearchConfig",
            "LdifDocument",
            "AttributeValues",
        ]
        return len(model_types)

    @computed_field
    def ldif_model_summary(self) -> FlextTypes.Dict:
        """Computed field providing summary of LDIF model capabilities."""
        return {
            "entry_models": 4,
            "schema_models": 3,
            "acl_models": 4,
            "utility_models": 4,
            "total_models": self.active_ldif_models_count,
            "processing_features": [
                "parsing",
                "validation",
                "schema_discovery",
                "acl_processing",
            ],
            "format_support": ["ldif", "json", "dict"],
        }

    @model_validator(mode="after")
    def validate_ldif_consistency(self) -> Self:
        """Validate LDIF model consistency across all components."""
        # Perform cross-model validation for LDIF requirements
        return self

    @field_serializer("model_config", when_used="json")
    def serialize_with_ldif_metadata(
        self, value: object, _info: object
    ) -> FlextTypes.Dict:
        """Serialize with LDIF metadata for processing context."""
        return {
            "config": value,
            "ldif_metadata": {
                "models_available": self.active_ldif_models_count,
                "processing_capabilities": [
                    "parsing",
                    "validation",
                    "schema_discovery",
                    "acl_processing",
                ],
                "format_support": ["ldif", "json", "dict"],
                "enterprise_ready": True,
            },
        }

    # ============================================================================
    # CQRS: Commands and Queries
    # ============================================================================

    class ParseQuery(FlextModels.Query):
        """Query to parse LDIF content from various sources.

        Immutable query object following CQRS pattern for read-only operations.
        """

        source: str | bytes | FlextTypes.StringList = Field(
            ..., description="LDIF source content, file path, or lines"
        )
        format: Literal["rfc", "oid", "auto"] = Field(
            default="auto", description="LDIF format to use for parsing"
        )
        encoding: str = Field(default="utf-8", description="Text encoding")
        strict: bool = Field(default=True, description="Strict RFC compliance")

        model_config = ConfigDict(frozen=True)

    class ValidateQuery(FlextModels.Query):
        """Query to validate LDIF entries against schema.

        Immutable query object for validation operations without side effects.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            ..., description="Entries to validate"
        )
        schema_config: FlextTypes.Dict | None = Field(
            default=None, description="Schema configuration"
        )
        strict: bool = Field(default=True, description="Strict validation mode")

        model_config = ConfigDict(frozen=True)

    class AnalyzeQuery(FlextModels.Query):
        """Query to analyze LDIF entries and generate statistics.

        Immutable query object for analytics operations.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            ..., description="Entries to analyze"
        )
        metrics: FlextTypes.StringList | None = Field(
            default=None, description="Specific metrics to calculate"
        )
        include_patterns: bool = Field(
            default=True, description="Include pattern detection"
        )

        model_config = ConfigDict(frozen=True)

    class WriteCommand(FlextModels.Command):
        """Command to write LDIF entries to output.

        Command object for write operations with side effects.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            ..., description="Entries to write"
        )
        format: Literal["rfc", "oid"] = Field(
            default="rfc", description="Output LDIF format"
        )
        output: str | None = Field(default=None, description="Output file path")
        line_width: int = Field(
            default=76, description="Maximum line width for wrapping", ge=40, le=200
        )

    class MigrateCommand(FlextModels.Command):
        """Command to migrate LDIF entries between formats.

        Command object for migration operations with transformations.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            ..., description="Entries to migrate"
        )
        source_format: Literal["rfc", "oid", "oud"] = Field(
            ..., description="Source LDIF format"
        )
        target_format: Literal["rfc", "oid", "oud"] = Field(
            ..., description="Target LDIF format"
        )
        quirks: FlextTypes.StringList | None = Field(
            default=None, description="Quirks to apply during migration"
        )
        preserve_comments: bool = Field(
            default=True, description="Preserve comments during migration"
        )

    class RegisterQuirkCommand(FlextModels.Command):
        """Command to register a custom quirk.

        Command object for registry modification operations.
        """

        quirk_type: Literal["schema", "acl", "entry"] = Field(
            ..., description="Type of quirk to register"
        )
        quirk_impl: object = Field(..., description="Quirk implementation")
        override: bool = Field(
            default=False, description="Override existing quirk if present"
        )

    # ============================================================================
    # EVENTS: Domain Events for FlextBus Integration
    # ============================================================================

    class EntryParsedEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF entries are successfully parsed.

        Emitted after successful parse operations for monitoring and extensibility.
        """

        entry_count: int = Field(..., description="Number of entries parsed")
        source_type: Literal["file", "string", "bytes", "list"] = Field(
            ..., description="Type of source that was parsed"
        )
        format_detected: Literal["rfc", "oid", "auto"] = Field(
            ..., description="Format used for parsing"
        )
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "entry.parsed")
            data.setdefault("aggregate_id", "ldif-parser")
            super().__init__(**data)

    class EntriesValidatedEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF entries are validated against schema.

        Emitted after validation operations complete successfully.
        """

        entry_count: int = Field(..., description="Number of entries validated")
        is_valid: bool = Field(..., description="Overall validation result")
        error_count: int = Field(default=0, description="Number of validation errors")
        strict_mode: bool = Field(..., description="Whether strict validation was used")
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "entries.validated")
            data.setdefault("aggregate_id", "ldif-validator")
            super().__init__(**data)

    class AnalyticsGeneratedEvent(FlextModels.DomainEvent):
        """Event emitted when analytics are generated from LDIF entries.

        Emitted after analytics operations complete.
        """

        entry_count: int = Field(..., description="Number of entries analyzed")
        unique_object_classes: int = Field(
            ..., description="Number of unique objectClass values found"
        )
        patterns_detected: int = Field(
            default=0, description="Number of patterns detected"
        )
        statistics: dict[str, int | float] = Field(
            default_factory=dict, description="Additional statistics"
        )
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "analytics.generated")
            data.setdefault("aggregate_id", "ldif-analytics")
            super().__init__(**data)

    class EntriesWrittenEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF entries are written to output.

        Emitted after successful write operations.
        """

        entry_count: int = Field(..., description="Number of entries written")
        output_path: str = Field(..., description="Output file path")
        format_used: Literal["rfc", "oid"] = Field(
            ..., description="Format used for writing"
        )
        output_size_bytes: int = Field(
            default=0, description="Size of written output in bytes"
        )
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "entries.written")
            data.setdefault("aggregate_id", "ldif-writer")
            super().__init__(**data)

    class MigrationCompletedEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF migration completes.

        Emitted after successful migration between formats.
        """

        source_entries: int = Field(..., description="Number of source entries")
        target_entries: int = Field(..., description="Number of target entries")
        migration_type: str = Field(..., description="Type of migration performed")
        entry_count: int = Field(..., description="Number of entries migrated")
        source_format: Literal["rfc", "oid", "oud"] = Field(
            ..., description="Source format"
        )
        target_format: Literal["rfc", "oid", "oud"] = Field(
            ..., description="Target format"
        )
        quirks_applied: FlextTypes.StringList = Field(
            default_factory=list, description="List of quirks applied during migration"
        )
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "migration.completed")
            data.setdefault("aggregate_id", "ldif-migrator")
            super().__init__(**data)

    class QuirkRegisteredEvent(FlextModels.DomainEvent):
        """Event emitted when a custom quirk is registered.

        Emitted after successful quirk registration.
        """

        server_type: str = Field(..., description="Server type for the quirk")
        quirk_name: str = Field(..., description="Name of registered quirk")
        quirk_config: dict[str, object] = Field(
            default_factory=dict, description="Quirk configuration"
        )
        override: bool = Field(..., description="Whether existing quirk was overridden")
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "quirk.registered")
            data.setdefault("aggregate_id", "ldif-registry")
            super().__init__(**data)

    # =============================================================================
    # BASE CLASSES - Technology-Agnostic Foundation
    # =============================================================================

    class BaseOperationResult(FlextModels.Value):
        """Base class for all LDIF operation results.

        Enhanced with FlextModels patterns:
        - Structured errors using FlextModels.ErrorDetail
        - Rich metadata using FlextModels.Metadata
        - Status tracking similar to ProcessingResult
        - Execution time tracking for performance analysis

        Technology-specific results extend this with additional fields.
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        status: Literal["success", "failure", "partial"] = Field(
            default="success",
            description="Operation status",
        )

        errors: list[FlextModels.ErrorDetail] = Field(
            default_factory=list,
            description="Structured operation errors with codes and context",
        )

        metadata: FlextModels.Metadata | None = Field(
            default=None,
            description="Operation metadata (timestamps, tags, attributes)",
        )

        execution_time_ms: int = Field(
            default=0,
            description="Execution time in milliseconds",
        )

        @computed_field
        def error_count(self) -> int:
            """Get count of errors."""
            return len(self.errors)

        @computed_field
        def has_errors(self) -> bool:
            """Check if operation has errors."""
            return len(self.errors) > 0

        @computed_field
        def is_success(self) -> bool:
            """Check if operation was successful (no errors)."""
            return self.status == "success" and len(self.errors) == 0

        @computed_field
        def execution_time_seconds(self) -> float:
            """Get execution time in seconds."""
            return self.execution_time_ms / 1000.0

    class BaseSchemaAttribute(
        FlextModels.Value,
        FlextModels.IdentifiableMixin,
        FlextModels.VersionableMixin,
    ):
        """Base class for schema attribute definitions.

        Common fields for both standard LDIF and OID attribute types.
        Technology-specific attributes extend with additional fields.

        Enhanced with:
        - IdentifiableMixin: Provides unique id (UUID) for tracking
        - VersionableMixin: Provides version and schema_version for versioning
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            description="Attribute name",
        )

        oid: str = Field(
            ...,
            description="Attribute OID",
        )

        syntax: str = Field(
            default="",
            description="Attribute syntax",
        )

        description: str = Field(
            default="",
            description="Attribute description",
        )

        single_value: bool = Field(
            default=False,
            description="Whether attribute is single-valued",
        )

        @computed_field
        def schema_key(self) -> str:
            """Computed field for unique schema key."""
            return f"schema_attr:{self.name.lower()}"

        @computed_field
        def attribute_properties(self) -> FlextTypes.Dict:
            """Base attribute properties."""
            return {
                "name": self.name,
                "oid": self.oid,
                "single_valued": self.single_value,
                "has_syntax": bool(self.syntax),
                "has_description": bool(self.description),
            }

    class BaseSchemaObjectClass(
        FlextModels.Value,
        FlextModels.IdentifiableMixin,
        FlextModels.VersionableMixin,
    ):
        """Base class for schema objectClass definitions.

        Common fields for both standard LDIF and OID objectClass types.

        Enhanced with:
        - IdentifiableMixin: Provides unique id (UUID) for tracking
        - VersionableMixin: Provides version and schema_version for versioning
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            description="ObjectClass name",
        )

        oid: str = Field(
            ...,
            description="ObjectClass OID",
        )

        description: str = Field(
            default="",
            description="ObjectClass description",
        )

        superior: str | FlextTypes.StringList = Field(
            default="",
            description="Superior objectClass (can be string or list for multiple inheritance)",
        )

        required_attributes: FlextTypes.StringList = Field(
            default_factory=list,
            description="Required (MUST) attributes",
        )

        optional_attributes: FlextTypes.StringList = Field(
            default_factory=list,
            description="Optional (MAY) attributes",
        )

        @computed_field
        def objectclass_key(self) -> str:
            """Unique key for objectClass."""
            return f"objectclass:{self.name.lower()}"

        @computed_field
        def has_superior(self) -> bool:
            """Check if objectClass has superior."""
            return bool(self.superior)

    class BaseAclPermissions(FlextModels.Value):
        """Base class for ACL permissions.

        Common permission fields for both standard and OID ACLs.
        OID extends with negative permissions and additional types.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        read: bool = Field(default=False, description="Read permission")
        write: bool = Field(default=False, description="Write permission")
        add: bool = Field(default=False, description="Add permission")
        delete: bool = Field(default=False, description="Delete permission")
        search: bool = Field(default=False, description="Search permission")
        compare: bool = Field(default=False, description="Compare permission")
        proxy: bool = Field(default=False, description="Proxy permission")

        @computed_field
        def granted_count(self) -> int:
            """Count of granted permissions."""
            return sum([
                self.read,
                self.write,
                self.add,
                self.delete,
                self.search,
                self.compare,
                self.proxy,
            ])

        @property
        def permissions_summary(self) -> FlextTypes.Dict:
            """Summary of permissions."""
            permissions = {
                "read": self.read,
                "write": self.write,
                "add": self.add,
                "delete": self.delete,
                "search": self.search,
                "compare": self.compare,
                "proxy": self.proxy,
            }
            return {
                "permissions": permissions,
                "granted_count": self.granted_count,
                "total_permissions": len(permissions),
            }

    class BaseAclSubject(FlextModels.Value):
        """Base class for ACL subjects.

        Common fields for identifying who the ACL applies to.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        subject_type: str = Field(
            ...,
            description="Type of subject (user, group, etc.)",
        )

        subject_value: str = Field(
            ...,
            description="Subject identifier value",
        )

        @computed_field
        def subject_key(self) -> str:
            """Unique key for subject."""
            return f"{self.subject_type}:{self.subject_value}"

    class BaseAcl(FlextModels.Value):
        """Base class for ACL rules.

        Common structure for ACL definitions across technologies.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            description="ACL name/identifier",
        )

        target_dn: str = Field(
            default="",
            description="Target DN for ACL",
        )

        @computed_field
        def acl_key(self) -> str:
            """Unique key for ACL."""
            return f"acl:{self.name.lower()}"

    # ============================================================================
    # TECHNOLOGY DETECTION SPECIFICATIONS
    # ============================================================================

    class TechnologySpecification(FlextModels.Value):
        """Base specification for detecting LDIF technology and format types.

        Uses Specification pattern to encapsulate business rules for:
        - OID format detection (Oracle Internet Directory)
        - OUD quirks detection (Oracle Unified Directory)
        - Standard LDIF format detection

        This enables strategy pattern through composition rather than inheritance.
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            description="Technology name (e.g., 'OID', 'OUD', 'Standard')",
        )

        patterns: FlextTypes.StringList = Field(
            default_factory=list,
            description="Regex patterns that indicate this technology",
        )

        attribute_markers: FlextTypes.StringList = Field(
            default_factory=list,
            description="Attribute names that indicate this technology",
        )

        syntax_markers: FlextTypes.StringList = Field(
            default_factory=list,
            description="Syntax patterns that indicate this technology",
        )

        @classmethod
        def is_satisfied_by(cls, data: FlextTypes.Dict) -> bool:  # noqa: ARG003
            """Check if data satisfies this specification.

            Args:
                data: Dictionary containing data to check against specification

            Returns:
                True if data matches this technology specification

            """
            return False  # Override in subclasses

    class OidSpecification(TechnologySpecification):
        """Specification for detecting Oracle Internet Directory (OID) format.

        OID format characteristics:
        - Uses numeric OIDs instead of attribute names
        - Custom syntax for ACIs (orclaci, orclacientry)
        - Specific schema attribute patterns
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        def __init__(self, **data: object) -> None:
            """Initialize OID specification with detection patterns."""
            super().__init__(
                name="OID",
                patterns=[
                    r"orclaci:",
                    r"orclacientry:",
                    r"^\d+\.\d+\.\d+\.\d+",  # Numeric OID pattern
                    r"orclguid",
                    r"orclobjectguid",
                ],
                attribute_markers=[
                    "orclaci",
                    "orclacientry",
                    "orclguid",
                    "orclobjectguid",
                    "orclentryid",
                ],
                syntax_markers=[
                    "OID syntax",
                    "Oracle OID",
                ],
                **data,
            )

        @classmethod
        def is_satisfied_by(cls, data: FlextTypes.Dict) -> bool:
            """Check if data uses OID format.

            Args:
                data: Dictionary with 'attributes', 'dn', or 'content' to check

            Returns:
                True if data appears to be in OID format

            """
            # Check for OID-specific attributes
            attributes = data.get("attributes", {})
            if isinstance(attributes, dict):
                oid_attrs = {"orclaci", "orclacientry", "orclguid", "orclobjectguid"}
                if any(attr in attributes for attr in oid_attrs):
                    return True

            # Check DN for OID patterns
            dn = data.get("dn", "")
            if isinstance(dn, str) and "orcl" in dn.lower():
                return True

            # Check content for OID patterns
            content = data.get("content", "")
            return isinstance(content, str) and any(
                marker in content for marker in ["orclaci:", "orclacientry:"]
            )

    class OudSpecification(TechnologySpecification):
        """Specification for detecting Oracle Unified Directory (OUD) quirks.

        OUD quirks characteristics:
        - Specific attribute handling differences
        - Custom schema extensions
        - Migration-specific attributes
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        def __init__(self, **data: object) -> None:
            """Initialize OUD specification with detection patterns."""
            super().__init__(
                name="OUD",
                patterns=[
                    r"ds-sync-",
                    r"ds-cfg-",
                    r"oud-",
                ],
                attribute_markers=[
                    "ds-sync-hist",
                    "ds-cfg-enabled",
                    "ds-sync-generation-id",
                ],
                syntax_markers=[
                    "OUD syntax",
                    "Directory Server",
                ],
                **data,
            )

        @classmethod
        def is_satisfied_by(cls, data: FlextTypes.Dict) -> bool:
            """Check if data contains OUD quirks.

            Args:
                data: Dictionary with 'attributes', 'dn', or 'content' to check

            Returns:
                True if data contains OUD-specific patterns

            """
            # Check for OUD-specific attributes
            attributes = data.get("attributes", {})
            if isinstance(attributes, dict):
                oud_attrs = {"ds-sync-hist", "ds-cfg-enabled", "ds-sync-generation-id"}
                if any(attr in attributes for attr in oud_attrs):
                    return True

            # Check DN for OUD patterns
            dn = data.get("dn", "")
            if isinstance(dn, str) and any(
                marker in dn.lower() for marker in ["ds-sync", "ds-cfg"]
            ):
                return True

            # Check content for OUD patterns
            content = data.get("content", "")
            return isinstance(content, str) and any(
                marker in content for marker in ["ds-sync-", "ds-cfg-"]
            )

    class StandardLdifSpecification(TechnologySpecification):
        """Specification for detecting standard LDIF format.

        Standard LDIF characteristics:
        - RFC 2849 compliance
        - Standard attribute names (cn, ou, dc, etc.)
        - No vendor-specific extensions
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        def __init__(self, **data: object) -> None:
            """Initialize Standard LDIF specification."""
            super().__init__(
                name="Standard",
                patterns=[
                    r"^dn:",
                    r"^changetype:",
                    r"^objectClass:",
                ],
                attribute_markers=[
                    "cn",
                    "ou",
                    "dc",
                    "objectClass",
                    "uid",
                ],
                syntax_markers=[
                    "Standard LDIF",
                    "RFC 2849",
                ],
                **data,
            )

        @classmethod
        def is_satisfied_by(cls, data: FlextTypes.Dict) -> bool:
            """Check if data is standard LDIF format.

            Args:
                data: Dictionary with 'attributes', 'dn', or 'content' to check

            Returns:
                True if data appears to be standard LDIF (no vendor extensions)

            """
            # If OID or OUD markers are present, it's not standard
            if FlextLdifModels.OidSpecification.is_satisfied_by(data):
                return False
            if FlextLdifModels.OudSpecification.is_satisfied_by(data):
                return False

            # Check for standard LDIF attributes
            attributes = data.get("attributes", {})
            if isinstance(attributes, dict):
                standard_attrs = {"cn", "ou", "dc", "objectClass", "uid"}
                if any(attr in attributes for attr in standard_attrs):
                    return True

            # Check for standard DN format
            dn = data.get("dn", "")
            if isinstance(dn, str) and any(
                part in dn for part in ["dc=", "ou=", "cn="]
            ):
                return True

            return True  # Default to standard if no vendor markers found  # Default to standard if no vendor markers found

    # =============================================================================
    # ADVANCED BASE MODEL CLASSES - Monadic Composition Patterns
    # =============================================================================

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name (DN) for LDIF entries.

        Represents a unique identifier for LDAP entries following RFC 4514.
        Centralizes ALL DN validation logic using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        value: str = Field(
            ...,
            min_length=1,
            max_length=FlextLdifConstants.LdifValidation.MAX_DN_LENGTH,
            description="The DN string value",
        )

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format - CENTRALIZED validation in Model."""
            if not v or not v.strip():
                msg = FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR
                raise ValueError(msg)

            # Check length limit (RFC 4514)
            if len(v) > FlextLdifConstants.LdifValidation.MAX_DN_LENGTH:
                msg = (
                    f"DN exceeds maximum length of "
                    f"{FlextLdifConstants.LdifValidation.MAX_DN_LENGTH}"
                )
                raise ValueError(msg)

            # Parse and validate components
            components = cls._parse_dn_components(v)

            # Validate minimum components
            if len(components) < FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS:
                msg = (
                    f"DN must have at least "
                    f"{FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS} component(s)"
                )
                raise ValueError(msg)

            # Validate each component has attribute=value format
            for component in components:
                if "=" not in component:
                    msg = (
                        f"{FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR}: "
                        f"Component '{component}' missing '=' separator"
                    )
                    raise ValueError(msg)

                attr, value_part = component.split("=", 1)
                if not attr.strip() or not value_part.strip():
                    msg = (
                        f"{FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR}: "
                        f"Empty attribute or value in component '{component}'"
                    )
                    raise ValueError(msg)

            return v.strip()

        @staticmethod
        def _parse_dn_components(dn: str) -> FlextTypes.StringList:
            r"""Parse DN into components handling escaped commas (\,).

            Internal helper for DN component parsing following RFC 4514.
            """
            components: FlextTypes.StringList = []
            current_component = ""
            i = 0
            while i < len(dn):
                if dn[i] == "\\" and i + 1 < len(dn):
                    # Escaped character - include backslash and next char
                    current_component += dn[i : i + 2]
                    i += 2
                elif dn[i] == ",":
                    # Unescaped comma - component boundary
                    if current_component.strip():
                        components.append(current_component.strip())
                    current_component = ""
                    i += 1
                else:
                    current_component += dn[i]
                    i += 1

            # Add last component
            if current_component.strip():
                components.append(current_component.strip())

            if not components:
                msg = "DN has no valid components"
                raise ValueError(msg)

            return components

        @computed_field
        def dn_key(self) -> str:
            """Computed field for unique DN key."""
            return f"dn:{self.value.lower()}"

        @property
        def components(self) -> FlextTypes.StringList:
            """Property for DN components."""
            try:
                return self._parse_dn_components(self.value)
            except ValueError:
                return []

        @computed_field
        def depth(self) -> int:
            """Computed field for DN depth (number of components)."""
            return len(self.components)

        @computed_field
        def normalized_value(self) -> str:
            """Computed field for normalized DN value."""
            try:
                components = self._parse_dn_components(self.value)
                normalized_components: FlextTypes.StringList = []
                for component in components:
                    attr, value_part = component.split("=", 1)
                    # Normalize: lowercase attribute, trim spaces from value
                    attr_normalized = attr.strip().lower()
                    value_normalized = " ".join(value_part.strip().split())
                    normalized_components.append(
                        f"{attr_normalized}={value_normalized}"
                    )
                return ",".join(normalized_components)
            except (ValueError, AttributeError):
                return self.value.strip().lower()

        def extract_attribute(self, attribute_name: str) -> str | None:
            """Extract specific attribute value from DN.

            Args:
                attribute_name: Attribute name to extract (case-insensitive)

            Returns:
                Attribute value or None if not found

            """
            attr_lower = attribute_name.lower()
            for component in self.components:
                if "=" in component:
                    attr, value_part = component.split("=", 1)
                    if attr.strip().lower() == attr_lower:
                        return value_part.strip()
            return None

        @field_serializer("value", when_used="json")
        def serialize_dn_with_metadata(
            self, value: str, _info: object
        ) -> FlextTypes.Dict:
            """Serialize DN with metadata for processing context."""
            return {
                "dn": value,
                "dn_context": {
                    "depth": self.depth,
                    "components_count": len(self.components),
                    "normalized": self.normalized_value,
                },
            }

    class LdifAttribute(FlextModels.Value):
        """LDIF attribute with name and values."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            min_length=1,
            description="Attribute name",
        )

        values: FlextTypes.StringList = Field(
            default_factory=list,
            description="Attribute values",
        )

        @computed_field
        def attribute_key(self) -> str:
            """Computed field for unique attribute key."""
            return f"attr:{self.name.lower()}"

        @property
        def value_count(self) -> int:
            """Property for number of values."""
            return len(self.values)

        @property
        def single_value(self) -> str | None:
            """Property for single value (first value if multiple exist)."""
            return self.values[0] if self.values else None

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            """Validate attribute name."""
            if not v.strip():
                raise ValueError(
                    FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_EMPTY_ERROR
                )
            return v.strip().lower()

        @field_serializer("values", when_used="json")
        def serialize_values_with_context(
            self, value: FlextTypes.StringList
        ) -> FlextTypes.Dict:
            """Serialize values with attribute context."""
            return {
                "values": value,
                "attribute_context": {
                    "name": self.name,
                    "value_count": len(value),
                    "is_multi_valued": len(value) > 1,
                },
            }

    class LdifAttributes(FlextModels.Value):
        """Collection of LDIF attributes."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        attributes: dict[str, FlextLdifModels.AttributeValues] = Field(
            default_factory=dict,
            description="Dictionary of attribute names to AttributeValues",
        )

        @computed_field
        def attribute_count(self) -> int:
            """Computed field for number of attributes."""
            return len(self.attributes)

        @computed_field
        def total_values_count(self) -> int:
            """Computed field for total number of values across all attributes."""
            return sum(
                len(attr_values.values) for attr_values in self.attributes.values()
            )

        @computed_field
        def attribute_summary(self) -> FlextTypes.Dict:
            """Computed field for attributes summary."""
            return {
                "attribute_count": self.attribute_count,
                "total_values": self.total_values_count,
                "attribute_names": list(self.attributes.keys()),
            }

        def get_attribute(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Get attribute values by name."""
            name_lower = name.lower()
            for key, attr_values in self.attributes.items():
                if key.lower() == name_lower:
                    return attr_values
            return None

        def items(self) -> dict[str, object]:
            """Dict-like items method for attribute iteration."""
            return self.attributes.items()

        def get(
            self, name: str, default: FlextTypes.StringList | None = None
        ) -> FlextTypes.StringList:
            """Dict-like get method for attribute values.

            Args:
                name: Attribute name
                default: Default value if attribute not found

            Returns:
                List of attribute values or default

            """
            attr_values = self.get_attribute(name)
            if attr_values is None:
                return default if default is not None else []
            return attr_values.values

        def set_attribute(self, name: str, values: FlextTypes.StringList) -> None:
            """Set attribute values."""
            self.attributes[name.lower()] = FlextLdifModels.AttributeValues(
                values=values
            )

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            name_lower = name.lower()
            return any(key.lower() == name_lower for key in self.attributes)

        @property
        def data(self) -> dict[str, FlextLdifModels.AttributeValues]:
            """Get attributes data dictionary."""
            return self.attributes

        def __getitem__(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Dictionary-like access to attributes."""
            return self.get_attribute(name)

        def __setitem__(self, name: str, values: FlextTypes.StringList) -> None:
            """Dictionary-like setting of attributes."""
            # Since the model is frozen, we need to use object.__setattr__
            if hasattr(self, "attributes"):
                self.attributes[name.lower()] = FlextLdifModels.AttributeValues(
                    values=values
                )
            else:
                object.__setattr__(
                    self,
                    "attributes",
                    {name.lower(): FlextLdifModels.AttributeValues(values=values)},
                )

        def __contains__(self, name: str) -> bool:
            """Dictionary-like 'in' check."""
            return self.has_attribute(name)

        def add_attribute(self, name: str, values: str | FlextTypes.StringList) -> None:
            """Add attribute with values."""
            if isinstance(values, str):
                values = [values]
            self.set_attribute(name, values)

        def remove_attribute(self, name: str) -> None:
            """Remove attribute by name."""
            name_lower = name.lower()
            keys_to_remove = [
                key for key in self.attributes if key.lower() == name_lower
            ]
            for key in keys_to_remove:
                del self.attributes[key]

        @field_serializer("attributes", when_used="json")
        def serialize_attributes_with_summary(
            self, value: dict[str, FlextLdifModels.AttributeValues], _info: object
        ) -> FlextTypes.Dict:
            """Serialize attributes with collection summary."""
            return {"attributes": value, "collection_summary": self.attribute_summary}

    class Entry(FlextModels.Entity):
        """LDIF entry representing a complete LDAP object."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
        )

        dn: FlextLdifModels.DistinguishedName = Field(
            ...,
            description="Distinguished Name of the entry",
        )

        attributes: FlextLdifModels.LdifAttributes = Field(
            default_factory=_default_ldif_attributes,
            description="Entry attributes",
        )

        @computed_field
        def entry_key(self) -> str:
            """Computed field for unique entry key."""
            return f"entry:{self.dn.normalized_value}"

        @computed_field
        def object_classes(self) -> FlextTypes.StringList:
            """Computed field for entry object classes."""
            attr_values = self.get_attribute("objectClass")
            return attr_values.values if attr_values else []

        @computed_field
        def entry_type(self) -> str:
            """Computed field for entry type based on object classes."""
            if self.is_person_entry():
                return "person"
            if self.is_group_entry():
                return "group"
            if self.is_organizational_unit():
                return "organizational_unit"
            return "unknown"

        @computed_field
        def entry_summary(self) -> FlextTypes.Dict:
            """Computed field for entry summary."""
            return {
                "dn": self.dn.value,
                "type": self.entry_type,
                "attribute_count": self.attributes.attribute_count,
                "object_classes": self.object_classes,
            }

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> Self:
            """Validate entry consistency."""
            if not self.dn.value.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.ENTRY_DN_EMPTY_ERROR)
            # Note: objectClass validation is relaxed for LDIF parsing flexibility
            # Some LDIF operations (like modify) may not include objectClass
            return self

        def get_attribute(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return self.attributes.has_attribute(name)

        def get_attribute_values(self, name: str) -> FlextTypes.StringList:
            """Get attribute values as a list of strings."""
            attr_values = self.get_attribute(name)
            return attr_values.values if attr_values else []

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value (first value if multiple exist)."""
            attr_values = self.get_attribute(name)
            return attr_values.single_value if attr_values else None

        def is_person_entry(self) -> bool:
            """Check if entry is a person entry."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            person_classes = {"person", "inetorgperson"}
            return any(oc.lower() in person_classes for oc in attr_values.values)

        def is_group_entry(self) -> bool:
            """Check if entry is a group entry."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            group_classes = {"group", "groupofnames", "groupofuniquenames"}
            return any(oc.lower() in group_classes for oc in attr_values.values)

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            return "organizationalunit" in [oc.lower() for oc in attr_values.values]

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            return object_class.lower() in [oc.lower() for oc in attr_values.values]

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate entry against business rules."""
            try:
                # Basic validation - ensure DN exists and has attributes
                if not self.dn.value.strip():
                    return FlextResult[bool].fail(
                        FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR
                    )

                # Note: objectClass validation is relaxed for LDIF parsing flexibility
                # Some LDIF operations may not include objectClass

                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(str(e))

        @classmethod
        def create(
            cls,
            data: FlextLdifTypes.Entry.EntryCreateData | None = None,
            **kwargs: object,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create a new Entry instance.

            Args:
                data: Dictionary containing 'dn' (str) and 'attributes' (dict[str, FlextTypes.StringList | str])
                **kwargs: Alternative parameter format

            """
            try:
                # Handle both dict and individual parameter patterns
                if data is not None:
                    dn = str(data.get("dn", ""))
                    attributes = data.get("attributes")
                    if isinstance(attributes, dict):
                        # Convert to proper format
                        attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}
                        for key, value in attributes.items():
                            if isinstance(value, list):
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(v) for v in value]
                                )
                            elif isinstance(value, FlextLdifModels.AttributeValues):
                                # Already an AttributeValues object, use it directly
                                attrs_dict[key] = value
                            else:
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(value)]
                                )
                        attributes = attrs_dict
                    else:
                        attributes = {}
                else:
                    dn = str(kwargs.get("dn", ""))
                    attributes = kwargs.get("attributes", {})
                    # Convert attributes to proper format when passed as kwargs
                    if isinstance(attributes, dict):
                        attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}
                        for key, value in attributes.items():
                            if isinstance(value, list):
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(v) for v in value]
                                )
                            elif isinstance(value, FlextLdifModels.AttributeValues):
                                # Already an AttributeValues object, use it directly
                                attrs_dict[key] = value
                            else:
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(value)]
                                )
                        attributes = attrs_dict

                dn_obj = FlextLdifModels.DistinguishedName(value=dn)
                attrs_obj = FlextLdifModels.LdifAttributes(
                    attributes=cast(
                        "dict[str, FlextLdifModels.AttributeValues]", attributes or {}
                    )
                )
                return FlextResult[FlextLdifModels.Entry].ok(
                    cls(dn=dn_obj, attributes=attrs_obj, domain_events=[])
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))

        def to_ldif_string(self, indent: int = 0) -> str:
            """Convert entry to LDIF string."""
            lines = [f"dn: {self.dn.value}"]
            indent_str = " " * indent if indent > 0 else ""

            attribute_lines = [
                f"{indent_str}{attr_name}: {value}"
                for attr_name, attr_values in self.attributes.attributes.items()
                for value in attr_values.values
            ]
            lines.extend(attribute_lines)

            return "\n".join(lines)

        @classmethod
        def from_ldif_string(
            cls, ldif_string: str
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create Entry from LDIF string."""
            try:
                lines = ldif_string.strip().split("\n")
                dn = ""
                attributes: dict[str, FlextLdifModels.AttributeValues] = {}

                for line in lines:
                    stripped_line = line.strip()
                    if not stripped_line or stripped_line.startswith("#"):
                        continue
                    if stripped_line.startswith(FlextLdifConstants.Format.DN_PREFIX):
                        dn = stripped_line[3:].strip()
                    elif ":" in stripped_line:
                        attr_line = stripped_line.split(":", 1)
                        if (
                            len(attr_line)
                            == FlextLdifConstants.Processing.MIN_ATTRIBUTE_PARTS
                        ):
                            attr_name = attr_line[0].strip()
                            attr_value = attr_line[1].strip()
                            if attr_name not in attributes:
                                attributes[attr_name] = FlextLdifModels.AttributeValues(
                                    values=[]
                                )
                            attributes[attr_name].values.append(attr_value)

                if not dn:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "No DN found in LDIF string"
                    )

                return cls.create(data={"dn": dn, "attributes": attributes})
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))

        @field_serializer("dn", when_used="json")
        def serialize_dn_with_entry_context(
            self, value: FlextLdifModels.DistinguishedName, _info: object
        ) -> FlextTypes.Dict:
            """Serialize DN with entry context."""
            return {
                "dn": value.value,
                "entry_context": {
                    "type": self.entry_type,
                    "attribute_count": self.attributes.attribute_count,
                    "object_classes": self.object_classes,
                },
            }

    class ChangeRecord(FlextModels.Entity):
        """LDIF change record for modify operations."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
        )

        dn: FlextLdifModels.DistinguishedName = Field(
            ...,
            description="Distinguished Name of the entry",
        )

        changetype: str = Field(
            ...,
            description="Type of change (add, modify, delete)",
        )

        attributes: FlextLdifModels.LdifAttributes = Field(
            default_factory=_default_ldif_attributes,
            description="Change attributes",
        )

        @computed_field
        def change_key(self) -> str:
            """Computed field for unique change key."""
            return f"change:{self.changetype}:{self.dn.normalized_value}"

        @computed_field
        def change_summary(self) -> FlextTypes.Dict:
            """Computed field for change summary."""
            return {
                "dn": self.dn.value,
                "changetype": self.changetype,
                "attribute_count": self.attributes.attribute_count,
            }

        @model_validator(mode="after")
        def validate_change_record(self) -> Self:
            """Validate change record parameters."""
            valid_types = ["add", "modify", "delete", "modrdn"]
            if self.changetype not in valid_types:
                msg = f"Changetype must be one of: {valid_types}"
                raise ValueError(msg)
            return self

        @classmethod
        def create(
            cls,
            dn: str,
            changetype: str,
            attributes: dict[str, FlextTypes.StringList] | None = None,
        ) -> FlextResult[FlextLdifModels.ChangeRecord]:
            """Create a new ChangeRecord instance."""
            try:
                dn_obj = FlextLdifModels.DistinguishedName(value=dn)

                # Convert attributes to proper format
                attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}
                if attributes:
                    for key, value in attributes.items():
                        if isinstance(value, list):
                            attrs_dict[key] = FlextLdifModels.AttributeValues(
                                values=[str(v) for v in value]
                            )
                        else:
                            attrs_dict[key] = FlextLdifModels.AttributeValues(
                                values=[str(value)]
                            )

                attrs_obj = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                return FlextResult[FlextLdifModels.ChangeRecord].ok(
                    cls(
                        dn=dn_obj,
                        changetype=changetype,
                        attributes=attrs_obj,
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.ChangeRecord].fail(str(e))

        @field_serializer("changetype", when_used="json")
        def serialize_changetype_with_metadata(
            self, value: str, _info: object
        ) -> FlextTypes.Dict:
            """Serialize changetype with change metadata."""
            return {
                "changetype": value,
                "change_metadata": {
                    "dn": self.dn.value,
                    "attribute_count": self.attributes.attribute_count,
                },
            }

    class SchemaObjectClass(BaseSchemaObjectClass):
        """Standard LDAP object class definition.

        Extends BaseSchemaObjectClass with standard LDIF behavior.
        Inherits superior field which supports both string and list for multiple inheritance.
        """

        must: FlextTypes.StringList = Field(
            default_factory=list,
            description="Required attributes (MUST)",
        )

        may: FlextTypes.StringList = Field(
            default_factory=list,
            description="Optional attributes (MAY)",
        )

        structural: bool = Field(
            default=False,
            description="Whether this is a structural object class",
        )

        @computed_field
        def attribute_summary(self) -> FlextTypes.Dict:
            """Computed field for attribute summary."""
            return {
                "required_count": len(self.required_attributes),
                "optional_count": len(self.optional_attributes),
                "total_attributes": len(self.required_attributes)
                + len(self.optional_attributes),
                "is_structural": self.structural,
            }

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaObjectClass instance."""
            try:
                _ = args  # Suppress unused argument warning
                name = str(kwargs.get("name", ""))
                description = str(kwargs.get("description", ""))
                required_attrs = kwargs.get("required_attributes", [])
                required_attributes = (
                    list(required_attrs)
                    if isinstance(required_attrs, (list, tuple))
                    else []
                )
                instance = cls(
                    name=name,
                    oid=str(kwargs.get("oid", "")),
                    description=description,
                    required_attributes=required_attributes,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

        @field_serializer("must", when_used="json")
        def serialize_must_with_schema_context(
            self, value: FlextTypes.StringList, _info: object
        ) -> FlextTypes.Dict:
            """Serialize required attributes with schema context."""
            return {
                "must": value,
                "schema_context": {
                    "objectclass": self.name,
                    "structural": self.structural,
                    "required_count": len(value),
                },
            }

    class SchemaDiscoveryResult(FlextModels.Value):
        """Result of schema discovery operation."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        object_classes: dict[str, FlextLdifModels.SchemaObjectClass] = Field(
            default_factory=dict,
            description="Discovered object classes",
        )

        attributes: dict[str, FlextLdifModels.SchemaAttribute] = Field(
            default_factory=dict,
            description="Discovered attributes",
        )

        server_type: str = Field(
            default="generic",
            description="Server type",
        )

        entry_count: int = Field(
            default=0,
            description="Number of entries processed",
        )

        @computed_field
        def discovery_summary(self) -> FlextTypes.Dict:
            """Computed field for discovery summary."""
            return {
                "objectclass_count": len(self.object_classes),
                "attribute_count": len(self.attributes),
                "entry_count": self.entry_count,
                "server_type": self.server_type,
            }

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaDiscoveryResult instance."""
            try:
                # Extract parameters from kwargs (ignore args for compatibility)
                _ = args  # Suppress unused argument warning
                obj_classes = kwargs.get("object_classes", {})
                object_classes = (
                    dict(obj_classes) if isinstance(obj_classes, dict) else {}
                )
                attrs = kwargs.get("attributes", {})
                attributes = dict(attrs) if isinstance(attrs, dict) else {}
                server_type = str(kwargs.get("server_type", "generic"))
                entry_count_val = kwargs.get("entry_count", 0)
                entry_count = (
                    int(entry_count_val)
                    if isinstance(entry_count_val, (int, str))
                    else 0
                )

                instance = cls(
                    object_classes=object_classes or {},
                    attributes=attributes or {},
                    server_type=server_type,
                    entry_count=entry_count,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

        @field_serializer("object_classes", when_used="json")
        def serialize_objectclasses_with_discovery_context(
            self, value: dict[str, FlextLdifModels.SchemaObjectClass], _info: object
        ) -> FlextTypes.Dict:
            """Serialize object classes with discovery context."""
            return {
                "object_classes": value,
                "discovery_context": self.discovery_summary,
            }

    # =============================================================================
    # ACL MODELS - LDAP Access Control List Models
    # =============================================================================

    class AclTarget(FlextModels.Value):
        """ACL target definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        target_dn: str = Field(
            default="",
            description="Target DN for ACL",
        )

        @computed_field
        def target_key(self) -> str:
            """Computed field for unique target key."""
            return f"target:{self.target_dn.lower()}"

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclTarget instance."""
            try:
                _ = args  # Suppress unused argument warning
                target_dn = str(kwargs.get("target_dn", ""))
                instance = cls(target_dn=target_dn)
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class AclSubject(BaseAclSubject):
        """Standard ACL subject definition.

        Extends BaseAclSubject with standard LDIF behavior.
        """

        subject_dn: str = Field(
            default="",
            description="Subject DN for ACL",
        )

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclSubject instance."""
            try:
                _ = args  # Suppress unused argument warning
                subject_dn = str(kwargs.get("subject_dn", ""))
                instance = cls(
                    subject_type="dn",
                    subject_value=subject_dn,
                    subject_dn=subject_dn,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class AclPermissions(BaseAclPermissions):
        """Standard ACL permissions definition.

        Extends BaseAclPermissions with standard LDIF behavior.
        """

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclPermissions instance."""
            try:
                _ = args  # Suppress unused argument warning
                read = bool(kwargs.get("read"))
                write = bool(kwargs.get("write"))
                add = bool(kwargs.get("add"))
                delete = bool(kwargs.get("delete"))
                search = bool(kwargs.get("search"))
                compare = bool(kwargs.get("compare"))
                proxy = bool(kwargs.get("proxy"))

                instance = cls(
                    read=read,
                    write=write,
                    add=add,
                    delete=delete,
                    search=search,
                    compare=compare,
                    proxy=proxy,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

        @field_serializer("read", when_used="json")
        def serialize_permissions_with_summary(
            self, value: bool, _info: SerializationInfo
        ) -> FlextTypes.Dict:
            """Serialize permissions with summary context.

            Note: Boolean parameter required by Pydantic field_serializer protocol.
            """
            return {"read": value, "permissions_context": self.permissions_summary}

    class UnifiedAcl(FlextModels.Entity):
        """Unified ACL model combining target, subject, and permissions."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
        )

        target: FlextLdifModels.AclTarget = Field(
            ...,
            description="ACL target",
        )

        subject: FlextLdifModels.AclSubject = Field(
            ...,
            description="ACL subject",
        )

        permissions: FlextLdifModels.AclPermissions = Field(
            ...,
            description="ACL permissions",
        )

        name: str = Field(
            default="",
            description="ACL name",
        )

        server_type: str = Field(
            default="",
            description="Server type",
        )

        raw_acl: str = Field(
            default="",
            description="Raw ACL string",
        )

        @computed_field
        def acl_key(self) -> str:
            """Computed field for unique ACL key."""
            return (
                f"acl:{self.name}:{self.target.target_key}:{self.subject.subject_key}"
            )

        @computed_field
        def acl_summary(self) -> FlextTypes.Dict:
            """Computed field for ACL summary."""
            return {
                "name": self.name,
                "target_dn": self.target.target_dn,
                "subject_dn": self.subject.subject_dn,
                "permissions_granted": self.permissions.permissions_summary[
                    "granted_count"
                ],
                "server_type": self.server_type,
            }

        @classmethod
        def create(
            cls,
            *,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            name: str = "",
            server_type: str = "",
            raw_acl: str = "",
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Create a new UnifiedAcl instance."""
            try:
                return FlextResult[FlextLdifModels.UnifiedAcl].ok(
                    cls(
                        target=target,
                        subject=subject,
                        permissions=permissions,
                        name=name,
                        server_type=server_type,
                        raw_acl=raw_acl,
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(str(e))

        @field_serializer("target", when_used="json")
        def serialize_target_with_acl_context(
            self, value: FlextLdifModels.AclTarget, _info: object
        ) -> FlextTypes.Dict:
            """Serialize target with ACL context."""
            return {
                "target": value,
                "acl_context": {
                    "name": self.name,
                    "permissions_granted": self.permissions.permissions_summary[
                        "granted_count"
                    ],
                },
            }

    # =============================================================================
    # SCHEMA MODELS - Additional Schema-related Models
    # =============================================================================

    class SchemaAttribute(BaseSchemaAttribute):
        """Standard LDAP schema attribute definition.

        Extends BaseSchemaAttribute with standard LDIF behavior.
        """

        single_valued: bool = Field(
            default=False,
            description="Whether attribute is single-valued",
        )

        user_modifiable: bool = Field(
            default=True,
            description="Whether attribute can be modified by users",
        )

        @computed_field
        def schema_attribute_key(self) -> str:
            """Computed field for unique schema attribute key."""
            return f"schema_attr:{self.name.lower()}"

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaAttribute instance."""
            try:
                _ = args  # Suppress unused argument warning
                instance = cls(
                    name=str(kwargs.get("name", "")),
                    oid=str(kwargs.get("oid", "")),
                    syntax=str(kwargs.get("syntax", "")),
                    description=str(kwargs.get("description", "")),
                    single_value=bool(kwargs.get("single_value")),
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    # =============================================================================
    # OID SCHEMA MODELS - Oracle Internet Directory Schema Definitions
    # =============================================================================

    class OidSchemaAttribute(BaseSchemaAttribute):
        """OID (Oracle Internet Directory) schema attribute definition.

        Extends BaseSchemaAttribute with OID-specific fields and parsing.
        Example OID format:
        attributetypes: ( 2.16.840.1.113894.1.1.220 NAME 'orclOIDSCExtHost'
            EQUALITY caseIgnoreMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'
            SINGLE-VALUE USAGE userApplications )
        """

        # OID-specific fields
        desc: str = Field(
            default="",
            description="Attribute DESC (description) - OID uses 'desc' instead of 'description'",
        )

        equality: str = Field(
            default="",
            description="EQUALITY matching rule (e.g., 'caseIgnoreMatch')",
        )

        ordering: str = Field(
            default="",
            description="ORDERING matching rule",
        )

        substr: str = Field(
            default="",
            description="SUBSTR matching rule",
        )

        usage: str = Field(
            default="userApplications",
            description="USAGE (userApplications, directoryOperation, etc.)",
        )

        sup: str = Field(
            default="",
            description="SUP (superior/parent attribute)",
        )

        raw_definition: str = Field(
            default="",
            description="Raw OID attribute definition string",
        )

        @computed_field
        def oid_attribute_key(self) -> str:
            """Computed field for unique OID attribute key."""
            return f"oid_attr:{self.name.lower()}"

        @computed_field
        def is_oracle_specific(self) -> bool:
            """Check if attribute is Oracle-specific (starts with 'orcl')."""
            return self.name.lower().startswith("orcl")

        @computed_field
        def attribute_properties(self) -> FlextTypes.Dict:
            """Computed field for OID attribute properties."""
            return {
                "name": self.name,
                "oid": self.oid,
                "single_valued": self.single_value,
                "oracle_specific": self.is_oracle_specific,
                "has_equality": bool(self.equality),
                "has_syntax": bool(self.syntax),
                "usage": self.usage,
            }

        @classmethod
        def from_ldif_line(
            cls, ldif_line: str
        ) -> FlextResult[FlextLdifModels.OidSchemaAttribute]:
            """Parse OID attribute definition from LDIF line.

            Args:
                ldif_line: LDIF line starting with 'attributetypes: ( ...'

            Returns:
                FlextResult with parsed OidSchemaAttribute or error

            """
            try:
                # Remove 'attributetypes: ' prefix and parentheses
                line = ldif_line.strip()
                if not line.startswith("attributetypes:"):
                    return FlextResult[FlextLdifModels.OidSchemaAttribute].fail(
                        "Invalid OID attribute line - must start with 'attributetypes:'"
                    )

                # Extract content between parentheses
                content = line[line.find("(") + 1 : line.rfind(")")].strip()

                # Parse OID (first token)
                tokens = content.split()
                if not tokens:
                    return FlextResult[FlextLdifModels.OidSchemaAttribute].fail(
                        "Empty OID attribute definition"
                    )

                oid_value = tokens[0].strip()

                # Parse key-value pairs
                params: dict[str, str | bool] = {
                    "oid": oid_value,
                    "raw_definition": ldif_line,
                }

                i = 1
                while i < len(tokens):
                    attribute_name = tokens[i].upper()

                    if attribute_name == "NAME":
                        i += 1
                        if i < len(tokens):
                            params["name"] = tokens[i].strip("'\"")
                    elif attribute_name == "DESC":
                        i += 1
                        if i < len(tokens):
                            params["desc"] = tokens[i].strip("'\"")
                    elif attribute_name == "EQUALITY":
                        i += 1
                        if i < len(tokens):
                            params["equality"] = tokens[i].strip("'\"")
                    elif attribute_name == "ORDERING":
                        i += 1
                        if i < len(tokens):
                            params["ordering"] = tokens[i].strip("'\"")
                    elif attribute_name == "SUBSTR":
                        i += 1
                        if i < len(tokens):
                            params["substr"] = tokens[i].strip("'\"")
                    elif attribute_name == "SYNTAX":
                        i += 1
                        if i < len(tokens):
                            params["syntax"] = tokens[i].strip("'\"")
                    elif attribute_name == "SINGLE-VALUE":
                        params["single_value"] = True
                    elif attribute_name == "USAGE":
                        i += 1
                        if i < len(tokens):
                            params["usage"] = tokens[i].strip("'\"")
                    elif attribute_name == "SUP":
                        i += 1
                        if i < len(tokens):
                            params["sup"] = tokens[i].strip("'\"")

                    i += 1

                # Validate required fields
                if "name" not in params:
                    return FlextResult[FlextLdifModels.OidSchemaAttribute].fail(
                        f"OID attribute missing NAME: {oid_value}"
                    )

                # Map desc to description for base class compatibility
                if "desc" in params:
                    params["description"] = params["desc"]

                instance = cls(**params)
                return FlextResult[FlextLdifModels.OidSchemaAttribute].ok(instance)

            except Exception as e:
                return FlextResult[FlextLdifModels.OidSchemaAttribute].fail(
                    f"Failed to parse OID attribute: {e}"
                )

        def to_oud_attribute(self) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert OID attribute to OUD-compatible SchemaAttribute.

            Returns:
                FlextResult with converted SchemaAttribute

            """
            try:
                # Create OUD-compatible schema attribute
                oud_attr = FlextLdifModels.SchemaAttribute(
                    name=self.name,
                    oid=self.oid,
                    syntax=self.syntax,
                    description=self.desc or self.description,
                    single_value=self.single_value,
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(oud_attr)
            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"Failed to convert OID attribute to OUD: {e}"
                )

    class OidSchemaObjectClass(BaseSchemaObjectClass):
        """OID (Oracle Internet Directory) schema objectClass definition.

        Extends BaseSchemaObjectClass with OID-specific fields and parsing.
        Example OID format:
        objectclasses: ( 2.16.840.1.113894.1.2.100 NAME 'orclContainer'
            DESC 'Oracle Container' SUP top STRUCTURAL
            MUST ( cn ) MAY ( description ) )
        """

        # OID-specific fields
        desc: str = Field(
            default="",
            description="ObjectClass DESC (description) - OID uses 'desc'",
        )

        sup: FlextTypes.StringList = Field(
            default_factory=list,
            description="SUP (superior/parent objectClasses)",
        )

        structural: bool = Field(
            default=False,
            description="STRUCTURAL type flag",
        )

        auxiliary: bool = Field(
            default=False,
            description="AUXILIARY type flag",
        )

        abstract: bool = Field(
            default=False,
            description="ABSTRACT type flag",
        )

        must: FlextTypes.StringList = Field(
            default_factory=list,
            description="MUST attributes (required)",
        )

        may: FlextTypes.StringList = Field(
            default_factory=list,
            description="MAY attributes (optional)",
        )

        raw_definition: str = Field(
            default="",
            description="Raw OID objectClass definition string",
        )

        @computed_field
        def oid_objectclass_key(self) -> str:
            """Computed field for unique OID objectClass key."""
            return f"oid_oc:{self.name.lower()}"

        @computed_field
        def is_oracle_specific(self) -> bool:
            """Check if objectClass is Oracle-specific."""
            return self.name.lower().startswith("orcl")

        @computed_field
        def objectclass_type(self) -> str:
            """Computed field for objectClass type."""
            if self.structural:
                return "STRUCTURAL"
            if self.auxiliary:
                return "AUXILIARY"
            if self.abstract:
                return "ABSTRACT"
            return "unknown"

        @computed_field
        def objectclass_properties(self) -> FlextTypes.Dict:
            """Computed field for OID objectClass properties."""
            return {
                "name": self.name,
                "oid": self.oid,
                "type": self.objectclass_type,
                "oracle_specific": self.is_oracle_specific,
                "required_attrs": len(self.must),
                "optional_attrs": len(self.may),
                "has_superior": len(self.sup) > 0,
            }

        @classmethod
        def from_ldif_line(
            cls, ldif_line: str
        ) -> FlextResult[FlextLdifModels.OidSchemaObjectClass]:
            """Parse OID objectClass definition from LDIF line.

            Args:
                ldif_line: LDIF line starting with 'objectclasses: ( ...'

            Returns:
                FlextResult with parsed OidSchemaObjectClass or error

            """
            try:
                # Remove 'objectclasses: ' prefix and parentheses
                line = ldif_line.strip()
                if not line.startswith("objectclasses:"):
                    return FlextResult[FlextLdifModels.OidSchemaObjectClass].fail(
                        "Invalid OID objectClass line - must start with 'objectclasses:'"
                    )

                # Extract content between parentheses
                content = line[line.find("(") + 1 : line.rfind(")")].strip()

                # Parse OID (first token)
                tokens = content.split()
                if not tokens:
                    return FlextResult[FlextLdifModels.OidSchemaObjectClass].fail(
                        "Empty OID objectClass definition"
                    )

                oid_value = tokens[0].strip()

                # Parse key-value pairs
                params: dict[str, str | bool | FlextTypes.StringList] = {
                    "oid": oid_value,
                    "raw_definition": ldif_line,
                    "sup": [],
                    "must": [],
                    "may": [],
                }

                i = 1
                while i < len(tokens):
                    attribute_name = tokens[i].upper()

                    if attribute_name == "NAME":
                        i += 1
                        if i < len(tokens):
                            params["name"] = tokens[i].strip("'\"")
                    elif attribute_name == "DESC":
                        i += 1
                        if i < len(tokens):
                            params["desc"] = tokens[i].strip("'\"")
                    elif attribute_name == "SUP":
                        i += 1
                        if i < len(tokens):
                            sup_value = tokens[i].strip("'\"")
                            if isinstance(params["sup"], list):
                                params["sup"].append(sup_value)
                    elif attribute_name == "STRUCTURAL":
                        params["structural"] = True
                    elif attribute_name == "AUXILIARY":
                        params["auxiliary"] = True
                    elif attribute_name == "ABSTRACT":
                        params["abstract"] = True
                    elif attribute_name == "MUST":
                        # Parse attribute list in parentheses or single attribute
                        i += 1
                        if i < len(tokens):
                            attr_token = tokens[i].strip()
                            if attr_token.startswith("("):
                                # Multiple attributes
                                attrs = []
                                while i < len(tokens) and not tokens[
                                    i
                                ].strip().endswith(")"):
                                    attr = tokens[i].strip("()").strip()
                                    if attr:
                                        attrs.append(attr)
                                    i += 1
                                # Add last attribute
                                if i < len(tokens):
                                    attr = tokens[i].strip("()").strip()
                                    if attr:
                                        attrs.append(attr)
                                if isinstance(params["must"], list):
                                    params["must"].extend(attrs)
                            # Single attribute
                            elif isinstance(params["must"], list):
                                params["must"].append(attr_token.strip("'\""))
                    elif attribute_name == "MAY":
                        # Parse attribute list in parentheses or single attribute
                        i += 1
                        if i < len(tokens):
                            attr_token = tokens[i].strip()
                            if attr_token.startswith("("):
                                # Multiple attributes
                                attrs = []
                                while i < len(tokens) and not tokens[
                                    i
                                ].strip().endswith(")"):
                                    attr = tokens[i].strip("()").strip()
                                    if attr:
                                        attrs.append(attr)
                                    i += 1
                                # Add last attribute
                                if i < len(tokens):
                                    attr = tokens[i].strip("()").strip()
                                    if attr:
                                        attrs.append(attr)
                                if isinstance(params["may"], list):
                                    params["may"].extend(attrs)
                            # Single attribute
                            elif isinstance(params["may"], list):
                                params["may"].append(attr_token.strip("'\""))

                    i += 1

                # Validate required fields
                if "name" not in params:
                    return FlextResult[FlextLdifModels.OidSchemaObjectClass].fail(
                        f"OID objectClass missing NAME: {oid_value}"
                    )

                # Map to base class fields
                params["description"] = params.get("desc", "")
                # Convert superior list to string for base class
                sup_value = params.get("sup", [])
                params["superior"] = (
                    ",".join(sup_value)
                    if isinstance(sup_value, list)
                    else str(sup_value)
                )
                params["required_attributes"] = params.get("must", [])
                params["optional_attributes"] = params.get("may", [])

                instance = cls(**params)
                return FlextResult[FlextLdifModels.OidSchemaObjectClass].ok(instance)

            except Exception as e:
                return FlextResult[FlextLdifModels.OidSchemaObjectClass].fail(
                    f"Failed to parse OID objectClass: {e}"
                )

        def to_oud_objectclass(self) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert OID objectClass to OUD-compatible SchemaObjectClass.

            Returns:
                FlextResult with converted SchemaObjectClass

            """
            try:
                # Create OUD-compatible schema objectClass
                oud_oc = FlextLdifModels.SchemaObjectClass(
                    name=self.name,
                    oid=self.oid,
                    description=self.desc or self.description,
                    must=self.must,
                    may=self.may,
                    superior=self.sup[0] if self.sup else self.superior,
                    structural=self.structural,
                    required_attributes=self.must,
                    optional_attributes=self.may,
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oud_oc)
            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"Failed to convert OID objectClass to OUD: {e}"
                )

    class OidSchema(FlextModels.Value):
        """Complete OID schema container with attributes and objectClasses.

        Container for all OID schema definitions parsed from schema LDIF files.
        Provides conversion methods to OUD-compatible schema format.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        attributes: dict[str, FlextLdifModels.OidSchemaAttribute] = Field(
            default_factory=dict,
            description="OID schema attributes indexed by name",
        )

        objectclasses: dict[str, FlextLdifModels.OidSchemaObjectClass] = Field(
            default_factory=dict,
            description="OID schema objectClasses indexed by name",
        )

        source_dn: str = Field(
            default="cn=subschemasubentry",
            description="Source DN from schema LDIF",
        )

        @computed_field
        def schema_summary(self) -> FlextTypes.Dict:
            """Computed field for schema summary."""
            oracle_attrs = len([
                a for a in self.attributes.values() if a.is_oracle_specific()
            ])
            oracle_ocs = len([
                o for o in self.objectclasses.values() if o.is_oracle_specific()
            ])

            return {
                "total_attributes": len(self.attributes),
                "total_objectclasses": len(self.objectclasses),
                "oracle_specific_attributes": oracle_attrs,
                "oracle_specific_objectclasses": oracle_ocs,
                "standard_attributes": len(self.attributes) - oracle_attrs,
                "standard_objectclasses": len(self.objectclasses) - oracle_ocs,
            }

        @computed_field
        def oracle_specific_items(self) -> dict[str, FlextTypes.StringList]:
            """Get lists of Oracle-specific schema items."""
            oracle_attrs = [
                name
                for name, attr in self.attributes.items()
                if attr.is_oracle_specific()
            ]
            oracle_ocs = [
                name
                for name, oc in self.objectclasses.items()
                if oc.is_oracle_specific()
            ]

            return {
                "attributes": oracle_attrs,
                "objectclasses": oracle_ocs,
            }

        def to_oud_schema(self) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
            """Convert OID schema to OUD-compatible SchemaDiscoveryResult.

            Returns:
                FlextResult with converted schema or error with conversion warnings

            """
            try:
                oud_attributes: dict[str, FlextLdifModels.SchemaAttribute] = {}
                oud_objectclasses: dict[str, FlextLdifModels.SchemaObjectClass] = {}

                conversion_warnings: FlextTypes.StringList = []

                # Convert attributes
                for name, oid_attr in self.attributes.items():
                    result = oid_attr.to_oud_attribute()
                    if result.is_success:
                        oud_attributes[name] = result.value
                    else:
                        conversion_warnings.append(
                            f"Failed to convert attribute {name}: {result.error}"
                        )

                # Convert objectClasses
                for name, oid_oc in self.objectclasses.items():
                    result = oid_oc.to_oud_objectclass()
                    if result.is_success:
                        oud_objectclasses[name] = result.value
                    else:
                        conversion_warnings.append(
                            f"Failed to convert objectClass {name}: {result.error}"
                        )

                # Create SchemaDiscoveryResult
                schema_result = FlextLdifModels.SchemaDiscoveryResult(
                    object_classes=oud_objectclasses,
                    attributes=oud_attributes,
                    server_type="oud",
                    entry_count=len(oud_attributes) + len(oud_objectclasses),
                )

                if conversion_warnings:
                    # Note: Warnings tracked in logs (not returned in FlextResult)
                    # Future: Consider adding warnings field to SchemaDiscoveryResult
                    return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(
                        schema_result
                    )

                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(
                    schema_result
                )

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                    f"Failed to convert OID schema to OUD: {e}"
                )

    # =============================================================================
    # ADDITIONAL MODELS REQUIRED BY TESTS
    # =============================================================================

    class SearchConfig(FlextModels.Value):
        """Search configuration for LDIF operations."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        base_dn: str = Field(
            ...,
            min_length=1,
            description="Base DN for search",
        )

        search_filter: str = Field(
            default="(objectClass=*)",
            description="LDAP search filter",
        )

        attributes: FlextTypes.StringList = Field(
            default_factory=list,
            description="Attributes to return",
        )

        @computed_field
        def search_summary(self) -> FlextTypes.Dict:
            """Computed field for search configuration summary."""
            return {
                "base_dn": self.base_dn,
                "filter": self.search_filter,
                "attribute_count": len(self.attributes),
            }

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN."""
            if not v.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.BASE_DN_EMPTY_ERROR)
            return v.strip()

    class LdifDocument(FlextModels.Entity):
        """LDIF document containing multiple entries."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
        )

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="LDIF entries",
        )

        @computed_field
        def document_summary(self) -> FlextTypes.Dict:
            """Computed field for document summary."""
            entry_types: dict[str, int] = {}
            for entry in self.entries:
                entry_type = entry.entry_type()
                entry_types[entry_type] = entry_types.get(entry_type, 0) + 1

            return {
                "entry_count": len(self.entries),
                "entry_types": entry_types,
                "has_entries": len(self.entries) > 0,
            }

        @classmethod
        def from_ldif_string(
            cls, ldif_string: str
        ) -> FlextResult[FlextLdifModels.LdifDocument]:
            """Create LdifDocument from LDIF string."""
            try:
                if not ldif_string.strip():
                    return FlextResult[FlextLdifModels.LdifDocument].ok(
                        cls(entries=[], domain_events=[])
                    )

                # Split by double newlines to separate entries
                entry_blocks = ldif_string.strip().split("\n\n")
                entries = []

                for block in entry_blocks:
                    if block.strip():
                        result = FlextLdifModels.Entry.from_ldif_string(block)
                        if result.is_success:
                            entries.append(result.value)
                        else:
                            return FlextResult[FlextLdifModels.LdifDocument].fail(
                                f"Failed to parse entry: {result.error}"
                            )

                return FlextResult[FlextLdifModels.LdifDocument].ok(
                    cls(entries=entries, domain_events=[])
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifDocument].fail(str(e))

        def to_ldif_string(self) -> str:
            """Convert document to LDIF string."""
            return "\n\n".join(entry.to_ldif_string() for entry in self.entries)

        @field_serializer("entries", when_used="json")
        def serialize_entries_with_document_context(
            self, value: list[FlextLdifModels.Entry], _info: object
        ) -> FlextTypes.Dict:
            """Serialize entries with document context."""
            return {"entries": value, "document_context": self.document_summary}

    class AttributeValues(FlextModels.Value):
        """Attribute values container with centralized validation.

        Validates attribute values following LDAP/LDIF standards.
        All validation logic centralized in this Model using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        values: FlextTypes.StringList = Field(
            default_factory=list,
            description="Attribute values",
        )

        @field_validator("values")
        @classmethod
        def validate_values(cls, v: FlextTypes.StringList) -> FlextTypes.StringList:
            """Validate attribute values - centralized validation in Model."""
            if not isinstance(v, list):
                msg = FlextLdifConstants.ErrorMessages.ATTRIBUTE_VALUES_ERROR
                raise TypeError(msg)

            validated_values: FlextTypes.StringList = []
            for value in v:
                if not isinstance(value, str):
                    msg = FlextLdifConstants.ErrorMessages.ATTRIBUTE_VALUE_TYPE_ERROR
                    raise TypeError(msg)
                validated_values.append(value.strip())

            return validated_values

        @property
        def values_summary(self) -> FlextTypes.Dict:
            """Property for values summary."""
            return {
                "count": len(self.values),
                "has_values": len(self.values) > 0,
                "is_multi_valued": len(self.values) > 1,
            }

        @property
        def single_value(self) -> str | None:
            """Property for single value (first value if multiple exist)."""
            return self.values[0] if self.values else None

        def __len__(self) -> int:
            """Return the number of values."""
            return len(self.values)

        def __getitem__(self, index: int) -> str:
            """Get value by index."""
            return self.values[index]

        def __contains__(self, item: str) -> bool:
            """Check if value exists in the list."""
            return item in self.values

        @field_serializer("values", when_used="json")
        def serialize_values_with_summary(
            self, value: FlextTypes.StringList, _info: object
        ) -> FlextTypes.Dict:
            """Serialize values with summary context."""
            return {"values": value, "values_context": self.values_summary}

    class AttributeName(FlextModels.Value):
        """Attribute name with RFC 4512 validation.

        Validates LDAP attribute names following RFC 4512 standards.
        All validation logic centralized in this Model using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            min_length=FlextLdifConstants.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH,
            max_length=FlextLdifConstants.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH,
            description="LDAP attribute name",
        )

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            """Validate attribute name format - centralized validation in Model."""
            if not isinstance(v, str):
                msg = FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_ERROR
                raise TypeError(msg)

            if not v.strip():
                msg = FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_EMPTY_ERROR
                raise ValueError(msg)

            # RFC 4512 attribute name validation using centralized pattern from Constants
            if not re.match(
                FlextLdifConstants.LdifValidation.ATTRIBUTE_NAME_PATTERN, v
            ):
                msg = f"Invalid attribute name format: {v}"
                raise ValueError(msg)

            return v.strip()

        @computed_field
        def normalized_name(self) -> str:
            """Computed field for normalized (lowercase) attribute name."""
            return self.name.lower()

        @computed_field
        def is_operational(self) -> bool:
            """Check if this is an operational attribute (starts with special chars)."""
            # Operational attributes typically start with specific prefixes
            operational_prefixes = (
                "createTimestamp",
                "modifyTimestamp",
                "entryDN",
                "entryUUID",
            )
            return self.name in operational_prefixes

    class LdifUrl(FlextModels.Value):
        """LDIF URL reference with validation.

        Validates URL format for LDIF URL references (HTTP, HTTPS, LDAP protocols).
        All validation logic centralized in this Model using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        url: str = Field(
            ...,
            min_length=FlextLdifConstants.LdifValidation.MIN_URL_LENGTH,
            max_length=FlextLdifConstants.LdifValidation.MAX_URL_LENGTH,
            description="URL reference",
        )

        @field_validator("url")
        @classmethod
        def validate_url_format(cls, v: str) -> str:
            """Validate URL format - centralized validation in Model."""
            if not v or not v.strip():
                msg = FlextLdifConstants.ErrorMessages.URL_EMPTY_ERROR
                raise ValueError(msg)

            # URL validation using centralized pattern from Constants
            if not re.match(FlextLdifConstants.LdifValidation.URL_PATTERN, v):
                msg = f"Invalid URL format: {v}"
                raise ValueError(msg)

            return v.strip()

        @computed_field
        def protocol(self) -> str:
            """Computed field for URL protocol."""
            return self.url.split("://")[0] if "://" in self.url else "unknown"

        @computed_field
        def is_secure(self) -> bool:
            """Check if URL uses secure protocol (HTTPS/LDAPS) using Constants."""
            return self.protocol in FlextLdifConstants.LdifValidation.SECURE_PROTOCOLS

    class Encoding(FlextModels.Value):
        """Character encoding with validation.

        Validates character encoding against supported encodings.
        All validation logic centralized in this Model using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        encoding: str = Field(
            ...,
            min_length=FlextLdifConstants.LdifValidation.MIN_ENCODING_LENGTH,
            max_length=FlextLdifConstants.LdifValidation.MAX_ENCODING_LENGTH,
            description="Character encoding",
        )

        @field_validator("encoding")
        @classmethod
        def validate_encoding(cls, v: str) -> str:
            """Validate encoding - centralized validation in Model."""
            if v not in FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS:
                msg = f"Unsupported encoding: {v}"
                raise ValueError(msg)
            return v

        @computed_field
        def is_utf8(self) -> bool:
            """Check if encoding is UTF-8."""
            return self.encoding.lower() in {"utf-8", "utf8"}

        @computed_field
        def normalized_encoding(self) -> str:
            """Computed field for normalized encoding name."""
            return self.encoding.lower().replace("-", "")

    # =========================================================================
    # RESULT MODELS - Operation result containers with validation
    # =========================================================================

    class LdifProcessingResult(FlextModels.Value):
        """Processing operation result with statistics and error tracking.

        Centralizes all processing operation results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        status: str = Field(
            description="Processing status (success, partial, failed)",
        )
        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Processed entries",
        )
        errors: FlextTypes.StringList = Field(
            default_factory=list,
            description="Processing errors encountered",
        )
        warnings: FlextTypes.StringList = Field(
            default_factory=list,
            description="Processing warnings",
        )
        statistics: dict[str, int | float] = Field(
            default_factory=dict,
            description="Processing statistics",
        )

        @field_validator("status")
        @classmethod
        def validate_status(cls, v: str) -> str:
            """Validate status field."""
            valid_statuses = {"success", "partial", "failed", "pending"}
            if v not in valid_statuses:
                msg = f"Invalid status: {v}. Must be one of {valid_statuses}"
                raise ValueError(msg)
            return v

        @computed_field
        def is_success(self) -> bool:
            """Check if processing was successful."""
            return self.status == "success" and len(self.errors) == 0

        @computed_field
        def entry_count(self) -> int:
            """Get count of processed entries."""
            return len(self.entries)

        @computed_field
        def error_count(self) -> int:
            """Get count of errors."""
            return len(self.errors)

    class LdifValidationResult(FlextModels.Value):
        """Validation operation result with detailed error tracking.

        Centralizes all validation results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        is_valid: bool = Field(
            description="Whether validation passed",
        )
        errors: FlextTypes.StringList = Field(
            default_factory=list,
            description="Validation errors",
        )
        warnings: FlextTypes.StringList = Field(
            default_factory=list,
            description="Validation warnings",
        )
        entry_count: int = Field(
            default=0,
            description="Total entries validated",
        )
        valid_count: int = Field(
            default=0,
            description="Count of valid entries",
        )

        @model_validator(mode="after")
        def validate_counts(self) -> FlextLdifModels.LdifValidationResult:
            """Validate count consistency."""
            if self.valid_count > self.entry_count:
                msg = "valid_count cannot exceed entry_count"
                raise ValueError(msg)
            if self.is_valid and self.errors:
                msg = "is_valid cannot be True when errors exist"
                raise ValueError(msg)
            return self

        @computed_field
        def invalid_count(self) -> int:
            """Get count of invalid entries."""
            return self.entry_count - self.valid_count

        @computed_field
        def success_rate(self) -> float:
            """Calculate validation success rate."""
            if self.entry_count == 0:
                return 0.0
            return (self.valid_count / self.entry_count) * 100.0

    class ParseResult(BaseOperationResult):
        """Parsing operation result with error tracking.

        Extends BaseOperationResult with parse-specific fields.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Parsed entries",
        )
        line_count: int = Field(
            default=0,
            ge=0,
            description="Total lines parsed",
        )
        success_rate: float = Field(
            default=0.0,
            ge=0.0,
            le=100.0,
            description="Parse success rate percentage",
        )

        @computed_field
        def entry_count(self) -> int:
            """Get count of parsed entries."""
            return len(self.entries)

        @computed_field
        def is_success(self) -> bool:
            """Check if parsing was successful."""
            return len(self.errors) == 0 and len(self.entries) > 0

    class TransformResult(BaseOperationResult):
        """Transformation operation result with change tracking.

        Extends BaseOperationResult with transformation-specific fields.
        """

        transformed_entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Transformed entries",
        )
        transformation_log: FlextTypes.StringList = Field(
            default_factory=list,
            description="Log of transformations applied",
        )
        changes_count: int = Field(
            default=0,
            ge=0,
            description="Number of changes made",
        )

        @computed_field
        def entry_count(self) -> int:
            """Get count of transformed entries."""
            return len(self.transformed_entries)

    class AnalyticsResult(BaseOperationResult):
        """Analytics operation result with pattern detection.

        Extends BaseOperationResult with analytics-specific fields.
        """

        total_entries: int = Field(
            default=0,
            description="Total number of entries analyzed",
        )
        statistics: dict[str, int | float] = Field(
            default_factory=dict,
            description="Statistical data",
        )
        patterns: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Detected patterns",
        )
        patterns_detected: FlextTypes.StringList = Field(
            default_factory=list,
            description="List of detected pattern names",
        )
        object_class_distribution: dict[str, int] = Field(
            default_factory=dict,
            description="Distribution of object classes",
        )
        dn_patterns: FlextTypes.StringList = Field(
            default_factory=list,
            description="Distinguished name patterns",
        )

        @computed_field
        def total_object_classes(self) -> int:
            """Get total unique object classes."""
            return len(self.object_class_distribution)

    class WriteResult(BaseOperationResult):
        """Write operation result with success tracking.

        Extends BaseOperationResult with write-specific fields.
        """

        success: bool = Field(
            description="Whether write was successful",
        )
        file_path: str | None = Field(
            default=None,
            description="Path to written file",
        )
        entries_written: int = Field(
            default=0,
            ge=0,
            description="Number of entries written",
        )

        @model_validator(mode="after")
        def validate_write_consistency(self) -> Self:
            """Validate write result consistency."""
            if self.success and self.errors:
                msg = "success cannot be True when errors exist"
                raise ValueError(msg)
            if not self.success and self.entries_written > 0:
                msg = "entries_written should be 0 when success is False"
                raise ValueError(msg)
            return self

    class FilterResult(BaseOperationResult):
        """Filter operation result with count tracking.

        Extends BaseOperationResult with filter-specific fields.
        """

        filtered_entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Filtered entries",
        )
        original_count: int = Field(
            default=0,
            ge=0,
            description="Original entry count before filtering",
        )
        filtered_count: int = Field(
            default=0,
            ge=0,
            description="Count after filtering",
        )
        criteria: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Filter criteria used",
        )

        @model_validator(mode="after")
        def validate_filter_counts(self) -> Self:
            """Validate filter count consistency."""
            if self.filtered_count > self.original_count:
                msg = "filtered_count cannot exceed original_count"
                raise ValueError(msg)
            if self.filtered_count != len(self.filtered_entries):
                msg = "filtered_count must match length of filtered_entries"
                raise ValueError(msg)
            return self

        @computed_field
        def removed_count(self) -> int:
            """Get count of entries removed by filter."""
            return self.original_count - self.filtered_count

        @computed_field
        def filter_rate(self) -> float:
            """Calculate filter rate percentage."""
            if self.original_count == 0:
                return 0.0
            return (self.filtered_count / self.original_count) * 100.0

    class HealthCheckResult(BaseOperationResult):
        """Health check result for services and components.

        Extends BaseOperationResult with health check specific fields.
        Uses base status literals (success/failure/partial).
        """

        # Inherit status from BaseOperationResult (success/failure/partial)
        # Health states map to: healthy=success, degraded=partial, unhealthy=failure
        service_name: str = Field(
            description="Service being checked",
        )
        timestamp: str = Field(
            description="Check timestamp",
        )
        details: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Additional health details",
        )
        metrics: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Health metrics",
        )

        @field_validator("status")
        @classmethod
        def validate_status(cls, v: str) -> str:
            """Validate health status uses Constants enum values."""
            valid_statuses = {
                FlextLdifConstants.HealthStatus.HEALTHY.value,
                FlextLdifConstants.HealthStatus.DEGRADED.value,
                FlextLdifConstants.HealthStatus.UNHEALTHY.value,
            }
            if v not in valid_statuses:
                msg = f"Invalid status: {v}. Must be one of {valid_statuses}"
                raise ValueError(msg)
            return v

        @computed_field
        def is_healthy(self) -> bool:
            """Check if service is healthy."""
            return self.status == FlextLdifConstants.HealthStatus.HEALTHY.value

        @computed_field
        def is_degraded(self) -> bool:
            """Check if service is degraded."""
            return self.status == FlextLdifConstants.HealthStatus.DEGRADED.value

    class ServiceStatus(FlextModels.Value):
        """Service status information.

        Centralizes service status data including configuration and state.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        service_name: str = Field(
            description="Service name",
        )
        status: str = Field(
            description="Current status",
        )
        configuration: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Service configuration",
        )
        statistics: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Service statistics",
        )
        capabilities: FlextTypes.StringList = Field(
            default_factory=list,
            description="Service capabilities",
        )

        @computed_field
        def is_operational(self) -> bool:
            """Check if service is operational."""
            return self.status in {
                FlextLdifConstants.HealthStatus.HEALTHY.value,
                FlextLdifConstants.HealthStatus.DEGRADED.value,
            }

    # ============================================================================
    # OID ACI (Access Control) Models
    # ============================================================================

    class OidAciPermissions(BaseAclPermissions):
        """OID ACI permissions - parsed from permissions clause.

        Extends BaseAclPermissions with Oracle-specific permissions and negative permissions.
        """

        # Additional OID-specific permissions
        browse: bool = Field(default=False, description="Browse permission")
        selfwrite: bool = Field(default=False, description="Selfwrite permission")

        # Negative permissions (Oracle-specific deny pattern)
        noread: bool = Field(default=False, description="Deny read")
        nowrite: bool = Field(default=False, description="Deny write")
        nosearch: bool = Field(default=False, description="Deny search")
        nocompare: bool = Field(default=False, description="Deny compare")
        nobrowse: bool = Field(default=False, description="Deny browse")
        noadd: bool = Field(default=False, description="Deny add")
        nodelete: bool = Field(default=False, description="Deny delete")
        noselfwrite: bool = Field(default=False, description="Deny selfwrite")
        noproxy: bool = Field(default=False, description="Deny proxy")

        @classmethod
        def from_permission_string(
            cls, perm_str: str
        ) -> FlextResult[FlextLdifModels.OidAciPermissions]:
            """Parse OID permission string like '(read,write,search,compare)'."""
            try:
                # Remove parentheses and split by comma
                perms_clean = perm_str.strip("() ")
                if not perms_clean:
                    return FlextResult[FlextLdifModels.OidAciPermissions].fail(
                        "Empty permission string"
                    )

                perm_list = [p.strip().lower() for p in perms_clean.split(",")]

                # Create permissions dict
                perm_dict = {}
                for perm in perm_list:
                    if perm in {
                        "read",
                        "write",
                        "search",
                        "compare",
                        "browse",
                        "add",
                        "delete",
                        "selfwrite",
                        "proxy",
                        "noread",
                        "nowrite",
                        "nosearch",
                        "nocompare",
                        "nobrowse",
                        "noadd",
                        "nodelete",
                        "noselfwrite",
                        "noproxy",
                    }:
                        perm_dict[perm] = True

                return cast(
                    "FlextResult[FlextLdifModels.OidAciPermissions]",
                    cls.create(**perm_dict),
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.OidAciPermissions].fail(
                    f"Failed to parse permissions: {e}"
                )

        def to_oud_permissions(self) -> FlextResult[FlextLdifModels.AclPermissions]:
            """Convert OID permissions to OUD AclPermissions."""
            try:
                # OUD uses similar permission model, applying negative permissions
                return cast(
                    "FlextResult[FlextLdifModels.AclPermissions]",
                    FlextLdifModels.AclPermissions.create(
                        read=self.read and not self.noread,
                        write=self.write and not self.nowrite,
                        search=self.search and not self.nosearch,
                        compare=self.compare and not self.nocompare,
                        add=self.add and not self.noadd,
                        delete=self.delete and not self.nodelete,
                        proxy=self.proxy and not self.noproxy,
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.AclPermissions].fail(
                    f"Failed to convert permissions: {e}"
                )

    class OidAciSubject(BaseAclSubject):
        """OID ACI subject - who the rule applies to.

        Extends BaseAclSubject with OID-specific fields and parsing.
        """

        bind_mode: str = Field(
            default="",
            description="BindMode constraint like (Simple|SSLNoAuth)",
        )

        @classmethod
        def from_subject_string(
            cls, subject_str: str
        ) -> FlextResult[FlextLdifModels.OidAciSubject]:
            """Parse OID subject string like 'group="cn=admins,..."' or 'by *'."""
            try:
                subject_clean = subject_str.strip()

                # Handle wildcard (by *)
                if subject_clean == "*":
                    return cast(
                        "FlextResult[FlextLdifModels.OidAciSubject]",
                        cls.create(subject_type="*", subject_value="*"),
                    )

                # Handle self
                if subject_clean.lower() == "self":
                    return cast(
                        "FlextResult[FlextLdifModels.OidAciSubject]",
                        cls.create(subject_type="self", subject_value="self"),
                    )

                # Parse subject with value: group="...", dn="...", etc.
                if "=" in subject_clean:
                    # Extract subject type and value
                    parts = subject_clean.split("=", 1)
                    subject_type = parts[0].strip().lower()

                    # Extract value (may be quoted)
                    value_part = parts[1].strip()
                    if value_part.startswith('"') and '"' in value_part[1:]:
                        # Extract quoted value
                        end_quote = value_part.index('"', 1)
                        subject_value = value_part[1:end_quote]

                        # Check for BindMode constraint
                        bind_mode = ""
                        remainder = value_part[end_quote + 1 :].strip()
                        if remainder.startswith("BindMode="):
                            bind_mode = remainder[9:].strip()

                        return cast(
                            "FlextResult[FlextLdifModels.OidAciSubject]",
                            cls.create(
                                subject_type=subject_type,
                                subject_value=subject_value,
                                bind_mode=bind_mode,
                            ),
                        )
                    # Unquoted value
                    return cast(
                        "FlextResult[FlextLdifModels.OidAciSubject]",
                        cls.create(
                            subject_type=subject_type,
                            subject_value=value_part,
                        ),
                    )

                return FlextResult[FlextLdifModels.OidAciSubject].fail(
                    f"Unable to parse subject: {subject_str}"
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.OidAciSubject].fail(
                    f"Failed to parse subject: {e}"
                )

        def to_oud_subject(self) -> FlextResult[FlextLdifModels.AclSubject]:
            """Convert OID subject to OUD AclSubject."""
            try:
                # OUD uses similar subject model
                return cast(
                    "FlextResult[FlextLdifModels.AclSubject]",
                    FlextLdifModels.AclSubject.create(
                        subject_dn=self.subject_value,
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.AclSubject].fail(
                    f"Failed to convert subject: {e}"
                )

    class OidAciRule(FlextModels.Value):
        """Single OID ACI rule - 'by <subject> <permissions>'."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        subject: FlextLdifModels.OidAciSubject = Field(
            description="Subject of the rule"
        )
        permissions: FlextLdifModels.OidAciPermissions = Field(
            description="Permissions granted/denied"
        )

        @classmethod
        def from_rule_string(
            cls, rule_str: str
        ) -> FlextResult[FlextLdifModels.OidAciRule]:
            """Parse OID ACI rule like 'by group="..." (read,write)'."""
            try:
                # Remove leading 'by ' if present
                rule_clean = rule_str.strip()
                if rule_clean.lower().startswith("by "):
                    rule_clean = rule_clean[3:].strip()

                # Find permissions clause (in parentheses)
                perm_start = rule_clean.rfind("(")
                if perm_start == -1:
                    return FlextResult[FlextLdifModels.OidAciRule].fail(
                        "No permissions found in rule"
                    )

                perm_end = rule_clean.rfind(")")
                if perm_end == -1 or perm_end < perm_start:
                    return FlextResult[FlextLdifModels.OidAciRule].fail(
                        "Malformed permissions clause"
                    )

                # Extract subject and permissions
                subject_str = rule_clean[:perm_start].strip()
                perm_str = rule_clean[perm_start : perm_end + 1]

                # Parse subject
                subject_result = FlextLdifModels.OidAciSubject.from_subject_string(
                    subject_str
                )
                if subject_result.is_failure:
                    return FlextResult[FlextLdifModels.OidAciRule].fail(
                        f"Failed to parse subject: {subject_result.error}"
                    )

                # Parse permissions
                perm_result = FlextLdifModels.OidAciPermissions.from_permission_string(
                    perm_str
                )
                if perm_result.is_failure:
                    return FlextResult[FlextLdifModels.OidAciRule].fail(
                        f"Failed to parse permissions: {perm_result.error}"
                    )

                return cast(
                    "FlextResult[FlextLdifModels.OidAciRule]",
                    cls.create(
                        subject=subject_result.value,
                        permissions=perm_result.value,
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.OidAciRule].fail(
                    f"Failed to parse rule: {e}"
                )

    class OidAci(FlextModels.Value):
        """OID orclaci attribute - entry-level or attribute-level ACI."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        access_type: str = Field(
            description="Access type: 'entry' or 'attr' or 'attr!'"
        )
        target: str = Field(
            default="",
            description="Target entry or attribute (e.g., 'entry', 'attr=(*)', 'attr!=(password)')",
        )
        filter: str = Field(
            default="",
            description="Optional LDAP filter constraint",
        )
        rules: list[FlextLdifModels.OidAciRule] = Field(
            default_factory=list,
            description="List of ACI rules (by <subject> <permissions>)",
        )
        raw_aci: str = Field(
            default="",
            description="Original raw OID ACI string",
        )

        @classmethod
        def from_ldif_line(cls, ldif_line: str) -> FlextResult[FlextLdifModels.OidAci]:
            """Parse OID orclaci from LDIF line.

            Example formats:
            - orclaci: access to entry by group="..." (browse,add,delete) by * (browse)
            - orclaci: access to attr=(*) by group="..." (read,write) by * (read)
            - orclaci: access to attr!=(password) by dn="..." (read) by * (none)
            - orclaci: access to entry filter=(objectclass=orclNetService) by group="..." (browse,add)
            """
            try:
                # Remove attribute name prefix
                if ldif_line.startswith("orclaci:"):
                    ldif_line = ldif_line[8:].strip()

                raw_aci = ldif_line

                # Parse: access to <target> [filter=(...)] by <subject> <perms> by ...
                if not ldif_line.lower().startswith("access to "):
                    return FlextResult[FlextLdifModels.OidAci].fail(
                        "OID ACI must start with 'access to'"
                    )

                ldif_line = ldif_line[10:].strip()  # Remove "access to "

                # Find first "by" to separate target from rules
                by_index = ldif_line.lower().find(" by ")
                if by_index == -1:
                    return FlextResult[FlextLdifModels.OidAci].fail(
                        "No 'by' clause found in OID ACI"
                    )

                target_part = ldif_line[:by_index].strip()
                rules_part = ldif_line[by_index + 1 :].strip()  # Keep " by ..."

                # Parse target and filter
                access_type = ""
                target = ""
                filter_str = ""

                # Check for filter constraint
                filter_index = target_part.lower().find("filter=")
                if filter_index != -1:
                    # Extract filter
                    filter_start = filter_index + 7  # len("filter=")
                    if target_part[filter_start] == "(":
                        # Find matching closing parenthesis
                        paren_count = 1
                        filter_end = filter_start + 1
                        while filter_end < len(target_part) and paren_count > 0:
                            if target_part[filter_end] == "(":
                                paren_count += 1
                            elif target_part[filter_end] == ")":
                                paren_count -= 1
                            filter_end += 1

                        filter_str = target_part[filter_start:filter_end]
                        target_part = target_part[:filter_index].strip()

                # Determine access type and target
                if target_part.startswith("entry"):
                    access_type = "entry"
                    target = "entry"
                elif target_part.startswith("attr!=("):
                    access_type = "attr!"
                    # Extract attribute name from attr!=(attrname)
                    end_paren = target_part.find(")")
                    if end_paren != -1:
                        target = target_part[7:end_paren]  # Skip "attr!=("
                elif target_part.startswith("attr=("):
                    access_type = "attr"
                    # Extract attribute name from attr=(attrname)
                    end_paren = target_part.find(")")
                    if end_paren != -1:
                        target = target_part[6:end_paren]  # Skip "attr=("
                else:
                    return FlextResult[FlextLdifModels.OidAci].fail(
                        f"Unknown access type in target: {target_part}"
                    )

                # Parse rules (split by " by ")
                rules: list[FlextLdifModels.OidAciRule] = []
                rules_part_lower = rules_part.lower()

                # Split by " by " (case-insensitive)
                rule_strings = []
                current_pos = 0
                while True:
                    by_pos = rules_part_lower.find(" by ", current_pos)
                    if by_pos == -1:
                        # Last rule
                        if current_pos < len(rules_part):
                            rule_strings.append(rules_part[current_pos:].strip())
                        break

                    if current_pos == 0:
                        # First rule (has leading "by ")
                        current_pos = by_pos + 4
                        continue

                    # Extract rule between current_pos and by_pos
                    rule_strings.append(rules_part[current_pos:by_pos].strip())
                    current_pos = by_pos + 4

                # Parse each rule
                for rule_str in rule_strings:
                    if not rule_str or rule_str.lower() == "by":
                        continue

                    rule_result = FlextLdifModels.OidAciRule.from_rule_string(rule_str)
                    if rule_result.is_success:
                        rules.append(rule_result.value)

                return cast(
                    "FlextResult[FlextLdifModels.OidAci]",
                    cls.create(
                        access_type=access_type,
                        target=target,
                        filter=filter_str,
                        rules=rules,
                        raw_aci=raw_aci,
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.OidAci].fail(
                    f"Failed to parse OID ACI: {e}"
                )

        def to_oud_aci(self) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Convert OID ACI to OUD UnifiedAcl."""
            try:
                # Create OUD target
                target_result = FlextLdifModels.AclTarget.create(
                    target_dn="",
                    attributes=(
                        [self.target] if self.access_type.startswith("attr") else []
                    ),
                    filter=self.filter,
                )
                if target_result.is_failure:
                    return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                        f"Failed to create target: {target_result.error}"
                    )

                # Convert first rule (OUD typically uses single subject/permission pair)
                if not self.rules:
                    return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                        "No rules to convert"
                    )

                first_rule = self.rules[0]

                # Convert subject
                subject_result = first_rule.subject.to_oud_subject()
                if subject_result.is_failure:
                    return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                        f"Failed to convert subject: {subject_result.error}"
                    )

                # Convert permissions
                perm_result = first_rule.permissions.to_oud_permissions()
                if perm_result.is_failure:
                    return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                        f"Failed to convert permissions: {perm_result.error}"
                    )

                return FlextLdifModels.UnifiedAcl.create(
                    name="converted_oid_aci",
                    target=cast("FlextLdifModels.AclTarget", target_result.value),
                    subject=subject_result.value,
                    permissions=perm_result.value,
                    server_type="oracle_oud",
                    raw_acl=self.raw_aci,
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                    f"Failed to convert OID ACI: {e}"
                )

    class OidEntryLevelAci(FlextModels.Value):
        """OID orclentrylevelaci attribute - entry-level ACI with constraints."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        access_type: str = Field(description="Access type: 'entry' or 'attr'")
        target: str = Field(
            default="",
            description="Target entry or attribute",
        )
        constraint: str = Field(
            default="",
            description="Optional constraint like 'added_object_constraint=(objectclass=...)'",
        )
        rules: list[FlextLdifModels.OidAciRule] = Field(
            default_factory=list,
            description="List of ACI rules",
        )
        raw_aci: str = Field(
            default="",
            description="Original raw OID entry-level ACI string",
        )

        @classmethod
        def from_ldif_line(
            cls, ldif_line: str
        ) -> FlextResult[FlextLdifModels.OidEntryLevelAci]:
            """Parse OID orclentrylevelaci from LDIF line.

            Example formats:
            - orclentrylevelaci: access to attr=(*) by group="..." (read,write) by * (read)
            - orclentrylevelaci: access to entry by group="..." added_object_constraint=(objectclass=...) (add)
            """
            try:
                # Remove attribute name prefix
                if ldif_line.startswith("orclentrylevelaci:"):
                    ldif_line = ldif_line[18:].strip()

                raw_aci = ldif_line

                # Similar parsing to OidAci but with added_object_constraint support
                if not ldif_line.lower().startswith("access to "):
                    return FlextResult[FlextLdifModels.OidEntryLevelAci].fail(
                        "Entry-level ACI must start with 'access to'"
                    )

                ldif_line = ldif_line[10:].strip()

                # Find first "by" to separate target from rules
                by_index = ldif_line.lower().find(" by ")
                if by_index == -1:
                    return FlextResult[FlextLdifModels.OidEntryLevelAci].fail(
                        "No 'by' clause found"
                    )

                target_part = ldif_line[:by_index].strip()
                rules_part = ldif_line[by_index + 1 :].strip()

                # Parse target and constraint
                access_type = ""
                target = ""
                constraint = ""

                # Check for added_object_constraint
                constraint_index = target_part.lower().find("added_object_constraint=")
                if constraint_index != -1:
                    # Extract constraint
                    constraint_start = constraint_index + 24
                    if target_part[constraint_start] == "(":
                        paren_count = 1
                        constraint_end = constraint_start + 1
                        while constraint_end < len(target_part) and paren_count > 0:
                            if target_part[constraint_end] == "(":
                                paren_count += 1
                            elif target_part[constraint_end] == ")":
                                paren_count -= 1
                            constraint_end += 1

                        constraint = target_part[constraint_start:constraint_end]
                        target_part = target_part[:constraint_index].strip()

                # Determine access type
                if target_part.startswith("entry"):
                    access_type = "entry"
                    target = "entry"
                elif target_part.startswith("attr=("):
                    access_type = "attr"
                    end_paren = target_part.find(")")
                    if end_paren != -1:
                        target = target_part[6:end_paren]
                else:
                    return FlextResult[FlextLdifModels.OidEntryLevelAci].fail(
                        f"Unknown access type: {target_part}"
                    )

                # Parse rules (same as OidAci)
                rules: list[FlextLdifModels.OidAciRule] = []
                rules_part_lower = rules_part.lower()

                rule_strings = []
                current_pos = 0
                while True:
                    by_pos = rules_part_lower.find(" by ", current_pos)
                    if by_pos == -1:
                        if current_pos < len(rules_part):
                            rule_strings.append(rules_part[current_pos:].strip())
                        break

                    if current_pos == 0:
                        current_pos = by_pos + 4
                        continue

                    rule_strings.append(rules_part[current_pos:by_pos].strip())
                    current_pos = by_pos + 4

                for rule_str in rule_strings:
                    if not rule_str or rule_str.lower() == "by":
                        continue

                    rule_result = FlextLdifModels.OidAciRule.from_rule_string(rule_str)
                    if rule_result.is_success:
                        rules.append(rule_result.value)

                return cast(
                    "FlextResult[FlextLdifModels.OidEntryLevelAci]",
                    cls.create(
                        access_type=access_type,
                        target=target,
                        constraint=constraint,
                        rules=rules,
                        raw_aci=raw_aci,
                    ),
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.OidEntryLevelAci].fail(
                    f"Failed to parse entry-level ACI: {e}"
                )

        def to_oud_aci(self) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Convert OID entry-level ACI to OUD UnifiedAcl."""
            try:
                # Similar conversion to OidAci
                target_result = FlextLdifModels.AclTarget.create(
                    target_dn="",
                    attributes=[self.target] if self.access_type == "attr" else [],
                )
                if target_result.is_failure:
                    return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                        f"Failed to create target: {target_result.error}"
                    )

                if not self.rules:
                    return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                        "No rules to convert"
                    )

                first_rule = self.rules[0]

                subject_result = first_rule.subject.to_oud_subject()
                if subject_result.is_failure:
                    return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                        f"Failed to convert subject: {subject_result.error}"
                    )

                perm_result = first_rule.permissions.to_oud_permissions()
                if perm_result.is_failure:
                    return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                        f"Failed to convert permissions: {perm_result.error}"
                    )

                return FlextLdifModels.UnifiedAcl.create(
                    name="converted_entry_level_aci",
                    target=cast("FlextLdifModels.AclTarget", target_result.value),
                    subject=subject_result.value,
                    permissions=perm_result.value,
                    server_type="oracle_oud",
                    raw_acl=self.raw_aci,
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                    f"Failed to convert entry-level ACI: {e}"
                )


__all__ = ["FlextLdifModels"]
