"""FLEXT LDIF Models - Unified Namespace for LDIF Domain Models.

This module provides a unified namespace class that aggregates all LDIF domain models
from specialized sub-modules. It extends flext-core FlextModels with LDIF-specific
domain entities organized into focused modules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextModels, FlextTypes
from pydantic import ConfigDict, Field, computed_field

from flext_ldif.commands import FlextLdifCommands
from flext_ldif.core import FlextLdifCore
from flext_ldif.events import FlextLdifEvents
from flext_ldif.results import FlextLdifResults
from flext_ldif.schema import FlextLdifSchema
from flext_ldif.specifications import FlextLdifSpecifications

# LDIF format constants (legacy compatibility)
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

    Unified namespace class that aggregates all LDIF domain models from specialized sub-modules.
    Provides a single access point for all LDIF models while maintaining modular organization.

    This class extends flext-core FlextModels and organizes LDIF-specific models into
    focused sub-modules for better maintainability and reduced complexity.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        extra="allow",  # Allow extra fields for backward compatibility
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

    # =========================================================================
    # CQRS MODELS - Commands and Queries
    # =========================================================================

    # Import CQRS models from commands module
    ParseQuery = FlextLdifCommands.ParseQuery
    ValidateQuery = FlextLdifCommands.ValidateQuery
    AnalyzeQuery = FlextLdifCommands.AnalyzeQuery
    WriteCommand = FlextLdifCommands.WriteCommand
    MigrateCommand = FlextLdifCommands.MigrateCommand
    RegisterQuirkCommand = FlextLdifCommands.RegisterQuirkCommand

    # =========================================================================
    # EVENT MODELS - Domain Events
    # =========================================================================

    # Import event models from events module
    EntryParsedEvent = FlextLdifEvents.EntryParsedEvent
    EntriesValidatedEvent = FlextLdifEvents.EntriesValidatedEvent
    AnalyticsGeneratedEvent = FlextLdifEvents.AnalyticsGeneratedEvent
    EntriesWrittenEvent = FlextLdifEvents.EntriesWrittenEvent
    MigrationCompletedEvent = FlextLdifEvents.MigrationCompletedEvent
    QuirkRegisteredEvent = FlextLdifEvents.QuirkRegisteredEvent

    # =========================================================================
    # CORE DOMAIN MODELS - Fundamental LDIF Entities
    # =========================================================================

    # Import core models from core module
    DistinguishedName = FlextLdifCore.DistinguishedName
    LdifAttribute = FlextLdifCore.LdifAttribute
    LdifAttributes = FlextLdifCore.LdifAttributes
    Entry = FlextLdifCore.Entry
    ChangeRecord = FlextLdifCore.ChangeRecord

    # =========================================================================
    # SPECIFICATION MODELS - Technology Detection
    # =========================================================================

    # Import specification models from specifications module
    TechnologySpecification = FlextLdifSpecifications.TechnologySpecification
    OidSpecification = FlextLdifSpecifications.OidSpecification
    OudSpecification = FlextLdifSpecifications.OudSpecification
    StandardLdifSpecification = FlextLdifSpecifications.StandardLdifSpecification

    # =========================================================================
    # SCHEMA MODELS - LDAP Schema Definitions
    # =========================================================================

    # Import schema models from schema module
    SchemaObjectClass = FlextLdifSchema.SchemaObjectClass
    SchemaDiscoveryResult = FlextLdifSchema.SchemaDiscoveryResult

    # =========================================================================
    # ACL MODELS - Access Control Lists
    # =========================================================================

    # Import ACL models from acl module
    AclTarget = FlextLdifAcl.AclTarget
    AclSubject = FlextLdifAcl.AclSubject
    AclPermissions = FlextLdifAcl.AclPermissions
    UnifiedAcl = FlextLdifAcl.UnifiedAcl

    # =========================================================================
    # RESULT MODELS - Operation Results
    # =========================================================================

    # Import result models from results module
    ParseResult = FlextLdifResults.ParseResult
    TransformResult = FlextLdifResults.TransformResult
    AnalyticsResult = FlextLdifResults.AnalyticsResult
    WriteResult = FlextLdifResults.WriteResult
    FilterResult = FlextLdifResults.FilterResult

    # =========================================================================
    # BASE CLASSES - Shared Foundations (for backward compatibility)
    # =========================================================================

    # Base classes for extension (imported from original models structure)
    # These are maintained for backward compatibility and internal use

    class BaseOperationResult(FlextModels.Value):
        """Base class for operation results with common fields."""

        operation_id: str = Field(default="", description="Unique operation identifier")
        timestamp: str = Field(default="", description="Operation timestamp")
        duration_ms: float = Field(
            default=0.0, ge=0, description="Operation duration in milliseconds"
        )
        errors: list[str] = Field(
            default_factory=list, description="List of error messages"
        )
        warnings: list[str] = Field(
            default_factory=list, description="List of warning messages"
        )

        @computed_field
        def has_errors(self) -> bool:
            """Check if operation has errors."""
            return len(self.errors) > 0

        @computed_field
        def has_warnings(self) -> bool:
            """Check if operation has warnings."""
            return len(self.warnings) > 0

    class BaseSchemaAttribute(FlextModels.Value):
        """Base class for schema attributes."""

        name: str = Field(..., description="Attribute name")
        oid: str = Field(default="", description="Attribute OID")
        description: str = Field(default="", description="Attribute description")
        syntax: str = Field(default="", description="Attribute syntax")
        single_value: bool = Field(
            default=False, description="Whether attribute is single-valued"
        )

        @property
        def required_attributes(self) -> list[str]:
            """Required attributes (for compatibility)."""
            return []

        @property
        def optional_attributes(self) -> list[str]:
            """Optional attributes (for compatibility)."""
            return [self.name]

    class BaseSchemaObjectClass(FlextModels.Value):
        """Base class for schema object classes."""

        name: str = Field(..., description="Object class name")
        oid: str = Field(default="", description="Object class OID")
        description: str = Field(default="", description="Object class description")
        superior: str | list[str] | None = Field(
            default=None, description="Superior object classes"
        )

        @property
        def required_attributes(self) -> list[str]:
            """Required attributes (MUST)."""
            return []

        @property
        def optional_attributes(self) -> list[str]:
            """Optional attributes (MAY)."""
            return []

    class BaseAclPermissions(FlextModels.Value):
        """Base class for ACL permissions."""

        read: bool = Field(default=False, description="Read permission")
        write: bool = Field(default=False, description="Write permission")
        add: bool = Field(default=False, description="Add permission")
        delete: bool = Field(default=False, description="Delete permission")
        search: bool = Field(default=False, description="Search permission")
        compare: bool = Field(default=False, description="Compare permission")
        proxy: bool = Field(default=False, description="Proxy permission")

        @computed_field
        def permissions_summary(self) -> FlextTypes.Dict:
            """Summary of granted permissions."""
            granted = [k for k, v in self.__dict__.items() if isinstance(v, bool) and v]
            return {
                "granted_count": len(granted),
                "total_permissions": 7,
                "granted_permissions": granted,
                "all_granted": len(granted) == 7,
            }

    class BaseAclSubject(FlextModels.Value):
        """Base class for ACL subjects."""

        subject_type: str = Field(..., description="Type of subject (dn, group, etc.)")
        subject_value: str = Field(..., description="Subject value")
        subject_dn: str = Field(default="", description="Subject DN if applicable")

        @computed_field
        def subject_key(self) -> str:
            """Unique key for the subject."""
            return f"{self.subject_type}:{self.subject_value}"

    # =========================================================================
    # COMPUTED FIELDS - Metadata and Statistics
    # =========================================================================

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
            "ParseResult",
            "TransformResult",
            "AnalyticsResult",
            "WriteResult",
            "FilterResult",
            "ParseQuery",
            "ValidateQuery",
            "AnalyzeQuery",
            "WriteCommand",
            "MigrateCommand",
            "EntryParsedEvent",
            "EntriesValidatedEvent",
            "AnalyticsGeneratedEvent",
            "TechnologySpecification",
            "OidSpecification",
            "OudSpecification",
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
            "result_models": 5,
            "event_models": 6,
            "command_models": 6,
            "total_models": self.active_ldif_models_count,
            "pattern_support": True,
            "validation_support": True,
            "serialization_support": True,
            "modular_organization": True,
        }
