"""Domain Entry model — LDIF entry and entry statistics.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, MutableSequence
from contextlib import suppress
from datetime import datetime
from typing import Annotated, ClassVar, Self, override

from pydantic import (
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from flext_core import m
from flext_ldif import (
    FlextLdifModelsDomainAcl,
    FlextLdifModelsDomainAttributes,
    FlextLdifModelsDomainDN,
    FlextLdifModelsDomainMetadata,
    FlextLdifModelsDomainSchema,
    FlextLdifModelsMetadata,
    FlextLdifUtilitiesEntry,
    c,
    p,
    r,
    t,
)


class FlextLdifModelsDomainEntry:
    """Namespace for LDIF entry domain models."""

    class EntryStatistics(m.FrozenDynamicModel):
        """Statistics tracking for entry-level transformations and validation.

        Tracks complete entry lifecycle from parsing through validation,
        transformation, filtering, and output. Captures all attribute
        modifications, quirk applications, and rejection reasons.

        Designed for aggregation across large LDIF files to provide
        comprehensive migration diagnostics.

        Inherits from m.BaseModel (flext-core):
        - model_config (frozen=True, validate_default=True, validate_assignment=True)
        - aggregate() classmethod (automatic statistics aggregation)
        """

        was_parsed: Annotated[
            bool,
            Field(description="Entry was successfully parsed from LDIF"),
        ] = True
        was_validated: Annotated[
            bool,
            Field(description="Entry passed validation checks"),
        ] = False
        was_filtered: Annotated[
            bool,
            Field(
                description="Entry was filtered by rules (base DN, schema, etc.)",
            ),
        ] = False
        was_written: Annotated[
            bool,
            Field(description="Entry was written to output LDIF"),
        ] = False
        was_rejected: Annotated[
            bool,
            Field(description="Entry was rejected during processing"),
        ] = False
        rejection_category: Annotated[
            str | None,
            Field(
                description="Rejection category (use RejectionCategory constants)",
            ),
        ] = None
        rejection_reason: Annotated[
            str | None,
            Field(description="Human-readable rejection reason"),
        ] = None
        attributes_added: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names added during processing",
            ),
        ]
        attributes_removed: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names removed during processing",
            ),
        ]
        attributes_modified: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names modified during processing",
            ),
        ]
        attributes_filtered: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names filtered by whitelist/blacklist",
            ),
        ]
        objectclasses_original: Annotated[
            MutableSequence[str],
            Field(description="Original objectClass values"),
        ]
        objectclasses_final: Annotated[
            MutableSequence[str],
            Field(
                description="Final objectClass values after transformation",
            ),
        ]
        quirks_applied: Annotated[
            MutableSequence[str],
            Field(
                description="List of quirk types applied to this entry",
            ),
        ]
        quirk_transformations: Annotated[
            int,
            Field(description="Count of quirk transformations applied"),
        ] = 0
        dn_statistics: FlextLdifModelsDomainDN.DNStatistics | None = Field(
            default=None, description="DN transformation statistics (if applicable)"
        )
        filters_applied: Annotated[
            MutableSequence[str],
            Field(
                description="List of filters applied (use FilterType constants)",
            ),
        ]
        filter_results: Annotated[
            t.MutableBoolMapping,
            Field(
                description="Filter results: {filter_name: passed}",
            ),
        ]
        errors: Annotated[
            MutableSequence[str],
            Field(
                description="Error messages (use ErrorCategory constants for keys)",
            ),
        ]
        warnings: Annotated[
            MutableSequence[str],
            Field(description="Warning messages"),
        ]
        category_assigned: Annotated[
            str | None,
            Field(
                description="Category assigned (schema, hierarchy, users, groups, acl)",
            ),
        ] = None
        category_confidence: Annotated[
            float,
            Field(
                ge=0.0,
                le=1.0,
                description="Confidence score for category assignment",
            ),
        ] = 1.0

        @computed_field
        def dn_was_transformed(self) -> bool:
            """Check if DN underwent transformation."""
            if self.dn_statistics is None:
                return False
            return bool(self.dn_statistics.was_transformed)

        @computed_field
        def had_errors(self) -> bool:
            """Check if any errors occurred."""
            return bool(self.errors)

        @computed_field
        def had_warnings(self) -> bool:
            """Check if any warnings occurred."""
            return bool(self.warnings)

        @computed_field
        def objectclasses_changed(self) -> bool:
            """Check if objectClass values changed."""
            return set(self.objectclasses_original) != set(self.objectclasses_final)

        @computed_field
        def total_attribute_changes(self) -> int:
            """Total count of attribute modifications."""
            return (
                len(self.attributes_added)
                + len(self.attributes_removed)
                + len(self.attributes_modified)
            )

        @classmethod
        def create_minimal(cls) -> Self:
            """Create minimal statistics for newly parsed entry."""
            return cls.model_validate({"was_parsed": True})

        @field_validator("filters_applied", mode="after")
        @classmethod
        def deduplicate_filters(cls, v: MutableSequence[str]) -> MutableSequence[str]:
            """Remove duplicate filters while preserving order."""
            seen: set[str] = set()
            result: MutableSequence[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        @field_validator("quirks_applied", mode="after")
        @classmethod
        def deduplicate_quirks(cls, v: MutableSequence[str]) -> MutableSequence[str]:
            """Remove duplicate quirks while preserving order."""
            seen: set[str] = set()
            result: MutableSequence[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        def add_error(self, error: str) -> Self:
            """Add error message.

            Returns new instance with error added (frozen model).
            """
            errors = [*self.errors, error]
            return self.model_copy(update={"errors": errors})

        def add_warning(self, warning: str) -> Self:
            """Add warning message.

            Returns new instance with warning added (frozen model).
            """
            warnings = [*self.warnings, warning]
            return self.model_copy(update={"warnings": warnings})

        def mark_filtered(self, filter_type: str, *, passed: bool) -> Self:
            """Mark entry as filtered with result.

            Args:
                filter_type: Type of filter applied
                passed: Whether entry passed the filter (keyword-only)

            Returns new instance with updated filter state (frozen model).

            """
            filters_applied = [*self.filters_applied, filter_type]
            filter_results = {**self.filter_results, filter_type: passed}
            return self.model_copy(
                update={
                    "was_filtered": True,
                    "filters_applied": filters_applied,
                    "filter_results": filter_results,
                },
            )

        def mark_rejected(self, category: str, reason: str) -> Self:
            """Mark entry as rejected.

            Returns new instance with rejection details (frozen model).
            """
            return self.model_copy(
                update={
                    "was_rejected": True,
                    "rejection_category": category,
                    "rejection_reason": reason,
                },
            )

    class Control(m.Value):
        """Structured RFC 2849 control line."""

        control_type: Annotated[
            str,
            Field(description="LDAP control OID or descriptor"),
        ]
        criticality: Annotated[
            bool | None,
            Field(description="Optional criticality flag from control line"),
        ] = None
        value: Annotated[
            str | None,
            Field(description="Optional control value"),
        ] = None
        value_origin: Annotated[
            c.Ldif.ValueOriginLiteral | None,
            Field(description="Original control value encoding/source"),
        ] = None
        raw_value: Annotated[
            str | None,
            Field(description="Original serialized control payload"),
        ] = None

    class ChangeOperationValue(m.Value):
        """Single value captured inside a modify operation block."""

        value: Annotated[
            str,
            Field(description="Decoded value used by the operation"),
        ]
        value_origin: Annotated[
            c.Ldif.ValueOriginLiteral,
            Field(description="Original LDIF encoding/source for this value"),
        ] = c.Ldif.ValueOrigin.PLAIN
        raw_value: Annotated[
            str | None,
            Field(description="Original serialized value payload before decoding"),
        ] = None

    class ChangeOperation(m.Value):
        """Structured RFC 2849 modify operation block."""

        operation: Annotated[
            c.Ldif.ChangeOperationLiteral,
            Field(description="Modify operation name"),
        ]
        attribute: Annotated[
            str,
            Field(description="Target attribute for the modify block"),
        ]
        values: Annotated[
            MutableSequence[FlextLdifModelsDomainEntry.ChangeOperationValue],
            Field(description="Decoded values in the block"),
        ] = Field(
            default_factory=lambda: list[
                FlextLdifModelsDomainEntry.ChangeOperationValue
            ](),
        )

    class Entry(m.Entity, m.DynamicModel):
        """LDIF entry domain model.

        Implements p.Models.Entry through structural typing.
        The protocol requires:
        - dn: str
        - attributes: FlextLdifModelsMetadata.DynamicMetadata

        This model provides these through:
        - dn field (DN) which has .value property returning str
        - attributes field (Attributes) which has .attributes property returning FlextLdifModelsDomainsEntries.UnconvertedAttributes

        Inherits DynamicModel to legitimize extra='allow' for LDIF dynamic attributes.
        """

        model_config: ClassVar[ConfigDict] = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra=c.ExtraConfig.ALLOW.value,
        )
        dn: FlextLdifModelsDomainDN.DN | None = Field(
            ...,
            description="Distinguished Name of the entry (REQUIRED per RFC 2849 § 2). Allows None for RFC violation capture. Coerced from str via field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry",
        )
        attributes: FlextLdifModelsDomainAttributes.Attributes | None = Field(
            ...,
            description="Entry attributes container (REQUIRED per RFC 2849 § 2). Allows None for RFC violation capture. Coerced from dict[str, list[str]] via field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry",
        )
        record_kind: Annotated[
            c.Ldif.RecordKindLiteral,
            Field(
                description="Whether this Entry represents LDIF content or an LDIF change record.",
            ),
        ] = c.Ldif.RecordKind.CONTENT
        controls: Annotated[
            MutableSequence[FlextLdifModelsDomainEntry.Control],
            Field(description="RFC 2849 control lines associated with the record"),
        ] = Field(
            default_factory=lambda: list[FlextLdifModelsDomainEntry.Control](),
        )
        change_operations: Annotated[
            MutableSequence[FlextLdifModelsDomainEntry.ChangeOperation],
            Field(
                description="Structured modify operation blocks for changetype=modify"
            ),
        ] = Field(
            default_factory=lambda: list[FlextLdifModelsDomainEntry.ChangeOperation](),
        )

        @field_validator("attributes", mode="before")
        @classmethod
        def coerce_attributes_from_dict(
            cls,
            value: FlextLdifModelsDomainAttributes.Attributes
            | t.MutableRecursiveContainerMapping
            | None,
        ) -> FlextLdifModelsDomainAttributes.Attributes | None:
            """Convert dict to Attributes instance.

            Allows None to pass through for violation capture in model_validator.
            RFC 2849 § 2 violations (attributes required) are captured in validate_entry_rfc_compliance.
            """
            if value is None:
                return None
            if isinstance(value, FlextLdifModelsDomainAttributes.Attributes):
                return value
            wrapped_value: t.MutableRecursiveContainerMapping = value
            if "attributes" not in value:
                wrapped_value = {"attributes": value}
            return FlextLdifModelsDomainAttributes.Attributes.model_validate(
                wrapped_value,
            )

        @field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls,
            value: FlextLdifModelsDomainDN.DN
            | t.MutableRecursiveContainerMapping
            | str
            | None,
        ) -> FlextLdifModelsDomainDN.DN | None:
            """Convert string DN to DN instance.

            Allows None to pass through for violation capture in model_validator.
            RFC 2849 § 2 violations are captured in validate_entry_rfc_compliance.
            """
            if value is None:
                return None
            if isinstance(value, FlextLdifModelsDomainDN.DN):
                return value
            if isinstance(value, Mapping):
                return FlextLdifModelsDomainDN.DN.model_validate(value)
            return FlextLdifModelsDomainDN.DN.model_validate({
                "value": str(value),
                "metadata": FlextLdifModelsMetadata.EntryMetadata.model_validate({}),
            })

        @field_validator("record_kind", mode="before")
        @classmethod
        def coerce_record_kind(
            cls,
            value: str,
        ) -> c.Ldif.RecordKindLiteral:
            """Accept both enum instances and serialized record kind strings."""
            return c.Ldif.RecordKind(value)

        changetype: Annotated[
            c.Ldif.LdifChangeTypeLiteral | None,
            Field(
                description="Change operation type per RFC 2849 § 5.7 (add/delete/modify/moddn/modrdn)",
            ),
        ] = None

        @field_validator("changetype", mode="before")
        @classmethod
        def coerce_changetype(
            cls,
            value: str | None,
        ) -> c.Ldif.LdifChangeTypeLiteral | None:
            """Accept both enum instances and serialized changetype strings."""
            if isinstance(value, str):
                return c.Ldif.LdifChangeType(value)
            return value

        newrdn: Annotated[
            str | None,
            Field(description="RFC 2849 newrdn field for moddn/modrdn records"),
        ] = None
        deleteoldrdn: Annotated[
            bool | None,
            Field(description="RFC 2849 deleteoldrdn field for moddn/modrdn records"),
        ] = None
        newsuperior: Annotated[
            str | None,
            Field(description="RFC 2849 newsuperior field for moddn/modrdn records"),
        ] = None
        raw_record_lines: Annotated[
            MutableSequence[str],
            Field(description="Original unfolded LDIF lines for loss-aware round-trip"),
        ] = Field(default_factory=lambda: list[str]())
        metadata: FlextLdifModelsDomainMetadata.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for processing data, ACLs, statistics, validation (non-RFC data)",
        )
        validation_metadata: t.ConfigMap | None = Field(
            default=None,
            description="Validation metadata captured during parsing and transformation.",
        )

        @computed_field
        def attributes_dict(self) -> t.MutableStrSequenceMapping:
            """Protocol compliance: p.Ldif.Entry.Entry requires attributes: dict[str, list[str]].

            Returns the attributes as a dict for protocol compatibility.
            """
            if self.attributes is None:
                return {}
            return self.attributes.attributes

        @computed_field
        def dn_str(self) -> str:
            """Protocol compliance: p.Ldif.Entry.Entry requires dn: str.

            Returns the DN as a string for protocol compatibility.
            """
            if self.dn is None:
                return ""
            return self.dn.value

        @computed_field
        def is_change_record(self) -> bool:
            """True when the entry represents an LDIF change record."""
            return bool(self.changetype) or self.record_kind == c.Ldif.RecordKind.CHANGE

        @computed_field
        def unconverted_attributes(
            self,
        ) -> MutableMapping[str, str | MutableSequence[str] | bytes]:
            """Get unconverted attributes from metadata extensions (read-only view, DRY pattern)."""
            empty_attrs: MutableMapping[str, str | MutableSequence[str] | bytes] = {}
            if self.metadata is None:
                return empty_attrs
            extra = self.metadata.extensions.__pydantic_extra__
            if extra is None:
                return empty_attrs
            result = extra.get("unconverted_attributes")
            if result is not None and FlextLdifUtilitiesEntry.is_string_key_mapping(
                result
            ):
                converted_unconverted_attributes: MutableMapping[
                    str,
                    str | MutableSequence[str] | bytes,
                ] = {}
                for key_candidate, raw_value in result.items():
                    key_str = key_candidate
                    if FlextLdifUtilitiesEntry.is_object_list(raw_value):
                        converted_unconverted_attributes[key_str] = [
                            str(item) for item in raw_value
                        ]
                    elif isinstance(raw_value, str | bytes):
                        converted_unconverted_attributes[key_str] = raw_value
                    else:
                        converted_unconverted_attributes[key_str] = str(raw_value)
                return converted_unconverted_attributes
            return empty_attrs

        @model_validator(mode="before")
        @classmethod
        def ensure_metadata_initialized(
            cls,
            data: t.MutableRecursiveContainerMapping,
        ) -> MutableMapping[
            str,
            t.RecursiveContainer
            | datetime
            | FlextLdifModelsDomainMetadata.QuirkMetadata,
        ]:
            """Ensure metadata field is always initialized to a QuirkMetadata instance.

            Also handles datetime coercion from ISO strings for JSON round-trips.
            This is necessary because strict=True doesn't auto-coerce strings to datetime.

            Pydantic v2 Context Pattern: Using model_validator with mode='before'
            to initialize fields before field validators run. This validator executes
            at instantiation time, when the module is fully loaded and FlextLdifModelsDomainsEntries
            is in scope.

            Args:
                data: Input data for model instantiation

            Returns:
                Modified data with metadata field initialized and datetimes coerced

            """
            data_dict: MutableMapping[
                str,
                t.RecursiveContainer
                | datetime
                | FlextLdifModelsDomainMetadata.QuirkMetadata,
            ] = dict(data)
            for dt_field in ("created_at", "updated_at"):
                field_value = data_dict.get(dt_field)
                if isinstance(field_value, str):
                    with suppress(ValueError):
                        data_dict[dt_field] = datetime.fromisoformat(field_value)
            if data_dict.get("metadata") is None:
                quirk_type_value = data_dict.get("quirk_type")
                final_quirk_type_val: c.Ldif.ServerTypes
                if isinstance(quirk_type_value, str):
                    try:
                        final_quirk_type_val = c.Ldif.ServerTypes(quirk_type_value)
                    except ValueError:
                        final_quirk_type_val = c.Ldif.ServerTypes.RFC
                else:
                    final_quirk_type_val = c.Ldif.ServerTypes.RFC
                metadata_obj = (
                    FlextLdifModelsDomainMetadata.QuirkMetadata.model_validate({
                        "quirk_type": final_quirk_type_val,
                    })
                )
                data_dict["metadata"] = metadata_obj
            return data_dict

        @override
        def model_post_init(
            self,
            _context: t.ScalarMapping | None,
            /,
        ) -> None:
            """Post-init hook to ensure metadata is always initialized.

            Properly initialized before any code tries to access it.
            Uses self.__dict__ assignment to bypass validate_assignment=True
            and prevent infinite re-validation recursion (Pydantic v2 pattern).
            """
            if self.metadata is None:
                self.metadata = FlextLdifModelsDomainMetadata.QuirkMetadata.create_for()

        @model_validator(mode="after")
        def normalize_record_kind(self) -> Self:
            """Keep record_kind aligned with changetype semantics."""
            if self.changetype and self.record_kind != c.Ldif.RecordKind.CHANGE:
                return self.model_copy(update={"record_kind": c.Ldif.RecordKind.CHANGE})
            if not self.changetype and self.record_kind != c.Ldif.RecordKind.CONTENT:
                return self.model_copy(
                    update={"record_kind": c.Ldif.RecordKind.CONTENT},
                )
            return self

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> Self:
            """Validate cross-field consistency in Entry model.

            Notes:
            - ObjectClass validation is optional - downstream code handles
            entries without objectClass via rejection or warnings.
            - Schema entries (dn: cn=schema) are allowed without objectClass
            as they contain schema definitions, not directory objects.

            Returns:
            Self (for method chaining)

            """
            return self

        @model_validator(mode="after")
        def validate_entry_rfc_compliance(self) -> Self:
            """Validate Entry RFC compliance - capture violations, DON'T reject.

            RFC 2849 § 2: DN and at least one attribute required
            RFC 4514 § 2.3, 2.4: DN format validation
            RFC 4512 § 2.5: Attribute name format validation

            Strategy: PRESERVE problematic entries for round-trip conversions,
            capture violations in validation_metadata for downstream handling.
            """
            violations: MutableSequence[str] = []
            dn_value = "<None>"
            if self.dn is None:
                violations.append("RFC 2849 § 2: DN is required")
            else:
                dn_value = str(self.dn.value)
                violations.extend(FlextLdifUtilitiesEntry.validate_dn_format(dn_value))
                violations.extend(
                    FlextLdifUtilitiesEntry.validate_attributes_required(self),
                )
                violations.extend(
                    FlextLdifUtilitiesEntry.validate_attribute_descriptions(self),
                )
                violations.extend(
                    FlextLdifUtilitiesEntry.validate_objectclass(self, dn_value),
                )
                violations.extend(
                    FlextLdifUtilitiesEntry.validate_naming_attribute(self, dn_value)
                )
                violations.extend(FlextLdifUtilitiesEntry.validate_binary_options(self))
                violations.extend(
                    FlextLdifUtilitiesEntry.validate_attribute_syntax(self)
                )
                violations.extend(FlextLdifUtilitiesEntry.validate_changetype(self))
            if violations and self.metadata is not None:
                attribute_count = len(self.attributes) if self.attributes else 0
                old_context: t.MutableStrMapping = {}
                if self.metadata.validation_results is not None:
                    old_context = {
                        key: str(value)
                        for key, value in self.metadata.validation_results.context.items()
                    }
                self.metadata.validation_results = (
                    FlextLdifModelsDomainMetadata.ValidationMetadata.model_validate({
                        "rfc_violations": violations,
                        "errors": [],
                        "warnings": [],
                        "context": {
                            **old_context,
                            "validator": "validate_entry_rfc_compliance",
                            "dn": dn_value,
                            "attribute_count": str(attribute_count),
                            "total_violations": str(len(violations)),
                        },
                        "server_specific_violations": [],
                        "validation_server_type": None,
                    })
                )
            return self

        @model_validator(mode="after")
        def validate_server_specific_rules(self) -> Self:
            """Validate Entry using server-injected validation rules."""
            if not self.metadata:
                return self
            if "validation_rules" not in self.metadata.extensions:
                return self
            validation_rules = self.metadata.extensions.get("validation_rules")
            if not validation_rules:
                return self
            rules = FlextLdifUtilitiesEntry.parse_validation_rules(validation_rules)
            if rules is None:
                return self
            dn_value = str(self.dn.value) if self.dn else ""
            server_violations: MutableSequence[str] = []
            server_violations.extend(
                FlextLdifUtilitiesEntry.check_objectclass_rule(self, rules, dn_value)
            )
            server_violations.extend(
                FlextLdifUtilitiesEntry.check_naming_attr_rule(self, rules, dn_value)
            )
            server_violations.extend(
                FlextLdifUtilitiesEntry.check_binary_option_rule(self, rules)
            )
            if self.metadata:
                self.metadata.extensions["validation_server_type"] = (
                    self.metadata.quirk_type
                )
            if server_violations and self.metadata:
                if self.metadata.validation_results is None:
                    self.metadata.validation_results = FlextLdifModelsDomainMetadata.ValidationMetadata.model_validate({
                        "rfc_violations": [],
                        "errors": [],
                        "warnings": [],
                        "context": {},
                        "server_specific_violations": [],
                        "validation_server_type": None,
                    })
                updated_validation_results = (
                    self.metadata.validation_results.model_copy(
                        update={
                            "server_specific_violations": server_violations,
                            "validation_server_type": self.metadata.quirk_type,
                        },
                    )
                )
                self.metadata.validation_results = updated_validation_results
                ext_violations: MutableSequence[t.Ldif.MetadataValue] = list(
                    server_violations,
                )
                self.metadata.extensions.server_specific_violations = ext_violations
            return self

        @computed_field
        def has_validation_errors(self) -> bool:
            """Check if entry has validation errors.

            Returns:
            True if entry has validation errors in validation_metadata, False otherwise

            """
            if self.metadata is None:
                return False
            if self.metadata.validation_results is None:
                return False
            return bool(self.metadata.validation_results.errors)

        @computed_field
        def is_acl_entry(self) -> bool:
            """Check if entry has Access Control Lists.

            Returns:
            True if entry has ACLs, False otherwise

            """
            if self.metadata is None:
                return False
            return bool(self.metadata.acls)

        @computed_field
        def is_schema_entry(self) -> bool:
            """Check if entry is a schema definition entry.

            Schema entries contain objectClass definitions and are typically
            found in the schema naming context.

            Returns:
            True if entry has objectClasses, False otherwise

            """
            if self.metadata is None:
                return False
            return bool(self.metadata.objectclasses)

        @classmethod
        def _build_extension_kwargs(
            cls,
            server_type: c.Ldif.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> t.MutableRecursiveContainerMapping:
            """Build extension kwargs for DynamicMetadata."""
            ext_kwargs: t.MutableRecursiveContainerMapping = {}
            if server_type:
                ext_kwargs["server_type"] = server_type
            if source_entry:
                ext_kwargs["source_entry"] = source_entry
            if unconverted_attributes:
                unconverted_dump = unconverted_attributes.model_dump()
                unconverted_typed: t.RecursiveContainer = unconverted_dump
                ext_kwargs["unconverted_attributes"] = unconverted_typed
            return ext_kwargs

        @classmethod
        def _build_metadata(
            cls,
            metadata: FlextLdifModelsDomainMetadata.QuirkMetadata | None,
            server_type: c.Ldif.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> FlextLdifModelsDomainMetadata.QuirkMetadata | None:
            """Build or update metadata with server-specific extensions."""
            has_new_metadata = server_type or source_entry or unconverted_attributes
            if metadata is None and has_new_metadata:
                ext_kwargs = cls._build_extension_kwargs(
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )
                extensions = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                    ext_kwargs,
                )
                return FlextLdifModelsDomainMetadata.QuirkMetadata.model_validate({
                    "quirk_type": c.Ldif.ServerTypes.GENERIC,
                    "extensions": extensions,
                })
            if metadata is not None and has_new_metadata:
                cls._update_existing_metadata(
                    metadata,
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )
            return metadata

        class _CreateEntryParams(m.Value):
            model_config: ClassVar[ConfigDict] = ConfigDict(
                extra="forbid",
                validate_assignment=True,
            )
            dn: str | FlextLdifModelsDomainDN.DN = Field(
                ...,
                description="Distinguished Name as string or DN object",
            )
            attributes: (
                t.MutableAttributeMapping | FlextLdifModelsDomainAttributes.Attributes
            ) = Field(
                ...,
                description="Entry attributes as dict or Attributes object",
            )
            metadata: FlextLdifModelsDomainMetadata.QuirkMetadata | None = Field(
                default=None,
                description="Quirk-specific metadata for the entry",
            )
            acls: MutableSequence[FlextLdifModelsDomainAcl.Acl] | None = Field(
                default=None,
                description="Access Control Lists for the entry",
            )
            objectclasses: (
                MutableSequence[FlextLdifModelsDomainSchema.SchemaObjectClass] | None
            ) = Field(
                default=None,
                description="Schema object class definitions",
            )
            attributes_schema: (
                MutableSequence[FlextLdifModelsDomainSchema.SchemaAttribute] | None
            ) = Field(
                default=None,
                description="Schema attribute definitions",
            )
            entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = Field(
                default=None,
                description="Entry-level metadata for processing details",
            )
            validation_metadata: (
                FlextLdifModelsDomainMetadata.ValidationMetadata | None
            ) = Field(
                default=None,
                description="Validation results from entry processing",
            )
            server_type: c.Ldif.ServerTypeLiteral | None = Field(
                default=None,
                description="LDAP server type identifier",
            )
            record_kind: c.Ldif.RecordKindLiteral = Field(
                default=c.Ldif.RecordKind.CONTENT,
                description="High-level LDIF record kind",
            )
            controls: MutableSequence[FlextLdifModelsDomainEntry.Control] | None = (
                Field(
                    default=None,
                    description="RFC 2849 controls associated with the record",
                )
            )
            change_operations: (
                MutableSequence[FlextLdifModelsDomainEntry.ChangeOperation] | None
            ) = Field(
                default=None,
                description="Structured modify operations for changetype=modify",
            )
            changetype: c.Ldif.LdifChangeTypeLiteral | None = Field(
                default=None,
                description="RFC 2849 changetype",
            )
            newrdn: str | None = Field(
                default=None,
                description="RFC 2849 newrdn value",
            )
            deleteoldrdn: bool | None = Field(
                default=None,
                description="RFC 2849 deleteoldrdn value",
            )
            newsuperior: str | None = Field(
                default=None,
                description="RFC 2849 newsuperior value",
            )
            raw_record_lines: MutableSequence[str] | None = Field(
                default=None,
                description="Original unfolded LDIF record lines",
            )
            source_entry: str | None = Field(
                default=None,
                description="Original LDIF source entry string",
            )
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None = (
                Field(
                    default=None,
                    description="Attributes preserved in original format",
                )
            )
            statistics: FlextLdifModelsDomainEntry.EntryStatistics | None = Field(
                default=None,
                description="Entry processing statistics",
            )

        @classmethod
        def _create_entry(cls, params: _CreateEntryParams) -> r[Self]:
            """Internal method for Entry creation with composition fields.

            Args:
            params: Validated payload model containing entry fields and metadata

            Returns:
            r[Self] with Entry instance or validation error

            """
            try:
                dn_obj = FlextLdifModelsDomainDN.DN.from_value(params.dn)
                attrs_obj = cls._normalize_attributes(params.attributes)
                metadata = cls._build_metadata(
                    params.metadata,
                    params.server_type,
                    params.source_entry,
                    params.unconverted_attributes,
                )
                entry_data: dict[str, object] = {
                    c.Ldif.DictKeys.DN: dn_obj,
                    c.Ldif.DictKeys.ATTRIBUTES: attrs_obj,
                }
                if metadata is not None:
                    entry_data["metadata"] = metadata
                if params.acls is not None:
                    entry_data["acls"] = params.acls
                if params.objectclasses is not None:
                    entry_data["objectclasses"] = params.objectclasses
                if params.attributes_schema is not None:
                    entry_data["attributes_schema"] = params.attributes_schema
                if params.entry_metadata is not None:
                    entry_data["entry_metadata"] = params.entry_metadata
                if params.validation_metadata is not None:
                    entry_data["validation_metadata"] = params.validation_metadata
                if params.statistics is not None:
                    entry_data["statistics"] = params.statistics
                entry_data["record_kind"] = params.record_kind
                if params.controls is not None:
                    entry_data["controls"] = params.controls
                if params.change_operations is not None:
                    entry_data["change_operations"] = params.change_operations
                if params.changetype is not None:
                    entry_data["changetype"] = params.changetype
                if params.newrdn is not None:
                    entry_data["newrdn"] = params.newrdn
                if params.deleteoldrdn is not None:
                    entry_data["deleteoldrdn"] = params.deleteoldrdn
                if params.newsuperior is not None:
                    entry_data["newsuperior"] = params.newsuperior
                if params.raw_record_lines is not None:
                    entry_data["raw_record_lines"] = list(params.raw_record_lines)
                entry_instance = cls.model_validate(entry_data)
                ok_result: p.Result[Self] = r[Self].ok(entry_instance)
                return ok_result
            except (ValueError, TypeError, AttributeError) as e:
                fail_result: p.Result[Self] = r[Self].fail(
                    f"Failed to create Entry: {e}"
                )
                return fail_result

        @classmethod
        def _normalize_attributes(
            cls,
            attributes: t.MutableAttributeMapping
            | FlextLdifModelsDomainAttributes.Attributes,
        ) -> FlextLdifModelsDomainAttributes.Attributes:
            """Normalize attributes to Attributes t.RecursiveContainer.

            Args:
                attributes: Attributes as dict or Attributes t.RecursiveContainer

            Returns:
                Attributes t.RecursiveContainer with normalized values

            Note:
                Lenient processing: Empty attributes dict is accepted and will be captured
                in validation_metadata as RFC violation.

            """
            if isinstance(attributes, FlextLdifModelsDomainAttributes.Attributes):
                return attributes
            attrs_dict: t.MutableStrSequenceMapping = {}
            for attr_name, attr_values in attributes.items():
                if isinstance(attr_values, list):
                    values_list: MutableSequence[str] = [str(v) for v in attr_values]
                elif isinstance(attr_values, str):
                    values_list = [attr_values]
                else:
                    values_list = [str(attr_values)]
                attrs_dict[attr_name] = values_list
            return FlextLdifModelsDomainAttributes.Attributes.model_validate({
                "attributes": attrs_dict,
                "attribute_metadata": {},
                "metadata": None,
            })

        @classmethod
        def _update_existing_metadata(
            cls,
            metadata: FlextLdifModelsDomainMetadata.QuirkMetadata,
            server_type: c.Ldif.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> None:
            """Update existing metadata extensions in place."""
            if server_type:
                metadata.extensions["server_type"] = server_type
            if source_entry:
                metadata.extensions["source_entry"] = source_entry
            if unconverted_attributes:
                extra = unconverted_attributes.__pydantic_extra__
                if extra:
                    for key, value in extra.items():
                        metadata.extensions[f"unconverted_{key}"] = str(value)

        @classmethod
        def create(
            cls,
            dn: str | FlextLdifModelsDomainDN.DN,
            attributes: t.MutableAttributeMapping
            | FlextLdifModelsDomainAttributes.Attributes,
            metadata: FlextLdifModelsDomainMetadata.QuirkMetadata | None = None,
            acls: MutableSequence[FlextLdifModelsDomainAcl.Acl] | None = None,
            objectclasses: MutableSequence[
                FlextLdifModelsDomainSchema.SchemaObjectClass
            ]
            | None = None,
            attributes_schema: MutableSequence[
                FlextLdifModelsDomainSchema.SchemaAttribute
            ]
            | None = None,
            entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = None,
            validation_metadata: FlextLdifModelsDomainMetadata.ValidationMetadata
            | None = None,
            server_type: c.Ldif.ServerTypeLiteral | None = None,
            record_kind: c.Ldif.RecordKindLiteral = c.Ldif.RecordKind.CONTENT,
            controls: MutableSequence[FlextLdifModelsDomainEntry.Control] | None = None,
            change_operations: MutableSequence[
                FlextLdifModelsDomainEntry.ChangeOperation
            ]
            | None = None,
            changetype: c.Ldif.LdifChangeTypeLiteral | None = None,
            newrdn: str | None = None,
            deleteoldrdn: bool | None = None,
            newsuperior: str | None = None,
            raw_record_lines: MutableSequence[str] | None = None,
            source_entry: str | None = None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata
            | None = None,
            statistics: FlextLdifModelsDomainEntry.EntryStatistics | None = None,
        ) -> r[Self]:
            params = cls._CreateEntryParams.model_validate({
                "dn": dn,
                "attributes": attributes,
                "metadata": metadata,
                "acls": acls,
                "objectclasses": objectclasses,
                "attributes_schema": attributes_schema,
                "entry_metadata": entry_metadata,
                "validation_metadata": validation_metadata,
                "server_type": server_type,
                "record_kind": record_kind,
                "controls": controls,
                "change_operations": change_operations,
                "changetype": changetype,
                "newrdn": newrdn,
                "deleteoldrdn": deleteoldrdn,
                "newsuperior": newsuperior,
                "raw_record_lines": raw_record_lines,
                "source_entry": source_entry,
                "unconverted_attributes": unconverted_attributes,
                "statistics": statistics,
            })
            return cls._create_entry(params=params)


__all__: list[str] = ["FlextLdifModelsDomainEntry"]
