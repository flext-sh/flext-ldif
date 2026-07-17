"""Domain Entry model — LDIF entry and entry statistics.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
)
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, ClassVar, Self, override

from flext_core import FlextUtilities as u, m
from flext_ldif import c, p, r, t
from flext_ldif._models.domain_attributes import (
    FlextLdifModelsDomainAttributes as mda,
)
from flext_ldif._models.domain_dn import FlextLdifModelsDomainDN as mdn
from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata as mdm
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry

if TYPE_CHECKING:
    from flext_ldif._models.domain_acl import FlextLdifModelsDomainAcl as mdac
    from flext_ldif._models.domain_schema import FlextLdifModelsDomainSchema as mds


class FlextLdifModelsDomainEntry:
    """Namespace for LDIF entry domain models."""

    class EntryStatistics(m.FrozenDynamicModel):
        """Statistics tracking for entry-level transformations and validation.

        Tracks complete entry lifecycle from parsing through validation,
        transformation, filtering, and output. Captures all attribute
        modifications, server applications, and rejection reasons.

        Designed for aggregation across large LDIF files to provide
        comprehensive migration diagnostics.

        Inherits from m.BaseModel (flext-core):
        - model_config (frozen=True, validate_default=True, validate_assignment=True)
        - aggregate() classmethod (automatic statistics aggregation)
        """

        was_parsed: Annotated[
            bool,
            u.Field(description="Entry was successfully parsed from LDIF"),
        ] = True
        was_validated: Annotated[
            bool,
            u.Field(description="Entry passed validation checks"),
        ] = False
        was_filtered: Annotated[
            bool,
            u.Field(
                description="Entry was filtered by rules (base DN, schema, etc.)",
            ),
        ] = False
        was_written: Annotated[
            bool,
            u.Field(description="Entry was written to output LDIF"),
        ] = False
        was_rejected: Annotated[
            bool,
            u.Field(description="Entry was rejected during processing"),
        ] = False
        rejection_category: Annotated[
            str | None,
            u.Field(
                description="Rejection category (use RejectionCategory constants)",
            ),
        ] = None
        rejection_reason: Annotated[
            str | None,
            u.Field(description="Human-readable rejection reason"),
        ] = None
        attributes_added: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Attribute names added during processing",
            ),
        ]
        attributes_removed: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Attribute names removed during processing",
            ),
        ]
        attributes_modified: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Attribute names modified during processing",
            ),
        ]
        attributes_filtered: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Attribute names filtered by whitelist/blacklist",
            ),
        ]
        objectclasses_original: Annotated[
            t.MutableSequenceOf[str],
            u.Field(description="Original objectClass values"),
        ]
        objectclasses_final: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Final objectClass values after transformation",
            ),
        ]
        servers_applied: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="List of server types applied to this entry",
            ),
        ]
        server_transformations: Annotated[
            int,
            u.Field(description="Count of server transformations applied"),
        ] = 0
        dn_statistics: Annotated[
            mdn.DNStatistics | None,
            u.Field(description="DN transformation statistics (if applicable)"),
        ] = None
        filters_applied: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="List of filters applied (use FilterType constants)",
            ),
        ]
        filter_results: Annotated[
            t.MutableBoolMapping,
            u.Field(
                description="Filter results: {filter_name: passed}",
            ),
        ]
        errors: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Error messages (use ErrorCategory constants for keys)",
            ),
        ]
        warnings: Annotated[
            t.MutableSequenceOf[str],
            u.Field(description="Warning messages"),
        ]
        category_assigned: Annotated[
            str | None,
            u.Field(
                description="Category assigned (schema, hierarchy, users, groups, acl)",
            ),
        ] = None
        category_confidence: Annotated[
            float,
            u.Field(
                ge=0.0,
                le=1.0,
                description="Confidence score for category assignment",
            ),
        ] = 1.0

        @u.computed_field()
        @property
        def dn_was_transformed(self) -> bool:
            """Whether DN underwent transformation."""
            if self.dn_statistics is None:
                return False
            return self.dn_statistics.was_transformed

        @u.computed_field()
        @property
        def had_errors(self) -> bool:
            """Whether any errors occurred."""
            return bool(self.errors)

        @u.computed_field()
        @property
        def had_warnings(self) -> bool:
            """Whether any warnings occurred."""
            return bool(self.warnings)

        @u.computed_field()
        @property
        def objectclasses_changed(self) -> bool:
            """Whether objectClass values changed."""
            return set(self.objectclasses_original) != set(self.objectclasses_final)

        @u.computed_field()
        @property
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
            validated: Self = cls.model_validate({"was_parsed": True})
            return validated

        @u.field_validator("filters_applied", mode="after")
        @classmethod
        def deduplicate_filters(
            cls,
            v: t.MutableSequenceOf[str],
        ) -> t.MutableSequenceOf[str]:
            """Remove duplicate filters while preserving order."""
            seen: set[str] = set()
            result: t.MutableSequenceOf[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        @u.field_validator("servers_applied", mode="after")
        @classmethod
        def deduplicate_servers(
            cls,
            v: t.MutableSequenceOf[str],
        ) -> t.MutableSequenceOf[str]:
            """Remove duplicate servers while preserving order."""
            seen: set[str] = set()
            result: t.MutableSequenceOf[str] = []
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
            copy_result: Self = self.model_copy(update={"errors": errors})
            return copy_result

        def add_warning(self, warning: str) -> Self:
            """Add warning message.

            Returns new instance with warning added (frozen model).
            """
            warnings = [*self.warnings, warning]
            copy_result: Self = self.model_copy(update={"warnings": warnings})
            return copy_result

        def mark_filtered(self, filter_type: str, *, passed: bool) -> Self:
            """Mark entry as filtered with result.

            Args:
                filter_type: Type of filter applied
                passed: Whether entry passed the filter (keyword-only)

            Returns new instance with updated filter state (frozen model).

            """
            filters_applied = [*self.filters_applied, filter_type]
            filter_results = {**self.filter_results, filter_type: passed}
            copy_result: Self = self.model_copy(
                update={
                    "was_filtered": True,
                    "filters_applied": filters_applied,
                    "filter_results": filter_results,
                },
            )
            return copy_result

        def mark_rejected(self, category: str, reason: str) -> Self:
            """Mark entry as rejected.

            Returns new instance with rejection details (frozen model).
            """
            copy_result: Self = self.model_copy(
                update={
                    "was_rejected": True,
                    "rejection_category": category,
                    "rejection_reason": reason,
                },
            )
            return copy_result

    class Control(m.Value):
        """Structured RFC 2849 control line."""

        control_type: Annotated[
            str,
            u.Field(description="LDAP control OID or descriptor"),
        ]
        criticality: Annotated[
            bool | None,
            u.Field(description="Optional criticality flag from control line"),
        ] = None
        value: Annotated[
            str | None,
            u.Field(description="Optional control value"),
        ] = None
        value_origin: Annotated[
            c.Ldif.ValueOrigin | None,
            u.Field(description="Original control value encoding/source"),
        ] = None
        raw_value: Annotated[
            str | None,
            u.Field(description="Original serialized control payload"),
        ] = None

    class ChangeOperationValue(m.Value):
        """Single value captured inside a modify operation block."""

        value: Annotated[
            str,
            u.Field(description="Decoded value used by the operation"),
        ]
        value_origin: Annotated[
            c.Ldif.ValueOrigin,
            u.Field(description="Original LDIF encoding/source for this value"),
        ] = c.Ldif.ValueOrigin.PLAIN
        raw_value: Annotated[
            str | None,
            u.Field(description="Original serialized value payload before decoding"),
        ] = None

    class ChangeOperation(m.Value):
        """Structured RFC 2849 modify operation block."""

        operation: Annotated[
            c.Ldif.ChangeOperation,
            u.Field(description="Modify operation name"),
        ]
        attribute: Annotated[
            str,
            u.Field(description="Target attribute for the modify block"),
        ]
        values: Annotated[
            t.MutableSequenceOf[FlextLdifModelsDomainEntry.ChangeOperationValue],
            u.Field(description="Decoded values in the block"),
        ] = u.Field(default_factory=list)

    class Entry(m.Entity, m.DynamicModel):
        """LDIF entry domain model.

        Implements p.Models.Entry through structural typing.
        The protocol requires:
        - dn: str
        - attributes: mda.Attributes

        This model provides these through:
        - dn field (DN) which has .value property returning str
        - attributes field (Attributes) which has .attributes property returning FlextLdifModelsDomainsEntries.UnconvertedAttributes

        Inherits DynamicModel to legitimize extra='allow' for LDIF dynamic attributes.
        """

        model_config: ClassVar[t.ConfigDict] = m.ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",
        )
        _DATETIME_FIELDS: ClassVar[t.StrPair] = ("created_at", "updated_at")
        _ATTRIBUTES_VALIDATE_DEFAULTS: ClassVar[t.MappingKV[str, object]] = (
            MappingProxyType(
                {
                    "attribute_metadata": {},
                    "metadata": None,
                },
            )
        )
        _VALIDATION_RULES_KEY: ClassVar[str] = "validation_rules"
        _VALIDATION_SERVER_TYPE_KEY: ClassVar[str] = "validation_server_type"
        _VALIDATION_CONTEXT_VALIDATOR_KEY: ClassVar[str] = "validator"
        _VALIDATION_CONTEXT_DN_KEY: ClassVar[str] = c.Ldif.DictKeys.DN
        _VALIDATION_CONTEXT_ATTRIBUTE_COUNT_KEY: ClassVar[str] = "attribute_count"
        _VALIDATION_CONTEXT_TOTAL_VIOLATIONS_KEY: ClassVar[str] = "total_violations"
        _VALIDATION_CONTEXT_RFC_COMPLIANCE_NAME: ClassVar[str] = (
            "validate_entry_rfc_compliance"
        )
        _EMPTY_VALIDATION_RESULT_PAYLOAD: ClassVar[t.MappingKV[str, object]] = (
            MappingProxyType(
                {
                    "rfc_violations": (),
                    "errors": (),
                    "warnings": (),
                    "context": {},
                    "server_specific_violations": (),
                    "validation_server_type": None,
                },
            )
        )
        dn: Annotated[
            mdn.DN | None,
            u.Field(
                description="Distinguished Name of the entry (REQUIRED per RFC 2849 § 2). Allows None for RFC violation capture. Coerced from str via u.field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry",
            ),
        ]
        attributes: Annotated[
            mda.Attributes | None,
            u.Field(
                description="Entry attributes container (REQUIRED per RFC 2849 § 2). Allows None for RFC violation capture. Coerced from dict[str, list[str]] via u.field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry",
            ),
        ]
        record_kind: Annotated[
            c.Ldif.RecordKind,
            u.Field(
                description="Whether this Entry represents LDIF content or an LDIF change record.",
            ),
        ] = c.Ldif.RecordKind.CONTENT
        controls: Annotated[
            t.SequenceOf[FlextLdifModelsDomainEntry.Control],
            u.Field(description="RFC 2849 control lines associated with the record"),
        ] = u.Field(default_factory=tuple)
        change_operations: Annotated[
            t.MutableSequenceOf[FlextLdifModelsDomainEntry.ChangeOperation],
            u.Field(
                description="Structured modify operation blocks for changetype=modify",
            ),
        ] = u.Field(default_factory=list)

        @u.field_validator("attributes", mode="before")
        @classmethod
        def coerce_attributes_from_dict(
            cls,
            value: mda.Attributes | t.MutableJsonMapping | None,
        ) -> mda.Attributes | None:
            """Convert dict to Attributes instance.

            Allows None to pass through for violation capture in u.model_validator.
            RFC 2849 § 2 violations (attributes required) are captured in validate_entry_rfc_compliance.
            """
            if value is None:
                return None
            if isinstance(value, mda.Attributes):
                return value
            if "attributes" not in value:
                validated_dict: mda.Attributes = mda.Attributes.model_validate(
                    {"attributes": dict(value)},
                )
                return validated_dict
            validated: mda.Attributes = mda.Attributes.model_validate(value)
            return validated

        @u.field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls,
            value: mdn.DN | t.MutableJsonMapping | str | None,
        ) -> mdn.DN | None:
            """Convert string DN to DN instance.

            Allows None to pass through for violation capture in u.model_validator.
            RFC 2849 § 2 violations are captured in validate_entry_rfc_compliance.
            """
            if value is None:
                return None
            if isinstance(value, mdn.DN):
                return value
            if isinstance(value, Mapping):
                validated: mdn.DN = mdn.DN.model_validate(value)
                return validated
            return mdn.DN(
                value=value,
                metadata={},
            )

        @u.field_validator("record_kind", mode="before")
        @classmethod
        def coerce_record_kind(
            cls,
            value: str,
        ) -> c.Ldif.RecordKind:
            """Accept both enum instances and serialized record kind strings."""
            return c.Ldif.RecordKind(value)

        changetype: Annotated[
            c.Ldif.ChangeType | None,
            u.Field(
                description="Change operation type per RFC 2849 § 5.7 (add/delete/modify/moddn/modrdn)",
            ),
        ] = None

        @u.field_validator("changetype", mode="before")
        @classmethod
        def coerce_changetype(
            cls,
            value: str | None,
        ) -> c.Ldif.ChangeType | None:
            """Accept both enum instances and serialized changetype strings."""
            if isinstance(value, str):
                return c.Ldif.ChangeType(value)
            return value

        newrdn: Annotated[
            str | None,
            u.Field(description="RFC 2849 newrdn field for moddn/modrdn records"),
        ] = None
        deleteoldrdn: Annotated[
            bool | None,
            u.Field(description="RFC 2849 deleteoldrdn field for moddn/modrdn records"),
        ] = None
        newsuperior: Annotated[
            str | None,
            u.Field(description="RFC 2849 newsuperior field for moddn/modrdn records"),
        ] = None
        raw_record_lines: Annotated[
            t.MutableSequenceOf[str],
            u.Field(
                description="Original unfolded LDIF lines for loss-aware round-trip",
            ),
        ] = u.Field(default_factory=list)
        metadata: Annotated[
            mdm.ServerMetadata | None,
            u.Field(
                description="Server-specific metadata for processing data, ACLs, statistics, validation (non-RFC data)",
            ),
        ] = None
        validation_metadata: Annotated[
            m.ConfigMap | None,
            u.Field(
                description="Validation metadata captured during parsing and transformation.",
            ),
        ] = None

        @u.computed_field()
        @property
        def attributes_dict(self) -> t.MutableStrSequenceMapping:
            """Protocol compliance: p.Ldif.Entry.Entry requires attributes: dict[str, list[str]].

            Returns the attributes as a dict for protocol compatibility.
            """
            if self.attributes is None:
                return {}
            return self.attributes.attributes

        @u.computed_field()
        @property
        def dn_str(self) -> str:
            """Protocol compliance: p.Ldif.Entry.Entry requires dn: str.

            Returns the DN as a string for protocol compatibility.
            """
            if self.dn is None:
                return ""
            return self.dn.value

        @u.computed_field()
        @property
        def is_change_record(self) -> bool:
            """True when the entry represents an LDIF change record."""
            return bool(self.changetype) or self.record_kind == c.Ldif.RecordKind.CHANGE

        @u.computed_field()
        @property
        def unconverted_attributes(
            self,
        ) -> t.Ldif.UnconvertedAttributes:
            """The unconverted attributes from metadata extensions (read-only view, DRY pattern)."""
            empty_attrs: t.Ldif.UnconvertedAttributes = {}
            if self.metadata is None:
                return empty_attrs
            # mro-wgwh.5 (agent: kimi-coder) — extensions is a plain mapping now.
            result = self.metadata.extensions.get("unconverted_attributes")
            return FlextLdifUtilitiesEntry.normalize_unconverted_attributes(result)

        @u.model_validator(mode="before")
        @classmethod
        def ensure_metadata_initialized(
            cls,
            data: t.MutableJsonMapping,
        ) -> MutableMapping[
            str,
            t.JsonValue | datetime | mdm.ServerMetadata,
        ]:
            """Ensure metadata field is always initialized to a ServerMetadata instance.

            Also handles datetime coercion from ISO strings for JSON round-trips.
            This is necessary because strict=True doesn't auto-coerce strings to datetime.

            Pydantic v2 Context Pattern: Using u.model_validator with mode='before'
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
                t.JsonValue | datetime | mdm.ServerMetadata,
            ] = dict(data)
            for dt_field in cls._DATETIME_FIELDS:
                field_value = data_dict.get(dt_field)
                if isinstance(field_value, str):
                    try:
                        data_dict[dt_field] = datetime.fromisoformat(field_value)
                    except ValueError:
                        data_dict[dt_field] = field_value
            if data_dict.get("metadata") is None:
                server_type_value = data_dict.get("server_type")
                final_server_type_val: c.Ldif.ServerTypes
                if isinstance(server_type_value, str):
                    try:
                        final_server_type_val = c.Ldif.ServerTypes(server_type_value)
                    except ValueError:
                        final_server_type_val = c.Ldif.ServerTypes.RFC
                else:
                    final_server_type_val = c.Ldif.ServerTypes.RFC
                # mro-wgwh.5 (agent: kimi-coder) — create_for removed from the model
                # (U17); models validate directly at this internal boundary.
                metadata_obj = mdm.ServerMetadata.model_validate({
                    "server_type": final_server_type_val,
                })
                data_dict["metadata"] = metadata_obj
            return data_dict

        @override
        def model_post_init(
            self,
            context: t.ScalarMapping | None,
            /,
        ) -> None:
            """Post-init hook to ensure metadata is always initialized.

            Properly initialized before any code tries to access it.
            Uses self.__dict__ assignment to bypass validate_assignment=True
            and prevent infinite re-validation recursion (Pydantic v2 pattern).
            """
            if self.metadata is None:
                self.metadata = mdm.ServerMetadata.model_validate({
                    "server_type": c.Ldif.ServerTypes.RFC,
                })

        @u.model_validator(mode="after")
        def normalize_record_kind(self) -> Self:
            """Keep record_kind aligned with changetype semantics."""
            if self.changetype and self.record_kind != c.Ldif.RecordKind.CHANGE:
                copy_change: Self = self.model_copy(
                    update={"record_kind": c.Ldif.RecordKind.CHANGE},
                )
                return copy_change
            if not self.changetype and self.record_kind != c.Ldif.RecordKind.CONTENT:
                copy_content: Self = self.model_copy(
                    update={"record_kind": c.Ldif.RecordKind.CONTENT},
                )
                return copy_content
            return self

        @u.model_validator(mode="after")
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

        @u.model_validator(mode="after")
        def validate_entry_rfc_compliance(self) -> Self:
            """Validate Entry RFC compliance - capture violations, DON'T reject.

            RFC 2849 § 2: DN and at least one attribute required
            RFC 4514 § 2.3, 2.4: DN format validation
            RFC 4512 § 2.5: Attribute name format validation

            Strategy: PRESERVE problematic entries for round-trip conversions,
            capture violations in validation_metadata for downstream handling.
            """
            violations: t.MutableSequenceOf[str] = []

            dn_value = "<None>"
            if self.dn is None:
                violations.append("RFC 2849 § 2: DN is required")
            else:
                dn_value = self.dn.value
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
                    FlextLdifUtilitiesEntry.validate_naming_attribute(self, dn_value),
                )
                violations.extend(FlextLdifUtilitiesEntry.validate_binary_options(self))
                violations.extend(
                    FlextLdifUtilitiesEntry.validate_attribute_syntax(self),
                )
                violations.extend(FlextLdifUtilitiesEntry.validate_changetype(self))
            if violations and self.metadata is not None:
                attribute_count = len(self.attributes) if self.attributes else 0
                old_context: t.MutableStrMapping = {}
                if self.metadata.validation_results is not None:
                    old_context = t.str_dict_adapter().validate_python(
                        self.metadata.validation_results.context,
                    )
                context_payload = self._build_rfc_validation_context(
                    old_context=old_context,
                    dn_value=dn_value,
                    attribute_count=attribute_count,
                    total_violations=len(violations),
                )
                payload: t.JsonMapping = t.json_mapping_adapter().validate_python({
                    **self._EMPTY_VALIDATION_RESULT_PAYLOAD,
                    "rfc_violations": list(violations),
                    "errors": list[str](),
                    "warnings": list[str](),
                    "server_specific_violations": list[str](),
                    "context": context_payload,
                })
                self.metadata.validation_results = (
                    mdm.ValidationMetadata.model_validate(
                        payload,
                    )
                )
            return self

        @u.model_validator(mode="after")
        def validate_server_specific_rules(self) -> Self:
            """Validate Entry using server-injected validation rules."""
            if not self.metadata:
                return self
            if self._VALIDATION_RULES_KEY not in self.metadata.extensions:
                return self
            validation_rules = self.metadata.extensions.get(self._VALIDATION_RULES_KEY)
            if not isinstance(validation_rules, (str, Mapping)):
                return self
            rules = FlextLdifUtilitiesEntry.parse_validation_rules(validation_rules)
            if rules is None:
                return self
            dn_value = self.dn.value if self.dn else ""
            server_violations: t.MutableSequenceOf[str] = []
            server_violations.extend(
                FlextLdifUtilitiesEntry.check_objectclass_rule(self, rules, dn_value),
            )
            server_violations.extend(
                FlextLdifUtilitiesEntry.check_naming_attr_rule(self, rules, dn_value),
            )
            server_violations.extend(
                FlextLdifUtilitiesEntry.check_binary_option_rule(self, rules),
            )
            if self.metadata:
                self.metadata.extensions[self._VALIDATION_SERVER_TYPE_KEY] = (
                    self.metadata.server_type
                )
            if server_violations and self.metadata:
                if self.metadata.validation_results is None:
                    self.metadata.validation_results = self._empty_validation_results()
                updated_validation_results = (
                    self.metadata.validation_results.model_copy(
                        update={
                            "server_specific_violations": server_violations,
                            "validation_server_type": self.metadata.server_type,
                        },
                    )
                )
                self.metadata.validation_results = updated_validation_results
                ext_violations: t.JsonValueList = list(server_violations)
                # mro-wgwh.5 (agent: kimi-coder) — extensions is a plain mapping now.
                self.metadata.extensions["server_specific_violations"] = ext_violations
            return self

        @classmethod
        def _empty_validation_results(
            cls,
        ) -> mdm.ValidationMetadata:
            """Create empty ValidationMetadata from canonical immutable payload."""
            payload: t.JsonMapping = t.json_mapping_adapter().validate_python({
                **cls._EMPTY_VALIDATION_RESULT_PAYLOAD,
                "rfc_violations": list[str](),
                "errors": list[str](),
                "warnings": list[str](),
                "server_specific_violations": list[str](),
            })
            validated: mdm.ValidationMetadata = mdm.ValidationMetadata.model_validate(
                payload,
            )
            return validated

        @classmethod
        def _build_rfc_validation_context(
            cls,
            old_context: t.StrMapping,
            dn_value: str,
            attribute_count: int,
            total_violations: int,
        ) -> dict[str, str]:
            """Build RFC validation context map reusing canonical key constants."""
            return {
                **old_context,
                cls._VALIDATION_CONTEXT_VALIDATOR_KEY: cls._VALIDATION_CONTEXT_RFC_COMPLIANCE_NAME,
                cls._VALIDATION_CONTEXT_DN_KEY: dn_value,
                cls._VALIDATION_CONTEXT_ATTRIBUTE_COUNT_KEY: str(attribute_count),
                cls._VALIDATION_CONTEXT_TOTAL_VIOLATIONS_KEY: str(total_violations),
            }

        @u.computed_field()
        @property
        def has_validation_errors(self) -> bool:
            """Whether entry has validation errors.

            Returns:
            True if entry has validation errors in validation_metadata, False otherwise

            """
            if self.metadata is None:
                return False
            if self.metadata.validation_results is None:
                return False
            return bool(self.metadata.validation_results.errors)

        @u.computed_field()
        @property
        def is_acl_entry(self) -> bool:
            """Whether entry has Access Control Lists.

            Returns:
            True if entry has ACLs, False otherwise

            """
            if self.metadata is None:
                return False
            return bool(self.metadata.acls)

        @u.computed_field()
        @property
        def is_schema_entry(self) -> bool:
            """Whether entry is a schema definition entry.

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
            server_type: c.Ldif.ServerTypes | None,
            source_entry: str | None,
            unconverted_attributes: t.Ldif.MetadataInputMapping | None,
        ) -> t.Ldif.MutableMetadataMapping:
            """Build extension kwargs for metadata extensions."""
            ext_kwargs: t.Ldif.MutableMetadataMapping = {}
            if server_type:
                ext_kwargs["server_type"] = server_type
            if source_entry:
                ext_kwargs["source_entry"] = source_entry
            if unconverted_attributes:
                # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: pass the plain mapping.
                ext_kwargs["unconverted_attributes"] = dict(unconverted_attributes)
            return ext_kwargs

        @classmethod
        def _build_metadata(
            cls,
            metadata: mdm.ServerMetadata | None,
            server_type: c.Ldif.ServerTypes | None,
            source_entry: str | None,
            unconverted_attributes: t.Ldif.MetadataInputMapping | None,
        ) -> mdm.ServerMetadata | None:
            """Build or update metadata with server-specific extensions."""
            has_new_metadata = server_type or source_entry or unconverted_attributes
            if metadata is None and has_new_metadata:
                ext_kwargs = cls._build_extension_kwargs(
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )
                # mro-wgwh.5 (agent: kimi-coder) — create_for removed; direct validated construction.
                validated_metadata: mdm.ServerMetadata = (
                    mdm.ServerMetadata.model_validate({
                        "server_type": c.Ldif.ServerTypes.GENERIC,
                        "extensions": ext_kwargs,
                    })
                )
                return validated_metadata
            if metadata is not None and has_new_metadata:
                cls._update_existing_metadata(
                    metadata,
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )
            return metadata

        @classmethod
        def _normalize_attributes(
            cls,
            attributes: t.MutableAttributeMapping | mda.Attributes,
        ) -> mda.Attributes:
            """Normalize attributes to Attributes t.JsonValue.

            Args:
                attributes: Attributes as dict or Attributes t.JsonValue

            Returns:
                Attributes t.JsonValue with normalized values

            Note:
                Lenient processing: Empty attributes dict is accepted and will be captured
                in validation_metadata as RFC violation.

            """
            if isinstance(attributes, mda.Attributes):
                return attributes
            attrs_dict: t.MutableStrSequenceMapping = {}
            for attr_name, attr_values in attributes.items():
                if isinstance(attr_values, str):
                    values_list: t.MutableSequenceOf[str] = [attr_values]
                else:
                    values_list = list(attr_values)
                attrs_dict[attr_name] = values_list
            validate_payload: t.JsonMapping = t.json_mapping_adapter().validate_python({
                "attributes": attrs_dict,
                **cls._ATTRIBUTES_VALIDATE_DEFAULTS,
            })
            validated: mda.Attributes = mda.Attributes.model_validate(
                validate_payload,
            )
            return validated

        @classmethod
        def _update_existing_metadata(
            cls,
            metadata: mdm.ServerMetadata,
            server_type: c.Ldif.ServerTypes | None,
            source_entry: str | None,
            unconverted_attributes: t.Ldif.MetadataInputMapping | None,
        ) -> None:
            """Update existing metadata extensions in place."""
            if server_type:
                metadata.extensions["server_type"] = server_type
            if source_entry:
                metadata.extensions["source_entry"] = source_entry
            if unconverted_attributes:
                # mro-wgwh.5 (agent: kimi-coder) — plain mapping items, no __pydantic_extra__.
                for key, value in unconverted_attributes.items():
                    metadata.extensions[f"unconverted_{key}"] = str(value)

        @classmethod
        def create(
            cls,
            dn: str | mdn.DN,
            attributes: t.MutableAttributeMapping | mda.Attributes,
            metadata: mdm.ServerMetadata | None = None,
            acls: t.MutableSequenceOf[mdac.Acl] | None = None,
            objectclasses: t.MutableSequenceOf[mds.SchemaObjectClass] | None = None,
            attributes_schema: t.MutableSequenceOf[mds.SchemaAttribute] | None = None,
            entry_metadata: t.MutableJsonMapping | None = None,
            validation_metadata: mdm.ValidationMetadata | None = None,
            server_type: c.Ldif.ServerTypes | None = None,
            record_kind: c.Ldif.RecordKind = c.Ldif.RecordKind.CONTENT,
            controls: t.SequenceOf[FlextLdifModelsDomainEntry.Control] | None = None,
            change_operations: t.MutableSequenceOf[
                FlextLdifModelsDomainEntry.ChangeOperation
            ]
            | None = None,
            changetype: c.Ldif.ChangeType | None = None,
            newrdn: str | None = None,
            deleteoldrdn: bool | None = None,
            newsuperior: str | None = None,
            raw_record_lines: t.MutableSequenceOf[str] | None = None,
            source_entry: str | None = None,
            unconverted_attributes: t.Ldif.MetadataInputMapping | None = None,
            statistics: FlextLdifModelsDomainEntry.EntryStatistics | None = None,
        ) -> p.Result[Self]:
            try:
                entry_data = cls._build_entry_data(
                    dn,
                    attributes,
                    metadata,
                    acls,
                    objectclasses,
                    attributes_schema,
                    entry_metadata,
                    validation_metadata,
                    server_type,
                    record_kind,
                    controls,
                    change_operations,
                    changetype,
                    newrdn,
                    deleteoldrdn,
                    newsuperior,
                    raw_record_lines,
                    source_entry,
                    unconverted_attributes,
                    statistics,
                )
                entry_instance: Self = cls.model_validate(entry_data)
                ok_result: p.Result[Self] = r[Self].ok(entry_instance)
                return ok_result
            except c.EXC_BASIC_TYPE as e:
                fail_result: p.Result[Self] = r[Self].fail(
                    f"Failed to create Entry: {e}",
                )
                return fail_result

        @classmethod
        def _build_entry_data(
            cls,
            dn: str | mdn.DN,
            attributes: t.MutableAttributeMapping | mda.Attributes,
            metadata: mdm.ServerMetadata | None,
            acls: t.MutableSequenceOf[mdac.Acl] | None,
            objectclasses: t.MutableSequenceOf[mds.SchemaObjectClass] | None,
            attributes_schema: t.MutableSequenceOf[mds.SchemaAttribute] | None,
            entry_metadata: t.MutableJsonMapping | None,
            validation_metadata: mdm.ValidationMetadata | None,
            server_type: c.Ldif.ServerTypes | None,
            record_kind: c.Ldif.RecordKind,
            controls: t.SequenceOf[FlextLdifModelsDomainEntry.Control] | None,
            change_operations: t.MutableSequenceOf[
                FlextLdifModelsDomainEntry.ChangeOperation
            ]
            | None,
            changetype: c.Ldif.ChangeType | None,
            newrdn: str | None,
            deleteoldrdn: bool | None,
            newsuperior: str | None,
            raw_record_lines: t.MutableSequenceOf[str] | None,
            source_entry: str | None,
            unconverted_attributes: t.Ldif.MetadataInputMapping | None,
            statistics: FlextLdifModelsDomainEntry.EntryStatistics | None,
        ) -> dict[str, t.JsonPayload]:
            """Build validated Entry model input."""
            dn_obj = mdn.DN.from_value(dn)
            attrs_obj = cls._normalize_attributes(attributes)
            resolved_metadata = cls._build_metadata(
                metadata,
                server_type,
                source_entry,
                unconverted_attributes,
            )
            entry_data: dict[str, t.JsonPayload] = {
                c.Ldif.DictKeys.DN: dn_obj,
                c.Ldif.DictKeys.ATTRIBUTES: attrs_obj,
                "record_kind": record_kind,
            }
            if resolved_metadata is not None:
                entry_data["metadata"] = resolved_metadata
            if acls is not None:
                entry_data["acls"] = acls
            if objectclasses is not None:
                entry_data["objectclasses"] = objectclasses
            if attributes_schema is not None:
                entry_data["attributes_schema"] = attributes_schema
            if entry_metadata is not None:
                entry_data["entry_metadata"] = entry_metadata
            if validation_metadata is not None:
                entry_data["validation_metadata"] = validation_metadata
            if controls is not None:
                entry_data["controls"] = controls
            if change_operations is not None:
                entry_data["change_operations"] = change_operations
            if changetype is not None:
                entry_data["changetype"] = changetype
            if newrdn is not None:
                entry_data["newrdn"] = newrdn
            if deleteoldrdn is not None:
                entry_data["deleteoldrdn"] = deleteoldrdn
            if newsuperior is not None:
                entry_data["newsuperior"] = newsuperior
            if raw_record_lines is not None:
                entry_data["raw_record_lines"] = list(raw_record_lines)
            if statistics is not None:
                entry_data["statistics"] = statistics
            return entry_data


__all__: list[str] = ["FlextLdifModelsDomainEntry"]
