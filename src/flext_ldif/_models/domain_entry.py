"""Domain Entry model — LDIF entry and entry statistics.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from datetime import datetime
from types import MappingProxyType
from typing import Annotated, ClassVar, Self, override

from flext_core import FlextUtilities as u, m, r
from flext_ldif import c, p, t
from flext_ldif._models.domain_attributes import FlextLdifModelsDomainAttributes as mda
from flext_ldif._models.domain_dn import FlextLdifModelsDomainDN as mdn
from flext_ldif._models.domain_entry_change import (
    FlextLdifModelsDomainEntryChangeOperation,
    FlextLdifModelsDomainEntryChangeOperationValue,
    FlextLdifModelsDomainEntryControl,
)
from flext_ldif._models.domain_entry_statistics import (
    FlextLdifModelsDomainEntryStatistics,
)
from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata as mdm
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry


class FlextLdifModelsDomainEntry:
    """Namespace for LDIF entry domain models."""

    EntryStatistics = FlextLdifModelsDomainEntryStatistics
    """Canonical entry statistics model.

    Implementation module: ``domain_entry_statistics``.
    """

    Control = FlextLdifModelsDomainEntryControl
    """Canonical RFC 2849 control line model.

    Implementation module: ``domain_entry_change``.
    """

    ChangeOperationValue = FlextLdifModelsDomainEntryChangeOperationValue
    """Canonical modify-operation value model.

    Implementation module: ``domain_entry_change``.
    """

    ChangeOperation = FlextLdifModelsDomainEntryChangeOperation
    """Canonical RFC 2849 modify operation model.

    Implementation module: ``domain_entry_change``.
    """

    class Entry(m.Entity, m.DynamicModel):
        """LDIF entry domain model.

        Implements p.Models.Entry through structural typing.
        The protocol requires:
        - dn: str
        - attributes: mda.Attributes

        This model provides these through:
        - dn field (DN) which has .value property returning str
        - attributes field (Attributes) which has .attributes property returning
        FlextLdifModelsDomainsEntries.UnconvertedAttributes

        Inherits DynamicModel to legitimize extra='allow' for LDIF dynamic attributes.
        """

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",
        )
        _DATETIME_FIELDS: ClassVar[t.StrPair] = ("created_at", "updated_at")
        _ATTRIBUTES_VALIDATE_DEFAULTS: ClassVar[t.MappingKV[str, t.JsonValue]] = (
            MappingProxyType({"attribute_metadata": {}, "metadata": None})
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
        _EMPTY_VALIDATION_RESULT_PAYLOAD: ClassVar[
            t.MappingKV[str, t.JsonValue | t.SequenceOf[str]]
        ] = MappingProxyType({
            "rfc_violations": (),
            "errors": (),
            "warnings": (),
            "context": {},
            "server_specific_violations": (),
            "validation_server_type": None,
        })
        dn: Annotated[
            mdn.DN | None,
            u.Field(
                description=(
                    "Distinguished Name of the entry (REQUIRED per RFC 2849 § 2). "
                    "Allows None for RFC violation capture. Coerced from str via "
                    "u.field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry"
                ),
            ),
        ]
        attributes: Annotated[
            mda.Attributes | None,
            u.Field(
                description=(
                    "Entry attributes container (REQUIRED per RFC 2849 § 2). Allows "
                    "None for RFC violation capture. Coerced from "
                    "dict[str, list[str]] via u.field_validator - PROTOCOL "
                    "COMPATIBLE with p.Ldif.Entry.Entry"
                ),
            ),
        ]
        record_kind: Annotated[
            c.Ldif.RecordKind,
            u.Field(
                description=(
                    "Whether this Entry represents LDIF content or an LDIF change "
                    "record."
                ),
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
            RFC 2849 § 2 violations (attributes required) are captured in
            validate_entry_rfc_compliance.

            Returns:
                The resulting ``mda.Attributes | None``.
            """
            if value is None or isinstance(value, mda.Attributes):
                return value
            if "attributes" not in value:
                return mda.Attributes.model_validate({"attributes": dict(value)})
            return mda.Attributes.model_validate(value)

        @u.field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls,
            value: mdn.DN | t.MutableJsonMapping | str | None,
        ) -> mdn.DN | None:
            """Convert string DN to DN instance.

            Allows None to pass through for violation capture in u.model_validator.
            RFC 2849 § 2 violations are captured in validate_entry_rfc_compliance.

            Returns:
                The resulting ``mdn.DN | None``.
            """
            if value is None or isinstance(value, mdn.DN):
                return value
            if isinstance(value, Mapping):
                return mdn.DN.model_validate(value)
            return mdn.DN(value=value, metadata={})

        @u.field_validator("record_kind", mode="before")
        @classmethod
        def coerce_record_kind(cls, value: str) -> c.Ldif.RecordKind:
            """Accept both enum instances and serialized record kind strings.

            Returns:
                The resulting ``c.Ldif.RecordKind``.
            """
            return c.Ldif.RecordKind(value)

        changetype: Annotated[
            c.Ldif.ChangeType | None,
            u.Field(
                description=(
                    "Change operation type per RFC 2849 § 5.7 "
                    "(add/delete/modify/moddn/modrdn)"
                ),
            ),
        ] = None

        @u.field_validator("changetype", mode="before")
        @classmethod
        def coerce_changetype(cls, value: str | None) -> c.Ldif.ChangeType | None:
            """Accept both enum instances and serialized changetype strings.

            Returns:
                The resulting ``c.Ldif.ChangeType | None``.
            """
            return c.Ldif.ChangeType(value) if isinstance(value, str) else value

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
                description=(
                    "Server-specific metadata for processing data, ACLs, "
                    "statistics, validation (non-RFC data)"
                ),
            ),
        ] = None
        validation_metadata: Annotated[
            m.ConfigMap | None,
            u.Field(
                description=(
                    "Validation metadata captured during parsing and transformation."
                ),
            ),
        ] = None

        @u.computed_field
        @property
        def attributes_dict(self) -> t.MutableStrSequenceMapping:
            """Protocol compliance: p.Ldif.Entry.Entry requires attributes:.

            dict[str, list[str]].

            Returns the attributes as a dict for protocol compatibility.
            """
            return {} if self.attributes is None else self.attributes.attributes

        @u.computed_field
        @property
        def dn_str(self) -> str:
            """Protocol compliance: p.Ldif.Entry.Entry requires dn: str.

            Returns the DN as a string for protocol compatibility.
            """
            return "" if self.dn is None else self.dn.value

        @u.computed_field
        @property
        def is_change_record(self) -> bool:
            """True when the entry represents an LDIF change record."""
            return bool(self.changetype) or self.record_kind == c.Ldif.RecordKind.CHANGE

        @u.computed_field
        @property
        def unconverted_attributes(self) -> t.Ldif.UnconvertedAttributes:
            """The unconverted attributes from metadata extensions (read-only view, DRY.

            pattern).
            """
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
        ) -> MutableMapping[str, t.JsonValue | datetime | mdm.ServerMetadata]:
            """Ensure metadata field is always initialized to a ServerMetadata instance.

            Also handles datetime coercion from ISO strings for JSON round-trips.
            This is necessary because strict=True doesn't auto-coerce strings
            to datetime.

            Pydantic v2 Context Pattern: Using u.model_validator with mode='before'
            to initialize fields before field validators run. This validator executes
            at instantiation time, when the module is fully loaded and
            FlextLdifModelsDomainsEntries is in scope.

            Args:
                data: Input data for model instantiation

            Returns:
                Modified data with metadata field initialized and datetimes coerced

            """
            data_dict: MutableMapping[
                str,
                t.JsonValue | datetime | mdm.ServerMetadata,
            ] = dict(data)
            cls._coerce_datetime_fields(data_dict)
            if data_dict.get("metadata") is None:
                # mro-wgwh.5 (agent: kimi-coder) — create_for removed from the model
                # (U17); models validate directly at this internal boundary.
                raw_server_type = data_dict.get("server_type")
                data_dict["metadata"] = mdm.ServerMetadata.model_validate({
                    "server_type": cls._coerce_default_server_type(
                        raw_server_type if isinstance(raw_server_type, str) else None,
                    ),
                })
            return data_dict

        @classmethod
        def _coerce_datetime_fields(
            cls,
            data_dict: MutableMapping[str, t.JsonValue | datetime | mdm.ServerMetadata],
        ) -> None:
            """Coerce ISO datetime strings in place.

            Strict mode lacks auto-coercion.
            """
            for dt_field in cls._DATETIME_FIELDS:
                field_value = data_dict.get(dt_field)
                if isinstance(field_value, str):
                    try:
                        data_dict[dt_field] = datetime.fromisoformat(field_value)
                    except ValueError:
                        data_dict[dt_field] = field_value

        @classmethod
        def _coerce_default_server_type(
            cls,
            server_type_value: t.JsonValue | None,
        ) -> c.Ldif.ServerTypes:
            """Coerce a raw server-type token into the enum.

            Returns:
                The parsed server type, defaulting to RFC.
            """
            if isinstance(server_type_value, str):
                try:
                    return c.Ldif.ServerTypes(server_type_value)
                except ValueError:
                    return c.Ldif.ServerTypes.RFC
            return c.Ldif.ServerTypes.RFC

        @override
        def model_post_init(self, context: t.ScalarMapping | None, /) -> None:
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
            """Keep record_kind aligned with changetype semantics.

            Returns:
                The resulting ``Self``.
            """
            target_kind = (
                c.Ldif.RecordKind.CHANGE
                if self.changetype
                else c.Ldif.RecordKind.CONTENT
            )
            if self.record_kind != target_kind:
                normalized: Self = self.model_copy(update={"record_kind": target_kind})
                return normalized
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

            Returns:
                The resulting ``Self``.
            """
            dn_value, violations = self._collect_rfc_violations()
            self._store_rfc_violations(dn_value, violations)
            return self

        def _collect_rfc_violations(self) -> tuple[str, t.MutableSequenceOf[str]]:
            """Collect RFC 2849/4514 violations without rejecting the entry.

            Returns:
                The resulting ``tuple[str, t.MutableSequenceOf[str]]``.
            """
            violations: t.MutableSequenceOf[str] = []
            dn_value = "<None>"
            if self.dn is None:
                violations.append("RFC 2849 § 2: DN is required")
                return (dn_value, violations)
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
            return (dn_value, violations)

        def _store_rfc_violations(
            self,
            dn_value: str,
            violations: t.MutableSequenceOf[str],
        ) -> None:
            """Persist collected violations into validation metadata."""
            if not violations or self.metadata is None:
                return
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
            self.metadata.validation_results = mdm.ValidationMetadata.model_validate(
                payload,
            )

        @u.model_validator(mode="after")
        def validate_server_specific_rules(self) -> Self:
            """Validate Entry using server-injected validation rules.

            Returns:
                The resulting ``Self``.
            """
            if (
                self.metadata is None
                or self._VALIDATION_RULES_KEY not in self.metadata.extensions
            ):
                return self
            validation_rules = self.metadata.extensions.get(self._VALIDATION_RULES_KEY)
            rules = (
                FlextLdifUtilitiesEntry.parse_validation_rules(validation_rules)
                if isinstance(validation_rules, (str, Mapping))
                else None
            )
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
            self.metadata.extensions[self._VALIDATION_SERVER_TYPE_KEY] = (
                self.metadata.server_type
            )
            if not server_violations:
                return self
            if self.metadata.validation_results is None:
                self.metadata.validation_results = self._empty_validation_results()
            updated_validation_results = self.metadata.validation_results.model_copy(
                update={
                    "server_specific_violations": server_violations,
                    "validation_server_type": self.metadata.server_type,
                },
            )
            self.metadata.validation_results = updated_validation_results
            ext_violations: t.JsonValueList = list(server_violations)
            # mro-wgwh.5 (agent: kimi-coder) — extensions is a plain mapping now.
            self.metadata.extensions["server_specific_violations"] = ext_violations
            return self

        @classmethod
        def _empty_validation_results(cls) -> mdm.ValidationMetadata:
            """Create empty ValidationMetadata from canonical immutable payload.

            Returns:
                The resulting ``mdm.ValidationMetadata``.
            """
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
        ) -> t.StrMapping:
            """Build RFC validation context map reusing canonical key constants.

            Returns:
                The resulting ``t.StrMapping``.
            """
            return {
                **old_context,
                cls._VALIDATION_CONTEXT_VALIDATOR_KEY: (
                    cls._VALIDATION_CONTEXT_RFC_COMPLIANCE_NAME
                ),
                cls._VALIDATION_CONTEXT_DN_KEY: dn_value,
                cls._VALIDATION_CONTEXT_ATTRIBUTE_COUNT_KEY: str(attribute_count),
                cls._VALIDATION_CONTEXT_TOTAL_VIOLATIONS_KEY: str(total_violations),
            }

        @u.computed_field
        @property
        def has_validation_errors(self) -> bool:
            """Whether entry has validation errors.

            Returns:
            True if entry has validation errors in validation_metadata, False otherwise

            """
            return bool(
                self.metadata
                and self.metadata.validation_results
                and self.metadata.validation_results.errors,
            )

        @u.computed_field
        @property
        def is_acl_entry(self) -> bool:
            """Whether entry has Access Control Lists.

            Returns:
            True if entry has ACLs, False otherwise

            """
            return bool(self.metadata and self.metadata.acls)

        @u.computed_field
        @property
        def is_schema_entry(self) -> bool:
            """Whether entry is a schema definition entry.

            Schema entries contain objectClass definitions and are typically
            found in the schema naming context.

            Returns:
            True if entry has objectClasses, False otherwise

            """
            return bool(self.metadata and self.metadata.objectclasses)

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
                Lenient processing: Empty attributes dict is accepted and will
                be captured in validation_metadata as RFC violation.

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
            validated: mda.Attributes = mda.Attributes.model_validate(validate_payload)
            return validated

        @classmethod
        def create(
            cls,
            dn: str | mdn.DN,
            attributes: t.MutableAttributeMapping | mda.Attributes,
            metadata: mdm.ServerMetadata | None = None,
        ) -> p.Result[Self]:
            """Create a validated Entry from canonical domain inputs.

            Returns:
                The resulting ``p.Result[Self]``.
            """
            try:
                entry_data = cls._build_entry_data(dn, attributes, metadata)
                entry_instance: Self = cls.model_validate(entry_data)
                ok_result: p.Result[Self] = r[Self].ok(entry_instance)
            except c.EXC_BASIC_TYPE as e:
                fail_result: p.Result[Self] = r[Self].fail(
                    f"Failed to create Entry: {e}",
                    exception=e,
                )
                return fail_result
            else:
                return ok_result

        @classmethod
        def _build_entry_data(
            cls,
            dn: str | mdn.DN,
            attributes: t.MutableAttributeMapping | mda.Attributes,
            metadata: mdm.ServerMetadata | None,
        ) -> t.MappingKV[str, t.JsonPayload]:
            """Build validated Entry model input.

            Returns:
                The resulting ``t.MappingKV[str, t.JsonPayload]``.
            """
            entry_data: t.MutableMappingKV[str, t.JsonPayload] = {
                c.Ldif.DictKeys.DN: mdn.DN.from_value(dn),
                c.Ldif.DictKeys.ATTRIBUTES: cls._normalize_attributes(attributes),
            }
            if metadata is not None:
                entry_data["metadata"] = metadata
            return entry_data


__all__: list[str] = ["FlextLdifModelsDomainEntry"]
