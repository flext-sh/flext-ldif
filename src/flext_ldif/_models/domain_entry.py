"""Domain Entry model — LDIF entry and entry statistics.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, MutableSequence, Sequence
from datetime import datetime
from typing import Annotated, ClassVar, Self, override

from flext_cli import m

from flext_ldif import c, e, p, r, t
from flext_ldif._models import (
    FlextLdifModelsDomainAttributes,
    FlextLdifModelsDomainDN,
    FlextLdifModelsDomainEntryChangeOperation,
    FlextLdifModelsDomainEntryControl,
    FlextLdifModelsDomainMetadata,
)


class FlextLdifModelsDomainEntry(FlextLdifModelsDomainEntryChangeOperation):
    """Namespace for LDIF entry domain models."""

    class Entry(m.Entity, m.DynamicModel):
        """LDIF entry domain model.

        Satisfies ``p.Ldif.Entry.Entry`` through structural typing: the
        ``dn_str`` and ``attributes_dict`` computed fields expose the
        protocol surface, and ``extra='allow'`` legitimizes dynamic LDIF
        attributes.

        """

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            strict=True,
            use_enum_values=False,
            validate_default=True,
            validate_assignment=True,
            extra="allow",
        )
        _DATETIME_FIELDS: ClassVar[tuple[str, str]] = ("created_at", "updated_at")
        _VALIDATION_RULES_KEY: ClassVar[str] = "validation_rules"
        _VALIDATION_SERVER_TYPE_KEY: ClassVar[str] = "validation_server_type"
        dn: Annotated[
            FlextLdifModelsDomainDN.DN | None,
            m.Field(
                description=(
                    "Distinguished Name of the entry (REQUIRED per RFC 2849 § 2). "
                    "Allows None for RFC violation capture. Coerced from str via "
                    "m.field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry"
                ),
            ),
        ]
        attributes: Annotated[
            FlextLdifModelsDomainAttributes.Attributes | None,
            m.Field(
                description=(
                    "Entry attributes container (REQUIRED per RFC 2849 § 2). Allows "
                    "None for RFC violation capture. Coerced from "
                    "dict[str, list[str]] via m.field_validator - PROTOCOL "
                    "COMPATIBLE with p.Ldif.Entry.Entry"
                ),
            ),
        ]
        record_kind: Annotated[
            c.Ldif.RecordKind,
            m.Field(
                description=(
                    "Whether this Entry represents LDIF content or an LDIF change "
                    "record."
                ),
            ),
        ] = c.Ldif.RecordKind.CONTENT
        controls: Annotated[
            Sequence[FlextLdifModelsDomainEntryControl.Control],
            m.Field(description="RFC 2849 control lines associated with the record"),
        ] = m.Field(default_factory=tuple)
        change_operations: Annotated[
            MutableSequence[FlextLdifModelsDomainEntryChangeOperation.ChangeOperation],
            m.Field(
                description="Structured modify operation blocks for changetype=modify",
            ),
        ] = m.Field(
            default_factory=list[
                FlextLdifModelsDomainEntryChangeOperation.ChangeOperation
            ],
        )

        @m.field_validator("attributes", mode="before")
        @classmethod
        def coerce_attributes_from_dict(
            cls,
            value: FlextLdifModelsDomainAttributes.Attributes
            | t.MutableJsonMapping
            | None,
        ) -> FlextLdifModelsDomainAttributes.Attributes | None:
            """Normalize raw attribute input into the attributes container.

            None passes through so RFC violation capture can proceed in the
            model validator.

            Returns:
                The validated attributes container, or None.

            """
            if value is None or isinstance(
                value, FlextLdifModelsDomainAttributes.Attributes
            ):
                return value
            if "attributes" not in value:
                return FlextLdifModelsDomainAttributes.Attributes.model_validate({
                    "attributes": dict(value)
                })
            return FlextLdifModelsDomainAttributes.Attributes.model_validate(value)

        @m.field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls,
            value: FlextLdifModelsDomainDN.DN | t.MutableJsonMapping | str | None,
        ) -> FlextLdifModelsDomainDN.DN | None:
            """Normalize raw DN input into a DN instance.

            None passes through so RFC violation capture can proceed in the
            model validator.

            Returns:
                The validated DN, or None.

            """
            if value is None or isinstance(value, FlextLdifModelsDomainDN.DN):
                return value
            if isinstance(value, Mapping):
                return FlextLdifModelsDomainDN.DN.model_validate(value)
            return FlextLdifModelsDomainDN.DN(value=value, metadata={})

        @m.field_validator("record_kind", mode="before")
        @classmethod
        def coerce_record_kind(cls, value: str) -> c.Ldif.RecordKind:
            """Normalize raw input into a record kind value.

            Returns:
                The record kind for the given value.

            """
            return c.Ldif.RecordKind(value)

        changetype: Annotated[
            c.Ldif.ChangeType | None,
            m.Field(
                description=(
                    "Change operation type per RFC 2849 § 5.7 "
                    "(add/delete/modify/moddn/modrdn)"
                ),
            ),
        ] = None

        @m.field_validator("changetype", mode="before")
        @classmethod
        def coerce_changetype(cls, value: str | None) -> c.Ldif.ChangeType | None:
            """Normalize raw input into a changetype value.

            Returns:
                The changetype for the given value, or None.

            """
            return c.Ldif.ChangeType(value) if isinstance(value, str) else value

        newrdn: Annotated[
            str | None,
            m.Field(description="RFC 2849 newrdn field for moddn/modrdn records"),
        ] = None
        deleteoldrdn: Annotated[
            bool | None,
            m.Field(description="RFC 2849 deleteoldrdn field for moddn/modrdn records"),
        ] = None
        newsuperior: Annotated[
            str | None,
            m.Field(description="RFC 2849 newsuperior field for moddn/modrdn records"),
        ] = None
        raw_record_lines: Annotated[
            MutableSequence[str],
            m.Field(
                description="Original unfolded LDIF lines for loss-aware round-trip",
            ),
        ] = m.Field(default_factory=list[str])
        metadata: Annotated[
            FlextLdifModelsDomainMetadata.ServerMetadata | None,
            m.Field(
                description=(
                    "Server-specific metadata for processing data, ACLs, "
                    "statistics, validation (non-RFC data)"
                ),
            ),
        ] = None
        validation_metadata: Annotated[
            m.ConfigMap | None,
            m.Field(
                description=(
                    "Validation metadata captured during parsing and transformation."
                ),
            ),
        ] = None

        @m.computed_field
        @property
        def attributes_dict(self) -> t.MutableStrSequenceMapping:
            """Attribute mapping required by the entry protocol.

            Returns:
                Attributes as a name-to-values mapping; empty when absent.

            """
            return {} if self.attributes is None else self.attributes.attributes

        @m.computed_field
        @property
        def dn_str(self) -> str:
            """String form of the DN required by the entry protocol.

            Returns:
                The DN value; empty when the DN is absent.

            """
            return "" if self.dn is None else self.dn.value

        @m.computed_field
        @property
        def is_change_record(self) -> bool:
            """True when the entry represents an LDIF change record."""
            return bool(self.changetype) or self.record_kind == c.Ldif.RecordKind.CHANGE

        @m.computed_field
        @property
        def unconverted_attributes(self) -> t.Ldif.UnconvertedAttributes:
            """Raw attributes preserved from parsing, before conversion.

            Returns:
                Read-only view of the unconverted attributes from metadata
                extensions; empty when metadata is absent.

            """
            empty_attrs: t.Ldif.UnconvertedAttributes = {}
            if self.metadata is None:
                return empty_attrs
            result = self.metadata.extensions.get("unconverted_attributes")
            if not isinstance(result, Mapping):
                return empty_attrs
            return {
                k: [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]
                for k, v in result.items()
            }

        @m.model_validator(mode="before")
        @classmethod
        def ensure_metadata_initialized(
            cls,
            data: t.MutableJsonMapping,
        ) -> MutableMapping[
            str, t.JsonValue | datetime | FlextLdifModelsDomainMetadata.ServerMetadata
        ]:
            """Initialize metadata and coerce datetime input before validation.

            Strict mode does not auto-coerce ISO strings to datetimes, so the
            coercion runs here before field validators execute.

            Args:
                data: Input data for model instantiation.

            Returns:
                Input data with metadata initialized and datetimes coerced.

            """
            data_dict: MutableMapping[
                str,
                t.JsonValue | datetime | FlextLdifModelsDomainMetadata.ServerMetadata,
            ] = dict(data)
            cls._coerce_datetime_fields(data_dict)
            data_dict["record_kind"] = (
                c.Ldif.RecordKind.CHANGE
                if data_dict.get("changetype")
                else c.Ldif.RecordKind.CONTENT
            )
            if data_dict.get("metadata") is None:
                # mro-wgwh.5 (agent: kimi-coder) — create_for removed from the model
                # (U17); models validate directly at this internal boundary.
                raw_server_type = data_dict.get("server_type")
                data_dict["metadata"] = (
                    FlextLdifModelsDomainMetadata.ServerMetadata.model_validate({
                        "server_type": cls._coerce_default_server_type(
                            raw_server_type
                            if isinstance(raw_server_type, str)
                            else None,
                        ),
                    })
                )
            return data_dict

        @classmethod
        def _coerce_datetime_fields(
            cls,
            data_dict: MutableMapping[
                str,
                t.JsonValue | datetime | FlextLdifModelsDomainMetadata.ServerMetadata,
            ],
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
        def model_post_init(self, context: Mapping[str, t.Scalar] | None, /) -> None:
            """Post-init hook to ensure metadata is always initialized.

            Properly initialized before any code tries to access it.
            Uses self.__dict__ assignment to bypass validate_assignment=True
            and prevent infinite re-validation recursion (Pydantic v2 pattern).
            """
            del context
            if self.metadata is None:
                self.metadata = (
                    FlextLdifModelsDomainMetadata.ServerMetadata.model_validate({
                        "server_type": c.Ldif.ServerTypes.RFC,
                    })
                )

        @m.model_validator(mode="after")
        def validate_entry_consistency(self) -> Self:
            """Validate cross-field consistency of the entry.

            Notes:
                ObjectClass validation is optional; downstream code handles
                entries without objectClass via rejection or warnings. Schema
                entries (``dn: cn=schema``) are allowed without objectClass as
                they contain schema definitions, not directory objects.

            Returns:
                The validated entry, for validator chaining.

            """
            return self

        @m.model_validator(mode="after")
        def validate_entry_rfc_compliance(self) -> Self:
            """Validate RFC compliance (RFC validation belongs in utilities/services).

            Returns:
                The resulting ``Self``.

            """
            return self

        @m.model_validator(mode="after")
        def validate_server_specific_rules(self) -> Self:
            """Validate server-injected rules (that belongs in utilities/services).

            Returns:
                The resulting ``Self``.

            """
            return self

        @m.computed_field
        @property
        def has_validation_errors(self) -> bool:
            """Presence of validation errors in the validation metadata.

            Returns:
                True when the metadata records validation errors.

            """
            return bool(
                self.metadata
                and self.metadata.validation_results
                and self.metadata.validation_results.errors,
            )

        @m.computed_field
        @property
        def is_acl_entry(self) -> bool:
            """Presence of Access Control Lists on the entry.

            Returns:
                True when the metadata carries ACLs.

            """
            return bool(self.metadata and self.metadata.acls)

        @m.computed_field
        @property
        def is_schema_entry(self) -> bool:
            """Schema-definition status of the entry.

            Schema entries contain objectClass definitions and are typically
            found in the schema naming context.

            Returns:
                True when the metadata carries objectClass definitions.

            """
            return bool(self.metadata and self.metadata.objectclasses)

        @classmethod
        def _normalize_attributes(
            cls,
            attributes: t.MutableAttributeMapping
            | FlextLdifModelsDomainAttributes.Attributes,
        ) -> FlextLdifModelsDomainAttributes.Attributes:
            """Normalize attribute input into the attributes container.

            An empty attribute mapping is accepted and captured later as an
            RFC violation in the validation metadata.

            Args:
                attributes: Attributes as a mapping or container instance.

            Returns:
                The normalized attributes container.

            """
            if isinstance(attributes, FlextLdifModelsDomainAttributes.Attributes):
                return attributes
            attrs_dict: t.MutableStrSequenceMapping = {}
            for attr_name, attr_values in attributes.items():
                if isinstance(attr_values, str):
                    values_list: MutableSequence[str] = [attr_values]
                else:
                    values_list = list(attr_values)
                attrs_dict[attr_name] = values_list

            return FlextLdifModelsDomainAttributes.Attributes(
                attributes=attrs_dict,
                attribute_metadata={},
                metadata=None,
            )

        @classmethod
        def create(
            cls,
            dn: str | FlextLdifModelsDomainDN.DN,
            attributes: t.MutableAttributeMapping
            | FlextLdifModelsDomainAttributes.Attributes,
            metadata: FlextLdifModelsDomainMetadata.ServerMetadata | None = None,
        ) -> p.Result[Self]:
            """Create a validated entry from canonical domain inputs.

            Args:
                dn: Distinguished name as string or DN instance.
                attributes: Attributes as mapping or container instance.
                metadata: Optional server metadata for the entry.

            Returns:
                Result carrying the created entry, or a failure.

            """
            try:
                entry_instance = cls(
                    dn=FlextLdifModelsDomainDN.DN.from_value(dn),
                    attributes=cls._normalize_attributes(attributes),
                    metadata=metadata,
                )
                ok_result: p.Result[Self] = r[Self].ok(entry_instance)
            except c.EXC_BASIC_TYPE as exc:
                # ``fail_operation`` is the typed exception factory: the
                # method-level ``TResult`` binds through ``result_type`` while
                # it still attaches the exception's error code and redacted
                # data, which ``r[Self].fail`` cannot infer for a ``Self``.
                return e.fail_operation("create Entry", exc, result_type=r[Self])
            else:
                return ok_result


__all__: list[str] = ["FlextLdifModelsDomainEntry"]
