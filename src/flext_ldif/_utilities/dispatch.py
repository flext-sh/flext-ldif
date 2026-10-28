"""Dispatch utilities for FLEXT-LDIF — routes between parent classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import Callable, MutableSequence, Sequence
from typing import ClassVar, TypeGuard, overload

from flext_cli import u

from flext_ldif import FlextLdifModels, c, p, r, t
from flext_ldif._utilities import (
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesPipeline,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesValidation,
)


class FlextLdifUtilitiesDispatch:
    """Override dispatchers that route between parent classes."""

    _ENTRY_LIST_ADAPTER: ClassVar[
        FlextLdifModels.TypeAdapter[list[FlextLdifModels.Ldif.Entry]]
    ] = u.type_adapter(list[FlextLdifModels.Ldif.Entry])
    _ACL_LIST_ADAPTER: ClassVar[
        FlextLdifModels.TypeAdapter[list[FlextLdifModels.Ldif.Acl]]
    ] = u.type_adapter(list[FlextLdifModels.Ldif.Acl])

    @staticmethod
    def as_entry(
        value: t.ModelInput[t.Ldif.EntryLike] | p.Model,
    ) -> FlextLdifModels.Ldif.Entry:
        """Coerce an entry-like value into the canonical LDIF entry model.

        Returns:
            The resulting ``FlextLdifModels.Ldif.Entry``.

        """
        validated: FlextLdifModels.Ldif.Entry = (
            FlextLdifModels.Ldif.Entry.model_validate(value)
        )
        return validated

    @staticmethod
    def as_entries(
        values: t.ModelInput[Sequence[t.Ldif.EntryLike]]
        | FlextLdifModels.Ldif.ParseResponse
        | p.Ldif.ParseResponse,
    ) -> MutableSequence[FlextLdifModels.Ldif.Entry]:
        """Coerce an entry sequence into canonical LDIF entry models.

        Returns:
            The resulting ``MutableSequence[FlextLdifModels.Ldif.Entry]``.

        """
        if isinstance(
            values, (FlextLdifModels.Ldif.ParseResponse, p.Ldif.ParseResponse)
        ):
            return list(values.entries)
        validated: MutableSequence[FlextLdifModels.Ldif.Entry] = (
            FlextLdifUtilitiesDispatch._ENTRY_LIST_ADAPTER.validate_python(values)
        )
        return validated

    @staticmethod
    def as_acl(value: t.ModelInput[t.Ldif.AclLike]) -> FlextLdifModels.Ldif.Acl:
        """Coerce an ACL-like value into the canonical LDIF ACL model.

        Returns:
            The resulting ``FlextLdifModels.Ldif.Acl``.

        """
        validated: FlextLdifModels.Ldif.Acl = FlextLdifModels.Ldif.Acl.model_validate(
            value,
        )
        return validated

    @staticmethod
    def as_acls(
        values: t.ModelInput[Sequence[t.Ldif.AclLike]],
    ) -> MutableSequence[FlextLdifModels.Ldif.Acl]:
        """Coerce an ACL sequence into canonical LDIF ACL models.

        Returns:
            The resulting ``MutableSequence[FlextLdifModels.Ldif.Acl]``.

        """
        validated: MutableSequence[FlextLdifModels.Ldif.Acl] = (
            FlextLdifUtilitiesDispatch._ACL_LIST_ADAPTER.validate_python(values)
        )
        return validated

    @staticmethod
    @overload
    def parse_definition(
        definition: str | FlextLdifModels.Ldif.DN | None,
        server_type: str | None = None,
        parse_parts_hook: None = None,
    ) -> p.Result[t.MutableStrPairSequence]: ...

    @staticmethod
    @overload
    def parse_definition(
        definition: str | FlextLdifModels.Ldif.DN | None,
        server_type: str | None,
        parse_parts_hook: Callable[[str], t.Ldif.MutableMetadataMapping]
        | Callable[[str], p.Result[t.Ldif.MutableMetadataMapping]],
    ) -> p.Result[t.Ldif.MutableMetadataMapping]: ...

    @staticmethod
    def parse_definition(
        definition: str | FlextLdifModels.Ldif.DN | None,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], t.Ldif.MutableMetadataMapping]
        | Callable[[str], p.Result[t.Ldif.MutableMetadataMapping]]
        | None = None,
    ) -> p.Result[t.MutableStrPairSequence] | p.Result[t.Ldif.MutableMetadataMapping]:

        result: (
            p.Result[t.MutableStrPairSequence] | p.Result[t.Ldif.MutableMetadataMapping]
        )
        if definition is None:
            result = r[t.Ldif.MutableMetadataMapping].fail("DN cannot be None")
        elif isinstance(definition, FlextLdifModels.Ldif.DN):
            result = FlextLdifUtilitiesDN.parse_dn(definition)
        elif parse_parts_hook is None:
            result = (
                FlextLdifUtilitiesDN.parse_dn(definition)
                if server_type is None
                else FlextLdifUtilitiesSchema.parse_attribute(definition)
            )
        else:
            parsed_value = parse_parts_hook(definition)
            if isinstance(parsed_value, p.Result):
                result = parsed_value
            else:
                converted: t.Ldif.MutableMetadataMapping = dict(parsed_value)
                result = r[t.Ldif.MutableMetadataMapping].ok(converted)
        return result

    @staticmethod
    def validate(
        value_or_entries: MutableSequence[FlextLdifModels.Ldif.Entry]
        | t.JsonValue
        | str
        | FlextLdifModels.Ldif.DN,
        *validators: p.ValidatorSpec,
        pipeline: FlextLdifUtilitiesPipeline.ValidationPipeline | None = None,
    ) -> (
        p.Result[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]
        | p.Result[t.JsonValue]
        | bool
    ):
        """Validate entries against rules.

        Returns:
            The resulting
                ``p.Result[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]
                | p.Result[t.JsonValue] | bool``.

        """
        match True:
            case _ if not validators and isinstance(
                value_or_entries,
                (str, FlextLdifModels.Ldif.DN),
            ):
                result: (
                    p.Result[
                        MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]
                    ]
                    | p.Result[t.JsonValue]
                    | bool
                ) = FlextLdifUtilitiesDN.validate_dn(value_or_entries)
            case _ if not validators and FlextLdifUtilitiesDispatch._is_entry_sequence(
                value_or_entries,
            ):
                result = FlextLdifUtilitiesDispatch._validate_entries(
                    value_or_entries,
                    pipeline=pipeline,
                )
            case _ if isinstance(value_or_entries, Sequence) and not isinstance(
                value_or_entries,
                c.STR_BYTES_TYPES,
            ):
                result = r[t.JsonValue].fail(
                    "validator call requires scalar, not entry sequence",
                )
            case _ if isinstance(value_or_entries, FlextLdifModels.Ldif.DN):
                result = FlextLdifUtilitiesValidation.validate_ldif_value(
                    value_or_entries.value,
                    *validators,
                )
            case _:
                validated_value: t.JsonValue = u.normalize_to_json_value(
                    value_or_entries,
                )
                result = FlextLdifUtilitiesValidation.validate_ldif_value(
                    validated_value,
                    *validators,
                )
        return result

    @staticmethod
    def _validate_entries(
        entries: MutableSequence[FlextLdifModels.Ldif.Entry],
        *,
        pipeline: FlextLdifUtilitiesPipeline.ValidationPipeline | None = None,
    ) -> p.Result[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]:
        """Validate LDIF entries.

        Returns:
            The resulting
                ``p.Result[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]``.

        """
        validation_pipeline = (
            pipeline or FlextLdifUtilitiesPipeline.ValidationPipeline()
        )
        return validation_pipeline.validate(entries)

    @staticmethod
    def _is_entry_sequence(
        obj: MutableSequence[FlextLdifModels.Ldif.Entry]
        | t.JsonValue
        | str
        | FlextLdifModels.Ldif.DN,
    ) -> TypeGuard[MutableSequence[FlextLdifModels.Ldif.Entry]]:
        """Check if value is a Sequence of Entry objects (dispatch helper).

        Returns:
            The resulting
                ``TypeGuard[MutableSequence[FlextLdifModels.Ldif.Entry]]``.

        """
        if isinstance(obj, (str, bytes, FlextLdifModels.Ldif.DN)):
            return False
        if not isinstance(obj, Sequence):
            return False
        FlextLdifUtilitiesDispatch._ENTRY_LIST_ADAPTER.validate_python(obj)
        return True


__all__: list[str] = ["FlextLdifUtilitiesDispatch"]
