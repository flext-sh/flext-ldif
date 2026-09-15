"""Dispatch utilities for FLEXT-LDIF — routes between parent classes."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import ClassVar, TypeGuard, overload

from flext_cli import u

from flext_core import r
from flext_ldif import FlextLdifModels, c, p, t

from .collection_ldif import FlextLdifUtilitiesCollectionLdif
from .dn import FlextLdifUtilitiesDN
from .pipeline import FlextLdifUtilitiesPipeline
from .schema import FlextLdifUtilitiesSchema
from .validation import FlextLdifUtilitiesValidation


class FlextLdifUtilitiesDispatch:
    """Override dispatchers that route between parent classes."""

    _ENTRY_LIST_ADAPTER: ClassVar[
        FlextLdifModels.TypeAdapter[list[FlextLdifModels.Ldif.Entry]]
    ] = FlextLdifModels.TypeAdapter(list[FlextLdifModels.Ldif.Entry])
    _ACL_LIST_ADAPTER: ClassVar[
        FlextLdifModels.TypeAdapter[list[FlextLdifModels.Ldif.Acl]]
    ] = FlextLdifModels.TypeAdapter(list[FlextLdifModels.Ldif.Acl])

    @staticmethod
    def as_entry(value: t.Ldif.EntryLike | t.ModelInput) -> FlextLdifModels.Ldif.Entry:
        """Coerce an entry-like value into the canonical LDIF entry model."""
        validated: FlextLdifModels.Ldif.Entry = (
            FlextLdifModels.Ldif.Entry.model_validate(value)
        )
        return validated

    @staticmethod
    def as_entries(
        values: t.SequenceOf[t.Ldif.EntryLike]
        | FlextLdifModels.Ldif.ParseResponse
        | t.ModelInput,
    ) -> t.MutableSequenceOf[FlextLdifModels.Ldif.Entry]:
        """Coerce an entry sequence into canonical LDIF entry models."""
        if isinstance(values, FlextLdifModels.Ldif.ParseResponse):
            return values.entries
        validated: t.MutableSequenceOf[FlextLdifModels.Ldif.Entry] = (
            FlextLdifUtilitiesDispatch._ENTRY_LIST_ADAPTER.validate_python(values)
        )
        return validated

    @staticmethod
    def as_acl(value: t.Ldif.AclLike | t.ModelInput) -> FlextLdifModels.Ldif.Acl:
        """Coerce an ACL-like value into the canonical LDIF ACL model."""
        validated: FlextLdifModels.Ldif.Acl = FlextLdifModels.Ldif.Acl.model_validate(
            value
        )
        return validated

    @staticmethod
    def as_acls(
        values: t.SequenceOf[t.Ldif.AclLike] | t.ModelInput,
    ) -> t.MutableSequenceOf[FlextLdifModels.Ldif.Acl]:
        """Coerce an ACL sequence into canonical LDIF ACL models."""
        validated: t.MutableSequenceOf[FlextLdifModels.Ldif.Acl] = (
            FlextLdifUtilitiesDispatch._ACL_LIST_ADAPTER.validate_python(values)
        )
        return validated

    @staticmethod
    @overload
    def parse(
        definition: str | FlextLdifModels.Ldif.DN | None,
        server_type: str | None = None,
        parse_parts_hook: None = None,
    ) -> p.Result[t.MutableStrPairSequence]: ...

    @staticmethod
    @overload
    def parse(
        definition: str | FlextLdifModels.Ldif.DN | None,
        server_type: str | None,
        parse_parts_hook: Callable[[str], t.Ldif.MutableMetadataMapping]
        | Callable[[str], p.Result[t.Ldif.MutableMetadataMapping]],
    ) -> p.Result[t.Ldif.MutableMetadataMapping]: ...

    @staticmethod
    def parse(
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
            result = (
                parsed_value
                if isinstance(parsed_value, p.Result)
                else r[t.Ldif.MutableMetadataMapping].ok(dict(parsed_value))
            )
        return result

    @staticmethod
    def validate(
        value_or_entries: t.MutableSequenceOf[FlextLdifModels.Ldif.Entry]
        | t.JsonValue
        | str
        | FlextLdifModels.Ldif.DN,
        *validators: p.ValidatorSpec,
        pipeline: FlextLdifUtilitiesPipeline.ValidationPipeline | None = None,
    ) -> (
        p.Result[t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]]
        | p.Result[t.JsonValue]
        | bool
    ):
        """Validate entries against rules."""
        match True:
            case _ if not validators and isinstance(
                value_or_entries, (str, FlextLdifModels.Ldif.DN)
            ):
                result: (
                    p.Result[
                        t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]
                    ]
                    | p.Result[t.JsonValue]
                    | bool
                ) = FlextLdifUtilitiesDN.validate_dn(value_or_entries)
            case _ if not validators and FlextLdifUtilitiesDispatch._is_entry_sequence(
                value_or_entries
            ):
                result = FlextLdifUtilitiesDispatch._validate_entries(
                    value_or_entries, pipeline=pipeline
                )
            case _ if isinstance(value_or_entries, Sequence) and not isinstance(
                value_or_entries, t.STR_BYTES_TYPES
            ):
                result = r[t.JsonValue].fail(
                    "validator call requires scalar, not entry sequence"
                )
            case _ if isinstance(value_or_entries, FlextLdifModels.Ldif.DN):
                result = FlextLdifUtilitiesValidation.validate_value(
                    value_or_entries.value, *validators
                )
            case _:
                validated_value: t.JsonValue = u.normalize_to_json_value(
                    value_or_entries
                )
                result = FlextLdifUtilitiesValidation.validate_value(
                    validated_value, *validators
                )
        return result

    @staticmethod
    def _validate_entries(
        entries: t.MutableSequenceOf[FlextLdifModels.Ldif.Entry],
        *,
        pipeline: FlextLdifUtilitiesPipeline.ValidationPipeline | None = None,
    ) -> p.Result[t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]]:
        """Validate LDIF entries."""
        validation_pipeline = (
            pipeline or FlextLdifUtilitiesPipeline.ValidationPipeline()
        )
        return validation_pipeline.validate(entries)

    @staticmethod
    def _is_entry_sequence(
        obj: t.MutableSequenceOf[FlextLdifModels.Ldif.Entry]
        | t.JsonValue
        | str
        | FlextLdifModels.Ldif.DN,
    ) -> TypeGuard[t.MutableSequenceOf[FlextLdifModels.Ldif.Entry]]:
        """Check if value is a Sequence of Entry objects (dispatch helper)."""
        if isinstance(obj, (str, bytes, FlextLdifModels.Ldif.DN)):
            return False
        if not isinstance(obj, Sequence):
            return False
        try:
            FlextLdifUtilitiesDispatch._ENTRY_LIST_ADAPTER.validate_python(obj)
        except c.EXC_VALIDATION_TYPE:
            raise
        else:
            return True

    # --- MRO conflict resolution: Collection methods (CollectionLdif vs FlextUtilities) ---

    @staticmethod
    def find(
        items: t.JsonList, *, predicate: Callable[..., bool]
    ) -> t.JsonValue | None:
        """Route to CollectionLdif.find (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.find(items, predicate=predicate)


__all__: list[str] = ["FlextLdifUtilitiesDispatch"]
