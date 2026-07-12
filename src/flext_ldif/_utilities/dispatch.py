"""Dispatch utilities for FLEXT-LDIF — routes between parent classes."""

from __future__ import annotations

from collections.abc import (
    Callable,
    Sequence,
)
from typing import ClassVar, TypeGuard, overload

from flext_cli import u
from flext_ldif import c, p, r, t
from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
from flext_ldif.models import FlextLdifModels as m


class FlextLdifUtilitiesDispatch:
    """Override dispatchers that route between parent classes."""

    _ENTRY_LIST_ADAPTER: ClassVar[m.TypeAdapter[list[m.Ldif.Entry]]] = m.TypeAdapter(
        list[m.Ldif.Entry],
    )
    _ACL_LIST_ADAPTER: ClassVar[m.TypeAdapter[list[m.Ldif.Acl]]] = m.TypeAdapter(
        list[m.Ldif.Acl],
    )

    @staticmethod
    def as_entry(value: t.Ldif.EntryLike | t.ModelInput) -> m.Ldif.Entry:
        """Coerce an entry-like value into the canonical LDIF entry model."""
        validated: m.Ldif.Entry = m.Ldif.Entry.model_validate(value)
        return validated

    @staticmethod
    def as_entries(
        values: t.SequenceOf[t.Ldif.EntryLike] | m.Ldif.ParseResponse | t.ModelInput,
    ) -> t.MutableSequenceOf[m.Ldif.Entry]:
        """Coerce an entry sequence into canonical LDIF entry models."""
        if isinstance(values, m.Ldif.ParseResponse):
            return values.entries
        validated: t.MutableSequenceOf[m.Ldif.Entry] = (
            FlextLdifUtilitiesDispatch._ENTRY_LIST_ADAPTER.validate_python(values)
        )
        return validated

    @staticmethod
    def as_acl(value: t.Ldif.AclLike | t.ModelInput) -> m.Ldif.Acl:
        """Coerce an ACL-like value into the canonical LDIF ACL model."""
        validated: m.Ldif.Acl = m.Ldif.Acl.model_validate(value)
        return validated

    @staticmethod
    def as_acls(
        values: t.SequenceOf[t.Ldif.AclLike] | t.ModelInput,
    ) -> t.MutableSequenceOf[m.Ldif.Acl]:
        """Coerce an ACL sequence into canonical LDIF ACL models."""
        validated: t.MutableSequenceOf[m.Ldif.Acl] = (
            FlextLdifUtilitiesDispatch._ACL_LIST_ADAPTER.validate_python(values)
        )
        return validated

    @staticmethod
    @overload
    def parse(
        definition: str | m.Ldif.DN | None,
        server_type: str | None = None,
        parse_parts_hook: None = None,
    ) -> p.Result[t.MutableStrPairSequence]: ...

    @staticmethod
    @overload
    def parse(
        definition: str | m.Ldif.DN | None,
        server_type: str | None,
        parse_parts_hook: Callable[[str], t.Ldif.MutableMetadataMapping]
        | Callable[[str], p.Result[t.Ldif.MutableMetadataMapping]],
    ) -> p.Result[t.Ldif.MutableMetadataMapping]: ...

    @staticmethod
    def parse(
        definition: str | m.Ldif.DN | None,
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
        elif isinstance(definition, m.Ldif.DN):
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
        value_or_entries: t.MutableSequenceOf[m.Ldif.Entry]
        | t.JsonValue
        | str
        | m.Ldif.DN,
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
                value_or_entries,
                (str, m.Ldif.DN),
            ):
                result: (
                    p.Result[
                        t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]
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
                t.STR_BYTES_TYPES,
            ):
                result = r[t.JsonValue].fail(
                    "validator call requires scalar, not entry sequence",
                )
            case _ if isinstance(value_or_entries, m.Ldif.DN):
                result = FlextLdifUtilitiesValidation.validate_value(
                    value_or_entries.value,
                    *validators,
                )
            case _:
                validated_value: t.JsonValue = u.normalize_to_json_value(
                    value_or_entries,
                )
                result = FlextLdifUtilitiesValidation.validate_value(
                    validated_value,
                    *validators,
                )
        return result

    @staticmethod
    def _validate_entries(
        entries: t.MutableSequenceOf[m.Ldif.Entry],
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
        obj: t.MutableSequenceOf[m.Ldif.Entry] | t.JsonValue | str | m.Ldif.DN,
    ) -> TypeGuard[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Check if value is a Sequence of Entry objects (dispatch helper)."""
        if isinstance(obj, (str, bytes, m.Ldif.DN)):
            return False
        if not isinstance(obj, Sequence):
            return False
        try:
            FlextLdifUtilitiesDispatch._ENTRY_LIST_ADAPTER.validate_python(obj)
            return True
        except c.EXC_VALIDATION_TYPE:
            return False

    # --- MRO conflict resolution: Collection methods (CollectionLdif vs FlextUtilities) ---

    @staticmethod
    def find(
        items: t.JsonList,
        *,
        predicate: Callable[..., bool],
    ) -> t.JsonValue | None:
        """Route to CollectionLdif.find (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.find(items, predicate=predicate)


__all__: list[str] = ["FlextLdifUtilitiesDispatch"]
