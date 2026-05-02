"""Dispatch utilities for FLEXT-LDIF — routes between parent classes."""

from __future__ import annotations

from collections.abc import (
    Callable,
    Mapping,
    Sequence,
)
from typing import ClassVar, TypeGuard, overload

from flext_cli import u
from flext_ldif import (
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesPipeline,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesValidation,
    c,
    m,
    p,
    r,
    t,
)


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
        values: t.SequenceOf[t.Ldif.EntryLike] | t.ModelInput,
    ) -> t.MutableSequenceOf[m.Ldif.Entry]:
        """Coerce an entry sequence into canonical LDIF entry models."""
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
    ) -> p.Result[t.MutableSequenceOf[tuple[str, str]]]: ...

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
    ) -> (
        p.Result[t.MutableSequenceOf[tuple[str, str]]]
        | p.Result[t.Ldif.MutableMetadataMapping]
    ):
        if definition is None:
            return r[t.Ldif.MutableMetadataMapping].fail("DN cannot be None")
        if isinstance(definition, m.Ldif.DN):
            return FlextLdifUtilitiesDN.parse_dn(definition)
        if parse_parts_hook is None and server_type is None:
            return FlextLdifUtilitiesDN.parse_dn(definition)
        if parse_parts_hook is None:
            return FlextLdifUtilitiesSchema.parse_attribute(definition)

        def attr_hook(value: str) -> p.Result[t.Ldif.MutableMetadataMapping]:
            parsed_value = parse_parts_hook(value)
            if isinstance(parsed_value, p.Result):
                return parsed_value
            return r[t.Ldif.MutableMetadataMapping].ok(dict(parsed_value))

        return attr_hook(definition)

    @staticmethod
    def matches_server_patterns(
        value: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        oid_pattern: t.MutableJsonMapping | str,
        detection_names: m.Ldif.ServerPatternsConfig | frozenset[str],
        detection_string: str | None = None,
        *,
        use_prefix_match: bool = False,
    ) -> bool:
        if isinstance(oid_pattern, Mapping) and isinstance(
            detection_names,
            m.Ldif.ServerPatternsConfig,
        ):
            entry_dn = value if isinstance(value, str) else str(value)
            attributes = dict(oid_pattern)
            attr_names_lower = {k.lower() for k in attributes}
            dn_patterns = detection_names.dn_patterns
            attr_prefixes = detection_names.attr_prefixes
            attr_names = detection_names.attr_names
            keyword_patterns = detection_names.keyword_patterns
            if dn_patterns and any(
                all(pattern in entry_dn for pattern in pattern_set)
                for pattern_set in dn_patterns
            ):
                return True
            if attr_prefixes and any(
                attr.startswith(prefix)
                for attr in attributes
                for prefix in attr_prefixes
            ):
                return True
            if attr_names and attr_names_lower & set(attr_names):
                return True
            if keyword_patterns:
                return any(
                    keyword in attr
                    for attr in attr_names_lower
                    for keyword in keyword_patterns
                )
            return False
        if isinstance(oid_pattern, str) and isinstance(detection_names, frozenset):
            return FlextLdifUtilitiesServer.matches_server_patterns(
                value=value,
                oid_pattern=oid_pattern,
                detection_names=detection_names,
                detection_string=detection_string,
                use_prefix_match=use_prefix_match,
            )
        return False

    @staticmethod
    def validate(
        value_or_entries: t.MutableSequenceOf[m.Ldif.Entry]
        | t.JsonValue
        | str
        | m.Ldif.DN,
        validator_first: p.ValidatorSpec | None = None,
        *validators_rest: p.ValidatorSpec,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> (
        p.Result[t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]]
        | p.Result[t.JsonValue]
        | bool
    ):
        """Validate entries against rules."""
        validators: tuple[p.ValidatorSpec, ...] = (
            (validator_first, *validators_rest) if validator_first else ()
        )
        match True:
            case _ if validator_first is None and isinstance(
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
            case _ if (
                validator_first is None
                and FlextLdifUtilitiesDispatch._is_entry_sequence(
                    value_or_entries,
                )
            ):
                result = FlextLdifUtilitiesDispatch._validate_entries(
                    value_or_entries,
                    strict=strict,
                    collect_all=collect_all,
                    max_errors=max_errors,
                )
            case _ if isinstance(value_or_entries, Sequence) and not isinstance(
                value_or_entries,
                (str, bytes),
            ):
                result = r[t.JsonValue].fail(
                    "validator call requires scalar, not entry sequence",
                )
            case _ if isinstance(value_or_entries, bytes):
                result = r[t.JsonValue].fail(
                    "bytes value not supported for validation",
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
        strict: bool,
        collect_all: bool,
        max_errors: int,
    ) -> p.Result[t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]]:
        """Internal: Validate LDIF entries."""
        pipeline = FlextLdifUtilitiesPipeline.ValidationPipeline(
            strict=strict,
            collect_all=collect_all,
            max_errors=max_errors,
        )
        return pipeline.validate(entries)

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
