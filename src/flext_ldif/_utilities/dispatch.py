"""Dispatch utilities for FLEXT-LDIF — routes between parent classes."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableSequence, Sequence
from typing import ClassVar, TypeGuard, overload

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
        list[m.Ldif.Entry]
    )
    _ACL_LIST_ADAPTER: ClassVar[m.TypeAdapter[list[m.Ldif.Acl]]] = m.TypeAdapter(
        list[m.Ldif.Acl]
    )

    @staticmethod
    def as_entry(value: t.Ldif.EntryLike | t.ModelInput) -> m.Ldif.Entry:
        """Coerce an entry-like value into the canonical LDIF entry model."""
        return m.Ldif.Entry.model_validate(value)

    @staticmethod
    def as_entries(
        values: Sequence[t.Ldif.EntryLike] | t.ModelInput,
    ) -> MutableSequence[m.Ldif.Entry]:
        """Coerce an entry sequence into canonical LDIF entry models."""
        return FlextLdifUtilitiesDispatch._ENTRY_LIST_ADAPTER.validate_python(values)

    @staticmethod
    def as_acl(value: t.Ldif.AclLike | t.ModelInput) -> m.Ldif.Acl:
        """Coerce an ACL-like value into the canonical LDIF ACL model."""
        return m.Ldif.Acl.model_validate(value)

    @staticmethod
    def as_acls(
        values: Sequence[t.Ldif.AclLike] | t.ModelInput,
    ) -> MutableSequence[m.Ldif.Acl]:
        """Coerce an ACL sequence into canonical LDIF ACL models."""
        return FlextLdifUtilitiesDispatch._ACL_LIST_ADAPTER.validate_python(values)

    @staticmethod
    @overload
    def parse(
        definition: str | m.Ldif.DN | None,
        server_type: str | None = None,
        parse_parts_hook: None = None,
    ) -> r[MutableSequence[tuple[str, str]]]: ...

    @staticmethod
    @overload
    def parse(
        definition: str | m.Ldif.DN | None,
        server_type: str | None,
        parse_parts_hook: Callable[[str], t.MutableRecursiveContainerMapping]
        | Callable[[str], r[t.MutableRecursiveContainerMapping]],
    ) -> r[t.MutableRecursiveContainerMapping]: ...

    @staticmethod
    def parse(
        definition: str | m.Ldif.DN | None,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], t.MutableRecursiveContainerMapping]
        | Callable[[str], r[t.MutableRecursiveContainerMapping]]
        | None = None,
    ) -> r[MutableSequence[tuple[str, str]]] | r[t.MutableRecursiveContainerMapping]:
        if definition is None:
            return r[t.MutableRecursiveContainerMapping].fail("DN cannot be None")
        if isinstance(definition, m.Ldif.DN):
            return FlextLdifUtilitiesDN.parse_dn(definition)
        if parse_parts_hook is None and server_type is None:
            return FlextLdifUtilitiesDN.parse_dn(definition)
        if parse_parts_hook is None:
            return FlextLdifUtilitiesSchema.parse_attribute(definition)

        def attr_hook(value: str) -> r[t.MutableRecursiveContainerMapping]:
            parsed_value = parse_parts_hook(value)
            if isinstance(parsed_value, r):
                return parsed_value
            return r[t.MutableRecursiveContainerMapping].ok(dict(parsed_value))

        return attr_hook(definition)

    @staticmethod
    def matches_server_patterns(
        value: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        oid_pattern: t.MutableRecursiveContainerMapping | str,
        detection_names: t.RecursiveContainer | frozenset[str],
        detection_string: str | None = None,
        *,
        use_prefix_match: bool = False,
    ) -> bool:
        if isinstance(oid_pattern, Mapping) and (
            not isinstance(detection_names, frozenset)
        ):
            entry_dn = value if isinstance(value, str) else str(value)
            attributes = dict(oid_pattern)
            attr_names_lower = {k.lower() for k in attributes}
            dn_patterns = getattr(detection_names, "dn_patterns", None)
            attr_prefixes = getattr(detection_names, "attr_prefixes", None)
            attr_names = getattr(detection_names, "attr_names", None)
            keyword_patterns = getattr(detection_names, "keyword_patterns", None)
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
    def matches(server_type: str, *allowed_types: str) -> bool:
        return FlextLdifUtilitiesServer.matches(server_type, *allowed_types)

    @staticmethod
    @overload
    def validate(
        value_or_entries: t.Container,
        validator_first: p.ValidatorSpec,
        *validators_rest: p.ValidatorSpec,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> r[t.Container]: ...

    @staticmethod
    @overload
    def validate(
        value_or_entries: MutableSequence[m.Ldif.Entry],
        *,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> r[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]: ...

    @staticmethod
    @overload
    def validate(
        value_or_entries: str | m.Ldif.DN,
        *,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> bool: ...

    @staticmethod
    def validate(
        value_or_entries: MutableSequence[m.Ldif.Entry] | t.Container | str | m.Ldif.DN,
        validator_first: p.ValidatorSpec | None = None,
        *validators_rest: p.ValidatorSpec,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> (
        r[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]
        | r[t.Container]
        | bool
    ):
        """Validate entries against rules."""
        if isinstance(value_or_entries, (str, m.Ldif.DN)) and validator_first is None:
            return FlextLdifUtilitiesDN.validate_dn(value_or_entries)
        if (
            FlextLdifUtilitiesDispatch._is_entry_sequence(value_or_entries)
            and validator_first is None
        ):
            return FlextLdifUtilitiesDispatch._validate_entries(
                value_or_entries,
                strict=strict,
                collect_all=collect_all,
                max_errors=max_errors,
            )
        validators: tuple[p.ValidatorSpec, ...] = (
            (validator_first, *validators_rest) if validator_first else ()
        )
        if isinstance(value_or_entries, Sequence) and (
            not isinstance(value_or_entries, (str, bytes))
        ):
            return r[t.Container].fail(
                "validator call requires scalar, not entry sequence",
            )
        if isinstance(value_or_entries, m.Ldif.DN):
            return FlextLdifUtilitiesValidation.validate_value(
                value_or_entries.value,
                *validators,
            )
        if isinstance(value_or_entries, bytes):
            return r[t.Container].fail("bytes value not supported for validation")
        return FlextLdifUtilitiesValidation.validate_value(
            value_or_entries,
            *validators,
        )

    @staticmethod
    def _validate_entries(
        entries: MutableSequence[m.Ldif.Entry],
        *,
        strict: bool,
        collect_all: bool,
        max_errors: int,
    ) -> r[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]:
        """Internal: Validate LDIF entries."""
        pipeline = FlextLdifUtilitiesPipeline.ValidationPipeline(
            strict=strict,
            collect_all=collect_all,
            max_errors=max_errors,
        )
        return pipeline.validate(entries)

    @staticmethod
    def _is_entry_sequence(
        obj: MutableSequence[m.Ldif.Entry] | t.Container | str | m.Ldif.DN,
    ) -> TypeGuard[MutableSequence[m.Ldif.Entry]]:
        """Check if value is a Sequence of Entry objects (dispatch helper)."""
        if isinstance(obj, (str, bytes, m.Ldif.DN)):
            return False
        if not isinstance(obj, Sequence):
            return False
        try:
            FlextLdifUtilitiesDispatch._ENTRY_LIST_ADAPTER.validate_python(obj)
            return True
        except (c.ValidationError, TypeError):
            return False

    # --- MRO conflict resolution: Collection methods (CollectionLdif vs FlextUtilities) ---

    @staticmethod
    def find(
        items: t.RecursiveContainerList,
        *,
        predicate: Callable[..., bool],
    ) -> t.RecursiveContainer | None:
        """Route to CollectionLdif.find (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.find(items, predicate=predicate)


__all__: list[str] = ["FlextLdifUtilitiesDispatch"]
