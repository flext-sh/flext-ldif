"""Dispatch utilities for FLEXT-LDIF — routes between parent classes."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Literal, TypeIs, overload, override

from flext_core import r

from flext_ldif import (
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesFilters,
    FlextLdifUtilitiesProcessing,
    FlextLdifUtilitiesResult,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesValidation,
    ValidationPipeline,
    ValidationResult,
    m,
    p,
    t,
)


class FlextLdifUtilitiesDispatch:
    """Override dispatchers that route between parent classes."""

    @staticmethod
    @override
    def extract_rdn(dn: str) -> r[str]:
        return FlextLdifUtilitiesDN.extract_rdn(dn)

    @staticmethod
    @overload
    def split(dn: str) -> list[str]: ...

    @staticmethod
    @overload
    def split(dn: m.Ldif.DN) -> list[str]: ...

    @staticmethod
    @override
    def split(dn: str | m.Ldif.DN) -> list[str]:
        return FlextLdifUtilitiesDN.split(dn)

    @staticmethod
    @override
    def has_objectclass(
        entry: m.Ldif.Entry,
        objectclasses: str | tuple[str, ...],
    ) -> bool:
        return FlextLdifUtilitiesEntry.has_objectclass(entry, objectclasses)

    @staticmethod
    @overload
    def validate_batch(
        values: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> r[list[tuple[str, bool, list[str]]]]: ...

    @staticmethod
    @overload
    def validate_batch(
        values: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> r[list[tuple[str, bool, str | None]]]: ...

    @staticmethod
    @override
    def validate_batch(
        values: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> r[list[tuple[str, bool, list[str]]]] | r[list[tuple[str, bool, str | None]]]:
        return FlextLdifUtilitiesDN.validate_dn_batch(
            values,
            collect_errors=collect_errors,
        )

    @staticmethod
    @overload
    def parse(
        definition: str,
    ) -> r[list[tuple[str, str]]]: ...

    @staticmethod
    @overload
    def parse(
        definition: m.Ldif.DN,
    ) -> r[list[tuple[str, str]]]: ...

    @staticmethod
    @overload
    def parse(
        definition: str | m.Ldif.DN,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], Mapping[str, t.NormalizedValue]]
        | Callable[[str], r[dict[str, t.NormalizedValue]]]
        | None = None,
    ) -> r[dict[str, t.NormalizedValue]]: ...

    @staticmethod
    @overload
    def parse(
        definition: str,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], Mapping[str, t.NormalizedValue]]
        | Callable[[str], r[dict[str, t.NormalizedValue]]]
        | None = None,
    ) -> r[dict[str, t.NormalizedValue]]: ...

    @staticmethod
    @override
    def parse(
        definition: str | m.Ldif.DN | None,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], Mapping[str, t.NormalizedValue]]
        | Callable[[str], r[dict[str, t.NormalizedValue]]]
        | None = None,
    ) -> r[list[tuple[str, str]]] | r[dict[str, t.NormalizedValue]]:
        if definition is None:
            return r[list[tuple[str, str]]].fail("DN cannot be None")
        if isinstance(definition, m.Ldif.DN):
            return FlextLdifUtilitiesDN.parse_dn(definition)
        if parse_parts_hook is None and server_type is None:
            return FlextLdifUtilitiesDN.parse_dn(definition)

        def attr_hook(value: str) -> r[dict[str, t.NormalizedValue]]:
            if parse_parts_hook is None:
                return r[dict[str, t.NormalizedValue]].ok({})
            parsed_value = parse_parts_hook(value)
            if isinstance(parsed_value, r):
                return parsed_value
            return r[dict[str, t.NormalizedValue]].ok(dict(parsed_value))

        return FlextLdifUtilitiesAttribute.resolve_attribute(
            definition=definition,
            server_type=server_type,
            parse_parts_hook=attr_hook if parse_parts_hook is not None else None,
        )

    @staticmethod
    @override
    def matches_server_patterns(
        value: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        oid_pattern: Mapping[str, t.NormalizedValue] | str,
        detection_names: t.NormalizedValue | frozenset[str],
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
    @override
    def matches(server_type: str, *allowed_types: str) -> bool:
        return FlextLdifUtilitiesServer.matches(server_type, *allowed_types)

    @staticmethod
    @overload
    def validate(
        value_or_entries: Sequence[m.Ldif.Entry],
        *,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> r[list[ValidationResult]]: ...

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
        value_or_entries: str | m.Ldif.DN,
        *,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> bool: ...

    @staticmethod
    @override
    def validate(
        value_or_entries: Sequence[m.Ldif.Entry] | t.Container | str | m.Ldif.DN,
        validator_first: p.ValidatorSpec | None = None,
        *validators_rest: p.ValidatorSpec,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> r[list[ValidationResult]] | r[t.Container] | bool:
        """Validate entries against rules."""
        if isinstance(value_or_entries, str | m.Ldif.DN) and validator_first is None:
            return FlextLdifUtilitiesDN.validate_dn(value_or_entries)
        if (
            FlextLdifUtilitiesDispatch._is_entry_sequence(value_or_entries)
            and validator_first is None
            and isinstance(value_or_entries, Sequence)
            and not isinstance(value_or_entries, (str, bytes))
        ):
            return FlextLdifUtilitiesDispatch.validate_entries(
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
        return FlextLdifUtilitiesValidation.validate_value(
            value_or_entries, *validators
        )

    @staticmethod
    def validate_entries(
        entries: Sequence[m.Ldif.Entry],
        *,
        strict: bool,
        collect_all: bool,
        max_errors: int,
    ) -> r[list[ValidationResult]]:
        """Internal: Validate LDIF entries."""
        pipeline = ValidationPipeline(
            strict=strict,
            collect_all=collect_all,
            max_errors=max_errors,
        )
        return pipeline.validate(entries)

    @staticmethod
    def _is_entry_sequence(
        obj: t.NormalizedValue,
    ) -> bool:
        """Check if value is a Sequence of Entry objects (dispatch helper)."""
        match obj:
            case str() | bytes():
                return False
            case Sequence() as seq if seq:
                match seq[0]:
                    case m.Ldif.Entry():
                        return True
                    case _:
                        return False
            case Sequence():
                return True
            case _:
                return False

    # --- MRO conflict resolution: filter (Processing vs Filters vs Result) ---

    @staticmethod
    @override
    def filter[T: t.NormalizedValue, R: t.NormalizedValue](
        items_or_entries: T
        | list[T]
        | tuple[T, ...]
        | Mapping[str, T]
        | Sequence[m.Ldif.Entry],
        predicate_or_filter1: Callable[..., bool]
        | FlextLdifUtilitiesFilters[m.Ldif.Entry],
        *filters: FlextLdifUtilitiesFilters[m.Ldif.Entry],
        _mapper: Callable[..., R] | None = None,
        mode: Literal["all", "any"] = "all",
    ) -> (
        list[t.NormalizedValue]
        | Mapping[str, t.NormalizedValue]
        | FlextLdifUtilitiesResult[list[m.Ldif.Entry]]
    ):
        """Route to Processing.filter (resolves Processing vs Filters vs Result)."""
        return FlextLdifUtilitiesProcessing.filter(
            items_or_entries,
            predicate_or_filter1,
            *filters,
            _mapper=_mapper,
            mode=mode,
        )

    # --- MRO conflict resolution: fold (CollectionLdif vs Writer) ---

    @staticmethod
    @override
    def fold(
        items: t.NormalizedValue,
        *,
        initial: t.NormalizedValue,
        folder: Callable[[t.NormalizedValue, t.NormalizedValue], t.NormalizedValue]
        | None = None,
        predicate: Callable[..., bool] | None = None,
    ) -> t.NormalizedValue:
        """Route to CollectionLdif.fold (resolves CollectionLdif vs Writer)."""
        return FlextLdifUtilitiesCollectionLdif.fold(
            items,
            initial=initial,
            folder=folder,
            predicate=predicate,
        )

    # --- MRO conflict resolution: is_entry_sequence (Processing vs TypeGuards) ---

    @staticmethod
    @override
    def is_entry_sequence(
        obj: t.NormalizedValue,
    ) -> TypeIs[Sequence[m.Ldif.Entry]]:
        """Route to Processing.is_entry_sequence (resolves Processing vs TypeGuards)."""
        return FlextLdifUtilitiesProcessing.is_entry_sequence(obj)


__all__ = ["FlextLdifUtilitiesDispatch"]
