"""Dispatch utilities for FLEXT-LDIF — routes between parent classes."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from pathlib import Path
from typing import Literal, TypeIs, overload

from flext_core import r

from flext_ldif import (
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesFilters,
    FlextLdifUtilitiesNormalization,
    FlextLdifUtilitiesPipeline,
    FlextLdifUtilitiesProcessing,
    FlextLdifUtilitiesResult,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
    m,
    p,
    t,
)


class FlextLdifUtilitiesDispatch:
    """Override dispatchers that route between parent classes."""

    @staticmethod
    def extract_rdn(dn: str) -> r[str]:
        return FlextLdifUtilitiesDN.extract_rdn(dn)

    @staticmethod
    @overload
    def split(dn: str) -> MutableSequence[str]: ...

    @staticmethod
    @overload
    def split(dn: m.Ldif.DN) -> MutableSequence[str]: ...

    @staticmethod
    def split(dn: str | m.Ldif.DN) -> MutableSequence[str]:
        return FlextLdifUtilitiesDN.split(dn)

    @staticmethod
    def has_objectclass(
        entry: m.Ldif.Entry,
        objectclasses: str | tuple[str, ...],
    ) -> bool:
        return FlextLdifUtilitiesEntry.has_objectclass(entry, objectclasses)

    @staticmethod
    def validate_batch(
        values: MutableSequence[str],
        *,
        collect_errors: bool = True,
    ) -> (
        r[MutableSequence[tuple[str, bool, MutableSequence[str]]]]
        | r[MutableSequence[tuple[str, bool, str | None]]]
    ):
        return FlextLdifUtilitiesDN.validate_dn_batch(
            values,
            collect_errors=collect_errors,
        )

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
        parse_parts_hook: Callable[[str], t.MutableContainerMapping]
        | Callable[[str], r[t.MutableContainerMapping]],
    ) -> r[t.MutableContainerMapping]: ...

    @staticmethod
    def parse(
        definition: str | m.Ldif.DN | None,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], t.MutableContainerMapping]
        | Callable[[str], r[t.MutableContainerMapping]]
        | None = None,
    ) -> r[MutableSequence[tuple[str, str]]] | r[t.MutableContainerMapping]:
        if definition is None:
            return r[MutableSequence[tuple[str, str]]].fail("DN cannot be None")
        if isinstance(definition, m.Ldif.DN):
            return FlextLdifUtilitiesDN.parse_dn(definition)
        if parse_parts_hook is None and server_type is None:
            return FlextLdifUtilitiesDN.parse_dn(definition)

        def attr_hook(value: str) -> r[t.MutableContainerMapping]:
            if parse_parts_hook is None:
                return r[t.MutableContainerMapping].ok({})
            parsed_value = parse_parts_hook(value)
            if isinstance(parsed_value, r):
                return parsed_value
            return r[t.MutableContainerMapping].ok(dict(parsed_value))

        return FlextLdifUtilitiesAttribute.resolve_attribute(
            definition=definition,
            server_type=server_type,
            parse_parts_hook=attr_hook if parse_parts_hook is not None else None,
        )

    @staticmethod
    def matches_server_patterns(
        value: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        oid_pattern: t.MutableContainerMapping | str,
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
    def matches(server_type: str, *allowed_types: str) -> bool:
        return FlextLdifUtilitiesServer.matches(server_type, *allowed_types)

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
            value_or_entries,
            *validators,
        )

    @staticmethod
    def validate_entries(
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
        obj: object,
    ) -> bool:
        """Check if value is a Sequence of Entry objects (dispatch helper)."""
        if isinstance(obj, (str, bytes)):
            return False
        if isinstance(obj, list):
            if not obj:
                return True
            return isinstance(obj[0], m.Ldif.Entry)
        if isinstance(obj, tuple):
            if not obj:
                return True
            return isinstance(obj[0], m.Ldif.Entry)
        return False

    # --- MRO conflict resolution: filter (Processing vs Filters vs Result) ---

    @staticmethod
    def filter[T: t.NormalizedValue, R: t.NormalizedValue](
        items_or_entries: T
        | MutableSequence[T]
        | tuple[T, ...]
        | MutableMapping[str, T]
        | MutableSequence[m.Ldif.Entry],
        predicate_or_filter1: Callable[..., bool]
        | FlextLdifUtilitiesFilters[m.Ldif.Entry],
        *filters: FlextLdifUtilitiesFilters[m.Ldif.Entry],
        _mapper: Callable[..., R] | None = None,
        mode: Literal["all", "any"] = "all",
    ) -> (
        t.MutableContainerList
        | t.MutableContainerMapping
        | FlextLdifUtilitiesResult[MutableSequence[m.Ldif.Entry]]
    ):
        """Route to Processing.filter (resolves Processing vs Filters vs Result)."""
        return FlextLdifUtilitiesProcessing.filter_with_predicates(
            items_or_entries,
            predicate_or_filter1,
            *filters,
            _mapper=_mapper,
            mode=mode,
        )

    # --- MRO conflict resolution: fold (CollectionLdif vs Writer) ---

    @staticmethod
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
    def is_entry_sequence(
        obj: object,
    ) -> TypeIs[MutableSequence[m.Ldif.Entry]]:
        """Route to Processing.is_entry_sequence (resolves Processing vs TypeGuards)."""
        return FlextLdifUtilitiesProcessing.is_entry_sequence(obj)

    # --- MRO conflict resolution: Collection methods (CollectionLdif vs FlextUtilities) ---

    @staticmethod
    def or_[T: t.NormalizedValue](
        *values: T | None,
        default: T | None = None,
    ) -> T | None:
        """Route to CollectionLdif.or_ (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.or_(*values, default=default)

    @classmethod
    def try_[TResult](
        cls,
        func: Callable[[], TResult],
        *,
        default: TResult | None = None,
        catch: type[Exception] | tuple[type[Exception], ...] = Exception,
    ) -> TResult | None:
        """Route to CollectionLdif.try_ (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.try_(func, default=default, catch=catch)

    @classmethod
    def update(
        cls,
        data: t.MutableContainerMapping,
        updates: t.MutableContainerMapping,
    ) -> t.MutableContainerMapping:
        """Route to CollectionLdif.update (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.update(data, updates)

    @classmethod
    def omit(
        cls,
        data: t.MutableContainerMapping,
        *keys: str,
    ) -> t.MutableContainerMapping:
        """Route to CollectionLdif.omit (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.omit(data, *keys)

    @staticmethod
    def pick(
        data: t.NormalizedValue,
        *keys: str,
        as_dict: bool = True,
    ) -> t.MutableContainerMapping | t.MutableContainerList:
        """Route to CollectionLdif.pick (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.pick(data, *keys, as_dict=as_dict)

    @classmethod
    def pluck(
        cls,
        items: t.MutableContainerList,
        *,
        key: str | int | Callable[..., t.NormalizedValue],
    ) -> t.MutableContainerList:
        """Route to CollectionLdif.pluck (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.pluck(items, key=key)

    @classmethod
    def prop(cls, key: str) -> Callable[..., t.NormalizedValue]:
        """Route to CollectionLdif.prop (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.prop(key)

    @staticmethod
    def take(
        data_or_items: t.NormalizedValue,
        key_or_n: str | int,
        *,
        as_type: type | None = None,
        default: t.NormalizedValue | None = None,
        from_start: bool = True,
    ) -> t.MutableContainerMapping | t.MutableContainerList | t.NormalizedValue | None:
        """Route to CollectionLdif.take (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.take(
            data_or_items,
            key_or_n,
            as_type=as_type,
            default=default,
            from_start=from_start,
        )

    @staticmethod
    def is_type(
        value: t.NormalizedValue,
        type_spec: str | type | tuple[type, ...],
    ) -> bool:
        """Route to CollectionLdif.is_type (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.is_type(value, type_spec)

    @staticmethod
    def count[T](
        items: MutableSequence[T] | tuple[T, ...],
        predicate: Callable[[T], bool] | None = None,
    ) -> int:
        """Route to CollectionLdif.count (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.count(items, predicate)

    @staticmethod
    def find(
        items: t.ContainerList,
        *,
        predicate: Callable[..., bool],
    ) -> t.NormalizedValue | None:
        """Route to CollectionLdif.find (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.find(items, predicate=predicate)

    @classmethod
    def group_by(
        cls,
        items: t.MutableContainerList,
        *,
        key: Callable[..., t.NormalizedValue],
    ) -> MutableMapping[t.NormalizedValue, t.MutableContainerList]:
        """Route to CollectionLdif.group_by (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.group_by(items, key=key)

    @classmethod
    def partition(
        cls,
        items: t.MutableContainerList,
        *,
        predicate: Callable[..., bool],
    ) -> tuple[t.MutableContainerList, t.MutableContainerList]:
        """Route to CollectionLdif.partition (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.partition(items, predicate=predicate)

    @staticmethod
    def build(
        value: t.NormalizedValue,
        *,
        ops: t.MutableContainerMapping | None = None,
    ) -> t.NormalizedValue:
        """Route to Normalization.build (resolves Normalization vs core)."""
        return FlextLdifUtilitiesNormalization.build(value, ops=ops)

    @staticmethod
    def write_file(
        content: str,
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> r[MutableMapping[str, str | int]]:
        """Route to Writer.write_file (resolves Writer vs core)."""
        path = file_path if isinstance(file_path, Path) else Path(file_path)
        return FlextLdifUtilitiesWriter.write_file(content, path, encoding)

    @staticmethod
    def _is_object_mapping(
        value: t.NormalizedValue,
    ) -> TypeIs[Mapping[str, t.NormalizedValue]]:
        """Route to Schema._is_object_mapping (resolves Schema vs core)."""
        return isinstance(value, Mapping)

    @staticmethod
    def _is_object_sequence(
        value: t.NormalizedValue,
    ) -> TypeIs[t.MutableContainerList]:
        """Route to Schema._is_object_sequence (resolves Schema vs core)."""
        return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


__all__ = ["FlextLdifUtilitiesDispatch"]
