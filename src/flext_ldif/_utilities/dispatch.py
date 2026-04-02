"""Dispatch utilities for FLEXT-LDIF — routes between parent classes."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableSequence, Sequence
from typing import overload

from flext_core import r
from flext_ldif import (
    FlextLdifModelsDomainsEntries,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesPipeline,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesValidation,
    m,
    p,
    t,
)

_Entry = FlextLdifModelsDomainsEntries.Entry
_DN = FlextLdifModelsDomainsEntries.DN


class FlextLdifUtilitiesDispatch:
    """Override dispatchers that route between parent classes."""

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
        value_or_entries: list[_Entry],
        *,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> r[MutableSequence[FlextLdifUtilitiesPipeline.ValidationResult]]: ...

    @staticmethod
    @overload
    def validate(
        value_or_entries: str | _DN,
        *,
        strict: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
    ) -> bool: ...

    @staticmethod
    def validate(
        value_or_entries: list[_Entry] | t.Container | str | _DN,
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
        if isinstance(value_or_entries, str | _DN) and validator_first is None:
            return FlextLdifUtilitiesDN.validate_dn(value_or_entries)
        if (
            FlextLdifUtilitiesDispatch._is_entry_sequence(value_or_entries)
            and validator_first is None
            and isinstance(value_or_entries, list)
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
        if isinstance(value_or_entries, _DN):
            return FlextLdifUtilitiesValidation.validate_value(
                value_or_entries.value,
                *validators,
            )
        if isinstance(value_or_entries, bytes):
            return r[t.Container].fail("bytes value not supported for validation")
        assert not isinstance(value_or_entries, _DN)  # noqa: S101  # narrowed at L196
        return FlextLdifUtilitiesValidation.validate_value(
            value_or_entries,
            *validators,
        )

    @staticmethod
    def _validate_entries(
        entries: list[m.Ldif.Entry],
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
    def _is_entry_sequence(obj: object) -> bool:
        """Check if value is a Sequence of Entry objects (dispatch helper)."""
        if isinstance(obj, (str, bytes)):
            return False
        if isinstance(obj, list):
            return not obj or isinstance(obj[0], m.Ldif.Entry)
        if isinstance(obj, tuple):
            return not obj or isinstance(obj[0], m.Ldif.Entry)
        return False

    # --- MRO conflict resolution: Collection methods (CollectionLdif vs FlextUtilities) ---

    @staticmethod
    def find(
        items: t.ContainerList,
        *,
        predicate: Callable[..., bool],
    ) -> t.NormalizedValue | None:
        """Route to CollectionLdif.find (resolves CollectionLdif vs core)."""
        return FlextLdifUtilitiesCollectionLdif.find(items, predicate=predicate)


__all__ = ["FlextLdifUtilitiesDispatch"]
