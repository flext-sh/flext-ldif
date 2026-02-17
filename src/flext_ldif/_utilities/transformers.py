"""Power Method Transformers - Entry transformation classes for pipelines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence

from flext_core import r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif.constants import c
from flext_ldif.models import FlextLdifModels as m
from flext_ldif.typings import t

# BASE TRANSFORMER CLASS


class EntryTransformer[T](ABC):
    """Abstract base class for entry transformers."""

    __slots__ = ()

    @abstractmethod
    def apply(self, item: T) -> r[T]:
        """Apply the transformation to an item."""
        ...

    def apply_batch(self, items: Sequence[T]) -> r[list[T]]:
        """Apply transformation to a batch of items."""
        return r.traverse(items, self.apply)


class NormalizeDnTransformer(EntryTransformer[m.Ldif.Entry]):
    """Transformer for DN normalization."""

    __slots__ = ("_case", "_spaces", "_validate")

    def __init__(
        self,
        *,
        case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
        spaces: c.Ldif.SpaceHandlingOption = c.Ldif.SpaceHandlingOption.TRIM,
        validate: bool = True,
    ) -> None:
        """Initialize DN normalization transformer."""
        self._case = case
        self._spaces = spaces
        self._validate = validate

    @staticmethod
    def _validate_dn_components(dn_str: str) -> r[bool]:
        """Helper: Validate DN components."""
        components = FlextLdifUtilitiesDN.split(dn_str)
        all_errors: list[str] = []
        for comp in components:
            if "=" not in comp:
                all_errors.append(f"Invalid RDN (missing '='): {comp}")
                continue
            _, _, value = comp.partition("=")
            is_valid, errors = FlextLdifUtilitiesDN.is_valid_dn_string(value.strip())
            if not is_valid:
                all_errors.extend([f"RDN value '{value}': {e}" for e in errors])
        if all_errors:
            return r[bool].fail(f"Invalid DN: {', '.join(all_errors)}")
        return r[bool].ok(True)  # Validation passed

    def _normalize_dn_case_and_spaces(self, normalized_dn: str) -> str:
        """Helper: Apply case folding and space handling."""
        if self._case == "lower":
            normalized_dn = normalized_dn.lower()
        elif self._case == "upper":
            normalized_dn = normalized_dn.upper()

        if self._spaces == "trim":
            normalized_dn = normalized_dn.strip()
        elif self._spaces == "normalize":
            parts = normalized_dn.split(",")
            normalized_dn = ",".join(p.strip() for p in parts)
        return normalized_dn

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Apply DN normalization to an entry."""
        if not isinstance(item, m.Ldif.Entry):
            return r[m.Ldif.Entry].fail(
                f"NormalizeDnTransformer.apply expected m.Ldif.Entry, got {type(item).__name__}: {item}",
            )

        if item.dn is None:
            return r[m.Ldif.Entry].fail("Entry has no DN")

        dn_str = item.dn.value if hasattr(item.dn, "value") else str(item.dn)

        if self._validate:
            validation_result = NormalizeDnTransformer._validate_dn_components(dn_str)
            if validation_result.is_failure:
                error_msg = (
                    str(validation_result.error)
                    if validation_result.error
                    else "DN validation failed"
                )
                return r[m.Ldif.Entry].fail(error_msg)

        norm_result = FlextLdifUtilitiesDN.norm(dn_str)
        if norm_result.is_failure:
            return r[m.Ldif.Entry].fail(norm_result.error)

        normalized_dn = norm_result.value
        normalized_dn = self._normalize_dn_case_and_spaces(normalized_dn)

        new_dn = FlextLdifModelsDomains.DN(value=normalized_dn)
        update_dict: dict[str, t.GeneralValueType] = {"dn": new_dn}
        updated_entry = item.model_copy(update=update_dict)

        return r[m.Ldif.Entry].ok(updated_entry)


class NormalizeAttrsTransformer(EntryTransformer[m.Ldif.Entry]):
    """Transformer for attribute normalization."""

    __slots__ = ("_case_fold_names", "_remove_empty", "_trim_values")

    def __init__(
        self,
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        remove_empty: bool = False,
    ) -> None:
        """Initialize attribute normalization transformer."""
        self._case_fold_names = case_fold_names
        self._trim_values = trim_values
        self._remove_empty = remove_empty

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Apply attribute normalization to an entry."""
        if item.attributes is None:
            return r[m.Ldif.Entry].fail("Entry has no attributes")

        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )

        if self._case_fold_names:
            attrs = {k.lower(): v for k, v in attrs.items()}

        def process_value_list(values: list[str]) -> list[str]:
            """Process a single attribute's values."""
            processed: list[str] = []
            for value_item in values:
                trimmed_value = value_item.strip() if self._trim_values else value_item
                if self._remove_empty and not trimmed_value:
                    continue
                processed.append(trimmed_value)
            return processed

        def map_process_value(_key: str, value: list[str]) -> list[str]:
            """Process value list for attribute."""
            return process_value_list(value)

        new_attrs = {key: map_process_value(key, value) for key, value in attrs.items()}
        needs_update = (
            self._case_fold_names
            or self._trim_values
            or self._remove_empty
            or new_attrs != attrs
        )

        if needs_update:
            new_attributes = FlextLdifModelsDomains.Attributes(attributes=new_attrs)
            update_dict: dict[str, t.GeneralValueType] = {"attributes": new_attributes}
            item = item.model_copy(update=update_dict)

        return r[str].ok(item)


class Normalize:
    """Factory class for normalization transformers."""

    __slots__ = ()

    @staticmethod
    def dn(
        *,
        case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
        spaces: c.Ldif.SpaceHandlingOption = c.Ldif.SpaceHandlingOption.TRIM,
        validate: bool = True,
    ) -> NormalizeDnTransformer:
        """Create a DN normalization transformer."""
        return NormalizeDnTransformer(case=case, spaces=spaces, validate=validate)

    @staticmethod
    def attrs(
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        remove_empty: bool = False,
    ) -> NormalizeAttrsTransformer:
        """Create an attribute normalization transformer."""
        return NormalizeAttrsTransformer(
            case_fold_names=case_fold_names,
            trim_values=trim_values,
            remove_empty=remove_empty,
        )


class ReplaceBaseDnTransformer(EntryTransformer[m.Ldif.Entry]):
    """Transformer for replacing base DN in entries."""

    __slots__ = ("_case_insensitive", "_new_base", "_old_base")

    def __init__(
        self,
        old_base: str,
        new_base: str,
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize base DN replacement transformer."""
        self._old_base = old_base
        self._new_base = new_base
        self._case_insensitive = case_insensitive

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Replace base DN in an entry."""
        if item.dn is None:
            return r[m.Ldif.Entry].fail("Entry has no DN")

        dn_str = item.dn.value if hasattr(item.dn, "value") else str(item.dn)

        new_dn_str = FlextLdifUtilitiesDN.transform_dn_attribute(
            dn_str,
            self._old_base,
            self._new_base,
        )

        new_dn = FlextLdifModelsDomains.DN(value=new_dn_str)
        update_dict: dict[str, t.GeneralValueType] = {"dn": new_dn}
        updated_entry = item.model_copy(update=update_dict)

        return r[str].ok(updated_entry)


class ConvertBooleansTransformer(EntryTransformer[m.Ldif.Entry]):
    """Transformer for converting boolean attribute values."""

    __slots__ = ("_attributes", "_format")

    def __init__(
        self,
        boolean_format: str = "TRUE/FALSE",
        *,
        attributes: Sequence[str] | None = None,
    ) -> None:
        """Initialize boolean conversion transformer."""
        self._format = boolean_format
        self._attributes = attributes

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Convert boolean attributes in an entry."""
        if item.attributes is None:
            return r[str].ok(item)

        attrs_dict = item.attributes.attributes
        boolean_attrs = {
            "userpassword",
            "pwdaccountlocked",
            "pwdlocked",
            "accountlocked",
            "passwordexpired",
            "passwordneverexpires",
        }

        if self._attributes:
            boolean_attrs = {attr.lower() for attr in self._attributes}

        converted_attrs = FlextLdifUtilitiesEntry.convert_boolean_attributes(
            attributes=attrs_dict,
            boolean_attr_names=boolean_attrs,
            target_format=self._format,
        )

        new_attributes = FlextLdifModelsDomains.Attributes(attributes=converted_attrs)
        update_dict: dict[str, t.GeneralValueType] = {"attributes": new_attributes}
        updated_entry = item.model_copy(update=update_dict)

        return r[str].ok(updated_entry)


class FilterAttrsTransformer(EntryTransformer[m.Ldif.Entry]):
    """Transformer for filtering entry attributes."""

    __slots__ = ("_exclude", "_include")

    def __init__(
        self,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ) -> None:
        """Initialize attribute filter transformer."""
        self._include = set(include) if include else None
        self._exclude = set(exclude) if exclude else set()

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Filter attributes in an entry."""
        if item.attributes is None:
            return r[m.Ldif.Entry].fail("Entry has no attributes")

        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )

        if self._include is not None:
            include_lower = {i.lower() for i in self._include}

            def key_in_include(key: str, _value: object) -> bool:
                """Check if key lowercase is in include set."""
                return key.lower() in include_lower

            attrs = {k: v for k, v in attrs.items() if key_in_include(k, v)}

        if self._exclude:
            exclude_lower = {e.lower() for e in self._exclude}

            def key_not_in_exclude(key: str, _value: object) -> bool:
                """Check if key lowercase is not in exclude set."""
                return key.lower() not in exclude_lower

            attrs = {k: v for k, v in attrs.items() if key_not_in_exclude(k, v)}

        new_attributes = FlextLdifModelsDomains.Attributes(attributes=attrs)
        update_dict: dict[str, t.GeneralValueType] = {"attributes": new_attributes}
        updated_entry = item.model_copy(update=update_dict)

        return r[str].ok(updated_entry)


class RemoveAttrsTransformer(EntryTransformer[m.Ldif.Entry]):
    """Transformer for removing specific attributes from entries."""

    __slots__ = ("_attributes",)

    def __init__(self, *attributes: str) -> None:
        """Initialize attribute removal transformer."""
        self._attributes = {attr.lower() for attr in attributes}

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Remove attributes from an entry."""
        updated_entry = FlextLdifUtilitiesEntry.remove_attributes(
            item,  # item is Entry (m.Ldif.Entry), which is what remove_attributes expects
            list(self._attributes),
        )

        return r[str].ok(updated_entry)


class CustomTransformer(EntryTransformer[m.Ldif.Entry]):
    """Transformer using a custom function."""

    __slots__ = ("_func",)

    def __init__(
        self,
        func: Callable[
            [m.Ldif.Entry],
            m.Ldif.Entry | r[m.Ldif.Entry],
        ],
    ) -> None:
        """Initialize custom transformer."""
        self._func = func

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Apply custom transformation to an entry."""
        result = self._func(item)
        if isinstance(result, r):
            return result
        return r[str].ok(result)


class Transform:
    """Factory class for general transformers."""

    __slots__ = ()

    @staticmethod
    def replace_base(
        old_base: str,
        new_base: str,
        *,
        case_insensitive: bool = True,
    ) -> ReplaceBaseDnTransformer:
        """Create a base DN replacement transformer."""
        return ReplaceBaseDnTransformer(
            old_base,
            new_base,
            case_insensitive=case_insensitive,
        )

    @staticmethod
    def convert_booleans(
        boolean_format: str = "TRUE/FALSE",
        *,
        attributes: Sequence[str] | None = None,
    ) -> ConvertBooleansTransformer:
        """Create a boolean conversion transformer."""
        return ConvertBooleansTransformer(boolean_format, attributes=attributes)

    @staticmethod
    def filter_attrs(
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ) -> FilterAttrsTransformer:
        """Create an attribute filter transformer."""
        return FilterAttrsTransformer(include=include, exclude=exclude)

    @staticmethod
    def remove_attrs(*attributes: str) -> RemoveAttrsTransformer:
        """Create an attribute removal transformer."""
        return RemoveAttrsTransformer(*attributes)

    @staticmethod
    def custom(
        func: Callable[
            [m.Ldif.Entry],
            m.Ldif.Entry | r[m.Ldif.Entry],
        ],
    ) -> CustomTransformer:
        """Create a custom transformer from a function."""
        return CustomTransformer(func)


__all__ = [
    "ConvertBooleansTransformer",
    "CustomTransformer",
    "EntryTransformer",
    "FilterAttrsTransformer",
    "Normalize",
    "NormalizeAttrsTransformer",
    "NormalizeDnTransformer",
    "RemoveAttrsTransformer",
    "ReplaceBaseDnTransformer",
    "Transform",
]
