"""Power Method Transformers - Entry transformation classes for pipelines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides transformer classes for the power method pipeline system:
    - EntryTransformer: Base class for entry transformations
    - Normalize: DN and attribute normalization transformers
    - Transform: General transformation utilities (replace_base, convert_booleans)

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - Self type for method chaining
    - runtime_checkable protocols

Usage:
    from flext_ldif._utilities.transformers import Normalize, Transform

    # Create transformation pipeline
    result = (
        FlextLdifResult.ok(entries)
        | Normalize.dn(case="lower")
        | Transform.replace_base("dc=old", "dc=new")
    )
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from typing import Literal, cast

from flext_core import FlextResult
from flext_core.utilities import FlextUtilities

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.configs import CaseFoldOption, SpaceHandlingOption
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry

# Aliases for simplified usage - after all imports
u = FlextUtilities  # Utilities
r = FlextResult  # Result

# =========================================================================
# TYPE ALIASES
# =========================================================================

type BooleanFormat = Literal["TRUE/FALSE", "true/false", "1/0", "yes/no"]
"""Boolean format options for attribute value conversion."""


# =========================================================================
# BASE TRANSFORMER CLASS
# =========================================================================


class EntryTransformer[T](ABC):
    """Abstract base class for entry transformers.

    Transformers implement the TransformerProtocol and can be used in
    pipeline chains with the `|` operator on FlextLdifResult.

    Type Parameters:
        T: The type being transformed (typically Entry or list[Entry])

    Subclasses must implement:
        - apply(): Apply transformation to a single item
    """

    __slots__ = ()

    @abstractmethod
    def apply(self, item: T) -> FlextResult[T]:
        """Apply the transformation to an item.

        Args:
            item: The item to transform

        Returns:
            FlextResult containing transformed item or error

        """
        ...

    def apply_batch(self, items: Sequence[T]) -> FlextResult[list[T]]:
        """Apply transformation to a batch of items.

        Default implementation applies transformation sequentially.
        Override for more efficient batch processing.

        Args:
            items: Sequence of items to transform

        Returns:
            FlextResult containing list of transformed items or error

        """
        results: list[T] = []
        batch_result = u.batch(
            list(items),
            self.apply,
            on_error="fail",
        )
        if batch_result.is_failure:
            return r.fail(batch_result.error or "Batch transform failed")
        results = cast("list[T]", batch_result.value["results"])
        return r.ok(results)


# =========================================================================
# NORMALIZE TRANSFORMERS - DN and Attribute normalization
# =========================================================================


class NormalizeDnTransformer(EntryTransformer["FlextLdifModelsDomains.Entry"]):
    """Transformer for DN normalization.

    Normalizes Distinguished Names according to specified options.

    Attributes:
        case: Case folding option (lower, upper, preserve)
        spaces: Space handling option (trim, preserve, normalize)
        validate: Whether to validate DN before normalization

    """

    __slots__ = ("_case", "_spaces", "_validate")

    def __init__(
        self,
        *,
        case: CaseFoldOption = "lower",
        spaces: SpaceHandlingOption = "trim",
        validate: bool = True,
    ) -> None:
        """Initialize DN normalization transformer.

        Args:
            case: Case folding option
            spaces: Space handling option
            validate: Validate DN before normalization

        """
        self._case = case
        self._spaces = spaces
        self._validate = validate

    @staticmethod
    def _validate_dn_components(dn_str: str) -> FlextResult[None]:
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
            return r.fail(f"Invalid DN: {', '.join(all_errors)}")
        return r.ok(None)

    def _normalize_dn_case_and_spaces(self, normalized_dn: str) -> str:
        """Helper: Apply case folding and space handling."""
        # Apply case folding
        if self._case == "lower":
            normalized_dn = normalized_dn.lower()
        elif self._case == "upper":
            normalized_dn = normalized_dn.upper()
        # "preserve" keeps as-is

        # Apply space handling
        if self._spaces == "trim":
            normalized_dn = normalized_dn.strip()
        elif self._spaces == "normalize":
            # Normalize internal spaces (single space between components)
            parts = normalized_dn.split(",")
            normalized_dn = ",".join(p.strip() for p in parts)
        return normalized_dn

    def apply(
        self, item: FlextLdifModelsDomains.Entry
    ) -> FlextResult[FlextLdifModelsDomains.Entry]:
        """Apply DN normalization to an entry.

        Args:
            item: Entry to transform

        Returns:
            FlextResult containing entry with normalized DN

        """
        if item.dn is None:
            return r.fail("Entry has no DN")

        # Get DN string value
        dn_str = item.dn.value if hasattr(item.dn, "value") else str(item.dn)

        # Validate if requested
        if self._validate:
            validation_result = NormalizeDnTransformer._validate_dn_components(dn_str)
            if validation_result.is_failure:
                return validation_result

        # Normalize DN
        norm_result = FlextLdifUtilitiesDN.norm(dn_str)
        if norm_result.is_failure:
            return r.fail(norm_result.error)

        normalized_dn = norm_result.unwrap()
        normalized_dn = self._normalize_dn_case_and_spaces(normalized_dn)

        # Update entry DN (create new DistinguishedName)
        new_dn = FlextLdifModelsDomains.DistinguishedName(value=normalized_dn)
        updated_entry = item.model_copy(update={"dn": new_dn})

        return r.ok(updated_entry)


class NormalizeAttrsTransformer(EntryTransformer["FlextLdifModelsDomains.Entry"]):
    """Transformer for attribute normalization.

    Normalizes attribute names and optionally values.

    Attributes:
        case_fold_names: Whether to lowercase attribute names
        trim_values: Whether to trim whitespace from values
        remove_empty: Whether to remove empty attribute values

    """

    __slots__ = ("_case_fold_names", "_remove_empty", "_trim_values")

    def __init__(
        self,
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        remove_empty: bool = False,
    ) -> None:
        """Initialize attribute normalization transformer.

        Args:
            case_fold_names: Lowercase attribute names
            trim_values: Trim whitespace from values
            remove_empty: Remove empty attribute values

        """
        self._case_fold_names = case_fold_names
        self._trim_values = trim_values
        self._remove_empty = remove_empty

    def apply(
        self, item: FlextLdifModelsDomains.Entry
    ) -> FlextResult[FlextLdifModelsDomains.Entry]:
        """Apply attribute normalization to an entry.

        Args:
            item: Entry to transform

        Returns:
            FlextResult containing entry with normalized attributes

        """
        if item.attributes is None:
            return r.fail("Entry has no attributes")

        # Get attributes dict
        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )

        # Apply case folding to attribute names
        # Note: u.map doesn't support key transformation, so we use dict comprehension
        if self._case_fold_names:
            attrs = {k.lower(): v for k, v in attrs.items()}

        # Process values using u.map to transform each attribute's values
        def process_value_list(values: list[str]) -> list[str]:
            """Process a single attribute's values."""
            processed: list[str] = []
            for value_item in values:
                trimmed_value = value_item.strip() if self._trim_values else value_item
                if self._remove_empty and not trimmed_value:
                    continue
                processed.append(trimmed_value)
            return processed

        new_attrs = u.map(attrs, mapper=lambda _k, v: process_value_list(v))
        needs_update = (
            self._case_fold_names
            or self._trim_values
            or self._remove_empty
            or new_attrs != attrs
        )

        # Update entry with processed attributes if anything changed
        if needs_update:
            new_attributes = FlextLdifModelsDomains.LdifAttributes(attributes=new_attrs)
            item = item.model_copy(update={"attributes": new_attributes})

        return r.ok(item)


class Normalize:
    """Factory class for normalization transformers.

    Provides static methods to create normalization transformers for
    use in pipeline chains.

    Examples:
        >>> result = entries | Normalize.dn(case="lower")
        >>> result = entries | Normalize.attrs(case_fold_names=True)

    """

    __slots__ = ()

    @staticmethod
    def dn(
        *,
        case: CaseFoldOption = "lower",
        spaces: SpaceHandlingOption = "trim",
        validate: bool = True,
    ) -> NormalizeDnTransformer:
        """Create a DN normalization transformer.

        Args:
            case: Case folding option (lower, upper, preserve)
            spaces: Space handling (trim, preserve, normalize)
            validate: Validate DN before normalization

        Returns:
            NormalizeDnTransformer instance

        """
        return NormalizeDnTransformer(case=case, spaces=spaces, validate=validate)

    @staticmethod
    def attrs(
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        remove_empty: bool = False,
    ) -> NormalizeAttrsTransformer:
        """Create an attribute normalization transformer.

        Args:
            case_fold_names: Lowercase attribute names
            trim_values: Trim whitespace from values
            remove_empty: Remove empty attribute values

        Returns:
            NormalizeAttrsTransformer instance

        """
        return NormalizeAttrsTransformer(
            case_fold_names=case_fold_names,
            trim_values=trim_values,
            remove_empty=remove_empty,
        )


# =========================================================================
# TRANSFORM UTILITIES - General transformations
# =========================================================================


class ReplaceBaseDnTransformer(EntryTransformer["FlextLdifModelsDomains.Entry"]):
    """Transformer for replacing base DN in entries.

    Replaces the base DN suffix with a new one.
    """

    __slots__ = ("_case_insensitive", "_new_base", "_old_base")

    def __init__(
        self,
        old_base: str,
        new_base: str,
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize base DN replacement transformer.

        Args:
            old_base: Old base DN to replace
            new_base: New base DN to use
            case_insensitive: Case-insensitive matching

        """
        self._old_base = old_base
        self._new_base = new_base
        self._case_insensitive = case_insensitive

    def apply(
        self, item: FlextLdifModelsDomains.Entry
    ) -> FlextResult[FlextLdifModelsDomains.Entry]:
        """Replace base DN in an entry.

        Args:
            item: Entry to transform

        Returns:
            FlextResult containing entry with replaced base DN

        """
        if item.dn is None:
            return r.fail("Entry has no DN")

        dn_str = item.dn.value if hasattr(item.dn, "value") else str(item.dn)

        # Business Rule: Replace base DN in DN string for server migration
        # Uses transform_dn_attribute which handles single DN string transformation
        # This preserves RFC 4514 compliance and DN normalization per RFC 4514 Section 2
        # Implication: Base DN replacement is critical for cross-server migrations where
        # source and target directories have different base DNs (e.g., dc=example vs dc=example,dc=com)
        new_dn_str = FlextLdifUtilitiesDN.transform_dn_attribute(
            dn_str,
            self._old_base,
            self._new_base,
        )

        # Create new DN and update entry
        new_dn = FlextLdifModelsDomains.DistinguishedName(value=new_dn_str)
        updated_entry = item.model_copy(update={"dn": new_dn})

        return r.ok(updated_entry)


class ConvertBooleansTransformer(EntryTransformer["FlextLdifModelsDomains.Entry"]):
    """Transformer for converting boolean attribute values.

    Converts boolean values between different formats.
    """

    __slots__ = ("_attributes", "_format")

    def __init__(
        self,
        boolean_format: BooleanFormat = "TRUE/FALSE",
        *,
        attributes: Sequence[str] | None = None,
    ) -> None:
        """Initialize boolean conversion transformer.

        Business Rule:
        - Converts boolean attribute values between formats (0/1 vs TRUE/FALSE)
        - Used for server-to-server migration where boolean formats differ
        - Common use case: OID uses 0/1, OUD uses TRUE/FALSE
        - If attributes not specified, converts all known boolean attributes

        Args:
            boolean_format: Target boolean format ("0/1" or "TRUE/FALSE")
            attributes: Specific attributes to convert (None = all boolean attrs)

        """
        self._format = boolean_format
        self._attributes = attributes

    def apply(
        self, item: FlextLdifModelsDomains.Entry
    ) -> FlextResult[FlextLdifModelsDomains.Entry]:
        """Convert boolean attributes in an entry.

        Args:
            item: Entry to transform

        Returns:
            FlextResult containing entry with converted booleans

        """
        # Business Rule: Convert boolean attribute values between formats (0/1 vs TRUE/FALSE)
        # convert_boolean_attributes expects attributes dict and boolean_attr_names set
        # Common LDAP boolean attributes that may need format conversion
        if item.attributes is None:
            return r.ok(item)

        attrs_dict = item.attributes.attributes
        # Common boolean attribute names in LDAP (case-insensitive matching)
        boolean_attrs = {
            "userpassword",
            "pwdaccountlocked",
            "pwdlocked",
            "accountlocked",
            "passwordexpired",
            "passwordneverexpires",
        }

        # Filter to specific attributes if provided
        if self._attributes:
            boolean_attrs = {attr.lower() for attr in self._attributes}

        # Convert boolean attributes
        converted_attrs = FlextLdifUtilitiesEntry.convert_boolean_attributes(
            attributes=attrs_dict,
            boolean_attr_names=boolean_attrs,
            target_format=self._format,
        )

        # Create new entry with converted attributes
        new_attributes = FlextLdifModelsDomains.LdifAttributes(
            attributes=converted_attrs
        )
        updated_entry = item.model_copy(update={"attributes": new_attributes})

        return r.ok(updated_entry)


class FilterAttrsTransformer(EntryTransformer["FlextLdifModelsDomains.Entry"]):
    """Transformer for filtering entry attributes.

    Includes or excludes specific attributes from entries.
    """

    __slots__ = ("_exclude", "_include")

    def __init__(
        self,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ) -> None:
        """Initialize attribute filter transformer.

        Args:
            include: Attributes to include (None = all)
            exclude: Attributes to exclude (applied after include)

        """
        self._include = set(include) if include else None
        self._exclude = set(exclude) if exclude else set()

    def apply(
        self, item: FlextLdifModelsDomains.Entry
    ) -> FlextResult[FlextLdifModelsDomains.Entry]:
        """Filter attributes in an entry.

        Args:
            item: Entry to transform

        Returns:
            FlextResult containing entry with filtered attributes

        """
        if item.attributes is None:
            return r.fail("Entry has no attributes")

        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )

        # Apply include filter using u.filter
        if self._include is not None:
            include_lower = {i.lower() for i in self._include}
            filtered = u.filter(
                attrs,
                predicate=lambda k, _v: k.lower() in include_lower,
            )
            attrs = filtered if isinstance(filtered, dict) else {}

        # Apply exclude filter
        if self._exclude:
            exclude_lower = {e.lower() for e in self._exclude}
            # Use u.filter to exclude attributes by lowercase name
            attrs = dict(
                u.filter(
                    attrs,
                    predicate=lambda k, _v: k.lower() not in exclude_lower,
                )
            )

        # Update entry with filtered attributes
        new_attributes = FlextLdifModelsDomains.LdifAttributes(attributes=attrs)
        updated_entry = item.model_copy(update={"attributes": new_attributes})

        return r.ok(updated_entry)


class RemoveAttrsTransformer(EntryTransformer["FlextLdifModelsDomains.Entry"]):
    """Transformer for removing specific attributes from entries."""

    __slots__ = ("_attributes",)

    def __init__(self, *attributes: str) -> None:
        """Initialize attribute removal transformer.

        Args:
            *attributes: Attribute names to remove

        """
        self._attributes = {attr.lower() for attr in attributes}

    def apply(
        self, item: FlextLdifModelsDomains.Entry
    ) -> FlextResult[FlextLdifModelsDomains.Entry]:
        """Remove attributes from an entry.

        Args:
            item: Entry to transform

        Returns:
            FlextResult containing entry with removed attributes

        """
        # Business Rule: Remove specified attributes from entry for data sanitization
        # remove_attributes expects entry and attributes list (positional args)
        updated_entry = FlextLdifUtilitiesEntry.remove_attributes(
            item,
            list(self._attributes),
        )

        return r.ok(updated_entry)


class CustomTransformer(EntryTransformer["FlextLdifModelsDomains.Entry"]):
    """Transformer using a custom function.

    Allows arbitrary transformations via a callable.
    """

    __slots__ = ("_func",)

    def __init__(
        self,
        func: Callable[
            [FlextLdifModelsDomains.Entry],
            FlextLdifModelsDomains.Entry | FlextResult[FlextLdifModelsDomains.Entry],
        ],
    ) -> None:
        """Initialize custom transformer.

        Args:
            func: Transformation function (returns Entry or FlextResult[Entry])

        """
        self._func = func

    def apply(
        self, item: FlextLdifModelsDomains.Entry
    ) -> FlextResult[FlextLdifModelsDomains.Entry]:
        """Apply custom transformation to an entry.

        Args:
            item: Entry to transform

        Returns:
            FlextResult containing transformed entry

        """
        result = self._func(item)
        if isinstance(result, FlextResult):
            return result
        return r.ok(result)


class Transform:
    """Factory class for general transformers.

    Provides static methods to create transformation objects for
    use in pipeline chains.

    Examples:
        >>> result = entries | Transform.replace_base("dc=old", "dc=new")
        >>> result = entries | Transform.convert_booleans("TRUE/FALSE")

    """

    __slots__ = ()

    @staticmethod
    def replace_base(
        old_base: str,
        new_base: str,
        *,
        case_insensitive: bool = True,
    ) -> ReplaceBaseDnTransformer:
        """Create a base DN replacement transformer.

        Args:
            old_base: Old base DN to replace
            new_base: New base DN to use
            case_insensitive: Case-insensitive matching

        Returns:
            ReplaceBaseDnTransformer instance

        """
        return ReplaceBaseDnTransformer(
            old_base, new_base, case_insensitive=case_insensitive
        )

    @staticmethod
    def convert_booleans(
        boolean_format: BooleanFormat = "TRUE/FALSE",
        *,
        attributes: Sequence[str] | None = None,
    ) -> ConvertBooleansTransformer:
        """Create a boolean conversion transformer.

        Args:
            boolean_format: Target boolean format
            attributes: Specific attributes to convert

        Returns:
            ConvertBooleansTransformer instance

        """
        return ConvertBooleansTransformer(boolean_format, attributes=attributes)

    @staticmethod
    def filter_attrs(
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ) -> FilterAttrsTransformer:
        """Create an attribute filter transformer.

        Args:
            include: Attributes to include (None = all)
            exclude: Attributes to exclude

        Returns:
            FilterAttrsTransformer instance

        """
        return FilterAttrsTransformer(include=include, exclude=exclude)

    @staticmethod
    def remove_attrs(*attributes: str) -> RemoveAttrsTransformer:
        """Create an attribute removal transformer.

        Args:
            *attributes: Attribute names to remove

        Returns:
            RemoveAttrsTransformer instance

        """
        return RemoveAttrsTransformer(*attributes)

    @staticmethod
    def custom(
        func: Callable[
            [FlextLdifModelsDomains.Entry],
            FlextLdifModelsDomains.Entry | FlextResult[FlextLdifModelsDomains.Entry],
        ],
    ) -> CustomTransformer:
        """Create a custom transformer from a function.

        Args:
            func: Transformation function

        Returns:
            CustomTransformer instance

        """
        return CustomTransformer(func)


__all__ = [
    # Type aliases
    "BooleanFormat",
    "ConvertBooleansTransformer",
    "CustomTransformer",
    # Base class
    "EntryTransformer",
    "FilterAttrsTransformer",
    "Normalize",
    "NormalizeAttrsTransformer",
    # Normalize transformers
    "NormalizeDnTransformer",
    "RemoveAttrsTransformer",
    # Transform utilities
    "ReplaceBaseDnTransformer",
    "Transform",
]
