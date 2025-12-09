"""Power Method Fluent APIs - Fluent operation chains for DN and Entry.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides fluent operation classes for method chaining:
    - DnOps: Fluent DN operations
    - EntryOps: Fluent entry operations

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - Self type for method chaining
    - FlextResult for error propagation

Usage:
    from flext_ldif._utilities.fluent import DnOps, EntryOps

    # Fluent DN operations
    result = (
        DnOps("CN=Test, DC=Example, DC=Com")
        .normalize(case="lower")
        .clean()
        .replace_base("dc=example,dc=com", "dc=new,dc=com")
        .build()
    )

    # Fluent entry operations
    result = (
        EntryOps(entry)
        .normalize_dn()
        .filter_attrs(exclude=["userPassword"])
        .attach_metadata(source="oid")
        .build()
    )
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, Self

from flext_core import FlextResult

from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.transformers import Normalize, Transform

# Import removed to avoid circular dependency
# Import CaseFoldOption directly to avoid circular import issues
from flext_ldif.constants import c
from flext_ldif.models import m

# REMOVED: Runtime aliases redundantes - use m.* diretamente (já importado com runtime alias)
# Entry: TypeAlias = m.Ldif.Entry  # Use m.Ldif.Entry directly
# LdifAttributes: TypeAlias = m.Ldif.LdifAttributes  # Use m.Ldif.LdifAttributes directly

# =========================================================================
# DN FLUENT OPERATIONS
# =========================================================================


class DnOps:
    """Fluent operations for Distinguished Name manipulation.

    Provides method chaining for common DN operations. Each method
    returns Self for chaining, and build() returns the final FlextResult.

    Examples:
        >>> result = (
        ...     DnOps("CN=Test, DC=Example, DC=Com")
        ...     .normalize(case="lower")
        ...     .clean()
        ...     .replace_base("dc=example,dc=com", "dc=new,dc=com")
        ...     .build()
        ... )
        >>> # result.unwrap() == "cn=test,dc=new,dc=com"

    """

    __slots__ = ("_dn", "_error")

    def __init__(self, dn: str) -> None:
        """Initialize DN operations.

        Args:
            dn: The DN to operate on

        """
        self._dn: str = dn
        self._error: str | None = None

    def normalize(
        self,
        *,
        case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
    ) -> Self:
        """Normalize the DN.

        Args:
            case: Case folding option (lower, upper, preserve)

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        result = FlextLdifUtilitiesDN.norm(self._dn)
        if result.is_failure:
            self._error = result.error
            return self

        normalized = result.unwrap()

        if case == "lower":
            self._dn = normalized.lower()
        elif case == "upper":
            self._dn = normalized.upper()
        else:
            self._dn = normalized

        return self

    def clean(
        self,
        *,
        _spaces: bool = True,
        _escapes: bool = True,
    ) -> Self:
        """Clean the DN (remove extra whitespace, normalize escapes).

        Args:
            _spaces: Clean whitespace (not yet implemented)
            _escapes: Normalize escape sequences (not yet implemented)

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        # clean_dn returns str directly, not FlextResult
        try:
            cleaned = FlextLdifUtilitiesDN.clean_dn(self._dn)
            self._dn = cleaned
        except Exception as e:
            self._error = str(e)

        return self

    def replace_base(self, old_base: str, new_base: str) -> Self:
        """Replace the base DN.

        Args:
            old_base: Old base DN to replace
            new_base: New base DN

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        # Business Rule: Replace base DN in DN string for server migration
        # Uses transform_dn_attribute which handles single DN string transformation
        # This preserves RFC 4514 compliance and DN normalization per RFC 4514 Section 2
        try:
            self._dn = FlextLdifUtilitiesDN.transform_dn_attribute(
                self._dn,
                old_base,
                new_base,
            )
        except Exception as e:
            self._error = f"Base DN replacement failed: {e}"
            return self

        return self

    def extract_rdn(self) -> FlextResult[str]:
        """Extract the RDN (Relative Distinguished Name).

        Business Rule:
        - Extracts leftmost RDN component from DN per RFC 4514
        - Returns RDN as string (e.g., "cn=John" from "cn=John,ou=Users,dc=example")
        - Used for entry identification and DN manipulation operations

        Returns:
            FlextResult containing RDN string (attr=value format)

        """
        if self._error:
            return FlextResult.fail(self._error)

        return FlextLdifUtilitiesDN.extract_rdn(self._dn)

    def extract_parent(self) -> FlextResult[str]:
        """Extract the parent DN.

        Returns:
            FlextResult containing parent DN

        """
        if self._error:
            return FlextResult.fail(self._error)

        return FlextLdifUtilitiesDN.extract_parent_dn(self._dn)

    def split(self) -> FlextResult[list[str]]:
        """Split DN into RDN components.

        Business Rule:
        - Splits DN into individual RDN components per RFC 4514 Section 2
        - Returns list of RDN strings (e.g., ["cn=John", "ou=Users", "dc=example"])
        - Uses parse() method for (attr, value) tuple format if needed

        Returns:
            FlextResult containing list of RDN component strings

        """
        if self._error:
            return FlextResult.fail(self._error)

        # split() returns list[str] directly, wrap in FlextResult
        rdn_components = FlextLdifUtilitiesDN.split(self._dn)
        return FlextResult.ok(rdn_components)

    def is_under(self, base: str) -> bool:
        """Check if DN is under a base DN.

        Args:
            base: Base DN to check

        Returns:
            True if this DN is under the base DN

        """
        if self._error:
            return False

        return FlextLdifUtilitiesDN.is_under_base(self._dn, base)

    def compare(self, other: str, *, _ignore_case: bool = True) -> bool:
        """Compare with another DN.

        Business Rule:
        - Compares two DNs per RFC 4514 (case-insensitive by default)
        - Returns True if DNs are equivalent, False otherwise
        - Uses compare_dns which returns FlextResult[int] (0 = equal, <0 = less, >0 = greater)

        Args:
            other: DN to compare with
            _ignore_case: Ignore case differences (default: True per RFC 4514)

        Returns:
            True if DNs are equivalent (compare_dns returns 0), False otherwise

        """
        if self._error:
            return False

        compare_result = FlextLdifUtilitiesDN.compare_dns(self._dn, other)
        if compare_result.is_failure:
            return False
        # compare_dns returns int: 0 = equal, <0 = less, >0 = greater
        return compare_result.unwrap() == 0

    def validate(self, *, strict: bool = True) -> FlextResult[bool]:
        """Validate the DN.

        Args:
            strict: Use strict RFC validation

        Returns:
            FlextResult containing True if valid

        """
        if self._error:
            return FlextResult.fail(self._error)

        # Validate each RDN value separately
        # is_valid_dn_string validates individual RDN values, not full DN strings
        components = FlextLdifUtilitiesDN.split(self._dn)
        all_errors: list[str] = []
        for comp in components:
            if "=" not in comp:
                all_errors.append(f"Invalid RDN (missing '='): {comp}")
                continue
            _, _, value = comp.partition("=")
            is_valid, errors = FlextLdifUtilitiesDN.is_valid_dn_string(
                value.strip(),
                strict=strict,
            )
            if not is_valid:
                all_errors.extend([f"RDN value '{value}': {e}" for e in errors])

        if all_errors:
            return FlextResult.fail(f"Invalid DN: {', '.join(all_errors)}")

        return FlextResult.ok(True)

    def build(self) -> FlextResult[str]:
        """Build and return the final DN.

        Returns:
            FlextResult containing the processed DN

        """
        if self._error:
            return FlextResult.fail(self._error)

        return FlextResult.ok(self._dn)

    @property
    def value(self) -> str:
        """Get current DN value (may have errors).

        Returns:
            Current DN string

        """
        return self._dn

    @property
    def has_error(self) -> bool:
        """Check if an error occurred during operations.

        Returns:
            True if an error occurred

        """
        return self._error is not None


# =========================================================================
# ENTRY FLUENT OPERATIONS
# =========================================================================


class EntryOps:
    """Fluent operations for Entry manipulation.

    Provides method chaining for common entry operations. Each method
    returns Self for chaining, and build() returns the final FlextResult.

    Examples:
        >>> result = (
        ...     EntryOps(entry)
        ...     .normalize_dn()
        ...     .normalize_attrs()
        ...     .filter_attrs(exclude=["userPassword"])
        ...     .attach_metadata(source="oid")
        ...     .build()
        ... )

    """

    __slots__ = ("_entry", "_error")

    def __init__(self, entry: m.Ldif.Entry) -> None:
        """Initialize entry operations.

        Args:
            entry: The entry to operate on

        """
        self._entry = entry
        self._error: str | None = None

    def normalize_dn(
        self,
        *,
        case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
        validate: bool = True,
    ) -> Self:
        """Normalize the entry's DN.

        Args:
            case: Case folding option
            validate: Validate DN before normalization

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        transformer = Normalize.dn(case=case, validate=validate)
        result = transformer.apply(self._entry)

        if result.is_failure:
            self._error = result.error
            return self

        # result.unwrap() returns Entry (m.Ldif.Entry), which matches self._entry type
        self._entry = result.unwrap()
        return self

    def normalize_attrs(
        self,
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        remove_empty: bool = False,
    ) -> Self:
        """Normalize the entry's attributes.

        Args:
            case_fold_names: Lowercase attribute names
            trim_values: Trim whitespace from values
            remove_empty: Remove empty values

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        transformer = Normalize.attrs(
            case_fold_names=case_fold_names,
            trim_values=trim_values,
            remove_empty=remove_empty,
        )
        result = transformer.apply(self._entry)

        if result.is_failure:
            self._error = result.error
            return self

        self._entry = result.unwrap()
        return self

    def add_attr(self, name: str, *values: str) -> Self:
        """Add an attribute with values.

        Args:
            name: Attribute name
            *values: Attribute values

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        if self._entry.attributes is None:
            self._error = "Entry has no attributes"
            return self

        attrs = (
            self._entry.attributes.attributes
            if hasattr(self._entry.attributes, "attributes")
            else {}
        )
        new_attrs = dict(attrs)

        if name in new_attrs:
            new_attrs[name] = list(new_attrs[name]) + list(values)
        else:
            new_attrs[name] = list(values)

        # Use dict[str, object] for model_copy update (Pydantic accepts object)
        new_attributes = m.Ldif.LdifAttributes(attributes=new_attrs)
        update_dict: dict[str, object] = {"attributes": new_attributes}
        self._entry = self._entry.model_copy(update=update_dict)

        return self

    def remove_attr(self, name: str) -> Self:
        """Remove an attribute.

        Args:
            name: Attribute name to remove

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        # Business Rule: Remove specified attributes from entry for data sanitization
        # remove_attributes expects m.Ldif.Entry, which is what Entry TypeAlias is
        self._entry = FlextLdifUtilitiesEntry.remove_attributes(
            self._entry,
            [name],
        )

        return self

    def rename_attr(self, old_name: str, new_name: str) -> Self:
        """Rename an attribute.

        Args:
            old_name: Current attribute name
            new_name: New attribute name

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        if self._entry.attributes is None:
            self._error = "Entry has no attributes"
            return self

        attrs = (
            self._entry.attributes.attributes
            if hasattr(self._entry.attributes, "attributes")
            else {}
        )
        new_attrs = {}

        # Find and rename attribute (case-insensitive)
        old_lower = old_name.lower()
        for key, values in attrs.items():
            if key.lower() == old_lower:
                new_attrs[new_name] = values
            else:
                new_attrs[key] = values

        # Use dict[str, object] for model_copy update (Pydantic accepts object)
        new_attributes = m.Ldif.LdifAttributes(attributes=new_attrs)
        update_dict: dict[str, object] = {"attributes": new_attributes}
        self._entry = self._entry.model_copy(update=update_dict)

        return self

    def filter_attrs(
        self,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ) -> Self:
        """Filter attributes.

        Args:
            include: Attributes to keep (None = all)
            exclude: Attributes to remove

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        transformer = Transform.filter_attrs(include=include, exclude=exclude)
        result = transformer.apply(self._entry)

        if result.is_failure:
            self._error = result.error
            return self

        self._entry = result.unwrap()
        return self

    def has_objectclass(
        self,
        *classes: str,
        mode: Literal["any", "all"] = "any",
    ) -> bool:
        """Check if entry has objectClasses.

        Args:
            *classes: objectClass names to check
            mode: "any" or "all"

        Returns:
            True if objectClass criteria is met

        """
        if self._error or not classes:
            return False

        # Entry TypeAlias is m.Ldif.Entry, which is what has_objectclass expects
        if mode == "any":
            return any(
                FlextLdifUtilitiesEntry.has_objectclass(self._entry, cls)
                for cls in classes
            )
        # "all"
        return all(
            FlextLdifUtilitiesEntry.has_objectclass(self._entry, cls) for cls in classes
        )

    def convert_booleans(
        self,
        format_str: Literal["TRUE/FALSE", "true/false", "1/0", "yes/no"] = "TRUE/FALSE",
    ) -> Self:
        """Convert boolean attribute values.

        Args:
            format_str: Target boolean format

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        transformer = Transform.convert_booleans(boolean_format=format_str)
        result = transformer.apply(self._entry)

        if result.is_failure:
            self._error = result.error
            return self

        self._entry = result.unwrap()
        return self

    def attach_metadata(
        self,
        **_metadata: str | float | bool | list[str] | None,
    ) -> Self:
        """Attach metadata to the entry.

        Args:
            **_metadata: Key-value pairs to attach as metadata (not yet implemented)

        Returns:
            Self for chaining

        """
        if self._error:
            return self

        # Business Rule: Attach metadata to entry for audit trail and transformation tracking
        # Note: Metadata attachment is not yet implemented
        # This would store metadata in entry.metadata field for round-trip conversions
        # When implemented, use FlextLdifUtilitiesMetadata.attach_metadata() here
        #     metadata=dict(_metadata),
        # )
        # For now, just store error to indicate not implemented
        self._error = "attach_metadata not yet implemented"

        return self

    def validate(
        self,
        *,
        strict: bool = True,
    ) -> FlextResult[bool]:
        """Validate the entry.

        Args:
            strict: Use strict validation

        Returns:
            FlextResult containing True if valid

        """
        if self._error:
            return FlextResult.fail(self._error)

        # Basic validation: DN and attributes must exist
        if self._entry.dn is None:
            return FlextResult.fail("Entry has no DN")

        if self._entry.attributes is None:
            return FlextResult.fail("Entry has no attributes")

        # Validate DN - validate each RDN value separately
        # is_valid_dn_string validates individual RDN values, not full DN strings
        dn_str = (
            self._entry.dn.value
            if hasattr(self._entry.dn, "value")
            else str(self._entry.dn)
        )

        components = FlextLdifUtilitiesDN.split(dn_str)
        all_errors: list[str] = []
        for comp in components:
            if "=" not in comp:
                all_errors.append(f"Invalid RDN (missing '='): {comp}")
                continue
            _, _, value = comp.partition("=")
            is_valid, errors = FlextLdifUtilitiesDN.is_valid_dn_string(
                value.strip(),
                strict=strict,
            )
            if not is_valid:
                all_errors.extend([f"RDN value '{value}': {e}" for e in errors])

        if all_errors:
            return FlextResult.fail(f"Invalid DN: {', '.join(all_errors)}")

        return FlextResult.ok(True)

    def build(self) -> FlextResult[m.Ldif.Entry]:
        """Build and return the final entry.

        Returns:
            FlextResult containing the processed entry

        """
        if self._error:
            return FlextResult.fail(self._error)

        return FlextResult.ok(self._entry)

    @property
    def entry(self) -> m.Ldif.Entry:
        """Get current entry (may have errors).

        Returns:
            Current entry object

        """
        return self._entry

    @property
    def has_error(self) -> bool:
        """Check if an error occurred during operations.

        Returns:
            True if an error occurred

        """
        return self._error is not None


__all__ = [
    "DnOps",
    "EntryOps",
]
