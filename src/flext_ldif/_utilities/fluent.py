"""Power Method Fluent APIs - Fluent operation chains for DN and Entry."""

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
from flext_ldif.typings import t

# REMOVED: Runtime aliases redundantes - use m.* diretamente (já importado com runtime alias)
# Entry: TypeAlias = m.Ldif.Entry  # Use m.Ldif.Entry directly
# Attributes: TypeAlias = m.Ldif.Attributes  # Use m.Ldif.Attributes directly

# DN FLUENT OPERATIONS


class DnOps:
    """Fluent operations for Distinguished Name manipulation."""

    __slots__ = ("_dn", "_error")

    def __init__(self, dn: str) -> None:
        """Initialize DN operations."""
        self._dn: str = dn
        self._error: str | None = None

    def normalize(
        self,
        *,
        case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
    ) -> Self:
        """Normalize the DN."""
        if self._error:
            return self

        result = FlextLdifUtilitiesDN.norm(self._dn)
        if result.is_failure:
            self._error = result.error
            return self

        normalized = result.value

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
        """Clean the DN (remove extra whitespace, normalize escapes)."""
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
        """Replace the base DN."""
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
        """Extract the RDN (Relative Distinguished Name)."""
        if self._error:
            return FlextResult.fail(self._error)

        return FlextLdifUtilitiesDN.extract_rdn(self._dn)

    def extract_parent(self) -> FlextResult[str]:
        """Extract the parent DN."""
        if self._error:
            return FlextResult.fail(self._error)

        return FlextLdifUtilitiesDN.extract_parent_dn(self._dn)

    def split(self) -> FlextResult[list[str]]:
        """Split DN into RDN components."""
        if self._error:
            return FlextResult.fail(self._error)

        # split() returns list[str] directly, wrap in FlextResult
        rdn_components = FlextLdifUtilitiesDN.split(self._dn)
        return FlextResult.ok(rdn_components)

    def is_under(self, base: str) -> bool:
        """Check if DN is under a base DN."""
        if self._error:
            return False

        return FlextLdifUtilitiesDN.is_under_base(self._dn, base)

    def compare(self, other: str, *, _ignore_case: bool = True) -> bool:
        """Compare with another DN."""
        if self._error:
            return False

        compare_result = FlextLdifUtilitiesDN.compare_dns(self._dn, other)
        if compare_result.is_failure:
            return False
        # compare_dns returns int: 0 = equal, <0 = less, >0 = greater
        return compare_result.value == 0

    def validate(self, *, strict: bool = True) -> FlextResult[bool]:
        """Validate the DN."""
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
        """Build and return the final DN."""
        if self._error:
            return FlextResult.fail(self._error)

        return FlextResult.ok(self._dn)

    @property
    def value(self) -> str:
        """Get current DN value (may have errors)."""
        return self._dn

    @property
    def has_error(self) -> bool:
        """Check if an error occurred during operations."""
        return self._error is not None


# ENTRY FLUENT OPERATIONS


class EntryOps:
    """Fluent operations for Entry manipulation."""

    __slots__ = ("_entry", "_error")

    def __init__(self, entry: m.Ldif.Entry) -> None:
        """Initialize entry operations."""
        self._entry = entry
        self._error: str | None = None

    def normalize_dn(
        self,
        *,
        case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
        validate: bool = True,
    ) -> Self:
        """Normalize the entry's DN."""
        if self._error:
            return self

        transformer = Normalize.dn(case=case, validate=validate)
        result = transformer.apply(self._entry)

        if result.is_failure:
            self._error = result.error
            return self

        # result.value returns Entry (m.Ldif.Entry), which matches self._entry type
        self._entry = result.value
        return self

    def normalize_attrs(
        self,
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        remove_empty: bool = False,
    ) -> Self:
        """Normalize the entry's attributes."""
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

        self._entry = result.value
        return self

    def add_attr(self, name: str, *values: str) -> Self:
        """Add an attribute with values."""
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

        # Use dict[str, t.GeneralValueType] for model_copy update (Pydantic accepts object)
        new_attributes = m.Ldif.Attributes(attributes=new_attrs)
        update_dict: dict[str, t.GeneralValueType] = {"attributes": new_attributes}
        self._entry = self._entry.model_copy(update=update_dict)

        return self

    def remove_attr(self, name: str) -> Self:
        """Remove an attribute."""
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
        """Rename an attribute."""
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

        # Use dict[str, t.GeneralValueType] for model_copy update (Pydantic accepts object)
        new_attributes = m.Ldif.Attributes(attributes=new_attrs)
        update_dict: dict[str, t.GeneralValueType] = {"attributes": new_attributes}
        self._entry = self._entry.model_copy(update=update_dict)

        return self

    def filter_attrs(
        self,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
    ) -> Self:
        """Filter attributes."""
        if self._error:
            return self

        transformer = Transform.filter_attrs(include=include, exclude=exclude)
        result = transformer.apply(self._entry)

        if result.is_failure:
            self._error = result.error
            return self

        self._entry = result.value
        return self

    def has_objectclass(
        self,
        *classes: str,
        mode: Literal["any", "all"] = "any",
    ) -> bool:
        """Check if entry has objectClasses."""
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
        """Convert boolean attribute values."""
        if self._error:
            return self

        transformer = Transform.convert_booleans(boolean_format=format_str)
        result = transformer.apply(self._entry)

        if result.is_failure:
            self._error = result.error
            return self

        self._entry = result.value
        return self

    def attach_metadata(self) -> Self:
        """Attach metadata to the entry."""
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
        """Validate the entry."""
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
        """Build and return the final entry."""
        if self._error:
            return FlextResult.fail(self._error)

        return FlextResult.ok(self._entry)

    @property
    def entry(self) -> m.Ldif.Entry:
        """Get current entry (may have errors)."""
        return self._entry

    @property
    def has_error(self) -> bool:
        """Check if an error occurred during operations."""
        return self._error is not None


__all__ = [
    "DnOps",
    "EntryOps",
]
