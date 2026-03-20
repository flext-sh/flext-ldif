"""Power Method Fluent APIs - Fluent operation chains for DN and Entry."""

from __future__ import annotations

import struct
from collections.abc import Sequence
from typing import Literal, Self

from flext_core import r

from flext_ldif import c
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.transformers import Normalize, Transform
from flext_ldif.models import m


class DnOps:
    """Fluent operations for Distinguished Name manipulation."""

    __slots__ = ("_dn", "_error")

    def __init__(self, dn: str) -> None:
        """Initialize DN operations."""
        super().__init__()
        self._dn: str = dn
        self._error: str | None = None

    @property
    def has_error(self) -> bool:
        """Check if an error occurred during operations."""
        return self._error is not None

    @property
    def value(self) -> str:
        """Get current DN value (may have errors)."""
        return self._dn

    def build(self) -> r[str]:
        """Build and return the final DN."""
        if self._error:
            return r[str].fail(self._error)
        return r[str].ok(self._dn)

    def clean(self, *, _spaces: bool = True, _escapes: bool = True) -> Self:
        """Clean the DN (remove extra whitespace, normalize escapes)."""
        if self._error:
            return self
        try:
            cleaned = FlextLdifUtilitiesDN.clean_dn(self._dn)
            self._dn = cleaned
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            self._error = str(e)
        return self

    def compare(self, other: str, *, _ignore_case: bool = True) -> bool:
        """Compare with another DN."""
        if self._error:
            return False
        compare_result = FlextLdifUtilitiesDN.compare_dns(self._dn, other)
        if compare_result.is_failure:
            return False
        return compare_result.value == 0

    def extract_parent(self) -> r[str]:
        """Extract the parent DN."""
        if self._error:
            return r[str].fail(self._error)
        return FlextLdifUtilitiesDN.extract_parent_dn(self._dn)

    def extract_rdn(self) -> r[str]:
        """Extract the RDN (Relative Distinguished Name)."""
        if self._error:
            return r[str].fail(self._error)
        return FlextLdifUtilitiesDN.extract_rdn(self._dn)

    def is_under(self, base: str) -> bool:
        """Check if DN is under a base DN."""
        if self._error:
            return False
        return FlextLdifUtilitiesDN.is_under_base(self._dn, base)

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

    def replace_base(self, old_base: str, new_base: str) -> Self:
        """Replace the base DN."""
        if self._error:
            return self
        try:
            self._dn = FlextLdifUtilitiesDN.transform_dn_attribute(
                self._dn,
                old_base,
                new_base,
            )
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            self._error = f"Base DN replacement failed: {e}"
            return self
        return self

    def split(self) -> r[list[str]]:
        """Split DN into RDN components."""
        if self._error:
            return r[list[str]].fail(self._error)
        rdn_components = FlextLdifUtilitiesDN.split(self._dn)
        return r[list[str]].ok(rdn_components)

    def validate(self, *, strict: bool = True) -> r[bool]:
        """Validate the DN."""
        if self._error:
            return r[bool].fail(self._error)
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
            return r[bool].fail(f"Invalid DN: {', '.join(all_errors)}")
        return r[bool].ok(True)


class EntryOps:
    """Fluent operations for Entry manipulation."""

    __slots__ = ("_entry", "_error")

    def __init__(self, entry: m.Ldif.Entry) -> None:
        """Initialize entry operations."""
        super().__init__()
        self._entry = entry
        self._error: str | None = None

    @property
    def entry(self) -> m.Ldif.Entry:
        """Get current entry (may have errors)."""
        return self._entry

    @property
    def has_error(self) -> bool:
        """Check if an error occurred during operations."""
        return self._error is not None

    def add_attr(self, name: str, *values: str) -> Self:
        """Add an attribute with values."""
        if self._error:
            return self
        if self._entry.attributes is None:
            self._error = "Entry has no attributes"
            return self
        attrs = (
            self._entry.attributes.attributes
            if getattr(self._entry.attributes, "attributes", None) is not None
            else {}
        )
        new_attrs = dict(attrs)
        if name in new_attrs:
            new_attrs[name] = list(new_attrs[name]) + list(values)
        else:
            new_attrs[name] = list(values)
        new_attributes = m.Ldif.Attributes(attributes=new_attrs)
        self._entry = self._entry.model_copy(update={"attributes": new_attributes})
        return self

    def attach_metadata(self) -> Self:
        """Attach metadata to the entry."""
        if self._error:
            return self
        metadata = self._entry.metadata
        if metadata is None:
            metadata = m.Ldif.QuirkMetadata.create_for()
        extensions_map = dict(metadata.extensions.items())
        extensions_map["fluent_metadata_attached"] = True
        extensions_map["fluent_metadata_method"] = "EntryOps.attach_metadata"
        updated_extensions = m.Ldif.DynamicMetadata.from_dict(extensions_map)
        updated_metadata = metadata.model_copy(
            update={"extensions": updated_extensions},
        )
        self._entry = self._entry.model_copy(update={"metadata": updated_metadata})
        return self

    def build(self) -> r[m.Ldif.Entry]:
        """Build and return the final entry."""
        if self._error:
            return r[m.Ldif.Entry].fail(self._error)
        return r[m.Ldif.Entry].ok(self._entry)

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
        if mode == "any":
            return any(
                FlextLdifUtilitiesEntry.has_objectclass(self._entry, cls)
                for cls in classes
            )
        return all(
            FlextLdifUtilitiesEntry.has_objectclass(self._entry, cls) for cls in classes
        )

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
        self._entry = result.value
        return self

    def remove_attr(self, name: str) -> Self:
        """Remove an attribute."""
        if self._error:
            return self
        self._entry = FlextLdifUtilitiesEntry.remove_attributes(self._entry, [name])
        return self

    def validate(self, *, strict: bool = True) -> r[bool]:
        """Validate the entry."""
        if self._error:
            return r[bool].fail(self._error)
        if self._entry.dn is None:
            return r[bool].fail("Entry has no DN")
        if self._entry.attributes is None:
            return r[bool].fail("Entry has no attributes")
        dn_str = (
            self._entry.dn.value
            if getattr(self._entry.dn, "value", None) is not None
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
            return r[bool].fail(f"Invalid DN: {', '.join(all_errors)}")
        return r[bool].ok(True)


__all__ = ["DnOps", "EntryOps"]
