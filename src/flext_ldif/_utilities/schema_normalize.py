"""Schema normalization helpers for FLEXT-LDIF."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_ldif import p, t


class FlextLdifUtilitiesSchemaNormalize:
    """Normalize and compare schema attribute/objectClass values."""

    @staticmethod
    def build_available_attributes_set(
        # NOTE (multi-agent, mro-0ftd.3.7.2): behavior layer accepts protocol (§3.2).
        attributes: t.MutableSequenceOf[p.Ldif.SchemaAttribute],
    ) -> set[str]:
        """Build set of available attribute names (lowercase) for dependency validation."""
        available: set[str] = set()
        for attr_data in attributes:
            attr_name = attr_data.name.lower()
            available.add(attr_name)
        return available

    @staticmethod
    def is_attribute_in_list(
        attribute_name: str | None,
        attribute_list: t.MutableSequenceOf[str] | set[str] | None,
    ) -> bool:
        """Check if attribute exists in list or set (case-insensitive)."""
        if not attribute_name or not attribute_list:
            return False
        normalized_input = FlextLdifUtilitiesSchemaNormalize.normalize_attribute_name(
            attribute_name
        )
        return any(
            FlextLdifUtilitiesSchemaNormalize.normalize_attribute_name(attr)
            == normalized_input
            for attr in attribute_list
        )

    @staticmethod
    def is_boolean_attribute(
        attribute_name: str | None, boolean_attributes: set[str]
    ) -> bool:
        """Check if attribute is in boolean attributes set (case-insensitive)."""
        if not attribute_name or not boolean_attributes:
            return False
        normalized_input = FlextLdifUtilitiesSchemaNormalize.normalize_attribute_name(
            attribute_name
        )
        normalized_set = {
            FlextLdifUtilitiesSchemaNormalize.normalize_attribute_name(attr)
            for attr in boolean_attributes
        }
        return normalized_input in normalized_set

    @staticmethod
    def normalize_attribute_name(
        attribute_name: str | None, *, case_sensitive: bool = False
    ) -> str | None:
        """Normalize attribute name for case-insensitive comparisons."""
        if not attribute_name:
            return attribute_name
        return attribute_name if case_sensitive else attribute_name.lower()

    @staticmethod
    def normalize_matching_rules(
        equality: str | None, substr: str | None = None, **kwargs: t.StrMapping | None
    ) -> tuple[str | None, str | None]:
        """Normalize EQUALITY and SUBSTR matching rules."""
        replacements = kwargs.get("replacements")
        substr_rules_in_equality = kwargs.get("substr_rules_in_equality")
        normalized_substr_values = kwargs.get("normalized_substr_values")
        result_equality = equality
        result_substr = substr
        if (
            substr_rules_in_equality
            and equality
            and (equality in substr_rules_in_equality)
        ):
            result_substr = equality
            result_equality = substr_rules_in_equality[equality]
        if (
            result_substr
            and normalized_substr_values
            and (result_substr in normalized_substr_values)
        ):
            result_substr = normalized_substr_values[result_substr]
        if replacements and result_equality and (result_equality in replacements):
            result_equality = replacements[result_equality]
        return (result_equality, result_substr)

    @staticmethod
    def normalize_name(
        name_value: str | None,
        suffixes_to_remove: t.MutableSequenceOf[str] | None = None,
        char_replacements: t.MutableStrMapping | None = None,
    ) -> str | None:
        """Normalize attribute NAME field."""
        if not name_value:
            return name_value
        result = name_value
        normalized_suffixes = (
            suffixes_to_remove if suffixes_to_remove is not None else [";binary"]
        )
        normalized_replacements = (
            char_replacements if char_replacements is not None else {"_": "-"}
        )
        for suffix in normalized_suffixes:
            if suffix in result:
                result = result.replace(suffix, "")
        for old, new in normalized_replacements.items():
            if old in result:
                result = result.replace(old, new)
        return result if result != name_value else name_value

    @staticmethod
    def normalize_syntax_oid(
        syntax: str | None, *, replacements: t.StrMapping | None = None
    ) -> str | None:
        """Normalize SYNTAX OID field."""
        if not syntax:
            return syntax
        result = syntax
        if result.startswith("'") and result.endswith("'"):
            result = result[1:-1]
        if replacements and result in replacements:
            result = replacements[result]
        return result

    @staticmethod
    def replace_invalid_substr_rule(
        substr: str | None, invalid_rules: t.OptionalStrMapping
    ) -> str | None:
        """Replace invalid SUBSTR rule with valid replacement."""
        if not substr or not invalid_rules:
            return substr
        if substr in invalid_rules:
            replacement: str | None = invalid_rules[substr]
            return replacement
        return substr


__all__: list[str] = ["FlextLdifUtilitiesSchemaNormalize"]
