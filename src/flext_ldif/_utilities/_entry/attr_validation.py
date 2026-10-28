"""LDIF entry attribute-description validation utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence

from flext_ldif import c, p


class FlextLdifUtilitiesEntryAttrValidation:
    """Validate attribute descriptions, options, and binary payloads."""

    @staticmethod
    def _base_name_violation(base_attr: str) -> str | None:
        """Return the RFC 4512 § 2.5 violation for an attribute base name.

        Returns:
            The resulting ``str | None``.

        """
        if c.Ldif.ATTRIBUTE_NAME_RE.match(base_attr):
            return None
        if not base_attr or not base_attr[0].isalpha():
            return f"RFC 4512 § 2.5: '{base_attr}' must start with letter"
        return f"RFC 4512 § 2.5: '{base_attr}' has invalid characters"

    @staticmethod
    def _option_violation(raw_option: str) -> str | None:
        """Return the RFC 4512 § 2.5 violation for one attribute option.

        Returns:
            The resulting ``str | None``.

        """
        option = raw_option.strip()
        if not option:
            return None
        if c.Ldif.ATTRIBUTE_OPTION_RE.match(option):
            return None
        if not option or not option[0].isalpha():
            return f"RFC 4512 § 2.5: option '{option}' must start with letter"
        return f"RFC 4512 § 2.5: option '{option}' has invalid characters"

    @staticmethod
    def _iter_attribute_parts(
        entry: p.Ldif.Entry,
    ) -> MutableSequence[MutableSequence[str]]:
        """Split each attribute description into base name and options.

        ``entry.attributes`` may be ``None`` when the entry is built with
        ``model_construct`` (bypasses validation).

        Returns:
            The resulting ``MutableSequence[MutableSequence[str]]``.

        """
        if entry.attributes is None or not entry.attributes:
            return []
        return [attr_desc.split(";") for attr_desc in entry.attributes.attributes]

    @staticmethod
    def validate_attribute_descriptions(
        entry: p.Ldif.Entry,
    ) -> MutableSequence[str]:
        """Validate attribute descriptions per RFC 4512 section 2.5.

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        violations: MutableSequence[str] = []
        for parts in FlextLdifUtilitiesEntryAttrValidation._iter_attribute_parts(entry):
            base_violation = FlextLdifUtilitiesEntryAttrValidation._base_name_violation(
                parts[0],
            )
            if base_violation is not None:
                violations.append(base_violation)
            for raw_option in parts[1:]:
                option_violation = (
                    FlextLdifUtilitiesEntryAttrValidation._option_violation(
                        raw_option,
                    )
                )
                if option_violation is not None:
                    violations.append(option_violation)
        return violations

    @staticmethod
    def validate_attribute_syntax(
        entry: p.Ldif.Entry,
    ) -> MutableSequence[str]:
        """Validate attribute name/option syntax per RFC 4512 section 2.5.1-2.5.2.

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        violations: MutableSequence[str] = []
        for parts in FlextLdifUtilitiesEntryAttrValidation._iter_attribute_parts(entry):
            base_name = parts[0]
            if not c.Ldif.ATTRIBUTE_NAME_RE.match(base_name):
                violations.append(f"RFC 4512 § 2.5.1: '{base_name}' invalid syntax")
            if len(parts) > 1:
                invalid_options = [
                    f"RFC 4512 § 2.5.2: option '{option}' invalid syntax"
                    for option in parts[1:]
                    if option and (not c.Ldif.ATTRIBUTE_NAME_RE.match(option))
                ]
                violations.extend(invalid_options)
        return violations

    @staticmethod
    def validate_binary_options(
        entry: p.Ldif.Entry,
    ) -> MutableSequence[str]:
        """Validate binary attribute options per RFC 2849 section 5.2.

        Uses compiled regex for O(1)-per-match detection instead of
        Python char-by-char ord() loops.

        Note: entry.attributes may be None when using model_construct (bypasses
        validation).

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        violations: MutableSequence[str] = []
        if entry.attributes is None or not entry.attributes:
            return violations
        for attr_name, attr_values in entry.attributes.items():
            if ";binary" in attr_name.lower():
                continue
            for value in attr_values:
                if c.Ldif.BINARY_CHAR_RE.search(value):
                    violations.append(
                        f"RFC 2849 § 5.2: '{attr_name}' may need ';binary' option",
                    )
                    break
        return violations


__all__: list[str] = ["FlextLdifUtilitiesEntryAttrValidation"]
