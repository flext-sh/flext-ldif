"""Attribute utilities for RFC 4512 § 2.5 compliance."""

from __future__ import annotations

import re
from typing import Final

from flext_ldif.constants import c


class FlextLdifUtilitiesAttribute:
    """Attribute utilities for RFC-compliant attribute operations."""

    # Compiled patterns (compile once at class level for performance)
    _ATTRIBUTE_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
        c.Ldif.LdifPatterns.ATTRIBUTE_NAME,
    )
    _ATTRIBUTE_OPTION_PATTERN: Final[re.Pattern[str]] = re.compile(
        c.Ldif.LdifPatterns.ATTRIBUTE_OPTION,
    )

    @staticmethod
    def split_attribute_description(
        attribute_description: str,
    ) -> tuple[str, list[str]]:
        """Split attribute description into base name and options."""
        if not attribute_description:
            msg = "attribute_description cannot be empty or None"
            raise ValueError(msg)

        # Split on semicolon to separate base attribute from options
        parts = attribute_description.split(";")

        # First part is base attribute, rest are options
        base_attribute = parts[0]
        options = parts[1:] if len(parts) > 1 else []

        return base_attribute, options

    @classmethod
    def validate_attribute_name(cls, attribute_name: str) -> bool:
        """Validate base attribute name against RFC 4512 § 2.5."""
        if not attribute_name:
            return False

        # RFC 4512 constraint: attribute names must not exceed 127 characters
        if len(attribute_name) > c.Ldif.LdifPatterns.MAX_ATTRIBUTE_NAME_LENGTH:
            return False

        # Must match pattern: starts with letter, followed by letters/digits/hyphens
        return cls._ATTRIBUTE_NAME_PATTERN.match(attribute_name) is not None

    @classmethod
    def validate_attribute_option(cls, option: str) -> bool:
        """Validate attribute option against RFC 4512 § 2.5 + RFC 3066."""
        if not option:
            return False

        # Handle option with value (e.g., "lang=ar") or without (e.g., "binary")
        option_name = option.split("=", maxsplit=1)[0] if "=" in option else option

        # Option name can have underscores (RFC 3066 language tags)
        # Pattern: starts with letter, followed by letters/digits/hyphens/underscores
        option_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-_]*$")
        return option_pattern.match(option_name) is not None

    @classmethod
    def validate_attribute_description(
        cls,
        attribute_description: str,
    ) -> tuple[bool, list[str]]:
        """Validate complete attribute description (base + options)."""
        violations: list[str] = []

        # Split into base and options
        base_attr, options = cls.split_attribute_description(attribute_description)

        # Validate base attribute
        if not cls.validate_attribute_name(base_attr):
            violations.append(
                f"Invalid base attribute '{base_attr}' - "
                f"must start with letter and contain only letters, digits, hyphens",
            )

        # Validate each option
        violations.extend(
            f"Invalid option '{option}' - "
            f"must start with letter and contain only letters, digits, hyphens, underscores"
            for option in options
            if not cls.validate_attribute_option(option)
        )

        return len(violations) == 0, violations


__all__ = ["FlextLdifUtilitiesAttribute"]
