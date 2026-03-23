"""Attribute utilities for RFC 4512 § 2.5 compliance."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final

from flext_core import r

from flext_ldif import FlextLdifUtilitiesSchema, c, t


class FlextLdifUtilitiesAttribute:
    """Attribute utilities for RFC-compliant attribute operations."""

    _ATTRIBUTE_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
        c.Ldif.ATTRIBUTE_NAME,
    )
    _ATTRIBUTE_OPTION_PATTERN: Final[re.Pattern[str]] = re.compile(
        c.Ldif.ATTRIBUTE_OPTION,
    )

    @classmethod
    def validate_attribute_description(
        cls,
        attribute_description: str,
    ) -> tuple[bool, list[str]]:
        """Validate complete attribute description (base + options)."""
        violations: list[str] = []
        base_attr, options = cls.split_attribute_description(attribute_description)
        if not cls.validate_attribute_name(base_attr):
            violations.append(
                f"Invalid base attribute '{base_attr}' - must start with letter and contain only letters, digits, hyphens",
            )
        violations.extend(
            f"Invalid option '{option}' - must start with letter and contain only letters, digits, hyphens, underscores"
            for option in options
            if not cls.validate_attribute_option(option)
        )
        return (len(violations) == 0, violations)

    @classmethod
    def validate_attribute_name(cls, attribute_name: str) -> bool:
        """Validate base attribute name against RFC 4512 § 2.5."""
        if not attribute_name:
            return False
        if len(attribute_name) > c.Ldif.MAX_ATTRIBUTE_NAME_LENGTH:
            return False
        return cls._ATTRIBUTE_NAME_PATTERN.match(attribute_name) is not None

    @classmethod
    def validate_attribute_option(cls, option: str) -> bool:
        """Validate attribute option against RFC 4512 § 2.5 + RFC 3066."""
        if not option:
            return False
        option_name = option.split("=", maxsplit=1)[0] if "=" in option else option
        option_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-_]*$")
        return option_pattern.match(option_name) is not None

    @staticmethod
    def resolve_attribute(
        definition: str,
        *,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], r[dict[str, t.NormalizedValue]]]
        | None = None,
    ) -> r[dict[str, t.NormalizedValue]]:
        """Parse RFC 4512 attribute definition into structured data."""
        _ = server_type
        if parse_parts_hook:
            return parse_parts_hook(definition)
        return FlextLdifUtilitiesSchema.parse_attribute(definition)

    @staticmethod
    def split_attribute_description(
        attribute_description: str,
    ) -> tuple[str, list[str]]:
        """Split attribute description into base name and options."""
        if not attribute_description:
            msg = "attribute_description cannot be empty or None"
            raise ValueError(msg)
        parts = attribute_description.split(";")
        base_attribute = parts[0]
        options = parts[1:] if len(parts) > 1 else []
        return (base_attribute, options)


__all__ = ["FlextLdifUtilitiesAttribute"]
