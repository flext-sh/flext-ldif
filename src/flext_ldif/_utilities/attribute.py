"""Attribute utilities for RFC 4512 § 2.5 compliance.

Provides utilities for parsing and validating LDAP attribute descriptions,
including support for attribute options (e.g., displayname;lang-ar).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import Final

from flext_ldif.constants import FlextLdifConstants


class FlextLdifUtilitiesAttribute:
    """Attribute utilities for RFC-compliant attribute operations.

    RFC 4512 § 2.5 - Attribute Descriptions:
        attribute-description = AttributeType *(";" option)

    Examples:
        - displayname (base attribute only)
        - displayname;lang-ar (attribute with language option)
        - userCertificate;binary (attribute with binary option)
        - cn;lang-ja;x-custom (attribute with multiple options)

    """

    # Compiled patterns (compile once at class level for performance)
    _ATTRIBUTE_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
        FlextLdifConstants.LdifPatterns.ATTRIBUTE_NAME
    )
    _ATTRIBUTE_OPTION_PATTERN: Final[re.Pattern[str]] = re.compile(
        FlextLdifConstants.LdifPatterns.ATTRIBUTE_OPTION
    )

    @staticmethod
    def split_attribute_description(
        attribute_description: str,
    ) -> tuple[str, list[str]]:
        """Split attribute description into base name and options.

        RFC 4512 § 2.5:
            attribute-description = AttributeType *(";" option)

        Args:
            attribute_description: Full attribute description (e.g., "displayname;lang-ar")

        Returns:
            Tuple of (base_attribute, [options])

        Examples:
            >>> split_attribute_description("displayname")
            ('displayname', [])

            >>> split_attribute_description("displayname;lang-ar")
            ('displayname', ['lang-ar'])

            >>> split_attribute_description("cn;lang-ja;x-custom")
            ('cn', ['lang-ja', 'x-custom'])

        """
        if not attribute_description:
            return "", []

        # Split on semicolon to separate base attribute from options
        parts = attribute_description.split(";")

        # First part is base attribute, rest are options
        base_attribute = parts[0]
        options = parts[1:] if len(parts) > 1 else []

        return base_attribute, options

    @classmethod
    def validate_attribute_name(cls, attribute_name: str) -> bool:
        """Validate base attribute name against RFC 4512 § 2.5.

        RFC 4512 § 2.5:
            AttributeType = ldap-oid / attr-descr
            attr-descr = ALPHA *(attr-char)
            attr-char = ALPHA / DIGIT / HYPHEN

        Args:
            attribute_name: Base attribute name (WITHOUT options)

        Returns:
            True if valid, False otherwise

        Examples:
            >>> validate_attribute_name("displayname")  # ✓ Valid
            True

            >>> validate_attribute_name("cn")  # ✓ Valid
            True

            >>> validate_attribute_name("displayname;lang-ar")  # ❌ Invalid (has option)
            False

            >>> validate_attribute_name("123invalid")  # ❌ Invalid (starts with digit)
            False

        """
        if not attribute_name:
            return False

        # RFC 4512 constraint: attribute names must not exceed 127 characters
        if len(attribute_name) > FlextLdifConstants.LdifPatterns.MAX_ATTRIBUTE_NAME_LENGTH:
            return False

        # Must match pattern: starts with letter, followed by letters/digits/hyphens
        return cls._ATTRIBUTE_NAME_PATTERN.match(attribute_name) is not None

    @classmethod
    def validate_attribute_option(cls, option: str) -> bool:
        """Validate attribute option against RFC 4512 § 2.5 + RFC 3066.

        RFC 4512 § 2.5:
            option = attr-option-name "=" attr-option-value
                   / attr-option-name
            attr-option-name = ALPHA *(attr-char / "_")

        RFC 3066 (Language Tags):
            Allows underscores in language tags (e.g., es_ES, pt_BR, fr_CA)

        Args:
            option: Single attribute option (WITHOUT leading semicolon)

        Returns:
            True if valid, False otherwise

        Examples:
            >>> validate_attribute_option("lang-ar")  # ✓ Valid
            True

            >>> validate_attribute_option("lang-es_es")  # ✓ Valid (RFC 3066)
            True

            >>> validate_attribute_option("binary")  # ✓ Valid
            True

            >>> validate_attribute_option("x-custom")  # ✓ Valid
            True

            >>> validate_attribute_option("123")  # ❌ Invalid (starts with digit)
            False

        """
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
        """Validate complete attribute description (base + options).

        RFC 4512 § 2.5 compliant validation of full attribute description.

        Args:
            attribute_description: Full attribute description with options

        Returns:
            Tuple of (is_valid, [violations])

        Examples:
            >>> validate_attribute_description("displayname")
            (True, [])

            >>> validate_attribute_description("displayname;lang-ar")
            (True, [])

            >>> validate_attribute_description("123invalid")
            (False, ["Invalid base attribute '123invalid'"])

            >>> validate_attribute_description("cn;123bad")
            (False, ["Invalid option '123bad'"])

        """
        violations: list[str] = []

        # Split into base and options
        base_attr, options = cls.split_attribute_description(attribute_description)

        # Validate base attribute
        if not cls.validate_attribute_name(base_attr):
            violations.append(
                f"Invalid base attribute '{base_attr}' - "
                f"must start with letter and contain only letters, digits, hyphens"
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
